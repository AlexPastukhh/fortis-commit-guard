#!/usr/bin/env python3
"""Read-only inspection of a pinned Git commit. Never imports candidate code."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import unicodedata


from core.objects import GitObjects, GuardError, digest, full_sha, strict_json
from core.profiles import classify, sensitive_control
from core.registry import validate_profile, trusted_execution_sha
from checks.file_content import windows_path_error, without_code_examples, ActiveHtml
from checks.secret_patterns import inspect_secrets
from checks.architecture import inspect_test_presence
ROOT = Path(__file__).resolve().parents[1]
SECURITY_MODULES = ["git-integrity", "file-zones", "windows-paths", "declared-capabilities", "control-changes", "secret-patterns"]

def check(repo: Path, candidate: str, policy: dict, policy_raw: bytes, architecture: bool = False) -> dict:
    validate_profile(policy)
    objects = GitObjects(repo)
    base = full_sha(policy["baseline_commit"])
    candidate = full_sha(candidate)
    tree, files = objects.snapshot(candidate, policy["max_files"])
    _, baseline = objects.snapshot(base, policy["max_files"])
    findings = []
    roles = {}
    changes = []
    javascript = []

    def finding(rule: str, path: str, message: str, severity="error"):
        if len(findings) < 200:
            findings.append({"severity": severity, "rule": rule, "path": path, "message": message})

    ancestry = subprocess.run(objects.command + ["merge-base", "--is-ancestor", base, candidate],
                              env=objects.env, capture_output=True, timeout=30)
    if ancestry.returncode:
        finding("baseline-ancestry", "", "Candidate must descend from the owner-selected baseline")
    folded, total_bytes = {}, 0
    for path, entry in sorted(files.items()):
        before = baseline.get(path)
        changed = before != entry
        if changed:
            changes.append(path)
        error = windows_path_error(path)
        if error:
            finding("windows-path", path, error)
        for i in range(1, len(path.split("/")) + 1):
            partial = "/".join(path.split("/")[:i])
            key = unicodedata.normalize("NFC", partial).casefold()
            if key in folded and folded[key] != partial:
                finding("windows-case-collision", path, "Two paths collide after normalization and case folding")
            folded[key] = partial
        if entry.mode != "100644":
            finding("file-mode", path, "Only regular non-executable files are allowed in this pilot")
            continue
        role = classify(path, policy, baseline)
        roles[role] = roles.get(role, 0) + 1
        if role == "unclassified":
            finding("unclassified-path", path, "Path or file type has no approved profile")
            continue
        if changed and (role == "frozen" or sensitive_control(path)):
            finding("owner-controlled-change", path, "This area needs an owner-approved profile change", "review")
        if changed and role == "build-control":
            finding("build-command-change", path, "Build/verification entrypoints require owner review", "review")
        if changed and role == "tests" and path.endswith(".mjs"):
            finding("test-code-change", path, "Executable test changes require owner review until a Node test capability profile is approved", "review")
        if changed and (path.startswith(tuple(policy["instruction_roots"])) or
                        path.endswith((".prompt.md", ".module.md", ".command.md"))):
            finding("instruction-change", path, "AI instructions need semantic review outside this checker", "review")
        if changed and role == "data":
            finding("projection-data-change", path, "Generated semantic projections need owner review in this first profile", "review")
        try:
            raw = objects.object("blob", entry.oid, policy["max_blob_bytes"])
        except GuardError:
            finding("text-object", path, "Object is too large, corrupt, unavailable, or not UTF-8")
            continue
        total_bytes += len(raw)
        if total_bytes > policy["max_total_bytes"]:
            finding("total-size", "", "Total inspected bytes exceed the approved limit")
            break
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeError:
            finding("text-object", path, "Object is too large, corrupt, unavailable, or not UTF-8")
            continue
        inspect_secrets(text, path, finding)
        if b"\0" in raw or raw.startswith((b"MZ", b"\x7fELF", b"PK\x03\x04")):
            finding("binary-payload", path, "Binary payload is not allowed in these profiles")
        if role == "docs":
            if text.lstrip("\ufeff\r\n ").startswith("#!"):
                finding("docs-interpreter-header", path, "Documentation must not begin with a script interpreter header")
            parser = ActiveHtml()
            parser.feed(without_code_examples(text))
            if parser.active:
                finding("docs-active-html", path, "Known active HTML outside code examples is not allowed")
        if role == "data" or path.endswith(".json"):
            try:
                data = strict_json(text)
            except (json.JSONDecodeError, GuardError):
                finding("invalid-json", path, "JSON data is invalid")
                continue
            if role == "package":
                if not isinstance(data, dict) or set(data) - {"name", "version", "private", "scripts"}:
                    finding("package-capabilities", path, "New package fields/dependencies need owner approval")
                if not isinstance(data, dict) or data.get("scripts") != policy["package_scripts"]:
                    finding("package-scripts", path, "Test/build commands differ from the approved contract")
                if (not isinstance(data, dict) or data.get("name") != policy["package_name"] or
                        data.get("private") is not True or
                        not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", str(data.get("version", "")))):
                    finding("package-identity", path, "Package identity/private flag/version violates the approved contract")
        if role in {"runtime", "userscript"}:
            javascript.append({"path": path, "source": text, "role": role})
        if role == "userscript":
            blocks = re.findall(r"// ==UserScript==\s*\n(.*?)// ==/UserScript==", text, re.S)
            if len(blocks) != 1:
                finding("userscript-header", path, "Exactly one metadata header is required")
            else:
                fields = {}
                for key, value in re.findall(r"^//\s*@([\w-]+)\s+(.+?)\s*$", blocks[0], re.M):
                    fields.setdefault(key, []).append(value)
                for key in policy["userscript_permissions"]:
                    if sorted(fields.get(key, [])) != sorted(policy["userscript_permissions"][key]):
                        finding("userscript-" + key, path, "Declared permissions differ from the approved contract")
                if set(fields) - set(policy["userscript_header_fields"]):
                    finding("userscript-extra-directive", path, "New userscript metadata directives need owner approval")
    for path in sorted(set(baseline) - set(files)):
        changes.append(path)
        if sensitive_control(path) or classify(path, policy, baseline) in {"frozen", "build-control", "package", "userscript"}:
            finding("protected-file-removed", path, "Removing this baseline file requires owner approval", "review")
    enabled_architecture = architecture or policy["architecture"]["enabled"]
    if enabled_architecture:
        inspect_test_presence(files, baseline, policy["test_roots"], finding)
    if javascript:
        node = shutil.which("node")
        if not node:
            raise GuardError("Pinned JavaScript analysis runtime is unavailable")
        analyzer = ROOT / "js_guard.mjs"
        result = subprocess.run([node, "--max-old-space-size=256", str(analyzer)],
                                input=json.dumps({"files": javascript, "policy": policy}).encode(),
                                capture_output=True, timeout=45, check=False)
        if result.returncode:
            raise GuardError("JavaScript analysis failed closed")
        findings.extend(strict_json(result.stdout.decode("utf-8")))
    trusted_files = sorted(["guard.py", "js_guard.mjs", "fetch_candidate.py", "registry.json", "modules.json", "vendor/acorn.cjs"] + [str(p.relative_to(ROOT)) for folder in ["core", "checks"] for p in (ROOT / folder).glob("*.py")])
    toolchain = "\n".join(name + ":" + digest((ROOT / name).read_bytes()) for name in trusted_files)
    status = "FAIL" if any(f["severity"] == "error" for f in findings) else "REVIEW_REQUIRED" if findings else "PASS"
    return {
        "status": status, "scope": "security-baseline-v2", "repository": policy["repository"],
        "architecture_enabled": enabled_architecture,
        "modules": {"required_security": SECURITY_MODULES, "architecture": "enabled" if enabled_architecture else "disabled-by-profile"},
        "execution_guard_sha": trusted_execution_sha(),
        "candidate_sha": candidate, "candidate_tree": tree, "baseline_sha": base,
        "policy_sha256": digest(policy_raw), "checker_sha256": digest((ROOT / "guard.py").read_bytes()),
        "toolchain_sha256": digest(toolchain.encode("utf-8")),
        "checked_files": len(files), "checked_bytes": total_bytes, "roles": roles,
        "changed_paths": sorted(changes), "findings": findings,
        "candidate_code_executed": False, "windows_execution_approved": False,
        "limitations": ["AST checks are not complete JavaScript dataflow/behavior analysis",
                        "Markdown filter is not a complete renderer/sanitizer",
                        "No proof of absence of malicious behavior",
                        "Secret patterns cover private-key payloads and common GitHub token prefixes only",
                        "Runtime behavior and dependency vulnerabilities are not tested by this version",
                        "A local report is not an authoritative external CI result"],
    }


