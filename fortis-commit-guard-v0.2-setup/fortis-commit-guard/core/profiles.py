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


from core.objects import Entry

def classify(path: str, policy: dict, baseline: dict[str, Entry]) -> str:
    helper = policy.get("helper_root", "")
    if helper and path == policy["helper_bundle"]:
        return "userscript"
    if helper and path == helper + "package.json":
        return "package"
    if path in policy["owner_review_files"]:
        return "build-control"
    for relative, role, suffixes in (("src/", "runtime", {".js"}),
                                     ("tests/", "tests", {".mjs", ".json", ".md"}),
                                     ("seed/", "data", {".json"})):
        if helper and path.startswith(helper + relative):
            return role if PurePosixPath(path).suffix in suffixes else "unclassified"
    if PurePosixPath(path).suffix in {".md", ".txt"} and (path.startswith(tuple(policy["documentation_roots"])) or path in policy["root_documents"]):
        return "docs"
    if path in baseline and (path.startswith(tuple(policy["other_project_roots"])) or
                             path.endswith(".json") or path in policy["root_control_files"] or
                             path.startswith(".github/")):
        return "frozen"
    return "unclassified"


def sensitive_control(path: str) -> bool:
    parts = path.split("/")
    name = parts[-1]
    return (path.startswith(".github/") or name in {".gitattributes", ".gitignore", ".gitmodules", ".npmrc", "CODEOWNERS", "AGENTS.md"}
            or ".vscode" in parts or ".devcontainer" in parts or name.startswith("eslint.config."))


