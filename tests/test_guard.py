import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zlib

import guard

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / "profiles/obs-planning-docs.json").read_text())
HELPER = POLICY["helper_root"]
BUNDLE = POLICY["helper_bundle"]
DOC = "planning/documentation/testing-planning/guide.md"
LEGACY = "planning/documentation/tools/replacement-package-app/src/main/java/Fixture.java"


def userscript(extra=""):
    return ("// ==UserScript==\n"
            "// @name Fixture\n// @namespace https://github.com/example/fixture\n"
            "// @version 1.0.0\n// @description Fixture\n// @author Fixture\n"
            "// @match https://chatgpt.com/*\n// @match https://chat.openai.com/*\n"
            "// @run-at document-idle\n"
            "// @grant GM_getValue\n// @grant GM_setValue\n// @grant GM_xmlhttpRequest\n"
            "// @connect api.github.com\n" + extra +
            "// ==/UserScript==\n(function () {})();\n")


class GuardContractTests(unittest.TestCase):
    def setUp(self):
        parent = ROOT / ".fixture-temp"
        parent.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "candidate.git"
        self.env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        self.git_executable = shutil.which("git")
        self.git("init", "--bare", "--quiet", str(self.repo), outside=True)
        package = {"name": POLICY["package_name"], "version": "0.40.8",
                   "private": True, "scripts": POLICY["package_scripts"]}
        self.files = {
            "README.md": (b"# Fixture\n", "100644"),
            DOC: (b"# Guide\n\nPlain documentation.\n", "100644"),
            HELPER + "src/core.js": (b"(function () {})();\n", "100644"),
            HELPER + "tests/core.test.mjs": (b"// ordinary candidate tests\n", "100644"),
            HELPER + "build-chat-command-palette.mjs": (b"// build fixture\n", "100644"),
            HELPER + "verify-chat-command-palette.mjs": (b"// verify fixture\n", "100644"),
            HELPER + "package.json": (json.dumps(package).encode(), "100644"),
            BUNDLE: (userscript().encode(), "100644"),
            LEGACY: (b"class Fixture {}\n", "100644"),
            ".github/workflows/sonarqube.yml": (b"name: fixture\n", "100644"),
            "planning/commands/example.command.md": (b"# Existing instruction\n", "100644"),
        }
        self.base = self.commit(self.files)
        self.policy = copy.deepcopy(POLICY)
        self.policy["baseline_commit"] = self.base

    def git(self, *args, data=None, outside=False):
        command = [self.git_executable, "-c", "core.hooksPath=/dev/null"]
        if not outside:
            command += ["-C", str(self.repo)]
        return subprocess.run(command + list(args), input=data, capture_output=True,
                              env=self.env, check=True).stdout.strip()

    def commit(self, files, parent=None):
        hierarchy = {}
        for path, (body, mode) in files.items():
            parts = path.split("/")
            current = hierarchy
            for part in parts[:-1]:
                current = current.setdefault(part, {})
            oid = ("1" * 40 if mode == "160000" else
                   self.git("hash-object", "-w", "--stdin", data=body).decode())
            current[parts[-1]] = mode, oid

        def tree(items):
            records = []
            for name, value in items.items():
                if isinstance(value, dict):
                    mode, oid, kind = "040000", tree(value), "tree"
                else:
                    mode, oid = value
                    kind = "commit" if mode == "160000" else "blob"
                records.append((mode + " " + kind + " " + oid + "\t" + name).encode() + b"\0")
            return self.git("mktree", "--missing", "-z", data=b"".join(records)).decode()
        root = tree(hierarchy)
        raw = ("tree " + root + "\n" + ("parent " + parent + "\n" if parent else "") +
               "author Fixture <fixture@localhost> 1700000000 +0000\n"
               "committer Fixture <fixture@localhost> 1700000000 +0000\n\nFixture\n").encode()
        return self.git("hash-object", "-w", "-t", "commit", "--stdin", data=raw).decode()

    def inspect(self, changes=None, remove=()):
        files = dict(self.files)
        for path, value in (changes or {}).items():
            files[path] = value if isinstance(value, tuple) else (value.encode(), "100644")
        for path in remove:
            files.pop(path)
        sha = self.commit(files, self.base)
        return guard.check(self.repo, sha, self.policy, json.dumps(self.policy).encode()), sha

    def has_rule(self, report, rule):
        return any(f["rule"] == rule for f in report["findings"])

    def test_baseline_passes_and_execution_is_not_approved(self):
        report, _ = self.inspect()
        self.assertEqual(report["status"], "PASS")
        self.assertFalse(report["candidate_code_executed"])
        self.assertFalse(report["windows_execution_approved"])

    def test_documentation_edit_passes(self):
        report, _ = self.inspect({DOC: "# Changed guide\n\nNew plain text.\n"})
        self.assertEqual(report["status"], "PASS")

    def test_aggregate_size_limit_fails_closed(self):
        self.policy["max_total_bytes"] = 1
        report, _ = self.inspect()
        self.assertEqual(report["status"], "FAIL")
        self.assertTrue(self.has_rule(report, "total-size"))

    def test_code_file_in_documentation_fails(self):
        report, _ = self.inspect({"planning/documentation/testing-planning/loader.js": "alert(1);"})
        self.assertTrue(self.has_rule(report, "unclassified-path"))
        self.assertEqual(report["status"], "FAIL")

    def test_disguised_interpreter_and_binary_fail(self):
        for body in ("#!/bin/sh\nexit 0\n", "MZ\0binary"):
            with self.subTest(body=body):
                report, _ = self.inspect({DOC: body})
                self.assertEqual(report["status"], "FAIL")

    def test_active_html_fails(self):
        for body in ('<script>run()</script>', '<a onclick="run()">x</a>',
                     '<a href="java&#x73;cript:run()">x</a>'):
            with self.subTest(body=body):
                report, _ = self.inspect({DOC: body})
                self.assertTrue(self.has_rule(report, "docs-active-html"))

    def test_code_examples_remain_documentation(self):
        fence = chr(96) * 3
        report, _ = self.inspect({DOC: "# Example\n\n" + fence + "html\n<script>example()</script>\n" + fence + "\n"})
        self.assertEqual(report["status"], "PASS")

    def test_template_placeholders_are_not_event_handlers(self):
        report, _ = self.inspect({DOC: "<Use one resolution surface>\n<optional; only when needed>\n<link>\n<Link ordinary Proposals about possible routes>"})
        self.assertEqual(report["status"], "PASS")

    def test_active_link_tag_is_still_blocked(self):
        report, _ = self.inspect({DOC: '<link rel="stylesheet" href="https://unexpected.example/x.css">'})
        self.assertTrue(self.has_rule(report, "docs-active-html"))

    def test_daily_planning_area_is_documentation(self):
        report, _ = self.inspect({"-Planning/Days/example.md": "# Daily notes\n"})
        self.assertEqual(report["status"], "PASS")

    def test_executable_symlink_and_submodule_modes_fail(self):
        for mode in ("100755", "120000", "160000"):
            with self.subTest(mode=mode):
                report, _ = self.inspect({DOC: (b"fixture", mode)})
                self.assertTrue(self.has_rule(report, "file-mode"))

    def test_windows_ads_and_device_names_fail(self):
        for name in ("guide.md:stream", "NUL.txt", "LPT1.md", "trailing.md."):
            with self.subTest(name=name):
                report, _ = self.inspect({"planning/" + name: "text"})
                self.assertTrue(self.has_rule(report, "windows-path"))

    def test_directory_case_collision_fails(self):
        report, _ = self.inspect({"planning/Docs/a.md": "one", "planning/docs/b.md": "two"})
        self.assertTrue(self.has_rule(report, "windows-case-collision"))

    def test_forged_test_command_fails(self):
        package = json.loads(self.files[HELPER + "package.json"][0])
        package["scripts"]["test"] = "node -e \"process.exit(0)\""
        report, _ = self.inspect({HELPER + "package.json": json.dumps(package)})
        self.assertTrue(self.has_rule(report, "package-scripts"))

    def test_new_dependency_fails(self):
        package = json.loads(self.files[HELPER + "package.json"][0])
        package["dependencies"] = {"unexpected-package": "1.0.0"}
        report, _ = self.inspect({HELPER + "package.json": json.dumps(package)})
        self.assertTrue(self.has_rule(report, "package-capabilities"))

    def test_new_userscript_capabilities_fail(self):
        for extra, rule in (("// @grant GM_cookie\n", "userscript-grant"),
                            ("// @connect unexpected.example\n", "userscript-connect"),
                            ("// @require https://unexpected.example/code.js\n", "userscript-extra-directive")):
            with self.subTest(rule=rule):
                report, _ = self.inspect({BUNDLE: userscript(extra)})
                self.assertTrue(self.has_rule(report, rule))

    def test_common_runtime_escape_surfaces_fail(self):
        for code, rule in (("eval('1')", "runtime-dynamic-execution"),
                           ("new Function('return 1')", "runtime-dynamic-execution"),
                           ("require('node:child_process')", "runtime-node-dependency"),
                           ("fetch('https://unexpected.example')", "runtime-network-surface")):
            with self.subTest(rule=rule):
                report, _ = self.inspect({HELPER + "src/core.js": code})
                self.assertTrue(self.has_rule(report, rule))

    def test_network_wiring_in_new_module_fails(self):
        report, _ = self.inspect({HELPER + "src/extra.js": "const adapter = GM_xmlhttpRequest;"})
        self.assertTrue(self.has_rule(report, "network-boundary"))

    def test_comments_and_string_examples_are_not_runtime_capabilities(self):
        code = "// eval('example')\nconst example = \"fetch('example')\";"
        report, _ = self.inspect({HELPER + "src/core.js": code})
        self.assertEqual(report["status"], "PASS")

    def test_statically_computed_eval_is_rejected(self):
        report, _ = self.inspect({HELPER + "src/core.js": "globalThis['e' + 'val']('1');"})
        self.assertTrue(self.has_rule(report, "runtime-dynamic-execution"))

    def test_runtime_cannot_import_documentation_as_code(self):
        report, _ = self.inspect({HELPER + "src/core.js": "import data from '../../../../../commands/example.command.md';"})
        self.assertTrue(self.has_rule(report, "runtime-layer-import"))

    def test_cookies_clipboard_and_node_globals_are_rejected(self):
        for code, rule in (("document.cookie", "runtime-cookie-access"),
                           ("navigator.clipboard.readText()", "runtime-clipboard-read"),
                           ("process.env", "runtime-node-global")):
            with self.subTest(rule=rule):
                report, _ = self.inspect({HELPER + "src/core.js": code})
                self.assertTrue(self.has_rule(report, rule))

    def test_relative_import_must_exist_in_runtime_area(self):
        report, _ = self.inspect({HELPER + "src/core.js": "import x from './missing.js';"})
        self.assertTrue(self.has_rule(report, "runtime-missing-module"))

    def test_umd_typeof_and_local_import_are_allowed(self):
        source = "const api = typeof require === 'function' ? require('./extra.js') : {};"
        report, _ = self.inspect({HELPER + "src/core.js": source,
                                 HELPER + "src/extra.js": "module.exports = {};"})
        self.assertEqual(report["status"], "PASS")

    def test_generated_bundle_imports_map_to_its_runtime_source_area(self):
        source = userscript() + "const api = typeof require === 'function' ? require('./core.js') : {};"
        report, _ = self.inspect({BUNDLE: source})
        self.assertEqual(report["status"], "PASS")

    def test_loader_alias_is_still_rejected(self):
        report, _ = self.inspect({HELPER + "src/core.js": "const loader = require; loader('node:fs');"})
        self.assertTrue(self.has_rule(report, "runtime-dynamic-import"))

    def test_other_project_changes_require_review(self):
        report, _ = self.inspect({LEGACY: "class Fixture { int changed; }\n"})
        self.assertEqual(report["status"], "REVIEW_REQUIRED")

    def test_verifier_cannot_be_replaced_to_get_pass(self):
        report, _ = self.inspect({HELPER + "verify-chat-command-palette.mjs": "process.exit(0);"})
        self.assertTrue(self.has_rule(report, "build-command-change"))
        self.assertEqual(report["status"], "REVIEW_REQUIRED")

    def test_instruction_changes_require_semantic_review(self):
        report, _ = self.inspect({"planning/commands/example.command.md": "# Changed instruction\n"})
        self.assertTrue(self.has_rule(report, "instruction-change"))

    def test_new_instruction_outside_library_still_requires_review(self):
        report, _ = self.inspect({"planning/elsewhere/example.prompt.md": "New instruction"})
        self.assertTrue(self.has_rule(report, "instruction-change"))

    def test_semantic_projection_changes_do_not_get_automatic_pass(self):
        report, _ = self.inspect({HELPER + "seed/commands.json": '{"new":"instruction"}'})
        self.assertEqual(report["status"], "REVIEW_REQUIRED")

    def test_fetch_rejects_non_sha_input_before_network_or_directory_creation(self):
        from fetch_candidate import fetch
        destination = Path(self.temp.name) / "must-not-be-created"
        for value in ("main", "abc", "main; echo bad", "0" * 40 + "\n"):
            with self.subTest(value=value), self.assertRaises(guard.GuardError):
                fetch(destination, self.base, value)
        self.assertFalse(destination.exists())

    def test_removing_tests_requires_review_when_architecture_is_enabled(self):
        self.policy["architecture"]["enabled"] = True
        report, _ = self.inspect(remove=(HELPER + "tests/core.test.mjs",))
        self.assertTrue(self.has_rule(report, "test-removed"))

    def test_candidate_policy_and_fake_pass_do_not_override_external_policy(self):
        report, _ = self.inspect({
            HELPER + "seed/guard-policy.json": '{"allow_all":true}',
            "planning/fake-pass.md": "PASS",
            "planning/documentation/testing-planning/loader.js": "code",
        })
        self.assertEqual(report["status"], "FAIL")

    def test_candidate_code_is_never_loaded(self):
        report, _ = self.inspect({HELPER + "src/core.js": "throw new Error('MUST_NOT_EXECUTE');"})
        self.assertEqual(report["status"], "PASS")
        self.assertFalse(report["candidate_code_executed"])

    def test_worktree_files_do_not_change_pinned_commit(self):
        (self.repo / "README.md").write_text("<script>not in the commit</script>")
        report, _ = self.inspect()
        self.assertEqual(report["status"], "PASS")

    def test_git_replace_refs_do_not_hide_bad_candidate(self):
        bad, sha = self.inspect({"planning/documentation/testing-planning/bad.js": "code"})
        self.assertEqual(bad["status"], "FAIL")
        _, good = self.inspect()
        self.git("update-ref", "refs/replace/" + sha, good)
        report = guard.check(self.repo, sha, self.policy, json.dumps(self.policy).encode())
        self.assertEqual(report["status"], "FAIL")

    def test_duplicate_json_keys_fail(self):
        report, _ = self.inspect({HELPER + "seed/data.json": '{"a":1,"a":2}'})
        self.assertTrue(self.has_rule(report, "invalid-json"))

    def test_corrupt_blob_cannot_masquerade_as_another_object(self):
        oid = self.git("hash-object", "--stdin", data=self.files["README.md"][0]).decode()
        location = self.repo / "objects" / oid[:2] / oid[2:]
        forged = b"changed object data"
        location.chmod(0o600)
        location.write_bytes(zlib.compress(b"blob " + str(len(forged)).encode() + b"\0" + forged))
        report, _ = self.inspect()
        self.assertTrue(self.has_rule(report, "text-object"))

    def test_branch_name_is_not_an_approval_identity(self):
        with self.assertRaises(guard.GuardError):
            guard.check(self.repo, "main", self.policy, json.dumps(self.policy).encode())

    def test_architecture_can_be_disabled_without_disabling_security(self):
        self.policy['architecture']['enabled'] = False
        report, _ = self.inspect(remove=(HELPER + 'tests/core.test.mjs',))
        self.assertEqual(report['status'], 'PASS')
        self.assertFalse(report['architecture_enabled'])
        report, _ = self.inspect({'planning/bad.js': 'code'}, remove=(HELPER + 'tests/core.test.mjs',))
        self.assertEqual(report['status'], 'FAIL')
        self.assertEqual(len(report['modules']['required_security']), 6)

    def test_executable_project_tests_are_not_an_unchecked_security_area(self):
        report, _ = self.inspect({HELPER + 'tests/core.test.mjs': "import {execSync} from 'node:child_process'; execSync('example-command');"})
        self.assertFalse(report['architecture_enabled'])
        self.assertEqual(report['status'], 'REVIEW_REQUIRED')
        self.assertTrue(self.has_rule(report, 'test-code-change'))

    def test_explicit_optional_architecture_adds_checks(self):
        _, sha = self.inspect(remove=(HELPER + 'tests/core.test.mjs',))
        report = guard.check(self.repo, sha, self.policy, json.dumps(self.policy).encode(), architecture=True)
        self.assertEqual(report['status'], 'REVIEW_REQUIRED')
        self.assertTrue(report['architecture_enabled'])

    def test_secret_patterns_block_without_disclosing_values(self):
        samples = ['gh' + 'p_' + 'A' * 36,
                   '-----BEGIN PRIVATE KEY-----\n' + 'A' * 64 + '\n-----END PRIVATE KEY-----']
        for value in samples:
            with self.subTest(kind=value[:10]):
                report, _ = self.inspect({DOC: '# Guide\n' + value})
                self.assertEqual(report['status'], 'FAIL')
                self.assertTrue(self.has_rule(report, 'secret-pattern'))
                self.assertNotIn(value, json.dumps(report))

    def test_private_key_description_without_payload_is_allowed(self):
        report, _ = self.inspect({DOC: 'Header example: -----BEGIN PRIVATE KEY-----; never paste a key here.'})
        self.assertEqual(report['status'], 'PASS')

    def test_profile_cannot_disable_security_modules(self):
        self.policy['security_enabled'] = False
        with self.assertRaises(guard.GuardError):
            self.inspect()

    def test_common_checks_are_reusable_without_browser_adapter(self):
        from core.registry import JS_KEYS
        for key in JS_KEYS:
            self.policy.pop(key, None)
        self.files = {path: value for path, value in self.files.items() if not path.startswith(HELPER) and path != BUNDLE}
        self.base = self.commit(self.files)
        self.policy['baseline_commit'] = self.base
        report, _ = self.inspect({DOC: '# Generic document project\n'})
        self.assertEqual(report['status'], 'PASS')
        report, _ = self.inspect({'planning/loader.js': 'code'})
        self.assertEqual(report['status'], 'FAIL')

    def test_many_empty_trees_cannot_bypass_file_count_budget(self):
        empty = self.git('mktree', data=b'').decode()
        records = b''.join(('040000 tree ' + empty + '\tarea' + str(i) + '\0').encode() for i in range(200))
        tree = self.git('mktree', '-z', data=records).decode()
        raw = ('tree ' + tree + '\nauthor Fixture <fixture@localhost> 1700000000 +0000\ncommitter Fixture <fixture@localhost> 1700000000 +0000\n\nFixture\n').encode()
        sha = self.git('hash-object', '-w', '-t', 'commit', '--stdin', data=raw).decode()
        with self.assertRaisesRegex(guard.GuardError, 'Tree traversal budget'):
            guard.GitObjects(self.repo).snapshot(sha, 1)

    def test_json_nonstandard_numbers_and_duplicate_keys_are_rejected(self):
        for text in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'):
            with self.subTest(text=text), self.assertRaises(guard.GuardError):
                guard.strict_json(text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
