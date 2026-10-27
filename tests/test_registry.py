import ast
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from checks.security import SECURITY_MODULES
from core.objects import GuardError
from core.registry import ROOT, load_project, validate_profile
from fetch_candidate import fetch, verify_public_identity


class RegistryTests(unittest.TestCase):
    def test_registered_project_has_exact_identity(self):
        profile, raw = load_project('obs-planning-docs')
        self.assertEqual(profile['repository'], 'AlexPastukhh/obs-planning-docs')
        self.assertEqual(profile['repository_id'], 1276070507)
        self.assertEqual(json.loads(raw), profile)

    def test_unknown_project_and_traversal_are_rejected(self):
        for value in ['unknown-project', '../profiles', 'https://example.com', 'obs-planning-docs\n']:
            with self.subTest(value=value), self.assertRaises(GuardError):
                load_project(value)

    def test_cli_error_writes_a_blocking_report(self):
        import guard
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'report.json'
            arguments = ['guard.py', '--repo', folder, '--project', 'obs-planning-docs', '--candidate', 'main', '--output', str(output)]
            with patch('sys.argv', arguments), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(guard.main(), 3)
            report = json.loads(output.read_text())
            self.assertEqual(report['status'], 'ERROR')
            self.assertFalse(report['windows_execution_approved'])

    def test_architecture_setting_must_be_boolean(self):
        profile, _ = load_project('obs-planning-docs')
        profile['architecture']['enabled'] = 'false'
        with self.assertRaises(GuardError):
            validate_profile(profile)

    def test_registry_profile_identity_mismatch_is_rejected(self):
        profile, _ = load_project('obs-planning-docs')
        profile['repository_id'] += 1
        registry = {'schema_version': 1, 'projects': {'obs-planning-docs': {'repository': profile['repository'], 'repository_id': 1276070507, 'profile': 'profiles/obs-planning-docs.json'}}}
        with patch('pathlib.Path.read_text', return_value=json.dumps(registry)), patch('pathlib.Path.read_bytes', return_value=json.dumps(profile).encode()):
            with self.assertRaises(GuardError):
                load_project('obs-planning-docs')

    def test_candidate_cannot_choose_a_different_baseline_for_fetch(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / 'never-created.git'
            with patch('fetch_candidate.verify_public_identity') as network:
                with self.assertRaises(GuardError):
                    fetch(destination, '1' * 40, '2' * 40)
                network.assert_not_called()
                self.assertFalse(destination.exists())

    def test_public_fetch_rejects_changed_repository_identity(self):
        profile, _ = load_project('obs-planning-docs')
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps({'id': 1, 'full_name': profile['repository'], 'private': False}).encode()
        with patch('urllib.request.build_opener') as opener:
            opener.return_value.open.return_value = response
            with self.assertRaises(GuardError):
                verify_public_identity(profile)

    def test_module_cards_cover_required_security_and_have_real_examples(self):
        catalog = json.loads((ROOT / 'modules.json').read_text())
        cards = catalog['modules']
        self.assertEqual({c['id'] for c in cards if c['purpose'] == 'security'}, set(SECURITY_MODULES))
        methods = set()
        for path in (ROOT / 'tests').glob('test_*.py'):
            methods.update(n.name for n in ast.walk(ast.parse(path.read_text())) if isinstance(n, ast.FunctionDef))
        fields = {'id', 'version', 'purpose', 'guarantee', 'applicability', 'parameters', 'method', 'decision', 'tests', 'limits'}
        self.assertEqual(len(cards), len({c['id'] for c in cards}))
        for card in cards:
            self.assertEqual(set(card), fields)
            self.assertTrue(card['guarantee'] and card['limits'])
            self.assertGreaterEqual(len(card['tests']), 2)
            self.assertTrue(set(card['tests']) <= methods, card['id'])
