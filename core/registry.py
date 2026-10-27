"""Owner-controlled project selection. No candidate-supplied profiles or URLs."""
from pathlib import Path
import os
import re

from core.objects import GuardError, full_sha, strict_json

ROOT = Path(__file__).resolve().parents[1]
COMMON_KEYS = {
    'profile_version', 'repository', 'repository_id', 'baseline_commit', 'max_files',
    'max_blob_bytes', 'max_total_bytes', 'root_documents', 'root_control_files',
    'owner_review_files', 'instruction_roots', 'other_project_roots',
    'documentation_roots', 'architecture', 'test_roots',
}
JS_KEYS = {
    'helper_root', 'helper_bundle', 'package_name', 'package_scripts',
    'userscript_permissions', 'userscript_header_fields', 'network_wiring_files',
}
PATH_LISTS = {
    'root_documents', 'root_control_files', 'owner_review_files', 'instruction_roots',
    'other_project_roots', 'documentation_roots', 'test_roots',
}


def path_value(value, prefix=False):
    if not isinstance(value, str) or not value or '\\' in value or '\x00' in value:
        raise GuardError('Invalid profile path')
    if value.startswith('/') or any(p in ('', '.', '..') for p in value.rstrip('/').split('/')):
        raise GuardError('Invalid relative profile path')
    if prefix and not value.endswith('/'):
        raise GuardError('Profile directory prefixes must end with a slash')


def validate_profile(profile):
    if not isinstance(profile, dict) or COMMON_KEYS - profile.keys() or profile.keys() - COMMON_KEYS - JS_KEYS:
        raise GuardError('Incomplete or unsupported profile')
    if profile['profile_version'] != 2:
        raise GuardError('Unsupported profile version')
    if not isinstance(profile['repository'], str) or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', profile['repository']):
        raise GuardError('Invalid registered repository')
    if type(profile['repository_id']) is not int or profile['repository_id'] <= 0:
        raise GuardError('Invalid repository identity')
    full_sha(profile['baseline_commit'])
    for key, maximum in [('max_files', 10000), ('max_blob_bytes', 4194304), ('max_total_bytes', 104857600)]:
        if type(profile[key]) is not int or not 1 <= profile[key] <= maximum:
            raise GuardError('Invalid inspection budget')
    for key in PATH_LISTS:
        values = profile[key]
        if not isinstance(values, list) or len(values) != len(set(values)):
            raise GuardError('Invalid profile path list')
        for value in values:
            path_value(value, key.endswith('_roots'))
    if not profile['documentation_roots'] and not profile['root_documents']:
        raise GuardError('Profile must identify approved document areas')
    architecture = profile['architecture']
    if not isinstance(architecture, dict) or set(architecture) != {'enabled'} or type(architecture['enabled']) is not bool:
        raise GuardError('Invalid optional architecture configuration')
    if profile.get('helper_root'):
        if JS_KEYS - profile.keys():
            raise GuardError('Incomplete browser-runtime profile')
        path_value(profile['helper_root'], True)
        path_value(profile['helper_bundle'])
        if not isinstance(profile['package_name'], str) or not profile['package_name']:
            raise GuardError('Missing package identity')
        scripts = profile['package_scripts']
        if not isinstance(scripts, dict) or not scripts or not all(isinstance(k, str) and isinstance(v, str) and v for k, v in scripts.items()):
            raise GuardError('Invalid trusted package commands')
        permissions = profile['userscript_permissions']
        if not isinstance(permissions, dict) or set(permissions) != {'grant', 'match', 'connect', 'run-at'}:
            raise GuardError('Incomplete userscript permission contract')
        for values in permissions.values():
            if not isinstance(values, list) or not all(isinstance(v, str) and v for v in values):
                raise GuardError('Invalid userscript permission values')
        fields = profile['userscript_header_fields']
        if not isinstance(fields, list) or not all(isinstance(v, str) and v for v in fields) or not set(permissions) <= set(fields):
            raise GuardError('Invalid userscript header contract')
        for value in profile['network_wiring_files']:
            path_value(value)
            if not value.startswith(profile['helper_root'] + 'src/'):
                raise GuardError('Network adapter must be a runtime source file')
    elif JS_KEYS & profile.keys():
        raise GuardError('Partial browser-runtime configuration')


def load_project(project):
    if not isinstance(project, str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', project):
        raise GuardError('Invalid project selector')
    registry = strict_json((ROOT / 'registry.json').read_text())
    if not isinstance(registry, dict) or set(registry) != {'schema_version', 'projects'} or registry['schema_version'] != 1:
        raise GuardError('Unsupported project registry')
    item = registry['projects'].get(project)
    if not isinstance(item, dict) or set(item) != {'repository', 'repository_id', 'profile'}:
        raise GuardError('Project is not registered')
    name = item['profile']
    path_value(name)
    path = ROOT / name
    if not name.startswith('profiles/') or path.is_symlink() or ROOT / 'profiles' not in path.resolve().parents:
        raise GuardError('Profile must be inside the trusted profile directory')
    raw = path.read_bytes()
    if len(raw) > 65536:
        raise GuardError('Profile size exceeds the limit')
    profile = strict_json(raw.decode('utf-8'))
    validate_profile(profile)
    if (profile['repository'], profile['repository_id']) != (item['repository'], item['repository_id']):
        raise GuardError('Registry/profile identity mismatch')
    return profile, raw


def trusted_execution_sha():
    value = os.environ.get('GITHUB_SHA', '')
    if os.environ.get('GITHUB_REPOSITORY') == 'AlexPastukhh/fortis-commit-guard' and re.fullmatch(r'[0-9a-f]{40}', value):
        return value
    return None
