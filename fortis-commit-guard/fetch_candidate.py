#!/usr/bin/env python3
"""Fetch a registered public repository into a fresh bare repository, without credentials."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import urllib.request

from core.objects import GuardError, full_sha
from core.registry import load_project


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise GuardError('Repository metadata redirects require an owner registry update')


def verify_public_identity(profile):
    request = urllib.request.Request('https://api.github.com/repos/' + profile['repository'], headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'Fortis-Commit-Guard'})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=15) as response:
        raw = response.read(65537)
    if len(raw) > 65536:
        raise GuardError('Repository metadata size limit exceeded')
    data = json.loads(raw)
    if data.get('id') != profile['repository_id'] or data.get('full_name', '').casefold() != profile['repository'].casefold() or data.get('private') is not False:
        raise GuardError('Registered public repository identity does not match')


def fetch(destination, baseline, candidate, project='obs-planning-docs'):
    baseline, candidate = full_sha(baseline), full_sha(candidate)
    profile, _ = load_project(project)
    if baseline != profile['baseline_commit']:
        raise GuardError('Baseline must come from the trusted project profile')
    if destination.exists():
        raise GuardError('Destination must be a new trusted directory')
    verify_public_identity(profile)
    destination.parent.mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_') and k not in ('GH_TOKEN', 'GITHUB_TOKEN')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0', GIT_ASKPASS='/bin/false')
    git = shutil.which('git')
    if not git:
        raise GuardError('Git is unavailable')
    prefix = [git, '-c', 'core.hooksPath=/dev/null', '-c', 'credential.helper=', '-c', 'http.sslVerify=true', '-c', 'http.followRedirects=false', '-c', 'fetch.fsckObjects=true', '-c', 'transfer.fsckObjects=true']
    subprocess.run(prefix + ['init', '--bare', '--quiet', str(destination)], env=env, check=True, timeout=30)
    subprocess.run(prefix + ['-C', str(destination), 'fetch', '--no-tags', 'https://github.com/' + profile['repository'] + '.git', baseline, candidate], env=env, check=True, timeout=180)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--project', required=True)
    args = parser.parse_args()
    profile, _ = load_project(args.project)
    fetch(args.destination, profile['baseline_commit'], os.environ['CANDIDATE_SHA'], args.project)
