#!/usr/bin/env python3
"""Entry point: trusted project selector and exact SHA, no candidate policy input."""
import argparse
import json
from pathlib import Path
import sys

from core.objects import GuardError, GitObjects, full_sha, strict_json
from core.registry import load_project
from checks.security import check


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--candidate', required=True)
    parser.add_argument('--project', required=True)
    parser.add_argument('--architecture', choices=('true', 'false'), default='false', help='Add optional architecture checks')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        candidate = full_sha(args.candidate)
        profile, raw = load_project(args.project)
        report = check(args.repo, candidate, profile, raw, args.architecture == 'true')
        report['project'] = args.project
    except Exception:
        report = {'status': 'ERROR', 'message': 'Inspection failed closed; review trusted configuration, tools and object availability',
                  'candidate_code_executed': False, 'windows_execution_approved': False}
    text = json.dumps(report, indent=2, ensure_ascii=True) + '\n'
    args.output.write_text(text, encoding='utf-8')
    print(text, end='')
    return {'PASS': 0, 'FAIL': 1, 'REVIEW_REQUIRED': 2, 'ERROR': 3}[report['status']]


if __name__ == '__main__':
    sys.exit(main())
