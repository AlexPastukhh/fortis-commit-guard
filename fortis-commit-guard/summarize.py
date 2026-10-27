#!/usr/bin/env python3
import json
import os
from pathlib import Path

path = Path("report.json")
if path.is_file():
    report = json.loads(path.read_text())
    candidate = report.get("candidate_sha", "unavailable")
    status = report["status"]
    text = ("### Commit Guard: " + status + "\n\n"
            "Candidate SHA: `" + candidate + "`\n\n"
            "Scope: security baseline; optional architecture: " + str(report.get("architecture_enabled", False)) + ".\n\n"
            "Candidate code was not executed. This is not Windows execution approval.\n")
else:
    text = "### Commit Guard: ERROR\n\nNo report was produced. Admission remains blocked.\n"
if os.environ.get("GITHUB_STEP_SUMMARY"):
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as output:
        output.write(text)
print(text)
