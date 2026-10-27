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


class GuardError(Exception):
    pass


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def full_sha(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise GuardError("A full lowercase SHA-1 commit ID is required")
    return value


def strict_json(text: str):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise GuardError("Duplicate JSON key")
            result[key] = value
        return result
    def invalid_constant(value):
        raise GuardError("Non-JSON numeric constant")
    return json.loads(text, object_pairs_hook=pairs, parse_constant=invalid_constant)


@dataclass(frozen=True)
class Entry:
    mode: str
    oid: str


class GitObjects:
    def __init__(self, directory: Path):
        executable = shutil.which("git")
        if not executable:
            raise GuardError("Git is unavailable")
        self.command = [executable, "--no-pager", "--no-optional-locks",
                        "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
                        "-c", "core.fsmonitor=false", "-C", str(directory)]
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith("GIT_") and k not in ("GH_TOKEN", "GITHUB_TOKEN")}
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_TERMINAL_PROMPT="0", GIT_NO_REPLACE_OBJECTS="1")
        self.cache: dict[tuple[str, str], bytes] = {}
        self.cached_bytes = 0

    def run(self, *args: str) -> bytes:
        result = subprocess.run(self.command + list(args), env=self.env,
                                capture_output=True, timeout=30, check=False)
        if result.returncode:
            raise GuardError("Required Git object or operation is unavailable")
        return result.stdout

    def object(self, kind: str, oid: str, limit: int) -> bytes:
        full_sha(oid)
        key = kind, oid
        if key not in self.cache:
            if self.run("cat-file", "-t", oid).strip().decode() != kind:
                raise GuardError("Git object has an unexpected type")
            size = int(self.run("cat-file", "-s", oid).strip())
            if size > limit:
                raise GuardError("Git object exceeds the inspection limit")
            raw = self.run("cat-file", kind, oid)
            header = (kind + " " + str(len(raw))).encode() + b"\0"
            if len(raw) != size or hashlib.sha1(header + raw).hexdigest() != oid:
                raise GuardError("Git object content does not match its ID")
            if self.cached_bytes + len(raw) > 134217728:
                raise GuardError("Object cache budget exceeded")
            self.cache[key] = raw
            self.cached_bytes += len(raw)
        return self.cache[key]

    def snapshot(self, commit: str, max_files: int) -> tuple[str, dict[str, Entry]]:
        raw = self.object("commit", full_sha(commit), 131072)
        header = raw.split(b"\n\n", 1)[0].splitlines()
        trees = [line[5:].decode("ascii") for line in header if line.startswith(b"tree ")]
        if len(trees) != 1:
            raise GuardError("Commit must contain exactly one tree")
        tree = full_sha(trees[0])
        entries: dict[str, Entry] = {}
        tree_visits = 0

        def walk(oid: str, prefix: str, depth: int):
            nonlocal tree_visits
            tree_visits += 1
            if tree_visits > max_files * 4 + 128:
                raise GuardError("Tree traversal budget exceeded")
            if depth > 64:
                raise GuardError("Tree nesting limit exceeded")
            data = self.object("tree", oid, 2097152)
            cursor = 0
            while cursor < len(data):
                space = data.find(b" ", cursor)
                end = data.find(b"\0", space + 1)
                if space < cursor or end < 0 or end + 21 > len(data):
                    raise GuardError("Invalid tree encoding")
                mode = data[cursor:space].decode("ascii")
                name = data[space + 1:end].decode("utf-8", errors="strict")
                child = data[end + 1:end + 21].hex()
                cursor = end + 21
                if not name or "/" in name or name in (".", ".."):
                    raise GuardError("Invalid Git tree path component")
                path = prefix + name
                if mode == "40000":
                    walk(child, path + "/", depth + 1)
                else:
                    if path in entries or len(entries) >= max_files:
                        raise GuardError("Duplicate path or file-count limit exceeded")
                    entries[path] = Entry(mode, child)
        walk(tree, "", 0)
        return tree, entries


