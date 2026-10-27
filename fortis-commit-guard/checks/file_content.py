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


def windows_path_error(path: str) -> str | None:
    if path.startswith("/") or "\\" in path:
        return "Absolute or backslash-containing path"
    for part in path.split("/"):
        if not part or part in (".", "..") or part.casefold() == ".git":
            return "Unsafe path component"
        if any(c in '<>:"|?*' or unicodedata.category(c) in ("Cc", "Cf") for c in part):
            return "Reserved or hidden control character in path"
        if part.endswith((".", " ")):
            return "Trailing dot or space in path"
        stem = part.split(".", 1)[0].upper()
        if stem in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} or re.fullmatch(r"(?:COM|LPT)[1-9¹²³]", stem):
            return "Reserved Windows device name"
        if len(part.encode("utf-16-le")) // 2 > 255:
            return "Path component exceeds 255 UTF-16 code units"
    return None


def without_code_examples(text: str) -> str:
    """A deliberately narrow Markdown filter, not a complete Markdown parser."""
    out, fence = [], None
    for line in text.splitlines():
        match = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if fence:
            if match and match[1][0] == fence[0] and len(match[1]) >= fence[1] and not line[match.end():].strip():
                fence = None
            continue
        if match:
            fence = match[1][0], len(match[1])
            continue
        out.append(re.sub(r"(`+).*?\1", "", line))
    return "\n".join(out)


class ActiveHtml(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.active = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() in {"script", "iframe", "object", "embed", "svg", "math", "style"}:
            self.active = True
        if tag.lower() in {"link", "base", "meta"} and any(value is not None for _, value in attrs):
            self.active = True
        for name, value in attrs:
            if name.lower().startswith("on") and value is not None:
                self.active = True
            normalized = "".join((value or "").split()).lower()
            if name.lower() in {"href", "src", "action", "formaction", "xlink:href"} and normalized.startswith(("javascript:", "vbscript:", "data:text/html")):
                self.active = True


