"""Small offline detector, not a replacement for comprehensive secret scanning."""
import re

PATTERNS = {
    'private-key-payload': re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----\s+[A-Za-z0-9+/=]{40,}'),
    'github-token-prefix': re.compile(r'(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,255})(?![A-Za-z0-9_])'),
}


def inspect_secrets(text, path, finding):
    for kind, pattern in PATTERNS.items():
        if pattern.search(text):
            finding('secret-pattern', path, 'Potential secret detected (' + kind + '); value redacted')
