#!/usr/bin/env python3
"""
Check the repository for things that should not be published. Run before pushing.

    python scripts/pre_push_check.py

Exit 0 if clean, 1 if anything needs a human decision.

WHY THIS EXISTS. Git history is permanent. A file committed once and deleted in the
next commit is still in the repository, still reachable, still indexed by anything
that scraped it in between. "I removed it" does not remove it. So the only moment
that matters is before the commit, and the only reliable way to use that moment is
to check mechanically rather than from memory.

This is a blunt instrument. It knows nothing about intent and will flag harmless
things. That is the correct bias: a check that stays silent to avoid annoying you
is a check you should not have written. Read each hit and decide.

WHAT IT DOES NOT DO. It scans the working tree, not git history. If something was
already committed, removing it now does not remove it from the history, and this
script will not tell you that. Cleaning published history needs git-filter-repo and,
if it was a real credential, rotating the credential - the file is recoverable, so
the secret must be changed, not hidden.
"""

from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "env",
             ".idea", ".vscode", "node_modules"}
SKIP_SUFFIXES = {".pyc", ".parquet", ".png", ".jpg", ".gif", ".pdf", ".zip"}

# Addresses that are safe to publish: private networks and the ranges RFC 5737
# reserves for documentation. Anything else in a sample log is somebody's real
# machine, named as an attacker, in a public repository.
SAFE_NETWORKS = [
    ipaddress.ip_network(n) for n in [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC 1918, private
        "127.0.0.0/8",                                      # loopback
        "169.254.0.0/16",                                   # link-local
        "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",  # RFC 5737, docs
        "0.0.0.0/8", "255.255.255.255/32",
    ]
]

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), "GitHub token"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}"), "API key (sk- prefix)"),
    (re.compile(r"(?i)\b(password|passwd|secret|api_?key|access_?token)\s*[:=]\s*"
                r"['\"][^'\"]{4,}['\"]"), "hardcoded credential"),
]

# A real email address in source. The noreply form GitHub provides is fine.
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
EMAIL_ALLOWED = re.compile(r"(users\.noreply\.github\.com|example\.(com|org)|"
                           r"@example|@domain)")

# Filenames that suggest a real log or capture rather than a generated sample.
RISKY_NAMES = re.compile(
    r"(?i)^(auth\.log|secure|syslog|messages|\.env|id_rsa|id_ed25519|"
    r".*\.evtx|.*\.pcap|.*\.pcapng|.*\.key|.*\.pem)$")

SAMPLE_SUFFIXES = {".log", ".csv"}


def walk() -> list[Path]:
    out = []
    for p in ROOT.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() in SKIP_SUFFIXES:
            continue
        out.append(p)
    return sorted(out)


def is_safe_ip(text: str) -> bool:
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return True                      # not an address, e.g. a version number
    return any(addr in net for net in SAFE_NETWORKS)


def check(path: Path, hits: list[str]) -> None:
    rel = path.relative_to(ROOT)

    if RISKY_NAMES.match(path.name):
        hits.append(f"{rel}: filename suggests a real log, capture or key. "
                    f"Generated samples are fine; real ones are not.")

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    for pattern, label in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            line = text[:m.start()].count("\n") + 1
            hits.append(f"{rel}:{line}: possible {label}")

    for m in EMAIL_RE.finditer(text):
        if EMAIL_ALLOWED.search(m.group()):
            continue
        line = text[:m.start()].count("\n") + 1
        hits.append(f"{rel}:{line}: email address {m.group()} "
                    f"(use the GitHub noreply form instead)")

    # Routable addresses only matter in the sample data, where they are labelled
    # as attackers. An address in a comment explaining RFC 5737 is not a problem.
    if path.suffix.lower() in SAMPLE_SUFFIXES:
        bad = sorted({m.group() for m in IP_RE.finditer(text)
                      if not is_safe_ip(m.group())})
        for ip in bad:
            hits.append(f"{rel}: routable address {ip} in sample data. "
                        f"Use 192.0.2.x / 198.51.100.x / 203.0.113.x instead.")


def main() -> int:
    hits: list[str] = []
    files = walk()
    for path in files:
        check(path, hits)

    print(f"scanned {len(files)} files under {ROOT.name}/\n")

    if not hits:
        print("No issues found.")
        print("\nThis checks the working tree only, not git history, and it cannot")
        print("tell whether a sample log is genuinely synthetic. Look at the file")
        print("list in `git status` before you commit.")
        return 0

    print(f"{len(hits)} thing(s) to look at:\n")
    for h in hits:
        print(f"  ! {h}")
    print("\nEach one needs a decision, not necessarily a fix. Nothing is wrong")
    print("with a hit you have looked at and understood.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
