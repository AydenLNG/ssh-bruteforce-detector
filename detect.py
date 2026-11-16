#!/usr/bin/env python3
"""
Command line entry point.

    python detect.py samples/auth_bruteforce.log
    python detect.py samples/auth_clean.log
    python detect.py samples/windows_security.csv
    python detect.py samples/auth_spray.log --json
    python detect.py /var/log/auth.log --out report.txt

Design note on the exit codes, because they are the part people forget: this exits
non-zero when something is found, so it composes with cron and CI.

    0   parsed, nothing found
    1   findings, none indicating a successful compromise
    2   a finding indicating possible compromise
    3   could not parse the input at all

Separating 1 from 2 is what lets you write `detect.py /var/log/auth.log || mail -s
...` and only get woken up for the case that matters. A tool that returns 0 for
everything cannot be automated, and a tool nobody automates gets run once.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from detector import parsers, report
from detector.rules import DEFAULTS, Thresholds, run_all


def build_thresholds(args: argparse.Namespace) -> Thresholds:
    """
    Thresholds from the command line, defaults otherwise.

    Exposing these matters more than it looks: it is the difference between "the
    tool decides what suspicious means" and "you decide, and the report records
    what you chose". The report prints them for exactly that reason.
    """
    return Thresholds(
        brute_force_failures=args.bf_failures,
        brute_force_window=args.bf_window,
        spray_users=args.spray_users,
        spray_window=args.spray_window,
        spray_max_per_user=args.spray_max_per_user,
        success_after_failures=args.success_failures,
        success_window=args.success_window,
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Detect SSH/RDP brute force, password spraying and "
                    "post-compromise logins, and write an incident report.",
        epilog="Exit codes: 0 clean, 1 attack attempted, 2 possible compromise, "
               "3 parse failure.",
    )
    ap.add_argument("logfile", help="auth.log, or a Windows Security CSV export")
    ap.add_argument("--json", action="store_true", help="JSON instead of text")
    ap.add_argument("--out", help="write to this file as well as stdout")
    ap.add_argument("--year", type=int, default=None,
                    help="year to assume for syslog timestamps (they omit it)")
    ap.add_argument("--evidence", type=int, default=6,
                    help="raw log lines quoted per finding (default 6)")

    g = ap.add_argument_group("thresholds")
    g.add_argument("--bf-failures", type=int, default=DEFAULTS.brute_force_failures)
    g.add_argument("--bf-window", type=int, default=DEFAULTS.brute_force_window)
    g.add_argument("--spray-users", type=int, default=DEFAULTS.spray_users)
    g.add_argument("--spray-window", type=int, default=DEFAULTS.spray_window)
    g.add_argument("--spray-max-per-user", type=int,
                   default=DEFAULTS.spray_max_per_user)
    g.add_argument("--success-failures", type=int,
                   default=DEFAULTS.success_after_failures)
    g.add_argument("--success-window", type=int, default=DEFAULTS.success_window)

    args = ap.parse_args(argv)

    path = Path(args.logfile)
    if not path.exists():
        print(f"error: no such file: {path}", file=sys.stderr)
        return 3

    parsed = parsers.parse(path, args.year)

    # A parser that understood nothing must not look like a clean log. These two
    # outcomes produce identical findings lists, so the distinction has to be made
    # here, loudly, or the tool reports "all clear" on a file it could not read.
    if not parsed.events:
        print(f"error: parsed 0 authentication events from {path}", file=sys.stderr)
        print(f"       {parsed.skipped} line(s) were not recognised.", file=sys.stderr)
        for sample in parsed.unparsed_samples:
            print(f"       unmatched: {sample[:110]}", file=sys.stderr)
        print("       If this is a real log, the format differs from what the "
              "parser expects.", file=sys.stderr)
        return 3

    thresholds = build_thresholds(args)
    findings = run_all(parsed.events, thresholds)

    text = (report.to_json(findings, parsed, str(path)) if args.json
            else report.render(findings, parsed, str(path), thresholds, args.evidence))
    print(text)

    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"\nwritten to {args.out}", file=sys.stderr)

    if any(f.rule == "success_after_failures" for f in findings):
        return 2
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
