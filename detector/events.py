"""
The normalised event model.

THIS FILE IS THE WHOLE ARCHITECTURE. Read the reasoning before the code.

The project has to read two completely different inputs: Linux `auth.log`, which is
unstructured text written for humans, and the Windows Security log, which is
structured records with numeric event IDs. The naive design handles them with two
separate detectors, one per platform.

That design fails for a specific reason: the detection logic is identical for both.
"Five failures from one IP in a minute" is the same question whether the failures
came from sshd or from Windows event 4625. If you write it twice you will fix a bug
in one copy and not the other, and you will never be able to test the logic without
also testing the parsing.

So: parsers are the ONLY code that knows what platform a log came from. They convert
everything into the Event objects below. Rules see nothing but Events. That split is
what makes rules.py testable with three hand-written events instead of a log file,
and it is the design decision worth talking about in an interview.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Outcome(str, Enum):
    """
    What happened in an authentication attempt.

    INVALID_USER is kept separate from FAILURE on purpose. Both are failed logins,
    but they mean different things: a failure against a real account is someone
    guessing a password, while a failure against an account that does not exist is
    someone guessing usernames. Collapsing them loses the distinction between brute
    force and enumeration, which is exactly the distinction this project claims to
    make.

    Subclassing `str` means an Outcome compares equal to its own string value and
    serialises to JSON without a custom encoder. Small convenience, saves real pain
    in report.py.
    """

    SUCCESS = "success"
    FAILURE = "failure"
    INVALID_USER = "invalid_user"

    @property
    def is_failed(self) -> bool:
        """True for anything that did not result in a session."""
        return self is not Outcome.SUCCESS


class Platform(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"


@dataclass(frozen=True)
class Event:
    """
    One authentication attempt, from either platform.

    Frozen because an Event is a record of something that already happened. Nothing
    downstream has any business mutating it, and frozen dataclasses are hashable,
    which lets you put them in sets while deduplicating.

    Fields:
        timestamp   when the attempt happened (naive local time, see the note below)
        source_ip   where it came from. None when the log does not record one, which
                    happens for console logons on Windows - those are NOT remote
                    attacks and rules must be able to drop them.
        username    the account targeted, lowercased by the parsers so that "Root"
                    and "root" are not counted as two different accounts
        outcome     see Outcome
        platform    which parser produced this
        host        the machine that wrote the log
        raw         the original log line, verbatim

    WHY `raw` IS KEPT. An incident report that says "5 failed logins from
    203.0.113.9" is an assertion. One that quotes the five lines it counted is
    evidence. Keeping the source line costs a few bytes and is the difference
    between a tool that reports and a tool that can be audited. It also saves you
    when a parser is subtly wrong: you can see what it read.

    TIMEZONE NOTE. These are naive datetimes. Real log analysis across hosts needs
    timezone handling, because an attack spanning two servers in two regions will
    appear out of order. That is out of scope here and is stated as a limitation in
    the README rather than silently ignored.
    """

    timestamp: datetime
    source_ip: str | None
    username: str | None
    outcome: Outcome
    platform: Platform
    host: str = ""
    raw: str = ""

    @property
    def is_remote(self) -> bool:
        """
        Did this come over the network?

        Console and service logons have no source IP. Counting them toward a
        per-IP threshold is meaningless, so rules filter on this.
        """
        return bool(self.source_ip)

    def __str__(self) -> str:
        ip = self.source_ip or "local"
        user = self.username or "-"
        return (f"{self.timestamp:%Y-%m-%d %H:%M:%S} {self.outcome.value:<13} "
                f"{user:<16} from {ip}")


@dataclass
class Finding:
    """
    One detection. The output of a rule.

    Not frozen: `related` is a list that rules append to while building a finding.

    Fields:
        rule        short machine name, e.g. "brute_force"
        severity    "low" | "medium" | "high" - a judgement, documented in rules.py
        source_ip   the IP responsible, when the finding is per-IP
        summary     one human sentence
        detail      dict of the numbers behind the finding. Anything a reader might
                    want to check goes here, not into prose.
        events      the Events that triggered it. Evidence, same reasoning as `raw`.
    """

    rule: str
    severity: str
    summary: str
    source_ip: str | None = None
    detail: dict = field(default_factory=dict)
    events: list[Event] = field(default_factory=list)

    @property
    def first_seen(self) -> datetime | None:
        return min((e.timestamp for e in self.events), default=None)

    @property
    def last_seen(self) -> datetime | None:
        return max((e.timestamp for e in self.events), default=None)

    def __str__(self) -> str:
        return f"[{self.severity.upper():<6}] {self.rule}: {self.summary}"


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """
    Highest severity first, then earliest.

    Sorting matters more than it looks. A report that lists findings in whatever
    order the rules happened to run buries the successful-login-after-brute-force
    finding under forty low-severity ones, and that finding is the only one that
    means you have actually been breached.
    """
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 9),
                       f.first_seen or datetime.max),
    )
