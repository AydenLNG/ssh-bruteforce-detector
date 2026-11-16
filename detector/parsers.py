"""
Parsers: raw log text in, Event objects out. The only code that knows about
platforms.

WHAT MAKES LOG PARSING HARD, which is worth understanding before reading the regexes:

1. Linux auth.log has no year. The syslog timestamp is "Nov 16 09:12:03" and that
   is all you get. A log that spans New Year will go backwards in time unless you
   handle it. We take an `assume_year` argument and document the limitation rather
   than pretending the problem does not exist.

2. There are several different failure lines for the same event. sshd logs "Failed
   password for invalid user admin" AND a separate "Invalid user admin" line for the
   same attempt. If you match both you double-count, and your thresholds are
   silently twice as sensitive as you think. We match the "Failed password" family
   and deliberately ignore the standalone "Invalid user" line, because the former
   carries the IP and the outcome together.

3. Not every line is an authentication attempt. sudo, CRON, systemd-logind and
   session-opened messages all live in auth.log. Anything we do not recognise is
   skipped and counted, and the count is reported. A parser that silently drops 90%
   of a file looks identical to one that works.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from detector.events import Event, Outcome, Platform

# ---------------------------------------------------------------------------
# Linux / OpenSSH
# ---------------------------------------------------------------------------

# Nov 16 09:12:03 ubuntu-vm sshd[1423]: Failed password for root from 203.0.113.9 port 48122 ssh2
_SYSLOG = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>\w+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# The message bodies we care about. Order matters: "invalid user" must be tried
# before the plain variant, because the plain pattern would also match it and
# report the wrong outcome.
_MESSAGES: list[tuple[re.Pattern, Outcome]] = [
    (re.compile(r"^Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+)"),
     Outcome.INVALID_USER),
    (re.compile(r"^Failed password for (?P<user>\S+) from (?P<ip>\S+)"),
     Outcome.FAILURE),
    (re.compile(r"^Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)"),
     Outcome.SUCCESS),
]

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


@dataclass
class ParseResult:
    """
    Events plus what was skipped.

    The skipped count exists so that a parser failure is visible. If you point this
    at a log format it does not understand, `events` is empty and `skipped` equals
    the line count, and the CLI says so loudly instead of reporting "no findings",
    which is what a clean log also reports. Those two cases must never look the same.
    """

    events: list[Event]
    skipped: int = 0
    unparsed_samples: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.unparsed_samples is None:
            self.unparsed_samples = []


def parse_auth_log(path: str | Path, assume_year: int | None = None) -> ParseResult:
    """
    Parse a Linux auth.log.

    `assume_year` fills in the year syslog does not record. Defaults to the current
    year. If a log crosses a year boundary this will be wrong for the earlier
    portion; that is a known limitation and is in the README.
    """
    year = assume_year or datetime.now().year
    events: list[Event] = []
    skipped = 0
    samples: list[str] = []

    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            ev = _parse_auth_line(line, year)
            if ev is None:
                skipped += 1
                if len(samples) < 5:
                    samples.append(line)
            else:
                events.append(ev)

    events.sort(key=lambda e: e.timestamp)
    return ParseResult(events, skipped, samples)


def _parse_auth_line(line: str, year: int) -> Event | None:
    """One line to one Event, or None if it is not an authentication attempt."""
    m = _SYSLOG.match(line)
    if not m:
        return None
    if m.group("proc") != "sshd":
        return None            # sudo, CRON, systemd - not our concern

    message = m.group("message")
    for pattern, outcome in _MESSAGES:
        mm = pattern.match(message)
        if not mm:
            continue
        try:
            ts = datetime.strptime(
                f"{year}-{_MONTHS[m.group('month')]:02d}-{int(m.group('day')):02d} "
                f"{m.group('time')}",
                "%Y-%m-%d %H:%M:%S",
            )
        except (KeyError, ValueError):
            return None
        return Event(
            timestamp=ts,
            source_ip=mm.group("ip"),
            username=mm.group("user").lower(),
            outcome=outcome,
            platform=Platform.LINUX,
            host=m.group("host"),
            raw=line,
        )
    return None


# ---------------------------------------------------------------------------
# Windows Security log
# ---------------------------------------------------------------------------

# 4624 = successful logon, 4625 = failed logon. These two IDs are the whole of
# Windows authentication monitoring for our purposes.
WIN_SUCCESS = "4624"
WIN_FAILURE = "4625"

# LogonType 3 is network, 10 is RemoteInteractive (RDP). 2 is the physical console
# and 5 is a service starting - neither is a remote attack, and both appear
# constantly on a normal machine. Including them would flood the output.
REMOTE_LOGON_TYPES = {"3", "10"}

# 4625 carries a SubStatus explaining WHY it failed. 0xC0000064 is "user does not
# exist", which is the Windows equivalent of sshd's "invalid user" and is how we
# tell username enumeration from password guessing on this platform.
SUBSTATUS_NO_SUCH_USER = {"0xc0000064", "0xC0000064", "3221225572"}


def parse_windows_csv(path: str | Path) -> ParseResult:
    """
    Parse a Security log exported to CSV.

    WHY CSV AND NOT .evtx. Reading the native binary event log needs either a
    Windows-only library or a third-party parser, and it would make this repo
    impossible to run or test on Linux or in CI. Exporting to CSV is one command
    (`wevtutil` or Event Viewer's Save As) and is documented in the README, so the
    cost is one manual step and the benefit is that the tool runs anywhere. That is
    the right trade for a portfolio project, but say so out loud rather than
    letting a reviewer discover it.

    Expected columns (case-insensitive, extra columns ignored):
        TimeCreated, EventID, TargetUserName, IpAddress, LogonType, SubStatus
    """
    events: list[Event] = []
    skipped = 0
    samples: list[str] = []

    with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        reader = csv.DictReader(fh)
        lower = {}
        if reader.fieldnames:
            lower = {name.lower().replace(" ", ""): name for name in reader.fieldnames}

        def get(row: dict, key: str) -> str:
            real = lower.get(key)
            return (row.get(real, "") or "").strip() if real else ""

        for row in reader:
            event_id = get(row, "eventid")
            if event_id not in (WIN_SUCCESS, WIN_FAILURE):
                skipped += 1
                if len(samples) < 5:
                    samples.append(str(row))
                continue

            logon_type = get(row, "logontype")
            ip = get(row, "ipaddress")
            # "-" and "::1" are Windows' way of saying "not from the network".
            if ip in ("", "-", "::1", "127.0.0.1") or logon_type not in REMOTE_LOGON_TYPES:
                skipped += 1
                continue

            ts = _parse_win_time(get(row, "timecreated"))
            if ts is None:
                skipped += 1
                continue

            if event_id == WIN_SUCCESS:
                outcome = Outcome.SUCCESS
            elif get(row, "substatus") in SUBSTATUS_NO_SUCH_USER:
                outcome = Outcome.INVALID_USER
            else:
                outcome = Outcome.FAILURE

            events.append(Event(
                timestamp=ts,
                source_ip=ip,
                username=get(row, "targetusername").lower() or None,
                outcome=outcome,
                platform=Platform.WINDOWS,
                host=get(row, "computer"),
                raw=",".join(f"{k}={v}" for k, v in row.items() if v),
            ))

    events.sort(key=lambda e: e.timestamp)
    return ParseResult(events, skipped, samples)


_WIN_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
]


def _parse_win_time(value: str) -> datetime | None:
    """
    Windows exports timestamps in whatever the machine's locale felt like.

    Note the ambiguity you cannot fix: 03/04/2026 is 3 April or 4 March depending
    on locale, and nothing in the file tells you which. We try day-first before
    month-first and document it. If this mattered for real use you would require
    ISO 8601 input and refuse anything else.
    """
    value = value.strip().split(".")[0].replace("Z", "")
    for fmt in _WIN_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def parse(path: str | Path, assume_year: int | None = None) -> ParseResult:
    """Pick a parser from the file extension. .csv is Windows, anything else syslog."""
    p = Path(path)
    if p.suffix.lower() == ".csv":
        return parse_windows_csv(p)
    return parse_auth_log(p, assume_year)
