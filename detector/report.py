"""
Incident report generation.

The point of this file: a detector's output is a list of findings, and a list of
findings is not an incident report. A report has to answer, in order, the questions
the person reading it actually has:

    Was I compromised?          <- first, always. Everything else is detail.
    By whom, and when?
    What did they try?
    What do I do now?
    How do you know?            <- the evidence, last, for whoever checks your work

Most tools stop at a findings list and call it a report. Writing the narrative is
what makes this project a "detection and incident report" rather than a log parser,
so it is worth more care than the formatting suggests.

ONE RULE OBSERVED THROUGHOUT: this file never invents a conclusion the rules did not
reach. "Possible compromise" when a success followed failures; never "you were
hacked". The detector sees authentication records and nothing else - it cannot know
whether the successful login was the attacker or the admin logging in to
investigate. Writing certainty you do not have is how a tool loses the reader's
trust, and it is the thing an interviewer will test you on.
"""

from __future__ import annotations

import json
from datetime import datetime

from detector.events import Event, Finding
from detector.parsers import ParseResult
from detector.rules import Thresholds

LINE = "=" * 78
THIN = "-" * 78


def _fmt(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "unknown"


def _window(findings: list[Finding]) -> tuple[datetime | None, datetime | None]:
    starts = [f.first_seen for f in findings if f.first_seen]
    ends = [f.last_seen for f in findings if f.last_seen]
    return (min(starts) if starts else None, max(ends) if ends else None)


def verdict(findings: list[Finding]) -> tuple[str, str]:
    """
    The headline. Returns (label, one-line explanation).

    Deliberately only three outcomes, because a reader skimming the top of a report
    is making one decision: do I act tonight, do I act this week, or do I file it.

    Note what the COMPROMISE label does not say. It says the records are consistent
    with a successful guess and that the account needs checking - not that an
    attacker is inside. The distinction is the difference between a report that gets
    acted on and one that gets ignored after the first false alarm.
    """
    if any(f.rule == "success_after_failures" for f in findings):
        return ("POSSIBLE COMPROMISE",
                "A login succeeded from an address that had just failed repeatedly. "
                "Treat the affected account as suspect until verified.")
    if findings:
        return ("ATTACK ATTEMPTED, NO SUCCESS OBSERVED",
                "Automated guessing was detected. No successful authentication from "
                "the same source appears in this log.")
    return ("NOTHING DETECTED",
            "No activity in this log crossed the configured thresholds.")


def render(findings: list[Finding],
           parsed: ParseResult,
           source: str,
           t: Thresholds,
           evidence_lines: int = 6) -> str:
    """
    The full text report.

    `evidence_lines` caps how many raw log lines are quoted per finding. Quoting all
    46 failures proves nothing the first 6 did not, and a report nobody finishes is
    a report nobody acts on.
    """
    label, explanation = verdict(findings)
    start, end = _window(findings)
    out: list[str] = []

    out += [LINE,
            "SSH / REMOTE AUTHENTICATION INCIDENT REPORT",
            LINE,
            f"Generated      {_fmt(datetime.now())}",
            f"Log analysed   {source}",
            f"Events parsed  {len(parsed.events)} authentication attempts"
            f"  ({parsed.skipped} non-auth lines skipped)",
            "",
            f"VERDICT        {label}",
            f"               {explanation}",
            ""]

    if findings:
        out += [f"Findings       {len(findings)}"
                f"  ({sum(1 for f in findings if f.severity == 'high')} high)",
                f"Activity span  {_fmt(start)} to {_fmt(end)}",
                ""]

    # -- Thresholds up front, not buried in an appendix. Every finding below is a
    # -- consequence of these numbers, so a reader who disagrees with the numbers
    # -- needs them before the findings, not after.
    out += [THIN,
            "DETECTION THRESHOLDS IN EFFECT",
            THIN,
            f"  brute force      >= {t.brute_force_failures} failures "
            f"in {t.brute_force_window}s from one address",
            f"  password spray   >= {t.spray_users} distinct accounts "
            f"in {t.spray_window}s, <= {t.spray_max_per_user} attempts each",
            f"  compromise       >= {t.success_after_failures} failures "
            f"in the {t.success_window}s before a success",
            ""]

    if not findings:
        out += [THIN,
                "NO FINDINGS",
                THIN,
                "  This is a result, not an absence of one: the log was parsed and",
                "  nothing in it crossed the thresholds above. An attack slower or",
                "  quieter than those thresholds would not appear here.",
                ""]
    else:
        out += [THIN, "FINDINGS", THIN, ""]
        for i, f in enumerate(findings, 1):
            out += [f"  {i}. [{f.severity.upper()}] {f.rule}",
                    f"     {f.summary}",
                    f"     source      {f.source_ip or 'n/a'}",
                    f"     first seen  {_fmt(f.first_seen)}",
                    f"     last seen   {_fmt(f.last_seen)}"]
            for k, v in f.detail.items():
                if isinstance(v, list):
                    shown = ", ".join(str(x) for x in v[:8])
                    if len(v) > 8:
                        shown += f", +{len(v) - 8} more"
                    v = shown
                out += [f"     {k:<21} {v}"]
            out += [""]

        out += recommendations(findings)
        out += evidence(findings, evidence_lines)

    out += [THIN,
            "LIMITATIONS OF THIS REPORT",
            THIN,
            "  - Source IP is used as a proxy for an actor. One address can be a",
            "    whole office behind NAT; one actor can be a thousand addresses.",
            "  - Only authentication records are examined. A successful login using",
            "    stolen valid credentials, with no failures first, looks identical",
            "    to a legitimate one here and will not be flagged.",
            "  - Timestamps are treated as naive local time. Correlating logs from",
            "    hosts in different timezones would need that fixed first.",
            "  - Thresholds are tuned against the clean sample in this repository,",
            "    not against the environment this log came from.",
            "",
            LINE]
    return "\n".join(out)


def recommendations(findings: list[Finding]) -> list[str]:
    """
    What to do, derived from which rules fired.

    Ordered by urgency, and each one tied to a specific finding rather than being
    generic advice. "Enable key-based authentication" is good advice in a blog post;
    in a report it needs to be there because THIS log showed password guessing
    against THIS account.
    """
    out = [THIN, "RECOMMENDED ACTIONS", THIN]
    compromised = [f for f in findings if f.rule == "success_after_failures"]
    ips = sorted({f.source_ip for f in findings if f.source_ip})

    if compromised:
        users = sorted({str(f.detail.get("username", "?")) for f in compromised})
        out += [
            "  IMMEDIATE",
            f"  1. Treat {', '.join(users)} as compromised until proven otherwise.",
            "     Reset the credential and revoke existing sessions and keys.",
            "  2. Check what happened after the successful login: shell history,",
            "     sudo use, new accounts, new SSH authorized_keys, scheduled jobs.",
            "     The successful login is the start of the incident, not the end.",
            f"  3. Block {', '.join(ips)} at the firewall, but do not treat that as",
            "     containment - if credentials leaked, the address is disposable.",
            "",
        ]

    out += [
        "  HARDENING",
        "  - Disable password authentication for SSH and use keys",
        "    (PasswordAuthentication no). This removes the attack entirely rather",
        "    than rate-limiting it.",
        "  - Disable direct root login (PermitRootLogin no).",
        "  - Install fail2ban or equivalent so repeated failures are blocked in",
        "    seconds rather than discovered in a log afterwards.",
        "  - Restrict the service to known source ranges, or put it behind a VPN,",
        "    if it does not need to face the internet.",
        "",
        "  DETECTION",
        "  - Ship these logs somewhere the attacker cannot edit them. Local-only",
        "    logs are worth little once a host is compromised.",
        "",
    ]
    return out


def evidence(findings: list[Finding], limit: int) -> list[str]:
    """
    Quoted log lines.

    This section is why `raw` is carried on every Event. A report that asserts
    counts is something a reader has to trust. A report that shows the lines it
    counted is something they can check, and being checkable is the entire value of
    an incident report.
    """
    out = [THIN, "EVIDENCE", THIN,
           f"  Raw log lines, up to {limit} per finding.", ""]
    for i, f in enumerate(findings, 1):
        out.append(f"  Finding {i} - {f.rule}")
        shown: list[Event] = f.events[:limit]
        for e in shown:
            out.append(f"    | {e.raw or str(e)}")
        if len(f.events) > limit:
            out.append(f"    | ... {len(f.events) - limit} further line(s) omitted")
        out.append("")
    return out


def to_json(findings: list[Finding], parsed: ParseResult, source: str) -> str:
    """
    Machine-readable output.

    Exists so the tool can feed something else - a ticket, a SIEM, a cron job that
    mails you - rather than only a human. Evidence is reduced to the raw lines
    because nothing downstream needs the parsed structure, and keeping the full
    Event objects would triple the size for no gain.
    """
    label, explanation = verdict(findings)
    return json.dumps({
        "source": source,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "events_parsed": len(parsed.events),
        "lines_skipped": parsed.skipped,
        "verdict": label,
        "verdict_detail": explanation,
        "findings": [{
            "rule": f.rule,
            "severity": f.severity,
            "source_ip": f.source_ip,
            "summary": f.summary,
            "first_seen": f.first_seen.isoformat() if f.first_seen else None,
            "last_seen": f.last_seen.isoformat() if f.last_seen else None,
            "detail": f.detail,
            "evidence": [e.raw or str(e) for e in f.events[:20]],
        } for f in findings],
    }, indent=2)
