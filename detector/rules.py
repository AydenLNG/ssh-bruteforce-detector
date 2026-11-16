"""
Detection rules. YOUR PART. The three functions marked TODO are blank.

Everything above them - thresholds, grouping, the sliding window - is done, because
that is mechanics. The detection logic is the thing worth writing yourself.

HOW TO WORK THROUGH THIS
    1. Read the docstring of the rule you are implementing. It states the algorithm
       in words, precisely enough to translate directly into code.
    2. Write it.
    3. Run `python -m pytest tests/test_rules.py -k <rule_name> -v`. The tests ARE
       the specification. If they pass, the rule is correct by definition.
    4. When stuck, ask and I will explain the error rather than hand you the answer.

THE THING MOST PEOPLE GET WRONG HERE, so watch for it: every one of these rules is
a threshold, and a threshold is a claim about normal behaviour. The tests include a
clean log that must produce ZERO findings. If your rule fires on it, the rule is
wrong even if it also catches the attack. A detector that alerts on everything is
not a detector.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Iterator

from detector.events import Event, Finding, Outcome

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Thresholds:
    """
    Every number the detector depends on, in one place.

    WHY THESE VALUES. They are defensible starting points, not truths. A reviewer
    may well ask where they came from, and "I tuned them against my clean sample
    until the false positive rate was zero" is a good answer. "They were in a blog
    post" is not.

    brute_force_failures / brute_force_window
        5 failures in 60 seconds. A human mistyping a password produces 2 or 3
        attempts and then stops to think, which takes longer than a minute. Five
        inside sixty seconds is automated.

    spray_users / spray_window
        10 distinct usernames from one IP in 10 minutes. Spraying is the inverse of
        brute force: few attempts per account, many accounts, which is designed
        specifically to stay under a per-account lockout threshold. The window is
        wider because spraying is deliberately slow.

    spray_max_per_user
        3. The discriminator between the two attacks. If an IP hit 20 accounts but
        tried 50 passwords on one of them, that is brute force that happened to
        touch several accounts, not a spray. Without this cap the two rules fire on
        each other's traffic and both findings become meaningless.

    success_after_failures / success_window
        3 failures in the 10 minutes before a success from the same IP. This is the
        highest-severity rule in the file because it is the only one describing an
        attack that WORKED. The threshold is lower than brute_force_failures on
        purpose: once a success is involved, the cost of a false negative is a
        missed breach, so the rule is deliberately more sensitive than the others.
    """

    brute_force_failures: int = 5
    brute_force_window: int = 60

    spray_users: int = 10
    spray_window: int = 600
    spray_max_per_user: int = 3

    success_after_failures: int = 3
    success_window: int = 600


DEFAULTS = Thresholds()


# ---------------------------------------------------------------------------
# Helpers - implemented for you
# ---------------------------------------------------------------------------

def remote_only(events: list[Event]) -> list[Event]:
    """
    Drop anything without a source IP.

    Console logons and service starts have no IP. They are not remote attacks and
    counting them toward a per-IP threshold is meaningless.
    """
    return [e for e in events if e.is_remote]


def group_by_ip(events: list[Event]) -> dict[str, list[Event]]:
    """
    Bucket events by source IP, each bucket sorted by time.

    Every rule here is per-IP, because an IP is the closest thing a log gives you to
    an actor. It is a weak proxy - NAT puts a whole office behind one address, and a
    botnet gives one actor thousands - and that limitation belongs in the README.
    """
    buckets: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.source_ip:
            buckets[e.source_ip].append(e)
    for ip in buckets:
        buckets[ip].sort(key=lambda e: e.timestamp)
    return dict(buckets)


def sliding_windows(events: list[Event], seconds: int) -> Iterator[list[Event]]:
    """
    Yield every maximal run of events that fits inside a `seconds`-long window.

    Events must already be sorted by time. For each starting event i, this yields
    the slice of events from i up to the last one within `seconds` of it.

    THE MISTAKE THIS HELPER EXISTS TO PREVENT. The obvious implementation of "5
    failures in 60 seconds" is to chop time into fixed one-minute buckets and count
    each bucket. That misses an attacker who sends 4 attempts at 09:00:59 and 4 more
    at 09:01:01 - eight attempts in two seconds, split across two buckets, each
    under the threshold. A sliding window has no boundary to hide on.

    Two pointers, so this is O(n) per IP rather than O(n squared).
    """
    if not events:
        return
    span = timedelta(seconds=seconds)
    right = 0
    for left in range(len(events)):
        if right < left:
            right = left
        while (right + 1 < len(events)
               and events[right + 1].timestamp - events[left].timestamp <= span):
            right += 1
        yield events[left:right + 1]


def failures(events: list[Event]) -> list[Event]:
    """Failed attempts only, both wrong-password and no-such-user."""
    return [e for e in events if e.outcome.is_failed]


# ---------------------------------------------------------------------------
# Rules - YOUR PART
# ---------------------------------------------------------------------------

def detect_brute_force(
    events: list[Event],
    t: Thresholds = DEFAULTS,
) -> list[Finding]:
    """
    Detects rapid failed logins against a small number of accounts from one IP.
    Five failures in 60 seconds suggests automated password guessing; a later
    success from the same IP raises the severity.
    """
    findings: list[Finding] = []

    for ip, ip_events in group_by_ip(events).items():
        failed = failures(ip_events)
        peak = max(
            (
                len(window)
                for window in sliding_windows(failed, t.brute_force_window)
            ),
            default=0,
        )

        if not failed or peak < t.brute_force_failures:
            continue

        usernames = sorted({e.username for e in failed})
        succeeded = any(e.outcome == Outcome.SUCCESS for e in ip_events)

        findings.append(
            Finding(
                rule="brute_force",
                severity="high" if succeeded else "medium",
                source_ip=ip,
                summary=(
                    f"{len(failed)} failed logins from {ip} against "
                    f"{len(usernames)} account(s), peak {peak} "
                    f"in {t.brute_force_window}s"
                ),
                detail={
                    "total_failures": len(failed),
                    "peak_in_window": peak,
                    "window_seconds": t.brute_force_window,
                    "usernames": usernames,
                    "succeeded": succeeded,
                },
                events=failed,
            )
        )

    return findings


def detect_password_spray(
    events: list[Event],
    t: Thresholds = DEFAULTS,
) -> list[Finding]:
    """
    Detects one IP making few attempts against many accounts, the inverse of
    brute force. The per-username cap keeps this rule from matching accounts
    that are actually being brute-forced.
    """
    findings: list[Finding] = []

    for ip, ip_events in group_by_ip(events).items():
        failed = failures(ip_events)

        for window in sliding_windows(failed, t.spray_window):
            counts = Counter(e.username for e in window)
            distinct_users = len(counts)
            max_attempts = max(counts.values(), default=0)

            if (
                distinct_users >= t.spray_users
                and max_attempts <= t.spray_max_per_user
            ):
                succeeded = any(
                    e.outcome == Outcome.SUCCESS for e in ip_events
                )

                findings.append(
                    Finding(
                        rule="password_spray",
                        severity="high" if succeeded else "medium",
                        source_ip=ip,
                        summary=(
                            f"Password spraying from {ip}: "
                            f"{distinct_users} accounts, max {max_attempts} "
                            f"attempts each, within {t.spray_window}s"
                        ),
                        detail={
                            "distinct_users": distinct_users,
                            "max_attempts_per_user": max_attempts,
                            "window_seconds": t.spray_window,
                            "usernames": sorted(counts),
                            "succeeded": succeeded,
                        },
                        events=window,
                    )
                )
                break

    return findings


def detect_success_after_failures(
    events: list[Event],
    t: Thresholds = DEFAULTS,
) -> list[Finding]:
    """
    Detects a successful login from an IP that had repeated failures just
    beforehand, indicating that password guessing may have succeeded. Only
    failures before the success count, and each success is reported separately.
    """
    findings: list[Finding] = []

    for ip, ip_events in group_by_ip(events).items():
        failed = failures(ip_events)

        for success in ip_events:
            if success.outcome != Outcome.SUCCESS:
                continue

            prior = [
                event
                for event in failed
                if 0
                < (success.timestamp - event.timestamp).total_seconds()
                <= t.success_window
            ]

            if len(prior) < t.success_after_failures:
                continue

            findings.append(
                Finding(
                    rule="success_after_failures",
                    severity="high",
                    source_ip=ip,
                    summary=(
                        f"Successful login as {success.username} from {ip} "
                        f"after {len(prior)} failed attempts in the preceding "
                        f"{t.success_window}s - possible compromise"
                    ),
                    detail={
                        "username": success.username,
                        "prior_failures": len(prior),
                        "window_seconds": t.success_window,
                        "success_time": success.timestamp.isoformat(),
                    },
                    events=[*prior, success],
                )
            )

    return findings



# ---------------------------------------------------------------------------
# Runner - implemented for you
# ---------------------------------------------------------------------------

ALL_RULES = (
    detect_brute_force,
    detect_password_spray,
    detect_success_after_failures,
)


def run_all(events: list[Event], t: Thresholds = DEFAULTS) -> list[Finding]:
    """
    Run every rule over the same events and return the findings, sorted.

    Filters to remote events once, here, so each rule does not have to remember to.
    """
    from detector.events import sort_findings

    remote = remote_only(events)
    out: list[Finding] = []
    for rule in ALL_RULES:
        out.extend(rule(remote, t))
    return sort_findings(out)
