"""
THE SPECIFICATION. If these pass, your rules are correct.

Read this file before you write any code in rules.py. It tells you exactly what
each rule must do, in a form a computer checks, which is more reliable than my
prose in the docstrings.

Run one rule at a time while you work:

    python -m pytest tests/test_rules.py -k brute_force -v
    python -m pytest tests/test_rules.py -k spray -v
    python -m pytest tests/test_rules.py -k success -v
    python -m pytest tests/test_rules.py -v          # everything

TWO KINDS OF TEST HERE, and the split is deliberate.

  UNIT tests build three or four events by hand. They are fast, and when one fails
  it tells you precisely which comparison is wrong. This is only possible because
  rules take Event objects rather than a file path - a rule that parsed its own log
  could not be tested this way.

  INTEGRATION tests run against the sample logs, where the ground truth is known
  because samples/generate.py created it. These catch the bugs unit tests miss:
  a rule that works on 4 events and double-counts on 46.

THE MOST IMPORTANT TEST IN THIS FILE is test_clean_log_produces_no_findings. Every
other test asks "does it catch the attack". That one asks "does it stay quiet when
nothing is happening", and a detector that fails it is useless in production no
matter how well it scores on the others.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from detector import parsers
from detector.events import Event, Outcome, Platform
from detector.rules import (
    DEFAULTS,
    Thresholds,
    detect_brute_force,
    detect_password_spray,
    detect_success_after_failures,
    run_all,
)

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
T0 = datetime(2026, 11, 16, 9, 0, 0)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def ev(offset: float, outcome: Outcome, user: str = "root",
       ip: str | None = "203.0.113.9") -> Event:
    """One event, `offset` seconds after T0."""
    return Event(
        timestamp=T0 + timedelta(seconds=offset),
        source_ip=ip,
        username=user,
        outcome=outcome,
        platform=Platform.LINUX,
        host="test",
        raw=f"synthetic {outcome.value} {user} {ip} +{offset}s",
    )


def fail(offset: float, user: str = "root", ip: str = "203.0.113.9") -> Event:
    return ev(offset, Outcome.FAILURE, user, ip)


def ok(offset: float, user: str = "root", ip: str = "203.0.113.9") -> Event:
    return ev(offset, Outcome.SUCCESS, user, ip)


def load(name: str):
    return parsers.parse(SAMPLES / name).events


def rules_of(findings) -> list[str]:
    return [f.rule for f in findings]


# ---------------------------------------------------------------------------
# detect_brute_force
# ---------------------------------------------------------------------------

class TestBruteForce:

    def test_fires_at_the_threshold(self):
        """Exactly 5 failures in 60s must fire. Off-by-one check on `>=`."""
        events = [fail(i * 10) for i in range(5)]      # 0,10,20,30,40 - 40s span
        assert len(detect_brute_force(events)) == 1

    def test_does_not_fire_below_the_threshold(self):
        """4 failures is not an attack. This is the false positive direction."""
        events = [fail(i * 10) for i in range(4)]
        assert detect_brute_force(events) == []

    def test_does_not_fire_when_spread_beyond_the_window(self):
        """
        10 failures, 90 seconds apart. Never 5 inside any 60-second window.

        A rule that totals failures per IP without regard to time passes every
        other test in this class and fails this one.
        """
        events = [fail(i * 90) for i in range(10)]
        assert detect_brute_force(events) == []

    def test_catches_a_burst_that_straddles_a_minute_boundary(self):
        """
        4 attempts just before 09:01:00 and 4 just after.

        Eight attempts in roughly two seconds. Fixed one-minute buckets split this
        into 4 and 4 and see nothing. A sliding window sees 8.
        """
        events = ([fail(59.0 + i * 0.2) for i in range(4)]
                  + [fail(61.0 + i * 0.2) for i in range(4)])
        assert len(detect_brute_force(events)) == 1

    def test_one_finding_per_ip_not_per_window(self):
        """
        46 failures produce dozens of breaching windows and exactly one finding.

        Get this wrong and the report is unreadable, which is a real failure even
        though the detection technically worked.
        """
        events = [fail(i * 5) for i in range(46)]
        findings = detect_brute_force(events)
        assert len(findings) == 1
        assert findings[0].source_ip == "203.0.113.9"

    def test_separate_ips_are_separate_findings(self):
        events = ([fail(i * 5, ip="203.0.113.9") for i in range(6)]
                  + [fail(i * 5, ip="198.51.100.7") for i in range(6)])
        findings = detect_brute_force(events)
        assert len(findings) == 2
        assert {f.source_ip for f in findings} == {"203.0.113.9", "198.51.100.7"}

    def test_successes_do_not_count_toward_the_threshold(self):
        """4 failures and 3 successes is not 7 failures."""
        events = [fail(i * 5) for i in range(4)] + [ok(30 + i) for i in range(3)]
        assert detect_brute_force(events) == []

    def test_severity_is_medium_without_a_success(self):
        findings = detect_brute_force([fail(i * 5) for i in range(6)])
        assert findings[0].severity == "medium"

    def test_severity_is_high_with_a_success_from_the_same_ip(self):
        events = [fail(i * 5) for i in range(6)] + [ok(40)]
        findings = detect_brute_force(events)
        assert findings[0].severity == "high"

    def test_detail_fields_are_present_and_correct(self):
        events = [fail(i * 5, user="root") for i in range(6)]
        events += [fail(30 + i * 5, user="admin") for i in range(6)]
        f = detect_brute_force(events)[0]
        assert f.detail["total_failures"] == 12
        assert f.detail["window_seconds"] == DEFAULTS.brute_force_window
        assert sorted(f.detail["usernames"]) == ["admin", "root"]
        assert f.detail["succeeded"] is False
        assert f.detail["peak_in_window"] >= DEFAULTS.brute_force_failures

    def test_evidence_is_attached(self):
        """A finding with no events cannot be checked by a reader."""
        f = detect_brute_force([fail(i * 5) for i in range(6)])[0]
        assert len(f.events) >= DEFAULTS.brute_force_failures
        assert all(e.outcome.is_failed for e in f.events)

    def test_respects_custom_thresholds(self):
        events = [fail(i * 10) for i in range(4)]
        assert detect_brute_force(events) == []
        loose = Thresholds(brute_force_failures=3)
        assert len(detect_brute_force(events, loose)) == 1

    def test_handles_empty_input(self):
        assert detect_brute_force([]) == []


# ---------------------------------------------------------------------------
# detect_password_spray
# ---------------------------------------------------------------------------

class TestPasswordSpray:

    def test_fires_on_many_accounts_few_attempts_each(self):
        events = [fail(i * 20, user=f"user{i}") for i in range(12)]
        findings = detect_password_spray(events)
        assert len(findings) == 1
        assert findings[0].detail["distinct_users"] == 12

    def test_does_not_fire_below_the_user_threshold(self):
        """9 accounts is under 10."""
        events = [fail(i * 20, user=f"user{i}") for i in range(9)]
        assert detect_password_spray(events) == []

    def test_does_not_fire_on_brute_force(self):
        """
        THE DISCRIMINATOR TEST. Read this one carefully.

        12 accounts, but 10 attempts against each. That is brute force that
        happened to touch several accounts, and calling it spraying describes the
        opposite of what the attacker did. The per-user cap is what prevents it.

        A rule that only counts distinct usernames passes every other test in this
        class and fails here.
        """
        events = []
        for u in range(12):
            for k in range(10):
                events.append(fail(u * 30 + k, user=f"user{u}"))
        assert detect_password_spray(events) == []

    def test_does_not_fire_when_spread_beyond_the_window(self):
        """14 accounts, one per hour. Spraying is slow, but not that slow."""
        events = [fail(i * 3600, user=f"user{i}") for i in range(14)]
        assert detect_password_spray(events) == []

    def test_one_finding_per_ip(self):
        events = [fail(i * 5, user=f"user{i}") for i in range(20)]
        assert len(detect_password_spray(events)) == 1

    def test_detail_fields(self):
        events = [fail(i * 20, user=f"user{i}") for i in range(12)]
        events += [fail(5 + i * 20, user=f"user{i}") for i in range(12)]
        f = detect_password_spray(events)[0]
        assert f.detail["distinct_users"] == 12
        assert f.detail["max_attempts_per_user"] == 2
        assert f.detail["window_seconds"] == DEFAULTS.spray_window
        assert len(f.detail["usernames"]) == 12

    def test_severity_high_when_one_landed(self):
        events = [fail(i * 20, user=f"user{i}") for i in range(12)]
        events.append(ok(400, user="user3"))
        assert detect_password_spray(events)[0].severity == "high"

    def test_handles_empty_input(self):
        assert detect_password_spray([]) == []


# ---------------------------------------------------------------------------
# detect_success_after_failures
# ---------------------------------------------------------------------------

class TestSuccessAfterFailures:

    def test_fires_when_failures_precede_a_success(self):
        events = [fail(0), fail(10), fail(20), ok(30)]
        findings = detect_success_after_failures(events)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert findings[0].detail["username"] == "root"
        assert findings[0].detail["prior_failures"] == 3

    def test_does_not_fire_when_the_success_comes_first(self):
        """
        DIRECTION TEST. The most common bug in this rule.

        A success, then failures. That is someone logging in and then fumbling a
        second session, and it happens constantly. If your comparison is
        `abs(delta) <= window` instead of a signed check, this test fails.
        """
        events = [ok(0), fail(10), fail(20), fail(30)]
        assert detect_success_after_failures(events) == []

    def test_does_not_fire_below_the_threshold(self):
        """Two mistypes then a success. This is a human, not an attack."""
        events = [fail(0), fail(5), ok(9)]
        assert detect_success_after_failures(events) == []

    def test_does_not_fire_when_failures_are_outside_the_window(self):
        """Failures yesterday, success today. Not related."""
        events = [fail(0), fail(10), fail(20), ok(86400)]
        assert detect_success_after_failures(events) == []

    def test_ignores_failures_from_a_different_ip(self):
        """
        Failures from one address, success from another.

        Per-IP is a weak proxy for an actor, but it is the proxy this tool uses,
        and mixing addresses would make every finding meaningless.
        """
        events = [fail(0, ip="1.1.1.1"), fail(10, ip="1.1.1.1"),
                  fail(20, ip="1.1.1.1"), ok(30, ip="2.2.2.2")]
        assert detect_success_after_failures(events) == []

    def test_one_finding_per_success(self):
        """Two accounts compromised from one address is two incidents."""
        events = [fail(0), fail(10), fail(20), ok(30, user="root"),
                  fail(40, user="admin"), fail(50, user="admin"),
                  fail(60, user="admin"), ok(70, user="admin")]
        findings = detect_success_after_failures(events)
        assert len(findings) == 2
        assert {f.detail["username"] for f in findings} == {"root", "admin"}

    def test_evidence_includes_the_success_itself(self):
        """
        The success is the point of the finding, so it must be in the evidence,
        and it must be last so the quoted lines read as a sequence.
        """
        events = [fail(0), fail(10), fail(20), ok(30)]
        f = detect_success_after_failures(events)[0]
        assert any(e.outcome is Outcome.SUCCESS for e in f.events)
        assert f.events[-1].outcome is Outcome.SUCCESS

    def test_invalid_user_failures_count(self):
        """A failure against a nonexistent account is still a failed attempt."""
        events = [ev(0, Outcome.INVALID_USER), ev(10, Outcome.INVALID_USER),
                  ev(20, Outcome.INVALID_USER), ok(30)]
        assert len(detect_success_after_failures(events)) == 1

    def test_handles_empty_input(self):
        assert detect_success_after_failures([]) == []


# ---------------------------------------------------------------------------
# Integration against the sample logs
# ---------------------------------------------------------------------------

class TestAgainstSamples:
    """
    Ground truth comes from samples/generate.py, which built these files and
    therefore knows exactly what is in them.
    """

    def test_clean_log_produces_no_findings(self):
        """
        THE FALSE POSITIVE TEST. The one that matters most.

        Five days of ordinary activity: a person mistyping their password, a
        service account authenticating constantly, scattered failures hours apart,
        and internet background noise. A correct detector reports nothing.

        If this fails, do not tune the test. Read which rule fired and fix the
        rule - the clean log is the definition of normal for this project, and a
        rule that fires on normal would be switched off within a week of real use.
        """
        findings = run_all(load("auth_clean.log"))
        assert findings == [], (
            "false positives on the clean log: "
            + "; ".join(f"{f.rule} on {f.source_ip} ({f.summary})" for f in findings)
        )

    def test_bruteforce_log(self):
        findings = run_all(load("auth_bruteforce.log"))
        rules = rules_of(findings)

        assert "brute_force" in rules
        assert "success_after_failures" in rules
        # 2 usernames, nowhere near the 10 a spray needs.
        assert "password_spray" not in rules

        bf = next(f for f in findings if f.rule == "brute_force")
        assert bf.source_ip == "203.0.113.9"
        assert bf.severity == "high"            # a success came from the same IP
        assert bf.detail["total_failures"] == 46
        assert sorted(bf.detail["usernames"]) == ["admin", "root"]

        comp = next(f for f in findings if f.rule == "success_after_failures")
        assert comp.detail["username"] == "root"
        assert comp.detail["prior_failures"] == 46

    def test_spray_log(self):
        findings = run_all(load("auth_spray.log"))
        rules = rules_of(findings)

        assert "password_spray" in rules
        # 28 failures over 8 minutes never reach 5 in any 60s window. This is the
        # whole reason spraying works against a brute-force-only detector.
        assert "brute_force" not in rules
        assert "success_after_failures" not in rules

        sp = next(f for f in findings if f.rule == "password_spray")
        assert sp.source_ip == "198.51.100.7"
        assert sp.severity == "medium"
        assert sp.detail["distinct_users"] == 14
        assert sp.detail["max_attempts_per_user"] == 2

    def test_windows_log(self):
        findings = run_all(load("windows_security.csv"))
        rules = rules_of(findings)

        assert "brute_force" in rules
        assert "success_after_failures" in rules

        bf = next(f for f in findings if f.rule == "brute_force")
        assert bf.source_ip == "10.0.0.66"
        assert bf.detail["total_failures"] == 24

        comp = next(f for f in findings if f.rule == "success_after_failures")
        assert comp.detail["username"] == "administrator"

    def test_console_logons_never_appear_in_findings(self):
        """
        LogonType 2 and 5 rows have no source IP and are not remote attacks.

        They are filtered in the parser, and remote_only() in rules.py is the
        second line of defence. Checking it here means a future change to either
        one cannot quietly reintroduce them.
        """
        findings = run_all(load("windows_security.csv"))
        for f in findings:
            assert f.source_ip not in (None, "", "-", "::1", "127.0.0.1")
            for e in f.events:
                assert e.is_remote


# ---------------------------------------------------------------------------
# Properties that must hold for every rule
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rule", [detect_brute_force,
                                  detect_password_spray,
                                  detect_success_after_failures])
class TestEveryRule:

    def test_empty_input(self, rule):
        assert rule([]) == []

    def test_returns_a_list(self, rule):
        assert isinstance(rule([fail(i) for i in range(3)]), list)

    def test_does_not_mutate_its_input(self, rule):
        """
        A rule that sorts its argument in place corrupts the list for every rule
        that runs after it. run_all() passes the same list to all three.
        """
        events = [fail(i * 5) for i in range(12)]
        before = list(events)
        rule(events)
        assert events == before

    def test_findings_carry_evidence(self, rule):
        events = [fail(i * 3, user=f"u{i % 14}") for i in range(30)] + [ok(200)]
        for f in rule(events):
            assert f.events, f"{f.rule} produced a finding with no evidence"
            assert f.summary
            assert f.severity in ("low", "medium", "high")
