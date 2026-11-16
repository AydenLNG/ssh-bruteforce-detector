"""
Parser tests. These already pass - the parsers are written.

They are here because parsing is where this kind of tool fails silently. A rule that
is wrong gives you a wrong finding, which is visible. A parser that is wrong gives
you an empty findings list, which looks exactly like a clean log.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from detector import parsers
from detector.events import Outcome, Platform

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


class TestAuthLogLines:

    def line(self, text: str):
        return parsers._parse_auth_line(text, 2026)

    def test_failed_password(self):
        e = self.line("Nov 16 09:12:03 ubuntu-vm sshd[1423]: Failed password "
                      "for root from 203.0.113.9 port 48122 ssh2")
        assert e is not None
        assert e.outcome is Outcome.FAILURE
        assert e.username == "root"
        assert e.source_ip == "203.0.113.9"
        assert e.host == "ubuntu-vm"
        assert e.timestamp == datetime(2026, 11, 16, 9, 12, 3)
        assert e.platform is Platform.LINUX

    def test_invalid_user_is_a_distinct_outcome(self):
        """
        Both are failures, but they mean different things: guessing a password
        against a real account, versus guessing which accounts exist.
        """
        e = self.line("Nov 16 09:12:04 ubuntu-vm sshd[1424]: Failed password "
                      "for invalid user admin from 203.0.113.9 port 48123 ssh2")
        assert e.outcome is Outcome.INVALID_USER
        assert e.outcome.is_failed
        assert e.username == "admin"

    def test_accepted_password(self):
        e = self.line("Nov 16 09:13:00 ubuntu-vm sshd[1500]: Accepted password "
                      "for ayden from 192.168.1.10 port 51234 ssh2")
        assert e.outcome is Outcome.SUCCESS
        assert not e.outcome.is_failed

    def test_accepted_publickey(self):
        e = self.line("Nov 16 09:13:00 ubuntu-vm sshd[1500]: Accepted publickey "
                      "for deploy from 192.168.1.22 port 51022 ssh2: RSA SHA256:x")
        assert e is not None
        assert e.outcome is Outcome.SUCCESS
        assert e.username == "deploy"

    def test_usernames_are_lowercased(self):
        """Otherwise Root and root count as two different accounts."""
        e = self.line("Nov 16 09:12:03 ubuntu-vm sshd[1423]: Failed password "
                      "for ROOT from 203.0.113.9 port 48122 ssh2")
        assert e.username == "root"

    def test_raw_line_is_preserved(self):
        text = ("Nov 16 09:12:03 ubuntu-vm sshd[1423]: Failed password "
                "for root from 203.0.113.9 port 48122 ssh2")
        assert self.line(text).raw == text

    def test_non_sshd_lines_are_ignored(self):
        """sudo and CRON live in auth.log and are not SSH authentication."""
        assert self.line("Nov 16 09:05:01 ubuntu-vm sudo: ayden : TTY=pts/0 ; "
                         "USER=root ; COMMAND=/usr/bin/apt update") is None
        assert self.line("Nov 16 09:05:00 ubuntu-vm CRON[9536]: "
                         "pam_unix(cron:session): session opened for user root") is None

    def test_sshd_lines_that_are_not_auth_attempts_are_ignored(self):
        assert self.line("Nov 16 09:12:10 ubuntu-vm sshd[1423]: Received "
                         "disconnect from 192.168.1.10 port 51234:11: "
                         "disconnected by user") is None

    def test_garbage_does_not_raise(self):
        assert self.line("") is None
        assert self.line("not a log line at all") is None
        assert self.line("Nov 99 99:99:99 host sshd[1]: Failed password for a "
                         "from 1.1.1.1") is None


class TestAuthLogFiles:

    def test_clean_log_parses(self):
        r = parsers.parse_auth_log(SAMPLES / "auth_clean.log", assume_year=2026)
        assert len(r.events) > 50
        assert r.skipped > 0, "the clean log contains non-auth noise on purpose"
        assert r.events == sorted(r.events, key=lambda e: e.timestamp)

    def test_bruteforce_log_counts(self):
        r = parsers.parse_auth_log(SAMPLES / "auth_bruteforce.log", assume_year=2026)
        attacker = [e for e in r.events if e.source_ip == "203.0.113.9"]
        assert len([e for e in attacker if e.outcome.is_failed]) == 46
        assert len([e for e in attacker if e.outcome is Outcome.SUCCESS]) == 1

    def test_spray_log_counts(self):
        r = parsers.parse_auth_log(SAMPLES / "auth_spray.log", assume_year=2026)
        attacker = [e for e in r.events if e.source_ip == "198.51.100.7"]
        assert len(attacker) == 28
        assert len({e.username for e in attacker}) == 14

    def test_unparsed_samples_are_reported(self):
        """
        So a parse failure is diagnosable. Without this the CLI can only say
        "0 events", which does not tell you why.
        """
        r = parsers.parse_auth_log(SAMPLES / "auth_clean.log", assume_year=2026)
        assert r.unparsed_samples
        assert len(r.unparsed_samples) <= 5


class TestWindowsCsv:

    def test_parses_and_filters(self):
        r = parsers.parse_windows_csv(SAMPLES / "windows_security.csv")
        assert len(r.events) == 26          # 24 failures + 2 remote successes
        assert all(e.is_remote for e in r.events)
        assert all(e.platform is Platform.WINDOWS for e in r.events)

    def test_console_and_service_logons_are_skipped(self):
        """
        LogonType 2 is someone at the keyboard, 5 is a service starting. Both are
        constant on a normal machine and neither is a remote attack.
        """
        r = parsers.parse_windows_csv(SAMPLES / "windows_security.csv")
        assert "-" not in {e.source_ip for e in r.events}
        assert r.skipped >= 3

    def test_unknown_event_ids_are_skipped_not_fatal(self):
        """Event 4672 is in the sample specifically to check this."""
        r = parsers.parse_windows_csv(SAMPLES / "windows_security.csv")
        assert r.events, "parser gave up instead of skipping the unknown ID"

    def test_substatus_maps_to_invalid_user(self):
        """0xC0000064 is 'that account does not exist' - Windows' invalid user."""
        r = parsers.parse_windows_csv(SAMPLES / "windows_security.csv")
        assert any(e.outcome is Outcome.INVALID_USER for e in r.events)
        assert any(e.outcome is Outcome.FAILURE for e in r.events)

    def test_4624_is_success(self):
        r = parsers.parse_windows_csv(SAMPLES / "windows_security.csv")
        assert any(e.outcome is Outcome.SUCCESS for e in r.events)


class TestDispatch:

    def test_csv_goes_to_the_windows_parser(self):
        r = parsers.parse(SAMPLES / "windows_security.csv")
        assert all(e.platform is Platform.WINDOWS for e in r.events)

    def test_log_goes_to_the_syslog_parser(self):
        r = parsers.parse(SAMPLES / "auth_bruteforce.log", 2026)
        assert all(e.platform is Platform.LINUX for e in r.events)


class TestTimestampEdgeCases:

    def test_windows_iso_and_space_separated(self):
        assert parsers._parse_win_time("2026-11-16T09:12:03") == \
            datetime(2026, 11, 16, 9, 12, 3)
        assert parsers._parse_win_time("2026-11-16 09:12:03") == \
            datetime(2026, 11, 16, 9, 12, 3)

    def test_windows_fractional_seconds_tolerated(self):
        assert parsers._parse_win_time("2026-11-16 09:12:03.1234567") == \
            datetime(2026, 11, 16, 9, 12, 3)

    def test_unparseable_time_returns_none(self):
        assert parsers._parse_win_time("not a date") is None
        assert parsers._parse_win_time("") is None

    def test_syslog_year_is_assumed_not_invented(self):
        """
        The year is the parser's one genuine blind spot. Changing assume_year must
        change the result, which is what makes the limitation visible rather than
        hidden.
        """
        text = ("Nov 16 09:12:03 h sshd[1]: Failed password for root "
                "from 1.1.1.1 port 2 ssh2")
        assert parsers._parse_auth_line(text, 2025).timestamp.year == 2025
        assert parsers._parse_auth_line(text, 2026).timestamp.year == 2026
