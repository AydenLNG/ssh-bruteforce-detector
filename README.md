# SSH Brute-Force Detection and Incident Report

Reads Linux `auth.log` or a Windows Security log export, detects three distinct
authentication attacks, and writes an incident report with quoted evidence.

No dependencies outside the Python standard library. Sample logs are included, so
the tool runs immediately after cloning.

```bash
git clone <repo>
cd ssh-bruteforce-detector
python detect.py samples/auth_bruteforce.log
```

---

## What it detects

| Rule | What it looks for | Why it is separate |
|---|---|---|
| `brute_force` | Many password attempts against few accounts, from one address, inside 60 seconds | The loud, obvious attack |
| `password_spray` | Few attempts against *many* accounts, deliberately slow | Designed to stay under account-lockout thresholds, so a brute-force-only detector misses it entirely |
| `success_after_failures` | A login that **succeeded** from an address that had just been failing | The only rule that describes an attack which worked |

The third rule is the one that matters. The first two find attempts; this one finds
compromises.

---

## Usage

```bash
python detect.py samples/auth_clean.log            # a clean log, for comparison
python detect.py samples/auth_bruteforce.log       # brute force ending in compromise
python detect.py samples/auth_spray.log            # password spraying
python detect.py samples/windows_security.csv      # Windows / RDP

python detect.py /var/log/auth.log --out report.txt
python detect.py /var/log/auth.log --json
python detect.py /var/log/auth.log --bf-failures 3 --bf-window 120
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Parsed successfully, nothing crossed a threshold |
| 1 | Attack attempted, no success observed |
| 2 | Possible compromise |
| 3 | Could not parse the input |

Separating 1 from 2 is what makes it automatable:

```bash
python detect.py /var/log/auth.log --out /tmp/r.txt
[ $? -ge 2 ] && mail -s "possible compromise on $(hostname)" me@example.com < /tmp/r.txt
```

### Getting a Windows log

The Windows Security log is read from a CSV export rather than the native `.evtx`
binary, so that the tool runs and is testable on any platform:

```powershell
wevtutil qe Security /q:"*[System[(EventID=4624 or EventID=4625)]]" /f:text > security.txt
```

Or in Event Viewer: Security log, **Save All Events As**, CSV. Required columns are
`TimeCreated, EventID, TargetUserName, IpAddress, LogonType, SubStatus`.

---

## Design

### Parsers are the only platform-aware code

`auth.log` is unstructured text written for humans. The Windows Security log is
structured records with numeric event IDs. The naive approach is one detector per
platform, which fails because the detection logic is identical for both: "five
failures from one address in a minute" is the same question regardless of which
service logged it. Writing it twice means fixing a bug in one copy and not the other.

So parsers convert both formats into a single `Event` type, and the rules see
nothing else:

```
auth.log ───▶ parse_auth_log    ─┐
                                 ├──▶ [Event] ──▶ rules ──▶ [Finding] ──▶ report
Security CSV ─▶ parse_windows_csv ┘
```

The practical payoff is testability. Rules can be tested with four hand-built
`Event` objects, so a failing test points at one comparison rather than at a whole
pipeline.

### Brute force and spraying need each other to be meaningful

Both rules count failures per address, and without a discriminator they fire on each
other's traffic. An address that tried 100 passwords against each of 15 accounts
matches "15 distinct accounts" and gets labelled a spray, which describes the
opposite of what happened.

The discriminator is `spray_max_per_user`: a spray requires many accounts **and** few
attempts per account. Removing that one condition makes both findings meaningless,
which is why it has a test of its own.

### Sliding windows, not fixed buckets

Counting failures in fixed one-minute buckets misses an attacker who sends four
attempts at 09:00:59 and four more at 09:01:01. Eight attempts in two seconds, split
across two buckets, each under the threshold. A sliding window has no boundary to
hide on. There is a test for exactly this.

### Evidence, not assertions

Every `Event` keeps its original log line, and every finding carries the events that
triggered it. A report that states "46 failed logins from 203.0.113.9" asks the
reader to trust it. One that quotes the lines it counted can be checked, and being
checkable is the entire value of an incident report.

### The report never claims more than the data supports

The verdict for a successful login after repeated failures is **POSSIBLE
COMPROMISE**, not "you were hacked". The tool sees authentication records and nothing
else. It cannot know whether the successful login was the attacker or an
administrator logging in to investigate.

---

## False positive rate

The claim most detection projects skip. Every rule here is a threshold, and a
threshold is a claim about what normal looks like, so the thresholds are tuned
against a known-clean sample rather than taken from a blog post.

`samples/auth_clean.log` is five days of ordinary activity and the detector reports
**zero findings** on it. It deliberately contains the cases that break naive rules:

- A user mistyping their password twice, then getting in. Two failures, under the
  threshold of three. A rule that alerts on *any* failure before a success fires
  here, would fire several times a day in production, and would be switched off
  within a week.
- Four failed logins from one office address, hours apart across the week. Under the
  count threshold, but more importantly spread far beyond the window. A rule using
  daily totals instead of a 60-second window fires here.
- A service account authenticating by key twelve times a day. High volume, all
  successful. A rule keyed on volume rather than failures fires here.
- Internet background noise: single failed attempts from unrelated addresses. Real,
  constant, and not actionable.

```bash
python detect.py samples/auth_clean.log     # exit 0, NOTHING DETECTED
```

Measured against these samples: 3 attacks detected, 0 false positives on 107 lines
of clean activity. That is a small sample and is not a production false positive
rate, which would require real logs from the environment being monitored.

---

## Thresholds

| Setting | Default | Reasoning |
|---|---|---|
| `brute_force_failures` / `window` | 5 in 60s | A human mistyping produces 2 or 3 attempts then pauses to think, which takes longer than a minute |
| `spray_users` / `window` | 10 accounts in 600s | Spraying is deliberately slow, so the window is wider |
| `spray_max_per_user` | 3 | The discriminator against brute force |
| `success_after_failures` / `window` | 3 in 600s | Lower than the brute-force threshold on purpose: once a success is involved, a false negative is a missed breach |

All are overridable on the command line, and the report prints the values it used,
so a reader who disagrees with the numbers can see what produced the findings.

---

## Tests

```bash
python -m pytest -v
```

71 tests. The rule tests double as the specification: unit tests on hand-built
events for precision, integration tests against the sample logs where the ground
truth is known because `samples/generate.py` generated it.

Notable cases:

- `test_clean_log_produces_no_findings` — the false positive test
- `test_catches_a_burst_that_straddles_a_minute_boundary` — fixed buckets fail this
- `test_does_not_fire_on_brute_force` — the spray discriminator
- `test_does_not_fire_when_the_success_comes_first` — direction of the time comparison
- `test_does_not_mutate_its_input` — all three rules receive the same list

Sample logs are generated, not captured, and the generator is committed so the data
is reproducible and the synthetic origin is stated rather than implied:

```bash
python samples/generate.py
```

There is also a pre-publication check, because a log analysis project is one copied
file away from publishing someone's real auth records:

```bash
python scripts/pre_push_check.py
```

It flags routable addresses in sample data, credential patterns, real email
addresses, and filenames that look like real captures rather than generated ones.
Every address in `samples/` is private (RFC 1918) or from a reserved documentation
range (RFC 5737), so none of them belongs to a real machine.

---

## Limitations

Stated here rather than discovered later.

- **Source IP is a weak proxy for an actor.** One address can be an entire office
  behind NAT. One actor can be a thousand addresses in a botnet. Every per-address
  finding inherits that weakness.
- **Only authentication records are examined.** A login using stolen valid
  credentials, with no failures first, is indistinguishable from a legitimate one
  here and will not be flagged. This tool detects guessing, not intrusion.
- **An attack slower than the thresholds is invisible.** A patient attacker trying
  one password per hour crosses nothing. This is inherent to threshold detection,
  not a bug, and is the reason thresholds are printed in the report.
- **Timestamps are naive local time.** Correlating logs from hosts in different
  timezones would need timezone handling first.
- **`auth.log` has no year.** Syslog records `Nov 16 09:12:03` and nothing more. The
  current year is assumed unless `--year` is passed, so a log spanning New Year will
  be wrong for the earlier portion.
- **Windows input is a CSV export, not `.evtx`.** Reading the native binary format
  needs a Windows-only library, which would make the project untestable elsewhere.
  The cost is one manual export step.
- **Thresholds are tuned against the clean sample in this repository**, not against
  any real environment.

## Possible extensions

- Geolocation and ASN lookup on source addresses, to separate residential noise from
  hosting providers
- Correlation across multiple hosts, which needs the timezone problem solved first
- Writing firewall rules directly, which would need a dry-run mode and a careful look
  at the consequences of acting on a false positive
