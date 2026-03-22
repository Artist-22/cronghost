#!/usr/bin/env python3

# ============================================================
# CronGhost — Scheduled Task Shadow Scanner
# FINAL VERSION — Fully loaded
# ============================================================
# Features:
#   Tier 1  — scans all 14 persistence locations
#   Tier 2  — package manager + age + owner + confidence score
#   Tier 3  — cryptographic SHA256 baseline comparison
#   NEW     — hidden file detector (dotfiles in cron dirs)
#   NEW     — encoding detector (base64/hex in scripts)
#   NEW     — network callback detector (IPs/domains in scripts)
#   NEW     — self integrity check (has CronGhost been tampered?)
#   NEW     — live watch mode (monitors for changes in real time)
#   NEW     — entropy analysis (encrypted/packed payloads)
#   NEW     — timestamp anomaly (files from the future)
#   NEW     — permission anomaly (world-writable persistence files)
#   NEW     — cross-reference check (same payload in multiple locations)
#   NEW     — rootkit evasion check (compares ls vs raw readdir)
#   NEW     — auto quarantine (moves suspicious files safely)
#   NEW     — threat history log (tracks findings over time)
# ============================================================

import os
import sys
import platform
import socket
import subprocess
import hashlib
import json
import re
import math
import stat
import time
import shutil
import signal
from datetime import datetime

# ── Colors ──────────────────────────────────────────────────
RESET  = "\033[0m"
WHITE  = "\033[97m"
GRAY   = "\033[90m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
BLINK  = "\033[5m"

# ── Paths ────────────────────────────────────────────────────
BASELINE_PATH  = "/var/lib/cronghost/baseline.json"
HISTORY_PATH   = "/var/lib/cronghost/history.log"
QUARANTINE_DIR = "/var/lib/cronghost/quarantine"
SELF_HASH_PATH = "/var/lib/cronghost/self.hash"

# ── Extended Kali whitelist ──────────────────────────────────
KALI_KNOWN_SAFE = {
    # ── /etc/profile.d/ — every file on your Kali ───────────
    "/etc/profile.d/70-systemd-shell-extra.sh",
    "/etc/profile.d/80-systemd-osc-context.sh",
    "/etc/profile.d/bash_completion.sh",
    "/etc/profile.d/bash_completion",
    "/etc/profile.d/dotnet-cli-tools-bin-path.sh",
    "/etc/profile.d/gawk.csh",
    "/etc/profile.d/gawk.sh",
    "/etc/profile.d/kali.sh",
    "/etc/profile.d/kali-themes.sh",
    "/etc/profile.d/nmap.sh",
    "/etc/profile.d/vte-2.91.sh",
    "/etc/profile.d/vte.csh",
    "/etc/profile.d/vte.sh",
    "/etc/profile.d/jvm.sh",
    "/etc/profile.d/locale.sh",
    "/etc/profile.d/colorls.sh",
    "/etc/profile.d/apps-bin-path.sh",
    "/etc/profile.d/cedilla.sh",
    "/etc/profile.d/input-method-config.sh",

    # ── /etc/cron.d/ — every file on your Kali ──────────────
    "/etc/cron.d/e2scrub_all",
    "/etc/cron.d/john",
    "/etc/cron.d/php",
    "/etc/cron.d/sysstat",
    "/etc/cron.d/.placeholder",

    # ── /etc/cron.daily/ ────────────────────────────────────
    "/etc/cron.daily/apt-compat",
    "/etc/cron.daily/dpkg",
    "/etc/cron.daily/logrotate",
    "/etc/cron.daily/man-db",
    "/etc/cron.daily/passwd",
    "/etc/cron.daily/exim4-base",

    # ── /etc/cron.hourly/ ────────────────────────────────────
    "/etc/cron.hourly/.placeholder",

    # ── /etc/cron.weekly/ ────────────────────────────────────
    "/etc/cron.weekly/man-db",
    "/etc/cron.weekly/update-notifier-common",
    "/etc/cron.weekly/.placeholder",

    # ── /etc/cron.monthly/ ───────────────────────────────────
    "/etc/cron.monthly/unattended-upgrades",
    "/etc/cron.monthly/.placeholder",

    # ── /etc/environment ─────────────────────────────────────
    "/etc/environment",

    # ── /etc/pam.d/ — all standard Kali PAM files ───────────
    "/etc/pam.d/common-auth",
    "/etc/pam.d/common-account",
    "/etc/pam.d/common-password",
    "/etc/pam.d/common-session",
    "/etc/pam.d/common-session-noninteractive",
    "/etc/pam.d/chfn",
    "/etc/pam.d/chpasswd",
    "/etc/pam.d/chsh",
    "/etc/pam.d/login",
    "/etc/pam.d/newusers",
    "/etc/pam.d/other",
    "/etc/pam.d/passwd",
    "/etc/pam.d/runuser",
    "/etc/pam.d/runuser-l",
    "/etc/pam.d/su",
    "/etc/pam.d/su-l",
    "/etc/pam.d/sshd",
    "/etc/pam.d/sudo",
    "/etc/pam.d/systemd-user",
    "/etc/pam.d/polkit-1",
    "/etc/pam.d/lightdm",
    "/etc/pam.d/lightdm-greeter",
    "/etc/pam.d/gdm-autologin",
    "/etc/pam.d/gdm-fingerprint",
    "/etc/pam.d/gdm-launch-environment",
    "/etc/pam.d/gdm-password",
    "/etc/pam.d/gdm-pin",
    "/etc/pam.d/gdm-smartcard",

    # ── /etc/xdg/autostart/ — all Kali desktop files ────────
    "/etc/xdg/autostart/at-spi-dbus-bus.desktop",
    "/etc/xdg/autostart/blueman.desktop",
    "/etc/xdg/autostart/geoclue-demo-agent.desktop",
    "/etc/xdg/autostart/gnome-keyring-pkcs11.desktop",
    "/etc/xdg/autostart/gnome-keyring-secrets.desktop",
    "/etc/xdg/autostart/kali-noautomount.desktop",
    "/etc/xdg/autostart/kali-sync-skel.desktop",
    "/etc/xdg/autostart/kali-vboxclient.desktop",
    "/etc/xdg/autostart/nm-applet.desktop",
    "/etc/xdg/autostart/onboard-autostart.desktop",
    "/etc/xdg/autostart/orca-autostart.desktop",
    "/etc/xdg/autostart/org.gnome.SettingsDaemon.DiskUtilityNotify.desktop",
    "/etc/xdg/autostart/pkcs11-register.desktop",
    "/etc/xdg/autostart/polkit-mate-authentication-agent-1.desktop",
    "/etc/xdg/autostart/print-applet.desktop",
    "/etc/xdg/autostart/user-dirs-update-gtk.desktop",
    "/etc/xdg/autostart/xcape-super-key-bind.desktop",
    "/etc/xdg/autostart/xdg-user-dirs.desktop",
    "/etc/xdg/autostart/xdg-user-dirs-kde.desktop",
    "/etc/xdg/autostart/xfce4-clipman-plugin-autostart.desktop",
    "/etc/xdg/autostart/xfce4-notifyd.desktop",
    "/etc/xdg/autostart/xfce4-power-manager.desktop",
    "/etc/xdg/autostart/xfce4-screensaver.desktop",
    "/etc/xdg/autostart/xfce-disable-motherboard-beep.desktop",
    "/etc/xdg/autostart/xfsettingsd.desktop",
    "/etc/xdg/autostart/xiccd.desktop",
}

# ── High confidence attack patterns ─────────────────────────
HIGH_PATTERNS = [
    {"p": "bash -i >& /dev/tcp/", "s": 95, "r": "classic bash reverse shell"},
    {"p": "/dev/tcp/",            "s": 90, "r": "raw TCP reverse shell"},
    {"p": "bash -i",              "s": 75, "r": "interactive bash spawn"},
    {"p": "nc -e /bin/bash",      "s": 95, "r": "netcat reverse shell"},
    {"p": "nc -e /bin/sh",        "s": 95, "r": "netcat reverse shell"},
    {"p": "/dev/shm/",            "s": 80, "r": "executes from shared memory"},
    {"p": "base64 -d | bash",     "s": 90, "r": "decode and execute payload"},
    {"p": "base64 -d | sh",       "s": 90, "r": "decode and execute payload"},
    {"p": "curl | bash",          "s": 85, "r": "download and execute"},
    {"p": "curl | sh",            "s": 85, "r": "download and execute"},
    {"p": "wget -O- | bash",      "s": 85, "r": "download and execute"},
    {"p": "wget -O- | sh",        "s": 85, "r": "download and execute"},
    {"p": "python -c 'import",    "s": 70, "r": "python reverse shell"},
    {"p": "python3 -c 'import",   "s": 70, "r": "python reverse shell"},
    {"p": "0>&1",                 "s": 85, "r": "stdout/stderr redirect — reverse shell"},
    {"p": "mkfifo",               "s": 80, "r": "named pipe — used in reverse shells"},
    {"p": "exec /bin/sh",         "s": 85, "r": "shell exec — privilege escalation"},
]

MEDIUM_PATTERNS = [
    {"p": "curl ",    "s": 35, "r": "downloads remote content"},
    {"p": "wget ",    "s": 35, "r": "downloads remote content"},
    {"p": "/tmp/",    "s": 40, "r": "references /tmp"},
    {"p": "base64",   "s": 40, "r": "base64 encoding present"},
    {"p": "pam_exec", "s": 60, "r": "PAM exec entry"},
    {"p": "chmod +x", "s": 30, "r": "makes file executable"},
    {"p": "nohup",    "s": 35, "r": "runs process immune to hangup"},
    {"p": "disown",   "s": 35, "r": "detaches process from terminal"},
    {"p": "crontab",  "s": 40, "r": "modifies crontab from script"},
]

# ── IP and domain regex ──────────────────────────────────────
IP_REGEX     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_REGEX = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|sh|onion|ru|cn|tk|top|xyz|club|info)\b')

# ── The 14 persistence locations ────────────────────────────
LOCATIONS = [
    {"id":  1, "name": "/etc/crontab",              "path": "/etc/crontab",             "kind": "file"},
    {"id":  2, "name": "/var/spool/cron/crontabs/", "path": "/var/spool/cron/crontabs", "kind": "directory"},
    {"id":  3, "name": "/etc/cron.d/",              "path": "/etc/cron.d",              "kind": "directory"},
    {"id":  4, "name": "/etc/cron.daily/",          "path": "/etc/cron.daily",          "kind": "directory"},
    {"id":  5, "name": "/etc/cron.hourly/",         "path": "/etc/cron.hourly",         "kind": "directory"},
    {"id":  6, "name": "/etc/cron.weekly/",         "path": "/etc/cron.weekly",         "kind": "directory"},
    {"id":  7, "name": "/etc/cron.monthly/",        "path": "/etc/cron.monthly",        "kind": "directory"},
    {"id":  8, "name": "/etc/anacrontab",           "path": "/etc/anacrontab",          "kind": "file"},
    {"id":  9, "name": "systemd timers",            "path": "/etc/systemd/system",      "kind": "systemd"},
    {"id": 10, "name": "/etc/profile.d/",           "path": "/etc/profile.d",           "kind": "directory"},
    {"id": 11, "name": "/etc/environment",          "path": "/etc/environment",         "kind": "file"},
    {"id": 12, "name": "PAM exec module",           "path": "/etc/pam.d",               "kind": "pam"},
    {"id": 13, "name": "/etc/rc.local",             "path": "/etc/rc.local",            "kind": "file"},
    {"id": 14, "name": "XDG autostart",             "path": "/etc/xdg/autostart",       "kind": "directory"},
]

# ── Helpers ──────────────────────────────────────────────────

def clear_screen():
    os.system("clear")

def print_line():
    print(GRAY + "  " + "─" * 62 + RESET)

def print_banner():
    print(WHITE + BOLD + r"""
  ____                  ____  _               _   
 / ___|_ __ ___  _ __  / ___|| |__   ___  ___| |_ 
| |   | '__/ _ \| '_ \| |  _ | '_ \ / _ \/ __| __|
| |___| | | (_) | | | | |_| || | | | (_) \__ \ |_ 
 \____|_|  \___/|_| |_|\____||_| |_|\___/|___/\__|
""" + RESET)
    print(GRAY + "  Scheduled Task Shadow Scanner — v4.0.0 — by Artist-22" + RESET)
    print()

def print_system_info(baseline_exists):
    hostname  = socket.gethostname()
    os_name   = platform.system() + " " + platform.release()
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    uid       = os.geteuid()
    user_lbl  = WHITE + "root" + RESET if uid == 0 else YELLOW + "not root — some scans limited" + RESET
    baseline  = GREEN + "active" + RESET if baseline_exists else YELLOW + "not set — choose option 5 to create" + RESET
    integrity = check_self_integrity()

    print_line()
    print()
    print(GRAY + "  Hostname    " + RESET + WHITE + hostname  + RESET)
    print(GRAY + "  System      " + RESET + WHITE + os_name   + RESET)
    print(GRAY + "  Scan time   " + RESET + WHITE + scan_time + RESET)
    print(GRAY + "  Running as  " + RESET + user_lbl)
    print(GRAY + "  Baseline    " + RESET + baseline)
    print(GRAY + "  Integrity   " + RESET + (GREEN + "verified — tool not tampered" + RESET if integrity else RED + BLINK + "WARNING — CronGhost may have been modified!" + RESET))
    print()

# ── NEW: Self integrity check ────────────────────────────────

def hash_self():
    """Hash CronGhost's own executable to detect tampering."""
    try:
        self_path = os.path.realpath(__file__)
        h = hashlib.sha256()
        with open(self_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def save_self_hash():
    """Save CronGhost's own hash on first run."""
    os.makedirs(os.path.dirname(SELF_HASH_PATH), exist_ok=True)
    h = hash_self()
    if h:
        with open(SELF_HASH_PATH, "w") as f:
            f.write(h)

def check_self_integrity():
    """
    Compare CronGhost current hash against saved hash.
    If they differ — CronGhost itself was tampered with.
    An expert attacker might modify our tool to hide results.
    This catches that.
    """
    if not os.path.exists(SELF_HASH_PATH):
        save_self_hash()
        return True
    try:
        with open(SELF_HASH_PATH) as f:
            saved = f.read().strip()
        return hash_self() == saved
    except Exception:
        return True

# ── NEW: Entropy analysis ────────────────────────────────────

def calculate_entropy(data):
    """
    Shannon entropy of file content.
    Normal scripts: entropy 3.5-5.0
    Encrypted/packed payloads: entropy 7.0-8.0
    High entropy in a shell script = hidden encrypted payload.
    """
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    length  = len(data)
    for count in freq.values():
        p        = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)

# ── NEW: Network callback detector ──────────────────────────

def find_network_callbacks(content):
    """Find IPs and domains in file content — C2 indicators."""
    ips     = IP_REGEX.findall(content)
    domains = DOMAIN_REGEX.findall(content)
    # Filter out localhost and common safe IPs
    safe_ips = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}
    ips      = [ip for ip in ips if ip not in safe_ips]
    return list(set(ips)), list(set(domains))

# ── NEW: Hidden file detector ────────────────────────────────

def find_hidden_files(dirpath):
    """
    Find dotfiles (hidden files) in persistence directories.
    Legitimate cron files are never hidden.
    An attacker hides their script as .update or .cache
    """
    hidden = []
    try:
        for f in os.listdir(dirpath):
            if f.startswith(".") and f not in (".", ".."):
                fp = os.path.join(dirpath, f)
                if os.path.isfile(fp):
                    hidden.append(fp)
    except Exception:
        pass
    return hidden

# ── NEW: Timestamp anomaly detector ─────────────────────────

def check_timestamp_anomaly(filepath):
    """
    Check for timestamp anomalies.
    Only flags genuinely suspicious patterns —
    NOT old files which are normal on long-running systems.
    """
    try:
        st    = os.stat(filepath)
        now   = time.time()
        mtime = st.st_mtime
        ctime = st.st_ctime

        anomalies = []

        # File timestamp is in the future — impossible legitimately
        if mtime > now + 60:
            anomalies.append("file timestamp is in the future — clock manipulation")

        # Timestamp zeroed out — attacker tried to erase timing evidence
        if mtime == 0 or ctime == 0:
            anomalies.append("timestamp zeroed — attacker tried to hide file age")

        # Do NOT flag old files — they are normal on Kali
        # Only flag if mtime is MUCH newer than ctime
        # (file content changed long after it was created)
        # and the change happened recently (within 30 days)
        days_since_change = (now - mtime) / 86400
        age_days          = (now - ctime) / 86400
        if mtime > ctime + 86400 * 30 and days_since_change < 30 and age_days > 90:
            anomalies.append("recently modified file that is very old — possible tampering")

        return anomalies
    except Exception:
        return []

# ── NEW: Permission anomaly detector ────────────────────────

def check_permissions(filepath):
    """
    Check for dangerous file permissions.
    Persistence files should never be world-writable.
    World-writable = anyone can modify this script.
    """
    try:
        mode     = os.stat(filepath).st_mode
        issues   = []
        if mode & stat.S_IWOTH:
            issues.append("world-writable — any user can modify this file")
        if mode & stat.S_IXOTH and mode & stat.S_IWOTH:
            issues.append("world-writable AND executable — critical permission issue")
        if mode & 0o4000:
            issues.append("SETUID bit set — runs as owner regardless of who executes")
        if mode & 0o2000:
            issues.append("SETGID bit set — inherits group permissions")
        return issues
    except Exception:
        return []

# ── NEW: Rootkit evasion check ───────────────────────────────

def rootkit_evasion_check(dirpath):
    """
    Compare raw os.listdir() against ls output.
    A rootkit hooks ls to hide files from view.
    If they disagree — something is being hidden.
    Fixed: use simple ls without -l to avoid parsing issues.
    """
    try:
        raw_files = set(os.listdir(dirpath))
        result    = subprocess.run(
            ["ls", dirpath],
            capture_output=True, text=True, timeout=5
        )
        ls_files = set(result.stdout.strip().split("\n")) if result.stdout.strip() else set()

        # Files in raw readdir but NOT in ls output
        hidden_by_rootkit = raw_files - ls_files - {".", ".."}

        # Filter out known false positives
        # Some files like .placeholder are hidden by ls by default
        hidden_by_rootkit = {
            f for f in hidden_by_rootkit
            if not f.startswith(".")  # ls hides dotfiles by default — not a rootkit
        }

        return list(hidden_by_rootkit)
    except Exception:
        return []

# ── NEW: Cross-reference check ───────────────────────────────

def find_duplicate_payloads(all_findings):
    """
    If the same payload appears in multiple locations —
    attacker planted it in several places for redundancy.
    This is a sign of a sophisticated persistent attacker.
    """
    payload_map = {}
    for f in all_findings:
        for hit in f.get("content_hits", []):
            key = hit["p"]
            if key not in payload_map:
                payload_map[key] = []
            payload_map[key].append(f["filepath"])

    duplicates = {k: v for k, v in payload_map.items() if len(v) > 1}
    return duplicates

# ── Baseline system ──────────────────────────────────────────

def hash_file(filepath):
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def create_baseline():
    print()
    print(WHITE + "  Creating baseline snapshot of your clean system..." + RESET)
    print(GRAY  + "  Every future scan compares against this." + RESET)
    print()

    os.makedirs(os.path.dirname(BASELINE_PATH), exist_ok=True)
    baseline = {
        "created" : datetime.now().isoformat(),
        "hostname": socket.gethostname(),
        "files"   : {}
    }

    all_files = collect_all_files()
    count     = 0

    for fp in all_files:
        h = hash_file(fp)
        if h:
            baseline["files"][fp] = {
                "hash" : h,
                "size" : os.path.getsize(fp),
                "mtime": os.path.getmtime(fp),
            }
            count += 1
            print(GRAY + f"  hashed  {fp}" + RESET)

    with open(BASELINE_PATH, "w") as f:
        json.dump(baseline, f, indent=2)

    # Save self hash at same time
    save_self_hash()

    print()
    print(GREEN + f"  Baseline saved. {count} files recorded." + RESET)
    print(GREEN + f"  CronGhost self-hash saved." + RESET)
    print()

def load_baseline():
    try:
        with open(BASELINE_PATH) as f:
            return json.load(f)
    except Exception:
        return None

def check_baseline_changes(baseline):
    if not baseline:
        return []

    changes   = []
    all_files = collect_all_files()

    for fp in all_files:
        if fp in KALI_KNOWN_SAFE:
            continue
        current_hash = hash_file(fp)
        if not current_hash:
            continue

        if fp in baseline["files"]:
            if current_hash != baseline["files"][fp]["hash"]:
                changes.append({
                    "type"      : "modified",
                    "filepath"  : fp,
                    "detail"    : "file content changed since baseline",
                    "confidence": 92,
                })
        else:
            changes.append({
                "type"      : "new",
                "filepath"  : fp,
                "detail"    : "file did not exist when baseline was created",
                "confidence": 87,
            })

    for fp in baseline["files"]:
        if not os.path.exists(fp) and fp not in KALI_KNOWN_SAFE:
            changes.append({
                "type"      : "deleted",
                "filepath"  : fp,
                "detail"    : "file existed in baseline but is now gone",
                "confidence": 72,
            })

    return changes

# ── Full analysis ────────────────────────────────────────────

def analyze_file(filepath):
    """Complete analysis of one file — every check combined."""
    if filepath in KALI_KNOWN_SAFE:
        return None

    SAFE_DIRS = [
        "/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.hourly/",
        "/etc/cron.weekly/", "/etc/cron.monthly/", "/etc/pam.d/",
        "/etc/xdg/autostart/", "/etc/profile.d/",
    ]
    in_safe_dir = any(filepath.startswith(d) for d in SAFE_DIRS)

    if in_safe_dir:
        try:
            with open(filepath, "rb") as f:
                raw = f.read()
            content = raw.decode("utf-8", errors="ignore")
            high_hits = [p for p in HIGH_PATTERNS if p["p"] in content]
            if not high_hits:
                return None
        except Exception:
            return None

    result = {
        "filepath"      : filepath,
        "verdict"       : "clean",
        "confidence"    : 0,
        "content_hits"  : [],
        "network_ips"   : [],
        "network_domains": [],
        "entropy"       : 0.0,
        "hidden"        : False,
        "timestamp_issues": [],
        "permission_issues": [],
        "age_info"      : "",
        "odd_hour"      : False,
        "owner_info"    : "root",
        "is_root"       : True,
        "pkg_known"     : None,
        "pkg_name"      : None,
        "pkg_modified"  : None,
    }

    # ── Content analysis ─────────────────────────────────────
    try:
        with open(filepath, "rb") as f:
            raw     = f.read()
        content     = raw.decode("utf-8", errors="ignore")

        # Entropy
        result["entropy"] = calculate_entropy(raw)

        # High confidence patterns
        for p in HIGH_PATTERNS:
            if p["p"] in content:
                result["confidence"] = max(result["confidence"], 85)
                result["content_hits"].append(p)

        # Medium confidence patterns
        if not result["content_hits"]:
            for p in MEDIUM_PATTERNS:
                if p["p"] in content:
                    result["confidence"] = max(result["confidence"], 45)
                    result["content_hits"].append(p)

        # Network callbacks
        result["network_ips"], result["network_domains"] = find_network_callbacks(content)
        if result["network_ips"] or result["network_domains"]:
            result["confidence"] = max(result["confidence"], 60)

        # High entropy (packed/encrypted payload)
        if result["entropy"] > 7.0:
            result["confidence"] = max(result["confidence"], 70)

    except PermissionError:
        result["confidence"] = max(result["confidence"], 10)
    except Exception:
        pass

    # ── Hidden file check ─────────────────────────────────────
    basename = os.path.basename(filepath)
    if basename.startswith("."):
        result["hidden"]     = True
        result["confidence"] = max(result["confidence"], 75)

    # ── Timestamp anomalies ───────────────────────────────────
    result["timestamp_issues"] = check_timestamp_anomaly(filepath)
    if result["timestamp_issues"]:
        result["confidence"] = max(result["confidence"], 65)

    # ── Permission issues ─────────────────────────────────────
    result["permission_issues"] = check_permissions(filepath)
    if result["permission_issues"]:
        result["confidence"] = max(result["confidence"], 55)

    # ── File age ─────────────────────────────────────────────
    try:
        st      = os.stat(filepath)
        created = datetime.fromtimestamp(st.st_ctime)
        hour    = created.hour
        days    = (datetime.now() - created).days
        result["age_info"]  = f"created {created.strftime('%Y-%m-%d %H:%M')} ({days}d ago)"
        result["odd_hour"]  = 1 <= hour <= 5
        if result["odd_hour"]:
            result["confidence"] = max(result["confidence"], result["confidence"] + 20)
    except Exception:
        pass

    # ── Owner ────────────────────────────────────────────────
    try:
        uid = os.stat(filepath).st_uid
        if uid != 0:
            import pwd
            try:
                name = pwd.getpwuid(uid).pw_name
            except Exception:
                name = str(uid)
            result["owner_info"] = f"{name} (uid {uid})"
            result["is_root"]    = False
            result["confidence"] = max(result["confidence"], result["confidence"] + 25)
    except Exception:
        pass

    # ── Package manager ───────────────────────────────────────
    try:
        r = subprocess.run(["dpkg", "-S", filepath], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            result["pkg_known"] = True
            result["pkg_name"]  = r.stdout.split(":")[0].strip()
            r2 = subprocess.run(["dpkg", "--verify", filepath], capture_output=True, text=True, timeout=5)
            result["pkg_modified"] = not (r2.returncode == 0 and not r2.stdout.strip())
        else:
            result["pkg_known"] = False
            result["confidence"] = max(result["confidence"], result["confidence"] + 40)
    except Exception:
        result["pkg_known"] = None

    # ── Final verdict ─────────────────────────────────────────
    conf = min(result["confidence"], 100)
    result["confidence"] = conf
    if conf >= 80:
        result["verdict"] = "critical"
    elif conf >= 55:
        result["verdict"] = "suspicious"
    elif conf >= 30:
        result["verdict"] = "low"
    else:
        return None

    return result

# ── File collection ──────────────────────────────────────────

def collect_all_files():
    files = []
    for loc in LOCATIONS:
        path = loc["path"]
        try:
            if loc["kind"] == "file":
                if os.path.exists(path):
                    files.append(path)
            elif loc["kind"] in ("directory", "pam"):
                if os.path.isdir(path):
                    for f in os.listdir(path):
                        fp = os.path.join(path, f)
                        if os.path.isfile(fp):
                            files.append(fp)
            elif loc["kind"] == "systemd":
                if os.path.isdir(path):
                    for f in os.listdir(path):
                        if f.endswith(".timer"):
                            files.append(os.path.join(path, f))
        except PermissionError:
            pass
    return files

def get_files_for_location(loc):
    files = []
    path  = loc["path"]
    try:
        if loc["kind"] == "file":
            if os.path.exists(path):
                files.append(path)
        elif loc["kind"] in ("directory", "pam"):
            if os.path.isdir(path):
                for f in os.listdir(path):
                    fp = os.path.join(path, f)
                    if os.path.isfile(fp):
                        files.append(fp)
        elif loc["kind"] == "systemd":
            if os.path.isdir(path):
                for f in os.listdir(path):
                    if f.endswith(".timer"):
                        files.append(os.path.join(path, f))
    except PermissionError:
        pass
    return files

# ── Scanner ──────────────────────────────────────────────────

def scan_all_locations(baseline):
    print_line()
    print()
    print(WHITE + "  Scanning all 14 persistence locations..." + RESET)
    print()

    all_results       = []
    baseline_alerts   = check_baseline_changes(baseline) if baseline else []
    total             = len(LOCATIONS)
    rootkit_warnings  = []

    for loc in LOCATIONS:
        files   = get_files_for_location(loc)
        flagged = []

        # Rootkit evasion check on directories
        if loc["kind"] in ("directory", "pam") and os.path.isdir(loc["path"]):
            hidden_by_rootkit = rootkit_evasion_check(loc["path"])
            if hidden_by_rootkit:
                rootkit_warnings.append({
                    "location": loc["name"],
                    "files"   : hidden_by_rootkit
                })

        # Check for hidden files (dotfiles) in directories
        hidden_files = []
        if loc["kind"] in ("directory", "pam") and os.path.isdir(loc["path"]):
            hidden_files = find_hidden_files(loc["path"])
            for hf in hidden_files:
                result = analyze_file(hf)
                if not result:
                    result = {
                        "filepath"  : hf,
                        "verdict"   : "suspicious",
                        "confidence": 75,
                        "content_hits": [],
                        "network_ips": [],
                        "network_domains": [],
                        "entropy"   : 0,
                        "hidden"    : True,
                        "timestamp_issues": [],
                        "permission_issues": [],
                        "age_info"  : "",
                        "odd_hour"  : False,
                        "owner_info": "root",
                        "is_root"   : True,
                        "pkg_known" : False,
                        "pkg_name"  : None,
                        "pkg_modified": None,
                    }
                flagged.append(result)

        for fp in files:
            if fp in [hf for hf in hidden_files]:
                continue
            result = analyze_file(fp)
            if result:
                flagged.append(result)

        num  = f"{loc['id']:2d}/{total}"
        name = loc["name"].ljust(30)

        if flagged:
            worst = max(r["confidence"] for r in flagged)
            if worst >= 80:
                status = RED    + "[!!]" + RESET
                note   = RED    + "critical" + RESET
            elif worst >= 55:
                status = YELLOW + "[!!]" + RESET
                note   = YELLOW + "suspicious" + RESET
            else:
                status = CYAN   + "[??]" + RESET
                note   = CYAN   + "low" + RESET
        else:
            status = GREEN + "[OK]" + RESET
            note   = ""

        print(f"  {status}  {GRAY}{num}{RESET}  {WHITE}{name}{RESET}  {note}")

        if flagged:
            all_results.append({"location": loc, "results": flagged})

    print()

    # Rootkit warnings
    if rootkit_warnings:
        print(RED + BLINK + "  ROOTKIT EVASION DETECTED — ls hides files that exist in raw filesystem!" + RESET)
        for w in rootkit_warnings:
            print(RED + f"  Location: {w['location']}" + RESET)
            for f in w["files"]:
                print(RED + f"    Hidden: {f}" + RESET)
        print()

    return all_results, baseline_alerts

# ── NEW: History logger ──────────────────────────────────────

def log_to_history(all_results, baseline_alerts):
    """Log findings to persistent history file."""
    os.makedirs(os.path.dirname(HISTORY_PATH), exist_ok=True)
    try:
        with open(HISTORY_PATH, "a") as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"Scan: {datetime.now()} | Host: {socket.gethostname()}\n")
            total = len(all_results) + len(baseline_alerts)
            f.write(f"Findings: {total}\n")
            for item in all_results:
                for r in item["results"]:
                    f.write(f"  [{r['verdict'].upper()}] {r['filepath']} ({r['confidence']}%)\n")
            for b in baseline_alerts:
                f.write(f"  [BASELINE-{b['type'].upper()}] {b['filepath']} ({b['confidence']}%)\n")
    except Exception:
        pass

# ── NEW: Auto quarantine ─────────────────────────────────────

def quarantine_file(filepath):
    """
    Move suspicious file to quarantine directory.
    Does NOT delete — preserves for forensic analysis.
    Replaces original with empty decoy so attacker does not notice.
    """
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
        basename  = os.path.basename(filepath)
        dest      = os.path.join(QUARANTINE_DIR, f"{ts}_{basename}")

        # Copy to quarantine
        shutil.copy2(filepath, dest)

        # Save metadata alongside
        meta = {
            "original_path": filepath,
            "quarantined"  : ts,
            "hash"         : hash_file(filepath),
        }
        with open(dest + ".meta.json", "w") as f:
            json.dump(meta, f, indent=2)

        # Replace with empty decoy (attacker thinks it still exists)
        with open(filepath, "w") as f:
            f.write("")
        os.chmod(filepath, 0o644)

        print(GREEN + f"  Quarantined: {filepath}" + RESET)
        print(GRAY  + f"  Saved to:    {dest}" + RESET)
        print(GRAY  + f"  Decoy left:  empty file to avoid attacker suspicion" + RESET)
    except PermissionError:
        print(RED + "  Permission denied — run as root." + RESET)
    except Exception as e:
        print(RED + f"  Error: {e}" + RESET)

# ── NEW: Live watch mode ─────────────────────────────────────

def live_watch_mode(baseline):
    """
    Monitors all 14 locations in real time.
    Alerts immediately when any file changes.
    Checks every 30 seconds.
    Press Ctrl+C to stop.
    """
    print()
    print(WHITE + "  Live watch mode active — monitoring all 14 locations" + RESET)
    print(GRAY  + "  Press Ctrl+C to stop" + RESET)
    print()

    previous_hashes = {}
    all_files       = collect_all_files()

    # Take initial snapshot
    for fp in all_files:
        h = hash_file(fp)
        if h:
            previous_hashes[fp] = h

    print(GREEN + f"  Watching {len(previous_hashes)} files..." + RESET)
    print()

    def handle_sigint(sig, frame):
        print()
        print(GRAY + "\n  Watch mode stopped." + RESET)
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    interval = 30
    while True:
        time.sleep(interval)
        timestamp = datetime.now().strftime("%H:%M:%S")
        all_files = collect_all_files()

        alerts = []
        for fp in all_files:
            if fp in KALI_KNOWN_SAFE:
                continue
            h = hash_file(fp)
            if not h:
                continue
            if fp not in previous_hashes:
                alerts.append(("NEW", fp))
                previous_hashes[fp] = h
            elif h != previous_hashes[fp]:
                alerts.append(("CHANGED", fp))
                previous_hashes[fp] = h

        for fp in list(previous_hashes.keys()):
            if not os.path.exists(fp) and fp not in KALI_KNOWN_SAFE:
                alerts.append(("DELETED", fp))
                del previous_hashes[fp]

        if alerts:
            for alert_type, fp in alerts:
                color = RED if alert_type in ("NEW", "CHANGED") else YELLOW
                print(color + f"  [{timestamp}] [{alert_type}] {fp}" + RESET)
        else:
            print(GRAY + f"  [{timestamp}] All clear — {len(previous_hashes)} files unchanged" + RESET)

# ── Results display ──────────────────────────────────────────

def confidence_bar(conf):
    filled = int(conf / 5)
    empty  = 20 - filled
    color  = RED if conf >= 80 else YELLOW if conf >= 55 else CYAN
    return f"[{color}{'█' * filled}{GRAY}{'░' * empty}{RESET}] {conf}%"

def print_results(all_results, baseline_alerts):
    total   = len(LOCATIONS)
    flagged = len(all_results)
    clean   = total - flagged

    print_line()
    print()
    print(WHITE + "  Scan results:" + RESET)
    print()
    print(GRAY + "  Total scanned      " + RESET + WHITE + str(total)  + RESET)
    print(GRAY + "  Clean              " + RESET + GREEN + str(clean)  + RESET)
    print(GRAY + "  Findings           " + RESET + (RED + str(flagged) + RESET if flagged else GREEN + "0" + RESET))
    print(GRAY + "  Baseline changes   " + RESET + (RED + str(len(baseline_alerts)) + RESET if baseline_alerts else GREEN + "0" + RESET))
    print()

    if not all_results and not baseline_alerts:
        print(GREEN + "  System is clean. No threats detected." + RESET)
        print()
        return

    # Baseline violations first — highest confidence
    if baseline_alerts:
        print_line()
        print()
        print(RED + "  Baseline violations:" + RESET)
        print()
        for alert in baseline_alerts:
            label = {
                "modified": RED    + "[CHANGED] " + RESET,
                "new"     : RED    + "[NEW FILE]" + RESET,
                "deleted" : YELLOW + "[DELETED] " + RESET,
            }.get(alert["type"], YELLOW + "[CHANGE]  " + RESET)
            print(f"  {label}  " + WHITE + alert["filepath"] + RESET)
            print(GRAY + "  Confidence    " + RESET + confidence_bar(alert["confidence"]))
            print(GRAY + "  Detail        " + RESET + alert["detail"])
            print()

    if all_results:
        print_line()
        print()
        print(WHITE + "  Smart detection findings:" + RESET)
        print()

        all_flat = [r for item in all_results for r in item["results"]]

        # Cross-reference check
        duplicates = find_duplicate_payloads(all_flat)
        if duplicates:
            print(RED + "  CROSS-REFERENCE ALERT — same payload in multiple locations:" + RESET)
            for payload, paths in duplicates.items():
                print(GRAY + f"  Pattern '{payload}' found in:" + RESET)
                for p in paths:
                    print(RED + f"    {p}" + RESET)
            print()

        for item in all_results:
            for r in item["results"]:
                vc    = RED if r["verdict"] == "critical" else YELLOW if r["verdict"] == "suspicious" else CYAN
                label = r["verdict"].upper()
                flags = []
                if r.get("hidden"):
                    flags.append(RED + "[HIDDEN FILE]" + RESET)
                if r.get("odd_hour"):
                    flags.append(YELLOW + "[ODD HOUR]" + RESET)
                if r.get("network_ips") or r.get("network_domains"):
                    flags.append(RED + "[C2 INDICATOR]" + RESET)
                if r.get("entropy", 0) > 7.0:
                    flags.append(RED + "[HIGH ENTROPY]" + RESET)
                if r.get("timestamp_issues"):
                    flags.append(YELLOW + "[TIMESTAMP ANOMALY]" + RESET)
                if r.get("permission_issues"):
                    flags.append(YELLOW + "[BAD PERMISSIONS]" + RESET)

                flag_str = " ".join(flags)
                print(vc + f"  [{label}]" + RESET + "  " + WHITE + r["filepath"] + RESET + ("  " + flag_str if flags else ""))
                print()
                print(GRAY + "  Confidence    " + RESET + confidence_bar(r["confidence"]))
                print(GRAY + "  Entropy       " + RESET + (RED if r.get("entropy",0) > 7.0 else GRAY) + f"{r.get('entropy', 0)} / 8.0" + RESET)
                print()

                if r.get("pkg_known") is True:
                    mod_c = RED if r.get("pkg_modified") else GREEN
                    print(GRAY + "  Package       " + RESET + GREEN + f"known — {r['pkg_name']}" + RESET)
                    print(GRAY + "  Modified      " + RESET + mod_c + ("YES — changed since install" if r.get("pkg_modified") else "no — matches original") + RESET)
                elif r.get("pkg_known") is False:
                    print(GRAY + "  Package       " + RESET + RED + "NOT in dpkg — manually placed" + RESET)

                oc = GREEN if r.get("is_root", True) else RED
                print(GRAY + "  Owner         " + RESET + oc + r.get("owner_info", "root") + RESET)
                ac = RED if r.get("odd_hour") else GRAY
                print(GRAY + "  File age      " + RESET + ac + r.get("age_info", "") + RESET)

                if r.get("network_ips"):
                    print(GRAY + "  C2 IPs        " + RESET + RED + ", ".join(r["network_ips"]) + RESET)
                if r.get("network_domains"):
                    print(GRAY + "  C2 Domains    " + RESET + RED + ", ".join(r["network_domains"]) + RESET)

                if r.get("timestamp_issues"):
                    for issue in r["timestamp_issues"]:
                        print(GRAY + "  Timestamp     " + RESET + YELLOW + issue + RESET)

                if r.get("permission_issues"):
                    for issue in r["permission_issues"]:
                        print(GRAY + "  Permissions   " + RESET + YELLOW + issue + RESET)

                if r.get("content_hits"):
                    print(GRAY + "  Content hits  " + RESET)
                    for h in r["content_hits"][:5]:
                        print(GRAY + f"    +{h['s']:2d}  " + YELLOW + h["p"].ljust(22) + RESET + GRAY + h["r"] + RESET)

                print()

# ── Menu ─────────────────────────────────────────────────────

def show_menu(all_results, baseline_alerts, baseline):
    print_line()
    print()
    print(WHITE + "  Options:" + RESET)
    print()
    print(GRAY + "  1)  " + RESET + "Run scan again")
    print(GRAY + "  2)  " + RESET + "Export full report to file")
    print(GRAY + "  3)  " + RESET + "Quarantine a suspicious file")
    print(GRAY + "  4)  " + RESET + "Start live watch mode")
    print(GRAY + "  5)  " + RESET + ("Rebuild baseline" if baseline else "Create baseline (first time setup)"))
    print(GRAY + "  6)  " + RESET + "View threat history log")
    print(GRAY + "  7)  " + RESET + "Quit")
    print()

    while True:
        try:
            choice = input("  Enter choice: ").strip()
        except (KeyboardInterrupt, EOFError):
            print(GRAY + "\n  Goodbye.\n" + RESET)
            sys.exit(0)

        if choice == "1":
            main()
            return
        elif choice == "2":
            export_report(all_results, baseline_alerts)
        elif choice == "3":
            fp = input("  Enter full path of file to quarantine: ").strip()
            if fp:
                quarantine_file(fp)
        elif choice == "4":
            live_watch_mode(baseline)
        elif choice == "5":
            create_baseline()
        elif choice == "6":
            view_history()
        elif choice == "7":
            print(GRAY + "\n  Goodbye.\n" + RESET)
            sys.exit(0)
        else:
            print(GRAY + "  Invalid choice. Enter 1-7." + RESET)

def view_history():
    """Show the threat history log."""
    if not os.path.exists(HISTORY_PATH):
        print(GRAY + "\n  No history yet — run a scan first.\n" + RESET)
        return
    print()
    print(WHITE + "  Threat history:" + RESET)
    print()
    try:
        with open(HISTORY_PATH) as f:
            lines = f.readlines()
        for line in lines[-50:]:
            print(GRAY + "  " + line.rstrip() + RESET)
    except Exception:
        print(RED + "  Could not read history file." + RESET)
    print()

def export_report(all_results, baseline_alerts):
    filename = f"cronghost_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    lines    = [
        "CronGhost — Scheduled Task Shadow Scanner — FINAL",
        f"Time     : {datetime.now()}",
        f"Hostname : {socket.gethostname()}",
        f"Version  : v4.0.0",
        "=" * 62,
    ]
    if baseline_alerts:
        lines.append("\nBASELINE VIOLATIONS:")
        for a in baseline_alerts:
            lines += [f"  [{a['type'].upper()}] {a['filepath']} ({a['confidence']}%)", f"  {a['detail']}"]
    if all_results:
        lines.append("\nSMART DETECTION FINDINGS:")
        for item in all_results:
            for r in item["results"]:
                lines += [
                    f"\n  [{r['verdict'].upper()}] {r['filepath']}",
                    f"  Confidence : {r['confidence']}%",
                    f"  Entropy    : {r.get('entropy', 0)}",
                    f"  Package    : {'known — ' + str(r.get('pkg_name')) if r.get('pkg_known') else 'NOT in dpkg'}",
                    f"  Owner      : {r.get('owner_info', 'root')}",
                    f"  Age        : {r.get('age_info', '')}",
                ]
                if r.get("network_ips"):
                    lines.append(f"  C2 IPs     : {', '.join(r['network_ips'])}")
                if r.get("network_domains"):
                    lines.append(f"  C2 Domains : {', '.join(r['network_domains'])}")
                for h in r.get("content_hits", []):
                    lines.append(f"  Hit        : {h['p']} (+{h['s']}) {h['r']}")
    if not all_results and not baseline_alerts:
        lines.append("No threats found.")
    with open(filename, "w") as f:
        f.write("\n".join(lines))
    log_to_history(all_results, baseline_alerts)
    print(GREEN + f"\n  Report saved to {filename}\n" + RESET)

# ── Main ─────────────────────────────────────────────────────

def main():
    if platform.system() != "Linux":
        print(RED + "Error: CronGhost only runs on Linux." + RESET)
        sys.exit(1)
    if os.geteuid() != 0:
        print(RED + "Error: CronGhost must run as root." + RESET)
        print(GRAY + "Run:  sudo cronghost" + RESET)
        sys.exit(1)

    clear_screen()
    print_banner()
    baseline = load_baseline()
    print_system_info(baseline is not None)
    all_results, baseline_alerts = scan_all_locations(baseline)
    log_to_history(all_results, baseline_alerts)
    print_results(all_results, baseline_alerts)
    show_menu(all_results, baseline_alerts, baseline)

if __name__ == "__main__":
    main()
