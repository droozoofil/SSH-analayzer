# ⚔ SSH Brute Force Detector

A lightweight, GUI-based log analyzer that scans Linux auth logs to detect SSH brute force attacks. Built with pure Python and Tkinter — no external dependencies required.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![Tkinter](https://img.shields.io/badge/GUI-Tkinter-informational?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## 📸 Features

| Feature | Description |
|---|---|
| 🔍 **Log Parsing** | Parses `/var/log/auth.log`, `/var/log/secure`, or any SSH log file |
| ⚡ **Brute Force Detection** | Flags IPs that exceed a configurable failure threshold |
| 🌐 **IP Breakdown** | Shows every IP, how many times it failed, which usernames it tried, and timestamps |
| 🟢 **Successful Logins** | Tracks accepted authentications separately |
| 📄 **Raw Log Viewer** | Color-coded raw log display (red = failed, green = success) |
| 🔎 **Live Filter** | Filter attackers table in real time by IP or username |
| ↓ **Export Report** | Save a full plaintext report of the scan results |
| 🧵 **Threaded** | Log parsing runs in a background thread — GUI never freezes |

---

## 🚀 Quick Start

### Requirements

- Python **3.8+**
- No external packages needed (uses stdlib only: `tkinter`, `socket`, `re`, `threading`, `collections`)

### Run

```bash
git clone https://github.com/yourname/ssh-brute-detector.git
cd ssh-brute-detector
python detector.py
```

> **Windows users:** Tkinter is bundled with the official Python installer from python.org.  
> **Linux users:** If Tkinter is missing, install it with:
> ```bash
> sudo apt install python3-tk   # Debian/Ubuntu
> sudo dnf install python3-tkinter  # Fedora/RHEL
> ```

---

## 🖥 Usage

1. **Browse** — Click the *Browse* button and select your log file (e.g. `/var/log/auth.log`)
2. **Set Threshold** — Choose how many failed attempts qualify as a brute force attempt (default: **5**)
3. **Analyze** — Click *▶ Analyze* — parsing runs in the background with a live progress bar
4. **Review tabs:**
   - 🔴 **Attackers** — sorted list of all IPs with failure counts, brute force flag, and usernames tried
   - 🟡 **Failed Logins** — every individual failed attempt with timestamp
   - 🟢 **Successful Logins** — all accepted authentications
   - 📄 **Raw Log** — color-highlighted full log view
5. **Double-click** any row in the Attackers tab to see a detailed log drill-down
6. **Export** — Save a plaintext report with *↓ Export*

---

## 🧪 Test with Sample Log

A `sample_auth.log` file is included for testing:

```bash
python detector.py
# Then browse to: sample_auth.log
```

The sample includes:
- **192.168.1.100** — 8 failed attempts (brute force)
- **172.16.0.99** — 10 failed attempts (brute force)
- **203.0.113.45** — 6 invalid user attempts (brute force)
- **10.0.0.50** — 3 failed attempts (below threshold)
- **198.51.100.9** — 2 failed attempts (below threshold)
- Successful logins for `jiraya` and `admin`

---

## 📁 Project Structure

```
ssh-brute-detector/
│
├── detector.py          # Main application (GUI + parser)
├── sample_auth.log      # Sample log file for testing
└── README.md            # This file
```

---

## 🔍 Detected Log Patterns

The tool matches the following standard sshd log patterns:

```
Failed password for <user> from <ip> port <port> ssh2
Failed password for invalid user <user> from <ip> port <port> ssh2
Invalid user <user> from <ip>
Accepted password for <user> from <ip> port <port> ssh2
Accepted publickey for <user> from <ip> port <port> ssh2
```

Compatible with logs from:
- Ubuntu / Debian (`/var/log/auth.log`)
- CentOS / RHEL / Fedora (`/var/log/secure`)
- Any distro running `openssh-server`

---

## ⚙️ Configuration

| Setting | Default | Description |
|---|---|---|
| Threshold | `5` | Minimum failed attempts to classify an IP as a brute force attacker |

The threshold can be adjusted live in the GUI before each scan.

---

## 📤 Export Format

The exported report includes:

```
SSH BRUTE FORCE DETECTION REPORT
Generated: 2025-05-01 12:00:00
Log file: /var/log/auth.log
Threshold: 5 attempts
============================================================

Total lines parsed : 3,241
Total failed logins: 187
Unique IPs flagged : 12
Brute force IPs    : 4
Successful logins  : 6

=== BRUTE FORCE ATTACKERS ===

IP: 192.168.1.100  |  Attempts: 8  |  First: May  1 10:00:01  |  Last: May  1 10:00:15
  Usernames tried: root, admin, ubuntu, user, pi, oracle, test

=== SUCCESSFUL LOGINS ===
  May  1 10:05:00  user=jiraya  ip=192.168.1.42
```

---

## 🛡 Defensive Use Cases

- **Post-incident review** — analyze logs after a suspected intrusion
- **SOC triage** — quickly identify which IPs to block or investigate
- **Hardening audits** — check if your server is being targeted and by which usernames
- **Training / CTF** — learn to read and analyze real auth logs

---

## 🔮 Possible Improvements

- [ ] GeoIP lookup for flagged IPs
- [ ] Auto-generate `iptables` / `ufw` block rules
- [ ] Watchdog mode (tail live log file)
- [ ] SQLite storage for historical tracking
- [ ] Fail2ban rule export

---

## 📝 License

MIT — free to use, modify, and distribute.

---

> Built as a practical cybersecurity tool for sysadmins and security engineers.
