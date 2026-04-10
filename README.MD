# 🔍 PersiScan v0.4

### Linux Persistence & Suspicious Startup Scanner

PersiScan is a lightweight, command-line security tool designed to detect **persistence mechanisms** and **suspicious startup entries** on Linux systems (especially Kali/Debian-based distributions).

It helps identify potential malware behavior by scanning common autostart locations, cron jobs, system services, and shell hooks—then assigning a **risk score** based on heuristics.

---

## 🚀 Features

* 🔎 **Comprehensive Enumeration**

  * Autostart entries (`~/.config/autostart`, `/etc/xdg/autostart`)
  * Cron jobs (user + system-wide)
  * Systemd services and timers
  * Shell startup hooks (`.bashrc`, `.profile`)
  * `/etc/rc.local` and `ld.so.preload`

* 🧠 **Heuristic-Based Detection**

  * Suspicious keywords (e.g., reverse shells, backdoors)
  * Risky file locations (`/tmp`, `/dev/shm`, `.cache`)
  * Dangerous file extensions (`.sh`, `.py`, `.js`, etc.)
  * Recently modified files

* 🎨 **Color-Coded Output**

  * 🟢 Low Risk
  * 🟡 Moderate Risk
  * 🔴 High Risk

* 📊 **Detailed Reporting**

  * Clean CLI summary
  * Verbose mode for full inspection
  * JSON export for integrations

* ⚠️ **Security-Focused Design**

  * Avoids common false positives
  * Highlights potential persistence techniques used by malware

---

## 🛠 Installation

### 1. Clone or Download

```bash
git clone https://github.com/yourusername/persiscan.git
cd persiscan
```

Or manually save the script as:

```bash
persiscan
```

---

### 2. Install Dependencies

```bash
pip install termcolor
```

---

### 3. Make Executable

```bash
chmod +x persiscan
```

---

## ▶️ Usage

### 🔹 Run Basic Scan (Recommended)

```bash
sudo ./persiscan
```

Displays a summarized report of moderate and high-risk entries.

---

### 🔹 Verbose Mode

```bash
sudo ./persiscan --verbose
```

Includes:

* Low-risk items
* Detailed breakdown of all findings

---

### 🔹 Export Report (JSON)

```bash
sudo ./persiscan --json report.json
```

Useful for:

* Logging
* Dashboards
* Further analysis

---

### 🔹 Attempt Removal (Experimental)

```bash
sudo ./persiscan --remove <ID>
```

⚠️ Note: Removal functionality is currently a placeholder and must be implemented manually.

---

## 📊 Example Output

```
PersiScan v0.4 Report
════════════════════════════════════
Scan time : 2026-04-10 12:30:00
Total items: 28
High risk  : 2
Moderate   : 3
Low risk   : 23

High risk (7–10):
  [  5]  9/10  suspicious_script.sh  (cron)
      → /tmp/script.sh
      reasons: suspicious-location, risky-extension
```

---

## 🧠 How It Works

PersiScan builds an **inventory of startup mechanisms** and evaluates each entry using a scoring system:

### 🔼 Score Increases If:

* Located in suspicious directories (`/tmp`, `/var/tmp`, etc.)
* Uses risky file types (`.sh`, `.py`, `.js`)
* Contains known malicious patterns (e.g., reverse shell commands)
* Recently modified (within 14 days)

### 🔽 Score Decreases If:

* Located in trusted system directories (`/usr/bin`, `/etc/cron.d`)
* Matches known safe services

Each item is assigned a **score from 0 to 10**, categorized as:

* **0–3** → Low Risk
* **4–6** → Moderate Risk
* **7–10** → High Risk

---

## ⚠️ Disclaimer

PersiScan is a **heuristic-based detection tool**, not a full antivirus solution.

* It may produce **false positives**
* Always manually verify suspicious entries before taking action
* Do not delete system files unless you are certain

---

## 🧪 Use Cases

* 🔐 Malware analysis & forensics
* 🛡 System auditing & hardening
* 🧑‍💻 Ethical hacking & penetration testing
* 🖥 Detecting unauthorized persistence mechanisms

---

## 🔮 Future Improvements

* ✅ Automated removal (systemctl disable, file cleanup)
* 📡 Integration with threat intelligence APIs (VirusTotal)
* 🖥 Web dashboard for visualization
* ⏱ Real-time monitoring agent
* 📦 Packaging as a pip-installable CLI tool

---

## 🤝 Contributing

Contributions are welcome! You can:

* Improve detection heuristics
* Add new persistence techniques
* Enhance reporting/UI

---

## 📜 License

This project is open-source and available under the MIT License.

---

## 👨‍💻 Author

Developed as a cybersecurity-focused tool for detecting persistence techniques in Linux environments.

---

## ⭐ Support

If you found this useful:

* Star the repository ⭐
* Share with others in the security community
* Contribute to make it better

---
