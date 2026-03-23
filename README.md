# ⚡ OXPOWER — Offensive Security & Vulnerability Analysis Engine

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20/%20Linux%20/%20MacOS-red)
![License](https://img.shields.io/badge/License-MIT-green)
![Author](https://img.shields.io/badge/Author-Ritik-purple)

OxPower is a highly advanced, automated CLI vulnerability and reconnaissance engine built for modern offensive security testing.

---

## ⚡ Features
- **High-Speed Port Scanner:** Scans all ports (1-65535) by default using 500 threads with banner grabbing.
- **Advanced URL Vulnerability Engine:** Automatically injects and detects XSS, SQLi, LFI, SSRF, OS Command Injection, and Open Redirects using comprehensive payload dictionaries.
- **Network Vulnerability Analysis:** Identifies critical dangerous ports (e.g., Docker APIs, unauthenticated Redis/MongoDB, weak SMB/RDP, Oracle DB).
- **DNS Security & Recon:** Extracts MX/TXT/SOA/CAA records, identifies SPF/DMARC email spoofing vulnerabilities, and aggressively attempts AXFR Zone Transfers across all targeted Name Servers.
- **Smart Directory Fuzzing:** Bruteforces hidden admin panels and sensitive system files (like `.env` and `.git`), protected by "Wildcard 200 OK" filtering to eliminate false positives.
- **Subdomain Enumeration:** Bruteforces over 200 common infrastructure, API, and cloud application subdomains.
- **Technology Fingerprinting:** Deeply analyzes HTML and Headers to identify 40+ distinct CMSs, web frameworks (React/Next.js/Spring Boot), backend languages, and WAFs (Cloudflare/AWS).
- **Security Header & SSL/TLS Audit:** Extracts weak cryptography, expiring certificates, and missing Security Headers (HSTS, CSP).
- **Automated JSON Reporting:** Compiles all module findings into a unified, actionable JSON report.

---

## 🛠️ Installation

### Step 1 — Update your system
```bash
sudo apt update && sudo apt upgrade -y
```

### Step 2 — Install Python3
```bash
sudo apt install python3 python3-pip -y
```

### Step 3 — Install Git
```bash
sudo apt install git -y
```

### Step 4 — Clone the repository
```bash
git clone https://github.com/ritik/OxPower.git
```

### Step 5 — Go into the folder
```bash
cd OxPwner
```

### Step 6 — Give permission
```bash
chmod +x oxpwner.py
```

### Step 7 — Run the tool
```bash
python3 oxpwner.py --help
```

---

## 🚀 Usage
```bash
# Full automated assessment
python3 oxpwner.py full http://target.com

# Target port scan
python3 oxpwner.py ports 192.168.1.1 --range 1-1024

# URL parameter vulnerability injection
python3 oxpwner.py url "http://site.com/page?id=1"

# Subdomain enumeration
python3 oxpwner.py subs example.com

# DNS Reconnaissance
python3 oxpwner.py dns example.com

# Hidden directory bruteforcing
python3 oxpwner.py dirs http://example.com

# Technology fingerprinting
python3 oxpwner.py tech http://example.com
```

---

## 📸 Tool Preview
```
    ███████                ███████████                                               
  ███░░░░░███             ░░███░░░░░███                                              
 ███     ░░███ █████ █████ ░███    ░███ █████ ███ █████ ████████    ██████  ████████ 
░███      ░███░░███ ░░███  ░██████████ ░░███ ░███░░███ ░░███░░███  ███░░███░░███░░███
░███      ░███ ░░░█████░   ░███░░░░░░   ░███ ░███ ░███  ░███ ░███ ░███████  ░███ ░░░ 
░░███     ███   ███░░░███  ░███         ░░███████████   ░███ ░███ ░███░░░   ░███     
 ░░░███████░   █████ █████ █████         ░░████░████    ████ █████░░██████  █████    
   ░░░░░░░    ░░░░░ ░░░░░ ░░░░░           ░░░░ ░░░░    ░░░░ ░░░░░  ░░░░░░  ░░░░░     
```

---

## ⚠️ Disclaimer
This tool is for **educational purposes** and **authorized penetration testing only**.
The author is not responsible for any misuse or damage caused by this tool.
Always get proper permission before scanning any target.

---

## 👨‍💻 Author
**Ritik**
GitHub: [@ritik](https://github.com/ritik)
