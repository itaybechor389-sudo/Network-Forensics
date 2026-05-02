# Network Forensics IOC Extractor

**Advanced PCAP analysis tool with automatic MITRE ATT&CK mapping.**  
Built for SOC Analysts and Network Forensics investigators.

> Cyberium Academy — NX216 Network Forensics  
> Author: Itay Bechor

---

## What It Does

Load any `.pcap` file and instantly get:

- All IP addresses (classified Private/Public with severity)
- DNS domains with Shannon entropy scoring
- HTTP URLs, User-Agents, Email addresses
- Automatic threat detection (port scan, C2 beaconing, DNS tunneling, brute force)
- MITRE ATT&CK technique mapping
- Visual charts (Protocol Distribution, Top IPs, Top Ports)
- Export to HTML report or JSON

---

## Screenshots

| Dashboard | MITRE ATT&CK |
|---|---|
| 16 IPs · 3 Domains · 4 Alerts · 2 Techniques | T1048.003 Exfiltration · T1071.004 DNS C2 |

| Alerts | Statistics |
|---|---|
| SMTP AUTH · Cleartext FTP detected | Protocol pie · Top IPs bar · Ports bar |

---

## Installation

```bash
# Install dependencies
sudo apt install python3-pyqt5 python3-matplotlib -y
pip3 install scapy --break-system-packages

# Run
python3 ioc_extractor.py
```

Tested on Kali Linux 2024.

---

## Features

### IOC Extraction
| IOC Type | Details |
|---|---|
| IP Addresses | Private/Public classification, packet count, bytes, severity |
| DNS Domains | Shannon entropy scoring, source IP, HIGH if entropy > 3.5 |
| HTTP URLs | Method, host, full URL |
| User-Agents | Flags tools like curl, python-requests, nmap, sqlmap |
| Emails | Extracted from SMTP traffic (MAIL FROM / RCPT TO) |

### Threat Detection Algorithms

**Port Scan** — flags source IPs connecting to 15+ unique ports (T1046)

**C2 Beaconing** — detects regular-interval SYN connections using coefficient of variation < 0.30 over 5+ connections (T1071)

**DNS Tunneling** — flags queries with subdomain length > 45 chars or Shannon entropy > 3.5 (T1071.004)

**Brute Force** — high packet volume on SSH/RDP/FTP/Telnet/VNC ports (T1110)

**Suspicious Ports** — traffic on known RAT/C2 ports: 4444, 31337, 1337, etc. (T1571)

**Lateral Movement** — SMB/RDP/SSH/WinRM traffic (T1021)

### MITRE ATT&CK Coverage

| ID | Technique | Tactic |
|---|---|---|
| T1595 | Active Scanning | Reconnaissance |
| T1046 | Network Service Discovery | Discovery |
| T1110 | Brute Force | Credential Access |
| T1059 | Command and Scripting Interpreter | Execution |
| T1021 | Remote Services | Lateral Movement |
| T1071.001 | Application Layer Protocol: HTTP | Command & Control |
| T1071.004 | Application Layer Protocol: DNS | Command & Control |
| T1071 | C2 Beaconing | Command & Control |
| T1571 | Non-Standard Port | Command & Control |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1048.003 | Exfiltration Over SMTP / FTP | Exfiltration |

---

## Usage

1. Run: `python3 ioc_extractor.py`
2. Click **Browse** and select a `.pcap` / `.pcapng` file
3. Click **Analyze**
4. Navigate the tabs: Dashboard → IP/IOCs → Domains & URLs → MITRE ATT&CK → Alerts → Statistics
5. Export results with **Export JSON** or **Export HTML Report**

---

## Project Structure

```
ioc_extractor.py    # Single-file application (GUI + analysis engine + report generator)
```

Single file, no external config needed. Just Python + PyQt5 + Scapy.

---

## Technical Stack

| Component | Technology |
|---|---|
| GUI Framework | PyQt5 |
| Packet Analysis | Scapy |
| Charts | Matplotlib (embedded Qt5) |
| Entropy Calculation | Shannon entropy (built-in) |
| Export | HTML + JSON |

---

## About

Built as part of **Cyberium Academy NX216 — Network Forensics** certification track.  
Part of the John Bryce / ThinkCyber cybersecurity program.

Connects to real-world skills: Wireshark analysis, C2 detection, network IOC hunting, MITRE ATT&CK framework.
