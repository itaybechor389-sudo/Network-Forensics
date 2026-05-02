#!/usr/bin/env python3
# Network Forensics IOC Extractor
# Cyberium Academy - NX216 - Author: Itay Bechor

import sys, os, re, math, json
from collections import defaultdict, Counter
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QPushButton, QLineEdit, QFileDialog,
    QTableWidget, QTableWidgetItem, QProgressBar, QFrame,
    QScrollArea, QComboBox, QHeaderView, QMessageBox,
    QAbstractItemView,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont

try:
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    import matplotlib
    matplotlib.use("Qt5Agg")
    import matplotlib.pyplot as plt
    plt.style.use("dark_background")
    HAS_MPL = True
except Exception:
    HAS_MPL = False

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw, ICMP, ARP
except ImportError:
    print("[-] scapy missing. Run: pip3 install scapy --break-system-packages")
    sys.exit(1)

import ipaddress

# =============================================================================
# MITRE ATT&CK Database
# =============================================================================

MITRE_DB = {
    "port_scan":        {"id": "T1046",     "name": "Network Service Discovery",         "tactic": "Discovery",         "color": "#F39C12"},
    "recon":            {"id": "T1595",     "name": "Active Scanning",                   "tactic": "Reconnaissance",    "color": "#E67E22"},
    "dns_c2":           {"id": "T1071.004", "name": "Application Layer Protocol: DNS",   "tactic": "Command & Control", "color": "#E74C3C"},
    "http_c2":          {"id": "T1071.001", "name": "Application Layer Protocol: HTTP",  "tactic": "Command & Control", "color": "#E74C3C"},
    "beaconing":        {"id": "T1071",     "name": "C2 Beaconing",                      "tactic": "Command & Control", "color": "#C0392B"},
    "dns_tunnel":       {"id": "T1071.004", "name": "DNS Tunneling",                     "tactic": "Exfiltration / C2", "color": "#C0392B"},
    "smtp_exfil":       {"id": "T1048.003", "name": "Exfiltration Over SMTP",            "tactic": "Exfiltration",      "color": "#9B59B6"},
    "data_exfil":       {"id": "T1041",     "name": "Exfiltration Over C2 Channel",      "tactic": "Exfiltration",      "color": "#9B59B6"},
    "ftp_exfil":        {"id": "T1048.003", "name": "Exfiltration Over FTP",             "tactic": "Exfiltration",      "color": "#8E44AD"},
    "non_std_port":     {"id": "T1571",     "name": "Non-Standard Port",                 "tactic": "Command & Control", "color": "#E74C3C"},
    "brute_force":      {"id": "T1110",     "name": "Brute Force",                       "tactic": "Credential Access", "color": "#F39C12"},
    "lateral_movement": {"id": "T1021",     "name": "Remote Services",                   "tactic": "Lateral Movement",  "color": "#E67E22"},
    "suspicious_ua":    {"id": "T1059",     "name": "Command and Scripting Interpreter", "tactic": "Execution",         "color": "#E74C3C"},
}

SUSPICIOUS_PORTS = {4444, 1234, 31337, 9999, 6666, 7777, 1337, 12345, 5555, 8888}
LATERAL_PORTS    = {445: "SMB", 3389: "RDP", 22: "SSH", 5985: "WinRM", 23: "Telnet"}
BRUTE_PORTS      = {22: "SSH", 3389: "RDP", 21: "FTP", 23: "Telnet", 5900: "VNC"}
SUSPICIOUS_UA    = ["python-requests", "curl/", "wget/", "masscan", "nmap", "nikto",
                    "sqlmap", "metasploit", "go-http-client", "java/", "scrapy"]

SEV_COLORS = {
    "HIGH":   ("#DA3633", "#3D0000"),
    "MEDIUM": ("#E3B341", "#2B2000"),
    "LOW":    ("#3FB950", "#001A00"),
}
TACTIC_COLORS = {
    "Reconnaissance":    "#E67E22",
    "Discovery":         "#F39C12",
    "Credential Access": "#E67E22",
    "Execution":         "#E74C3C",
    "Lateral Movement":  "#E67E22",
    "Command & Control": "#E74C3C",
    "Exfiltration / C2": "#C0392B",
    "Exfiltration":      "#9B59B6",
}

# =============================================================================
# Utility
# =============================================================================

_PRIVATE = [ipaddress.IPv4Network(n) for n in
            ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]

def is_private(ip):
    try:
        a = ipaddress.IPv4Address(ip)
        return any(a in n for n in _PRIVATE)
    except Exception:
        return False

def entropy(s):
    if not s:
        return 0.0
    f = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in f.values())

def fmt_bytes(b):
    for u in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return "%s %s" % (round(b, 1), u)
        b /= 1024
    return "%s TB" % round(b, 1)

# =============================================================================
# Packet parsers
# =============================================================================

def _parse_http(payload, src, dst, ts, out):
    try:
        text = payload.decode("utf-8", errors="ignore")
        lines = text.split("\r\n")
        meth = None
        for m in ("GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"):
            if lines[0].startswith(m):
                meth = m
                break
        if not meth:
            return
        parts = lines[0].split(" ")
        path = parts[1] if len(parts) > 1 else "/"
        host = ""
        ua = ""
        for line in lines[1:]:
            ll = line.lower()
            if ll.startswith("host:"):
                host = line.split(":", 1)[1].strip()
            elif ll.startswith("user-agent:"):
                ua = line.split(":", 1)[1].strip()
        url = ("http://" + host + path) if host else path
        out.append({"method": meth, "path": path, "host": host,
                    "url": url, "user_agent": ua, "src": src, "dst": dst, "time": ts})
    except Exception:
        pass

def _parse_smtp(payload, src, dst, ts, out):
    try:
        text = payload.decode("utf-8", errors="ignore")
        for cmd in ("EHLO", "HELO", "MAIL FROM:", "RCPT TO:", "DATA", "AUTH"):
            if cmd in text:
                e = {"command": cmd, "src": src, "dst": dst, "time": ts}
                m = re.search(r"MAIL FROM:\s*<?([^>\r\n]+)>?", text, re.I)
                if m:
                    e["from"] = m.group(1).strip()
                m = re.search(r"RCPT TO:\s*<?([^>\r\n]+)>?", text, re.I)
                if m:
                    e["to"] = m.group(1).strip()
                out.append(e)
                return
    except Exception:
        pass

def _parse_dns(pkt, src, dst, ts, out):
    try:
        d = pkt["DNS"]
        if d.qr == 0 and d.qd:
            q = d.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
            out.append({"query": q, "src": src, "dst": dst, "time": ts})
    except Exception:
        pass

# =============================================================================
# Threat detection
# =============================================================================

def detect_port_scan(ip_traffic, thresh=15):
    return [(ip, len(d["ports"]))
            for ip, d in ip_traffic.items()
            if len(d["ports"]) >= thresh]

def detect_beaconing(packets, min_n=5, max_cv=0.30):
    times = defaultdict(list)
    for p in packets:
        try:
            if p.haslayer("TCP") and (p["TCP"].flags & 0x02):
                k = (p["IP"].src, p["IP"].dst, p["TCP"].dport)
                times[k].append(float(p.time))
        except Exception:
            pass
    out = []
    for (src, dst, port), ts in times.items():
        if len(ts) < min_n:
            continue
        ts.sort()
        ivs = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
        avg = sum(ivs) / len(ivs)
        if avg < 0.5:
            continue
        variance = sum((x - avg) ** 2 for x in ivs) / len(ivs)
        cv = math.sqrt(variance) / avg if avg else 1.0
        if cv <= max_cv:
            out.append({"src": src, "dst": dst, "port": port,
                        "count": len(ts), "interval": avg, "cv": cv})
    return sorted(out, key=lambda x: x["count"], reverse=True)[:5]

def detect_dns_tunnel(queries):
    out = []
    for q in queries:
        s = q.get("query", "")
        parts = s.split(".")
        sub = ".".join(parts[:-2]) if len(parts) > 2 else (parts[0] if parts else "")
        if len(sub) > 45 or (len(sub) > 20 and entropy(sub) > 3.5):
            out.append(q)
    return out[:10]

def detect_brute(port_counts, thresh=60):
    return [{"port": p, "service": s, "count": port_counts[p]}
            for p, s in BRUTE_PORTS.items()
            if port_counts.get(p, 0) >= thresh]

# =============================================================================
# Main analyzer engine
# =============================================================================

class PCAPAnalyzer:
    def __init__(self):
        self.packets = []
        self.filepath = ""
        self.results = {}

    def load(self, fp):
        self.filepath = fp
        self.packets = rdpcap(fp)

    def analyze(self, cb=None):
        R = {
            "meta": {},
            "iocs": {"ips": [], "domains": [], "urls": [], "emails": [], "user_agents": []},
            "alerts": [],
            "mitre": [],
            "stats": {}
        }
        ip_tr = defaultdict(lambda: {"packets": 0, "bytes": 0, "ports": set()})
        dns_q = []
        http_r = []
        smtp_d = []
        proto = Counter()
        ports = Counter()
        total = len(self.packets)

        # Pass 1: extract
        for i, pkt in enumerate(self.packets):
            if cb and i % 200 == 0:
                cb(int(i / total * 60))
            try:
                if not pkt.haslayer("IP"):
                    if pkt.haslayer("IPv6"):
                        proto["IPv6"] += 1
                    elif pkt.haslayer("ARP"):
                        proto["ARP"] += 1
                    elif pkt.haslayer("ICMP"):
                        proto["ICMP"] += 1
                    continue
                proto["IPv4"] += 1
                src = pkt["IP"].src
                dst = pkt["IP"].dst
                plen = len(pkt)
                ts = float(pkt.time)
                ip_tr[src]["packets"] += 1
                ip_tr[src]["bytes"] += plen
                ip_tr[dst]["packets"] += 1
                if pkt.haslayer("TCP"):
                    proto["TCP"] += 1
                    dport = pkt["TCP"].dport
                    ip_tr[src]["ports"].add(dport)
                    ports[dport] += 1
                    if pkt.haslayer("Raw"):
                        raw = bytes(pkt["Raw"].load)
                        _parse_http(raw, src, dst, ts, http_r)
                        _parse_smtp(raw, src, dst, ts, smtp_d)
                elif pkt.haslayer("UDP"):
                    proto["UDP"] += 1
                    ports[pkt["UDP"].dport] += 1
                if pkt.haslayer("ICMP"):
                    proto["ICMP"] += 1
                if pkt.haslayer("DNS"):
                    proto["DNS"] += 1
                    _parse_dns(pkt, src, dst, ts, dns_q)
            except Exception:
                continue

        if cb:
            cb(65)

        # Pass 2: threat detection
        alerts = []
        mitre_on = {}

        for ip, n in detect_port_scan(ip_tr):
            alerts.append({"severity": "HIGH", "type": "Port Scan", "src": ip,
                           "description": "Scanned %d unique ports" % n, "mitre": "T1046"})
            mitre_on["port_scan"] = True
            mitre_on["recon"] = True

        for b in detect_beaconing(self.packets):
            alerts.append({
                "severity": "HIGH", "type": "C2 Beaconing", "src": b["src"],
                "description": "Regular connections to %s:%d every ~%.1fs (%d times)" % (
                    b["dst"], b["port"], b["interval"], b["count"]),
                "mitre": "T1071"
            })
            mitre_on["beaconing"] = True

        for t in detect_dns_tunnel(dns_q):
            q = t.get("query", "")
            alerts.append({
                "severity": "HIGH", "type": "DNS Tunneling", "src": t["src"],
                "description": "Long/encoded DNS query: %s%s" % (q[:65], "..." if len(q) > 65 else ""),
                "mitre": "T1071.004"
            })
            mitre_on["dns_tunnel"] = True

        for bf in detect_brute(ports):
            alerts.append({
                "severity": "MEDIUM",
                "type": "Brute Force (%s)" % bf["service"],
                "src": "Multiple",
                "description": "High volume on port %d/%s: %d packets" % (
                    bf["port"], bf["service"], bf["count"]),
                "mitre": "T1110"
            })
            mitre_on["brute_force"] = True

        for port in SUSPICIOUS_PORTS:
            if ports.get(port, 0):
                alerts.append({
                    "severity": "HIGH", "type": "Suspicious Port", "src": "Multiple",
                    "description": "Traffic on port %d - common C2/RAT port (%d packets)" % (
                        port, ports[port]),
                    "mitre": "T1571"
                })
                mitre_on["non_std_port"] = True

        if smtp_d:
            for s in smtp_d[:3]:
                alerts.append({
                    "severity": "MEDIUM", "type": "SMTP Traffic", "src": s.get("src", "?"),
                    "description": "SMTP command: %s" % s.get("command", "?"),
                    "mitre": "T1048.003"
                })
            mitre_on["smtp_exfil"] = True

        for ip, d in ip_tr.items():
            if d["bytes"] > 5000000 and not is_private(ip):
                alerts.append({
                    "severity": "MEDIUM", "type": "Large Transfer", "src": ip,
                    "description": "Large outbound transfer: %s" % fmt_bytes(d["bytes"]),
                    "mitre": "T1041"
                })
                mitre_on["data_exfil"] = True

        if ports.get(21, 0):
            alerts.append({
                "severity": "LOW", "type": "Cleartext FTP", "src": "Multiple",
                "description": "Unencrypted FTP detected (%d packets)" % ports[21],
                "mitre": "T1048.003"
            })
            mitre_on["ftp_exfil"] = True

        for port, svc in LATERAL_PORTS.items():
            if ports.get(port, 0) > 10:
                alerts.append({
                    "severity": "MEDIUM",
                    "type": "Lateral Movement (%s)" % svc,
                    "src": "Multiple",
                    "description": "%s traffic: %d packets" % (svc, ports[port]),
                    "mitre": "T1021"
                })
                mitre_on["lateral_movement"] = True

        if cb:
            cb(80)

        # Pass 3: compile IOCs
        alert_srcs = {a["src"] for a in alerts}

        seen = set()
        for ip, d in sorted(ip_tr.items(), key=lambda x: x[1]["bytes"], reverse=True)[:60]:
            if ip in seen:
                continue
            seen.add(ip)
            sev = "HIGH" if ip in alert_srcs else ("LOW" if is_private(ip) else "MEDIUM")
            R["iocs"]["ips"].append({
                "value": ip,
                "type": "Private" if is_private(ip) else "Public",
                "packets": d["packets"],
                "bytes": fmt_bytes(d["bytes"]),
                "severity": sev
            })

        seen = set()
        for q in dns_q:
            d = q.get("query", "").rstrip(".")
            if not d or d in seen:
                continue
            seen.add(d)
            parts = d.split(".")
            sub = ".".join(parts[:-2]) if len(parts) > 2 else ""
            sev = "HIGH" if (len(d) > 50 or (sub and entropy(sub) > 3.5)) else "LOW"
            R["iocs"]["domains"].append({
                "value": d, "src": q.get("src", "?"),
                "entropy": "%.2f" % entropy(d), "severity": sev
            })

        seen = set()
        for r in http_r:
            u = r.get("url", "")
            if not u or u in seen:
                continue
            seen.add(u)
            R["iocs"]["urls"].append({
                "value": u, "method": r.get("method", "?"),
                "host": r.get("host", "?"), "severity": "MEDIUM"
            })

        seen = set()
        for r in http_r:
            ua = r.get("user_agent", "")
            if not ua or ua in seen:
                continue
            seen.add(ua)
            sev = "HIGH" if any(p in ua.lower() for p in SUSPICIOUS_UA) else (
                "MEDIUM" if len(ua) < 10 else "LOW")
            if sev != "LOW":
                mitre_on["suspicious_ua"] = True
            R["iocs"]["user_agents"].append({"value": ua, "severity": sev})

        seen = set()
        for s in smtp_d:
            for f in ("from", "to"):
                em = s.get(f, "")
                if em and em not in seen:
                    seen.add(em)
                    R["iocs"]["emails"].append({
                        "value": em, "type": "Email %s" % f.upper(), "severity": "MEDIUM"
                    })

        if dns_q:
            mitre_on["dns_c2"] = True
        if http_r:
            mitre_on["http_c2"] = True

        seen_ids = set()
        for k in mitre_on:
            if k in MITRE_DB:
                t = dict(MITRE_DB[k])
                t["key"] = k
                if t["id"] not in seen_ids:
                    seen_ids.add(t["id"])
                    R["mitre"].append(t)

        sc = Counter(a["severity"] for a in alerts)
        R["stats"] = {
            "total_packets": total,
            "protocols": dict(proto),
            "top_ips": sorted([(ip, d["bytes"]) for ip, d in ip_tr.items()],
                              key=lambda x: x[1], reverse=True)[:10],
            "top_ports": ports.most_common(10),
            "dns_count": len(dns_q),
            "http_count": len(http_r),
            "smtp_count": len(smtp_d),
            "alert_count": len(alerts),
            "ioc_count": sum(len(v) for v in R["iocs"].values()),
            "technique_count": len(R["mitre"]),
            "severity_counts": dict(sc)
        }
        R["meta"] = {
            "filename": self.filepath,
            "analyzed_at": datetime.now().isoformat(),
            "total_packets": total
        }
        R["alerts"] = sorted(alerts,
                             key=lambda a: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(a["severity"], 3))
        self.results = R
        if cb:
            cb(100)
        return R

# =============================================================================
# HTML report generator
# =============================================================================

def gen_html(R, filepath=""):
    stats = R.get("stats", {})
    alerts = R.get("alerts", [])
    mitre = R.get("mitre", [])
    iocs = R.get("iocs", {})
    sc = stats.get("severity_counts", {})
    fn = os.path.basename(R.get("meta", {}).get("filename", filepath))
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def badge(sev):
        c = {"HIGH": "#DA3633", "MEDIUM": "#E3B341", "LOW": "#3FB950"}.get(sev, "#888")
        return ('<span style="background:%s22;color:%s;border:1px solid %s44;'
                'padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold">%s</span>') % (c, c, c, sev)

    ip_rows = "".join(
        '<tr><td><code style="color:#79C0FF">%s</code></td><td>%s</td>'
        '<td>%s</td><td>%s</td><td>%s</td></tr>' % (
            i["value"], i["type"], i["packets"], i["bytes"], badge(i["severity"]))
        for i in iocs.get("ips", []))

    alert_rows = "".join(
        '<tr><td>%s</td><td style="font-weight:bold">%s</td>'
        '<td><code>%s</code></td><td>%s</td>'
        '<td><code style="color:#E3B341">%s</code></td></tr>' % (
            badge(a["severity"]), a["type"], a["src"], a["description"], a["mitre"])
        for a in alerts)

    mitre_cards = "".join(
        '<div style="background:#161B22;border-left:5px solid %s;border-radius:8px;'
        'padding:14px;margin-bottom:10px">'
        '<code style="color:%s;font-size:14px;font-weight:bold">%s</code>'
        ' &nbsp; <span style="color:%s;font-size:11px">%s</span><br>'
        '<b style="color:#E6EDF3;font-size:15px">%s</b></div>' % (
            t["color"], t["color"], t["id"], t["color"], t["tactic"], t["name"])
        for t in mitre)

    html = """<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>IOC Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0D1117;color:#E6EDF3;font-family:'Segoe UI',Arial,sans-serif;padding:32px;font-size:14px}
h2{color:#58A6FF;font-size:17px;margin:24px 0 10px;padding-bottom:6px;border-bottom:1px solid #21262D}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:16px 0}
.card{background:#161B22;border:1px solid #30363D;border-radius:8px;padding:16px}
.card .n{font-size:32px;font-weight:700}.card .l{color:#8B949E;font-size:12px;margin-top:3px}
table{width:100%;border-collapse:collapse;margin-bottom:8px}
th{background:#21262D;color:#8B949E;padding:8px 10px;text-align:left;font-size:11px;text-transform:uppercase}
td{padding:8px 10px;border-bottom:1px solid #21262D;font-size:13px}
tr:hover td{background:#161B22}
code{font-family:monospace;font-size:12px}
</style></head><body>
<h1 style="color:#58A6FF;font-size:24px;margin-bottom:6px">Network Forensics IOC Report</h1>
<p style="color:#8B949E;margin-bottom:20px">%s &nbsp;|&nbsp; %s &nbsp;|&nbsp; %d packets</p>
<div class="grid">
<div class="card" style="border-color:#DA363344"><div class="n" style="color:#DA3633">%d</div><div class="l">HIGH alerts</div></div>
<div class="card" style="border-color:#E3B34144"><div class="n" style="color:#E3B341">%d</div><div class="l">MEDIUM alerts</div></div>
<div class="card" style="border-color:#3FB95044"><div class="n" style="color:#3FB950">%d</div><div class="l">LOW alerts</div></div>
<div class="card" style="border-color:#58A6FF44"><div class="n" style="color:#58A6FF">%d</div><div class="l">MITRE techniques</div></div>
</div>
<h2>Alerts</h2>
<table><thead><tr><th>Severity</th><th>Type</th><th>Source</th><th>Description</th><th>MITRE</th></tr></thead>
<tbody>%s</tbody></table>
<h2>MITRE ATT&CK Techniques</h2>%s
<h2>IP Addresses</h2>
<table><thead><tr><th>IP</th><th>Type</th><th>Packets</th><th>Bytes</th><th>Severity</th></tr></thead>
<tbody>%s</tbody></table>
<footer style="color:#30363D;text-align:center;margin-top:40px;font-size:12px;border-top:1px solid #21262D;padding-top:14px">
Network Forensics IOC Extractor | Cyberium NX216 | Itay Bechor</footer>
</body></html>""" % (
        fn, now, stats.get("total_packets", 0),
        sc.get("HIGH", 0), sc.get("MEDIUM", 0), sc.get("LOW", 0), len(mitre),
        alert_rows, mitre_cards, ip_rows)
    return html

def gen_json(R):
    def fix(o):
        if isinstance(o, set):
            return list(o)
        if isinstance(o, dict):
            return {k: fix(v) for k, v in o.items()}
        if isinstance(o, list):
            return [fix(i) for i in o]
        return o
    return json.dumps(fix(R), indent=2, ensure_ascii=False)

# =============================================================================
# Stylesheet
# =============================================================================

STYLE = (
    "QMainWindow,QWidget{background:#0D1117;color:#E6EDF3;"
    "font-family:'Segoe UI','Ubuntu',Arial,sans-serif}"
    "QTabWidget::pane{border:1px solid #30363D;background:#0D1117;border-radius:6px}"
    "QTabBar::tab{background:#161B22;color:#8B949E;padding:9px 18px;margin-right:2px;"
    "border-top-left-radius:6px;border-top-right-radius:6px;font-size:13px;min-width:120px}"
    "QTabBar::tab:selected{background:#0D1117;color:#58A6FF;border-bottom:2px solid #58A6FF}"
    "QTabBar::tab:hover{background:#21262D;color:#E6EDF3}"
    "QPushButton{background:#21262D;color:#E6EDF3;border:1px solid #30363D;"
    "padding:8px 16px;border-radius:6px;font-size:13px}"
    "QPushButton:hover{background:#30363D;border-color:#58A6FF}"
    "QPushButton:disabled{color:#484F58;border-color:#21262D}"
    "QPushButton#analyzeBtn{background:#238636;color:#fff;font-weight:bold;"
    "font-size:14px;padding:10px 26px;border:none;border-radius:8px;min-width:130px}"
    "QPushButton#analyzeBtn:hover{background:#2EA043}"
    "QPushButton#analyzeBtn:disabled{background:#21262D;color:#484F58}"
    "QPushButton#expBtn{background:#1F6FEB22;color:#58A6FF;border:1px solid #58A6FF55;border-radius:6px}"
    "QPushButton#expBtn:hover{background:#1F6FEB44}"
    "QLineEdit{background:#161B22;color:#E6EDF3;border:1px solid #30363D;"
    "padding:8px 12px;border-radius:6px;font-size:13px}"
    "QLineEdit:focus{border-color:#58A6FF}"
    "QTableWidget{background:#161B22;color:#E6EDF3;border:1px solid #30363D;"
    "gridline-color:#1C2128;font-size:12px;alternate-background-color:#13191F}"
    "QTableWidget::item{padding:5px 10px}"
    "QTableWidget::item:selected{background:#1F6FEB;color:#fff}"
    "QHeaderView::section{background:#21262D;color:#8B949E;padding:8px 10px;"
    "border:none;border-bottom:1px solid #30363D;border-right:1px solid #30363D;"
    "font-weight:bold;font-size:11px}"
    "QProgressBar{border:none;background:#21262D;border-radius:4px;height:6px}"
    "QProgressBar::chunk{background:#238636;border-radius:4px}"
    "QScrollBar:vertical{background:#0D1117;width:8px;border-radius:4px}"
    "QScrollBar::handle:vertical{background:#30363D;border-radius:4px;min-height:24px}"
    "QScrollBar::handle:vertical:hover{background:#58A6FF}"
    "QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0}"
    "QComboBox{background:#21262D;color:#E6EDF3;border:1px solid #30363D;"
    "padding:5px 10px;border-radius:6px;font-size:12px}"
    "QLabel{color:#E6EDF3}"
    "QScrollArea{border:none;background:transparent}"
)

# =============================================================================
# Widgets
# =============================================================================

class StatCard(QFrame):
    def __init__(self, title, value, color="#58A6FF"):
        super().__init__()
        self.setStyleSheet(
            "QFrame{background:#161B22;border:1px solid %s33;"
            "border-left:4px solid %s;border-radius:8px;padding:14px}" % (color, color))
        lay = QVBoxLayout(self)
        lay.setSpacing(4)
        n = QLabel(value)
        n.setStyleSheet("color:%s;font-size:30px;font-weight:bold" % color)
        l = QLabel(title)
        l.setStyleSheet("color:#8B949E;font-size:12px")
        lay.addWidget(n)
        lay.addWidget(l)


class AlertRow(QFrame):
    def __init__(self, a):
        super().__init__()
        sev = a.get("severity", "LOW")
        fg, bg = SEV_COLORS.get(sev, ("#888", "#111"))
        self.setStyleSheet(
            "QFrame{background:%s;border:1px solid %s44;"
            "border-left:4px solid %s;border-radius:6px;padding:9px 12px;margin:2px 0}" % (bg, fg, fg))
        lay = QHBoxLayout(self)
        lay.setSpacing(10)
        badge = QLabel(sev)
        badge.setStyleSheet(
            "background:%s22;color:%s;border:1px solid %s44;"
            "padding:2px 6px;border-radius:10px;font-weight:bold;font-size:11px" % (fg, fg, fg))
        badge.setFixedWidth(68)
        tp = QLabel('<b style="color:%s">%s</b>' % (fg, a["type"]))
        tp.setTextFormat(Qt.RichText)
        tp.setFixedWidth(155)
        src = QLabel('<code style="color:#79C0FF">%s</code>' % a["src"])
        src.setTextFormat(Qt.RichText)
        src.setFixedWidth(125)
        desc = QLabel(a["description"])
        desc.setStyleSheet("color:#C9D1D9;font-size:12px")
        desc.setWordWrap(True)
        mid = QLabel('<code style="color:#E3B341">%s</code>' % a["mitre"])
        mid.setTextFormat(Qt.RichText)
        mid.setFixedWidth(88)
        lay.addWidget(badge)
        lay.addWidget(tp)
        lay.addWidget(src)
        lay.addWidget(desc, 1)
        lay.addWidget(mid)


class MITRECard(QFrame):
    def __init__(self, t):
        super().__init__()
        c = t.get("color", "#58A6FF")
        tc = TACTIC_COLORS.get(t.get("tactic", ""), c)
        self.setStyleSheet(
            "QFrame{background:#161B22;border:1px solid %s33;"
            "border-left:5px solid %s;border-radius:8px;padding:13px 15px;margin:3px 0}" % (c, c))
        lay = QVBoxLayout(self)
        lay.setSpacing(5)
        top = QHBoxLayout()
        tid = QLabel(t["id"])
        tid.setStyleSheet(
            "color:%s;font-family:monospace;font-size:14px;font-weight:bold;"
            "background:%s11;padding:3px 9px;border-radius:4px;border:1px solid %s44" % (c, c, c))
        tact = QLabel(t["tactic"])
        tact.setStyleSheet(
            "color:%s;background:%s22;padding:3px 10px;border-radius:10px;font-size:11px;font-weight:bold" % (tc, tc))
        tech_id_url = t["id"].replace(".", "/")
        url = QLabel('<a href="https://attack.mitre.org/techniques/%s/" '
                     'style="color:%s;font-size:11px;text-decoration:none">Link ATT&CK</a>' % (tech_id_url, c))
        url.setOpenExternalLinks(True)
        url.setTextFormat(Qt.RichText)
        top.addWidget(tid)
        top.addWidget(tact)
        top.addStretch()
        top.addWidget(url)
        nm = QLabel(t["name"])
        nm.setStyleSheet("color:#E6EDF3;font-size:15px;font-weight:600")
        desc_text = MITRE_DB.get(t.get("key", ""), {}).get("name", "")
        ds = QLabel(desc_text)
        ds.setStyleSheet("color:#8B949E;font-size:12px")
        ds.setWordWrap(True)
        lay.addLayout(top)
        lay.addWidget(nm)
        lay.addWidget(ds)


def _scroll(w):
    sa = QScrollArea()
    sa.setWidgetResizable(True)
    sa.setWidget(w)
    sa.setStyleSheet("QScrollArea{border:none;background:transparent}")
    return sa


def _table(headers, rows, widths=None):
    t = QTableWidget(len(rows), len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setAlternatingRowColors(True)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.verticalHeader().setVisible(False)
    t.horizontalHeader().setStretchLastSection(True)
    if widths:
        for i, w in enumerate(widths):
            if w == -1:
                t.horizontalHeader().setSectionResizeMode(i, QHeaderView.Stretch)
            else:
                t.setColumnWidth(i, w)
    for r, row in enumerate(rows):
        for c, cell in enumerate(row):
            item = QTableWidgetItem(str(cell))
            if str(cell) in SEV_COLORS:
                fg, _ = SEV_COLORS[str(cell)]
                item.setForeground(QColor(fg))
                item.setFont(QFont("", 11, QFont.Bold))
            t.setItem(r, c, item)
    t.resizeRowsToContents()
    return t

# =============================================================================
# Background thread
# =============================================================================

class AnalyzerThread(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, fp):
        super().__init__()
        self.fp = fp

    def run(self):
        try:
            eng = PCAPAnalyzer()
            eng.load(self.fp)
            self.finished.emit(eng.analyze(cb=self.progress.emit))
        except Exception as e:
            self.error.emit(str(e))

# =============================================================================
# Main Window
# =============================================================================

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Forensics IOC Extractor - Cyberium NX216")
        self.setMinimumSize(1150, 750)
        self.resize(1350, 840)
        self.results = {}
        self._build()

    def _build(self):
        cw = QWidget()
        self.setCentralWidget(cw)
        root = QVBoxLayout(cw)
        root.setSpacing(0)
        root.setContentsMargins(0, 0, 0, 0)
        root.addWidget(self._header())
        self.pbar = QProgressBar()
        self.pbar.setVisible(False)
        self.pbar.setFixedHeight(6)
        self.pbar.setTextVisible(False)
        root.addWidget(self.pbar)
        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)
        self._empty_tabs()
        # status bar at bottom
        self.status = QLabel("Ready - load a PCAP file to begin.")
        self.status.setStyleSheet(
            "color:#8B949E;font-size:12px;background:#161B22;"
            "border-top:1px solid #30363D;padding:5px 16px")
        root.addWidget(self.status)

    def _header(self):
        w = QWidget()
        w.setStyleSheet("background:#161B22;border-bottom:1px solid #30363D")
        vlay = QVBoxLayout(w)
        vlay.setContentsMargins(16, 10, 16, 10)
        vlay.setSpacing(8)

        # Row 1: title
        row1 = QHBoxLayout()
        row1.setSpacing(10)
        title = QLabel("Network Forensics IOC Extractor")
        title.setStyleSheet("color:#58A6FF;font-size:17px;font-weight:bold")
        sub = QLabel("Cyberium Academy - NX216")
        sub.setStyleSheet("color:#8B949E;font-size:11px")
        row1.addWidget(title)
        row1.addWidget(sub)
        row1.addStretch()
        vlay.addLayout(row1)

        # Row 2: file picker + all buttons
        row2 = QHBoxLayout()
        row2.setSpacing(8)
        self.finput = QLineEdit()
        self.finput.setPlaceholderText("Select .pcap / .pcapng file ...")
        self.finput.setReadOnly(True)
        browse = QPushButton("Browse")
        browse.clicked.connect(self._browse)
        self.abtn = QPushButton("Analyze")
        self.abtn.setObjectName("analyzeBtn")
        self.abtn.setEnabled(False)
        self.abtn.clicked.connect(self._start)
        ej = QPushButton("Export JSON")
        ej.setObjectName("expBtn")
        ej.clicked.connect(self._expj)
        eh = QPushButton("Export HTML")
        eh.setObjectName("expBtn")
        eh.clicked.connect(self._exph)
        row2.addWidget(self.finput, 1)
        row2.addWidget(browse)
        row2.addWidget(self.abtn)
        row2.addWidget(ej)
        row2.addWidget(eh)
        vlay.addLayout(row2)
        return w

    def _empty_tabs(self):
        for lbl in ["Dashboard", "IP / IOCs", "Domains & URLs",
                    "MITRE ATT&CK", "Alerts", "Statistics"]:
            p = QLabel("Load a PCAP file to see: " + lbl)
            p.setAlignment(Qt.AlignCenter)
            p.setStyleSheet("color:#484F58;font-size:15px;padding:60px")
            self.tabs.addTab(p, lbl)

    def _browse(self):
        p, _ = QFileDialog.getOpenFileName(
            self, "Open PCAP", "", "PCAP (*.pcap *.pcapng *.cap);;All (*)")
        if p:
            self.finput.setText(p)
            self.abtn.setEnabled(True)
            self._st("Loaded: " + os.path.basename(p))

    def _start(self):
        p = self.finput.text().strip()
        if not p or not os.path.exists(p):
            QMessageBox.warning(self, "Error", "Please select a valid PCAP file.")
            return
        self.abtn.setEnabled(False)
        self.pbar.setValue(0)
        self.pbar.setVisible(True)
        self._st("Analyzing ...")
        self.thread = AnalyzerThread(p)
        self.thread.progress.connect(lambda v: (self.pbar.setValue(v),
                                                self._st("Analyzing ... %d%%" % v)))
        self.thread.finished.connect(self._done)
        self.thread.error.connect(self._err)
        self.thread.start()

    def _done(self, R):
        self.results = R
        self.pbar.setVisible(False)
        self.abtn.setEnabled(True)
        self._populate(R)
        s = R.get("stats", {})
        self._st("Done - %d alerts | %d IOCs | %d MITRE techniques" % (
            s.get("alert_count", 0), s.get("ioc_count", 0), s.get("technique_count", 0)))

    def _err(self, msg):
        self.pbar.setVisible(False)
        self.abtn.setEnabled(True)
        QMessageBox.critical(self, "Error", msg)
        self._st("Error: " + msg)

    def _st(self, msg):
        self.status.setText(msg)

    def _populate(self, R):
        self.tabs.clear()
        self._t_dash(R)
        self._t_ips(R)
        self._t_doms(R)
        self._t_mitre(R)
        self._t_alerts(R)
        self._t_stats(R)

    def _t_dash(self, R):
        s = R.get("stats", {})
        sc = s.get("severity_counts", {})
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setContentsMargins(20, 20, 20, 20)
        vl.setSpacing(14)
        meta = R.get("meta", {})
        fn = os.path.basename(meta.get("filename", "?"))
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        info = QLabel("File: %s  |  %s  |  %d packets" % (fn, now, s.get("total_packets", 0)))
        info.setStyleSheet(
            "color:#8B949E;font-size:13px;background:#161B22;"
            "border:1px solid #30363D;border-radius:6px;padding:10px 14px")
        vl.addWidget(info)
        r1 = QHBoxLayout()
        r1.setSpacing(12)
        for v, t, c in [(sc.get("HIGH", 0), "HIGH Alerts", "#DA3633"),
                        (sc.get("MEDIUM", 0), "MEDIUM Alerts", "#E3B341"),
                        (sc.get("LOW", 0), "LOW Alerts", "#3FB950"),
                        (s.get("technique_count", 0), "MITRE Techniques", "#58A6FF")]:
            r1.addWidget(StatCard(t, str(v), c))
        vl.addLayout(r1)
        iocs = R.get("iocs", {})
        r2 = QHBoxLayout()
        r2.setSpacing(12)
        for k, t, c in [("ips", "IP Addresses", "#79C0FF"),
                        ("domains", "Domains", "#A5D6FF"),
                        ("urls", "URLs", "#D2A8FF"),
                        ("emails", "Emails", "#FFA657"),
                        ("user_agents", "User-Agents", "#7EE787")]:
            r2.addWidget(StatCard(t, str(len(iocs.get(k, []))), c))
        vl.addLayout(r2)
        r3 = QHBoxLayout()
        r3.setSpacing(12)
        for v, t, c in [(s.get("total_packets", 0), "Total Packets", "#58A6FF"),
                        (s.get("dns_count", 0), "DNS Queries", "#A5D6FF"),
                        (s.get("http_count", 0), "HTTP Requests", "#D2A8FF"),
                        (s.get("smtp_count", 0), "SMTP", "#FFA657")]:
            r3.addWidget(StatCard(t, str(v), c))
        vl.addLayout(r3)
        vl.addStretch()
        self.tabs.addTab(w, "Dashboard")

    def _t_ips(self, R):
        ips = R.get("iocs", {}).get("ips", [])
        uas = R.get("iocs", {}).get("user_agents", [])
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setContentsMargins(16, 16, 16, 16)
        fr = QHBoxLayout()
        fr.addWidget(QLabel("Filter:"))
        flt = QLineEdit()
        flt.setPlaceholderText("Search IP ...")
        fr.addWidget(flt, 1)
        sc = QComboBox()
        sc.addItems(["All", "HIGH", "MEDIUM", "LOW"])
        fr.addWidget(sc)
        vl.addLayout(fr)
        rows = [[i["value"], i["type"], str(i["packets"]), i["bytes"], i["severity"]]
                for i in ips]
        tbl = _table(["IP Address", "Type", "Packets", "Bytes", "Severity"],
                     rows, [150, 90, 80, 90, -1])
        vl.addWidget(tbl, 3)
        if uas:
            l = QLabel("User-Agents")
            l.setStyleSheet("color:#58A6FF;font-size:14px;font-weight:bold;margin-top:10px")
            vl.addWidget(l)
            vl.addWidget(_table(["User-Agent", "Severity"],
                                [[u["value"], u["severity"]] for u in uas], [-1, 80]), 1)
        def _f(*_):
            txt = flt.text().lower()
            sev = sc.currentText()
            for r in range(tbl.rowCount()):
                mt = any(txt in (tbl.item(r, c) and tbl.item(r, c).text() or "").lower()
                         for c in range(tbl.columnCount()))
                ms = sev == "All" or (tbl.item(r, 4) and tbl.item(r, 4).text() == sev)
                tbl.setRowHidden(r, not (mt and ms))
        flt.textChanged.connect(_f)
        sc.currentIndexChanged.connect(_f)
        self.tabs.addTab(w, "IP / IOCs")

    def _t_doms(self, R):
        iocs = R.get("iocs", {})
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setContentsMargins(16, 16, 16, 16)

        def sec(t, c="#58A6FF"):
            l = QLabel(t)
            l.setStyleSheet("color:%s;font-size:14px;font-weight:bold;"
                            "margin-top:8px;margin-bottom:4px" % c)
            vl.addWidget(l)

        doms = iocs.get("domains", [])
        sec("DNS Domains (%d)" % len(doms))
        if doms:
            vl.addWidget(_table(["Domain", "Source IP", "Entropy", "Severity"],
                                [[d["value"], d["src"], d["entropy"], d["severity"]]
                                 for d in doms], [-1, 130, 70, 80]))
        urls = iocs.get("urls", [])
        sec("HTTP URLs (%d)" % len(urls), "#A5D6FF")
        if urls:
            vl.addWidget(_table(["URL", "Method", "Host", "Severity"],
                                [[u["value"], u["method"], u["host"], u["severity"]]
                                 for u in urls], [-1, 70, 200, 80]))
        em = iocs.get("emails", [])
        sec("Emails (%d)" % len(em), "#FFA657")
        if em:
            vl.addWidget(_table(["Email", "Type", "Severity"],
                                [[e["value"], e["type"], e["severity"]] for e in em],
                                [-1, 120, 80]))
        self.tabs.addTab(w, "Domains & URLs")

    def _t_mitre(self, R):
        techs = R.get("mitre", [])
        sw = QWidget()
        vl = QVBoxLayout(sw)
        vl.setContentsMargins(16, 16, 16, 16)
        vl.setSpacing(4)
        if not techs:
            l = QLabel("No MITRE ATT&CK techniques detected.")
            l.setAlignment(Qt.AlignCenter)
            l.setStyleSheet("color:#484F58;font-size:15px;padding:60px")
            vl.addWidget(l)
        else:
            by_t = defaultdict(list)
            for t in techs:
                by_t[t["tactic"]].append(t)
            for tac, items in by_t.items():
                tc = TACTIC_COLORS.get(tac, "#58A6FF")
                lbl = QLabel("  %s  " % tac)
                lbl.setStyleSheet(
                    "color:%s;background:%s22;border:1px solid %s44;"
                    "border-radius:12px;font-size:12px;font-weight:bold;"
                    "padding:4px 12px;margin-bottom:3px" % (tc, tc, tc))
                lbl.setFixedWidth(210)
                lbl.setAlignment(Qt.AlignCenter)
                vl.addWidget(lbl)
                for t in items:
                    vl.addWidget(MITRECard(t))
                vl.addSpacing(6)
        vl.addStretch()
        self.tabs.addTab(_scroll(sw), "MITRE ATT&CK")

    def _t_alerts(self, R):
        alerts = R.get("alerts", [])
        sw = QWidget()
        vl = QVBoxLayout(sw)
        vl.setContentsMargins(16, 16, 16, 16)
        vl.setSpacing(0)
        if not alerts:
            l = QLabel("No alerts detected.")
            l.setAlignment(Qt.AlignCenter)
            l.setStyleSheet("color:#484F58;font-size:15px;padding:60px")
            vl.addWidget(l)
        else:
            hdr = QWidget()
            hdr.setStyleSheet("background:#21262D;border-radius:6px;padding:5px")
            hl = QHBoxLayout(hdr)
            hl.setContentsMargins(12, 3, 12, 3)
            for t, fw in [("SEVERITY", 68), ("TYPE", 155), ("SOURCE", 125),
                          ("DESCRIPTION", 0), ("MITRE", 88)]:
                l = QLabel(t)
                l.setStyleSheet("color:#8B949E;font-size:10px;font-weight:bold")
                if fw:
                    l.setFixedWidth(fw)
                hl.addWidget(l, 0 if fw else 1)
            vl.addWidget(hdr)
            vl.addSpacing(4)
            for a in alerts:
                vl.addWidget(AlertRow(a))
        vl.addStretch()
        self.tabs.addTab(_scroll(sw), "Alerts")

    def _t_stats(self, R):
        s = R.get("stats", {})
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setContentsMargins(16, 16, 16, 16)
        if HAS_MPL:
            row = QHBoxLayout()
            proto = {k: v for k, v in s.get("protocols", {}).items() if v > 0}
            if proto:
                fig1 = Figure(figsize=(5, 4), dpi=100, facecolor="#161B22")
                c1 = FigureCanvas(fig1)
                ax = fig1.add_subplot(111)
                ax.set_facecolor("#161B22")
                colors = ["#58A6FF", "#3FB950", "#E3B341", "#F785B1",
                          "#A5D6FF", "#DA3633", "#FFA657", "#79C0FF"]
                wedges, texts, autos = ax.pie(
                    list(proto.values()), labels=list(proto.keys()),
                    colors=colors[:len(proto)], autopct="%1.1f%%", startangle=140,
                    textprops={"color": "#E6EDF3", "fontsize": 9},
                    wedgeprops={"linewidth": 1.5, "edgecolor": "#0D1117"})
                for a in autos:
                    a.set_color("#0D1117")
                    a.set_fontsize(8)
                ax.set_title("Protocol Distribution", color="#58A6FF", fontsize=13, pad=12)
                fig1.tight_layout()
                row.addWidget(c1, 1)
            top = s.get("top_ips", [])[:8]
            if top:
                fig2 = Figure(figsize=(6, 4), dpi=100, facecolor="#161B22")
                c2 = FigureCanvas(fig2)
                ax2 = fig2.add_subplot(111)
                ax2.set_facecolor("#161B22")
                ax2.barh([ip for ip, _ in top], [b / 1024 for _, b in top],
                         color="#58A6FF", edgecolor="#0D1117", alpha=0.8)
                ax2.set_xlabel("Traffic (KB)", color="#8B949E", fontsize=10)
                ax2.set_title("Top IPs by Traffic", color="#58A6FF", fontsize=13, pad=12)
                ax2.tick_params(colors="#8B949E", labelsize=8)
                for sp in ["top", "right"]:
                    ax2.spines[sp].set_visible(False)
                for sp in ["left", "bottom"]:
                    ax2.spines[sp].set_color("#30363D")
                fig2.tight_layout()
                row.addWidget(c2, 1)
            vl.addLayout(row)
            tp = s.get("top_ports", [])[:12]
            if tp:
                fig3 = Figure(figsize=(12, 3), dpi=100, facecolor="#161B22")
                c3 = FigureCanvas(fig3)
                ax3 = fig3.add_subplot(111)
                ax3.set_facecolor("#161B22")
                ax3.bar([str(p) for p, _ in tp], [c for _, c in tp],
                        color="#E3B341", edgecolor="#0D1117", alpha=0.85)
                ax3.set_xlabel("Port", color="#8B949E", fontsize=10)
                ax3.set_ylabel("Packets", color="#8B949E", fontsize=10)
                ax3.set_title("Top Destination Ports", color="#58A6FF", fontsize=13, pad=12)
                ax3.tick_params(colors="#8B949E", labelsize=9)
                for sp in ["top", "right"]:
                    ax3.spines[sp].set_visible(False)
                for sp in ["left", "bottom"]:
                    ax3.spines[sp].set_color("#30363D")
                fig3.tight_layout()
                vl.addWidget(c3)
        else:
            vl.addWidget(QLabel("Install matplotlib for charts: pip3 install matplotlib"))
            proto_rows = [[p, str(c)] for p, c in
                          sorted(s.get("protocols", {}).items(), key=lambda x: x[1], reverse=True)]
            vl.addWidget(_table(["Protocol", "Packets"], proto_rows, [200, -1]))
        self.tabs.addTab(w, "Statistics")

    def _expj(self):
        if not self.results:
            QMessageBox.information(self, "Export", "No results yet.")
            return
        p, _ = QFileDialog.getSaveFileName(self, "Save JSON", "ioc_report.json", "JSON (*.json)")
        if p:
            with open(p, "w", encoding="utf-8") as f:
                f.write(gen_json(self.results))
            self._st("JSON saved: " + p)

    def _exph(self):
        if not self.results:
            QMessageBox.information(self, "Export", "No results yet.")
            return
        p, _ = QFileDialog.getSaveFileName(self, "Save HTML", "ioc_report.html", "HTML (*.html)")
        if p:
            with open(p, "w", encoding="utf-8") as f:
                f.write(gen_html(self.results, self.finput.text()))
            self._st("HTML report saved: " + p)

# =============================================================================
# Entry point
# =============================================================================

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
