#!/usr/bin/env python3
"""
RedSim Simple - Basic Web Security Scanner
Usage: python scanner.py -t example.com
"""

import argparse
import socket
import json
import os
from datetime import datetime

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Settings ────────────────────────────────────────────────────────────────

TIMEOUT = 5
THREADS = 10
USER_AGENT = "Mozilla/5.0 (Security Scanner)"

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]

PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}

RISKY_PORTS = {
    21: "FTP - bisa anonymous login, credentials dikirim plaintext",
    23: "Telnet - remote access tanpa enkripsi",
    445: "SMB - target umum ransomware",
    3389: "RDP - target brute-force",
    5900: "VNC - sering tanpa autentikasi",
    6379: "Redis - sering unauthenticated, bisa RCE",
    27017: "MongoDB - sering expose data tanpa auth",
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]

SENSITIVE_PATHS = [
    "/.env", "/.git/HEAD", "/config.php", "/phpinfo.php",
    "/admin", "/wp-admin", "/phpmyadmin", "/backup.sql",
    "/robots.txt", "/sitemap.xml", "/.htaccess",
    "/debug", "/server-status", "/api/swagger.json",
    "/docker-compose.yml", "/.env.local",
]

# ─── Port Scanner ─────────────────────────────────────────────────────────────

def scan_ports(target):
    print(f"\n[*] Scanning ports on {target}...")
    
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Tidak bisa resolve hostname: {target}")
        return {"error": "hostname tidak bisa diresolved", "open_ports": []}

    open_ports = []
    
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def check_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            result = s.connect_ex((ip, port))
            s.close()
            return port if result == 0 else None
        except:
            return None

    with ThreadPoolExecutor(max_workers=THREADS) as exe:
        futures = {exe.submit(check_port, p): p for p in COMMON_PORTS}
        for f in as_completed(futures):
            result = f.result()
            if result:
                open_ports.append(result)

    open_ports.sort()
    
    findings = []
    for port in open_ports:
        service = PORT_NAMES.get(port, "Unknown")
        risk = "HIGH" if port in RISKY_PORTS else "INFO"
        note = RISKY_PORTS.get(port, "")
        print(f"  [OPEN] Port {port} ({service}) - {note if note else 'OK'}")
        findings.append({
            "port": port,
            "service": service,
            "risk": risk,
            "note": note,
        })

    print(f"  Total open: {len(open_ports)} port(s)")
    return {
        "ip": ip,
        "open_ports": open_ports,
        "findings": findings,
    }


# ─── HTTP Header Analysis ─────────────────────────────────────────────────────

def analyze_http(target):
    print(f"\n[*] Analyzing HTTP headers on {target}...")

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    result = {
        "target": target,
        "status_code": None,
        "server": None,
        "missing_headers": [],
        "cookies": [],
        "findings": [],
    }

    try:
        resp = requests.get(
            target,
            timeout=TIMEOUT,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
        result["status_code"] = resp.status_code
        result["final_url"] = resp.url
        print(f"  Status: {resp.status_code} | URL: {resp.url}")

        # Server header
        server = resp.headers.get("Server") or resp.headers.get("X-Powered-By")
        if server:
            result["server"] = server
            result["findings"].append({
                "title": "Server Info Terekspose",
                "detail": f"Header menampilkan: {server}",
                "risk": "LOW",
            })
            print(f"  [LOW] Server/Framework terekspose: {server}")

        # Security headers
        missing = []
        for header in SECURITY_HEADERS:
            if header not in resp.headers:
                missing.append(header)

        result["missing_headers"] = missing
        if missing:
            result["findings"].append({
                "title": "Security Headers Tidak Lengkap",
                "detail": f"Header tidak ada: {', '.join(missing)}",
                "risk": "MEDIUM",
            })
            print(f"  [MEDIUM] Missing headers: {', '.join(missing)}")

        # Cookies
        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append("Secure flag tidak ada")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("HttpOnly flag tidak ada")
            if issues:
                result["cookies"].append({"name": cookie.name, "issues": issues})
                result["findings"].append({
                    "title": f"Cookie Lemah: {cookie.name}",
                    "detail": ", ".join(issues),
                    "risk": "LOW",
                })
                print(f"  [LOW] Cookie '{cookie.name}': {', '.join(issues)}")

        # HTTPS check
        if resp.url.startswith("http://"):
            result["findings"].append({
                "title": "Tidak Menggunakan HTTPS",
                "detail": "Koneksi tidak terenkripsi",
                "risk": "HIGH",
            })
            print(f"  [HIGH] Site tidak pakai HTTPS")

    except requests.exceptions.SSLError:
        result["findings"].append({
            "title": "SSL Error",
            "detail": "Sertifikat SSL bermasalah",
            "risk": "HIGH",
        })
        print(f"  [HIGH] SSL error")
    except requests.exceptions.ConnectionError:
        result["error"] = "Tidak bisa connect"
        print(f"  [!] Tidak bisa connect ke {target}")
    except Exception as e:
        result["error"] = str(e)
        print(f"  [!] Error: {e}")

    return result


# ─── Sensitive Path Checker ────────────────────────────────────────────────────

def check_sensitive_paths(target):
    print(f"\n[*] Checking sensitive paths on {target}...")

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    found = []
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    for path in SENSITIVE_PATHS:
        url = target.rstrip("/") + path
        try:
            resp = session.get(url, timeout=TIMEOUT, verify=False, allow_redirects=False)
            if resp.status_code in [200, 301, 302, 403]:
                risk = "HIGH" if resp.status_code == 200 else "MEDIUM"
                found.append({
                    "path": path,
                    "status": resp.status_code,
                    "risk": risk,
                    "url": url,
                })
                marker = "[HIGH]" if risk == "HIGH" else "[MEDIUM]"
                print(f"  {marker} {path} -> {resp.status_code}")
        except:
            continue

    print(f"  Ditemukan {len(found)} path sensitif")
    return {"found": found}


# ─── DNS Info ─────────────────────────────────────────────────────────────────

def get_dns_info(target):
    print(f"\n[*] Getting DNS info for {target}...")

    result = {
        "target": target,
        "ipv4": [],
        "ipv6": [],
        "hostname": None,
        "findings": [],
    }

    # IPv4
    try:
        addrs = socket.getaddrinfo(target, None, socket.AF_INET)
        result["ipv4"] = list(set([r[4][0] for r in addrs]))
        print(f"  IPv4: {result['ipv4']}")
    except:
        pass

    # IPv6
    try:
        addrs = socket.getaddrinfo(target, None, socket.AF_INET6)
        result["ipv6"] = list(set([r[4][0] for r in addrs]))
    except:
        pass

    # Reverse lookup
    if result["ipv4"]:
        try:
            hostname, _, _ = socket.gethostbyaddr(result["ipv4"][0])
            result["hostname"] = hostname
            print(f"  Hostname: {hostname}")
        except:
            pass

    # Try dnspython if available
    try:
        import dns.resolver
        subdomains_to_check = ["www", "mail", "api", "dev", "admin", "ftp", "smtp", "vpn"]
        found_subs = []
        for sub in subdomains_to_check:
            fqdn = f"{sub}.{target}"
            try:
                answers = dns.resolver.resolve(fqdn, "A", lifetime=2)
                ips = [str(r) for r in answers]
                found_subs.append({"subdomain": fqdn, "ips": ips})
                print(f"  Subdomain: {fqdn} -> {ips}")
            except:
                continue
        result["subdomains"] = found_subs
    except ImportError:
        pass

    return result


# ─── Report Generator ─────────────────────────────────────────────────────────

def save_report(target, results, output_dir="./output"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = target.replace(".", "_").replace("/", "_")

    # JSON report
    json_path = os.path.join(output_dir, f"scan_{safe_name}_{timestamp}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # HTML report
    html_path = os.path.join(output_dir, f"scan_{safe_name}_{timestamp}.html")
    html = build_html_report(target, results, timestamp)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n[+] Laporan disimpan:")
    print(f"    JSON : {json_path}")
    print(f"    HTML : {html_path}")
    return json_path, html_path


def build_html_report(target, results, timestamp):
    # Kumpulkan semua findings
    all_findings = []
    for section in ["port_scan", "http", "paths"]:
        data = results.get(section, {})
        for f in data.get("findings", []):
            all_findings.append(f)
        for f in data.get("found", []):
            all_findings.append({
                "title": f"Path Sensitif: {f['path']}",
                "detail": f"Status {f['status']} - {f['url']}",
                "risk": f["risk"],
            })

    risk_color = {"CRITICAL": "#dc3545", "HIGH": "#fd7e14", "MEDIUM": "#ffc107", "LOW": "#28a745", "INFO": "#17a2b8"}

    findings_html = ""
    for f in all_findings:
        color = risk_color.get(f.get("risk", "INFO"), "#17a2b8")
        findings_html += f"""
        <div style="border-left:4px solid {color}; padding:10px; margin:10px 0; background:#f9f9f9; border-radius:4px;">
            <strong>{f.get('title','')}</strong>
            <span style="background:{color}; color:white; font-size:11px; padding:2px 8px; border-radius:10px; float:right;">{f.get('risk','INFO')}</span>
            <div style="margin-top:5px; color:#555; font-size:13px;">{f.get('detail','')}</div>
        </div>"""

    open_ports = results.get("port_scan", {}).get("open_ports", [])
    port_names = [f"{p} ({PORT_NAMES.get(p,'?')})" for p in open_ports]
    ports_str = ", ".join(port_names) if port_names else "Tidak ada"

    total_findings = len(all_findings)
    high_count = sum(1 for f in all_findings if f.get("risk") in ["CRITICAL","HIGH"])
    med_count = sum(1 for f in all_findings if f.get("risk") == "MEDIUM")

    html = f"""<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Report - {target}</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; margin: 0; background: #f0f2f5; color: #333; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px 40px; }}
        .header h1 {{ margin: 0 0 5px 0; font-size: 24px; }}
        .header p {{ margin: 0; opacity: 0.7; font-size: 13px; }}
        .container {{ max-width: 900px; margin: 30px auto; padding: 0 20px; }}
        .card {{ background: white; border-radius: 8px; padding: 20px 25px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
        .card h2 {{ margin: 0 0 15px 0; font-size: 16px; color: #1a1a2e; border-bottom: 2px solid #f0f2f5; padding-bottom: 10px; }}
        .stats {{ display: flex; gap: 15px; margin-bottom: 20px; }}
        .stat {{ flex: 1; text-align: center; background: white; border-radius: 8px; padding: 15px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
        .stat .num {{ font-size: 28px; font-weight: bold; }}
        .stat .label {{ font-size: 12px; color: #777; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th {{ background: #f0f2f5; padding: 8px 12px; text-align: left; }}
        td {{ padding: 8px 12px; border-bottom: 1px solid #f0f2f5; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; color: white; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 RedSim Simple - Scan Report</h1>
        <p>Target: {target} &nbsp;|&nbsp; Waktu: {timestamp} &nbsp;|&nbsp; IP: {results.get('dns', {}).get('ipv4', ['?'])[0] if results.get('dns', {}).get('ipv4') else '?'}</p>
    </div>
    <div class="container">

        <div class="stats">
            <div class="stat">
                <div class="num" style="color:#1a1a2e">{total_findings}</div>
                <div class="label">Total Temuan</div>
            </div>
            <div class="stat">
                <div class="num" style="color:#fd7e14">{high_count}</div>
                <div class="label">High / Critical</div>
            </div>
            <div class="stat">
                <div class="num" style="color:#ffc107">{med_count}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat">
                <div class="num" style="color:#17a2b8">{len(open_ports)}</div>
                <div class="label">Port Terbuka</div>
            </div>
        </div>

        <div class="card">
            <h2>📋 Ringkasan Target</h2>
            <table>
                <tr><th>Target</th><td>{target}</td></tr>
                <tr><th>IP Address</th><td>{results.get('dns', {}).get('ipv4', ['N/A'])[0] if results.get('dns', {}).get('ipv4') else 'N/A'}</td></tr>
                <tr><th>HTTP Status</th><td>{results.get('http', {}).get('status_code', 'N/A')}</td></tr>
                <tr><th>Server</th><td>{results.get('http', {}).get('server', 'Tersembunyi / Tidak ada')}</td></tr>
                <tr><th>Port Terbuka</th><td>{ports_str}</td></tr>
            </table>
        </div>

        <div class="card">
            <h2>⚠️ Daftar Temuan</h2>
            {findings_html if findings_html else '<p style="color:#777; font-size:13px;">Tidak ada temuan signifikan.</p>'}
        </div>

        <div class="card">
            <h2>🔌 Detail Port Scan</h2>
            <table>
                <tr><th>Port</th><th>Service</th><th>Risiko</th><th>Catatan</th></tr>
                {"".join(f"<tr><td>{f['port']}</td><td>{f['service']}</td><td><span class='badge' style='background:{risk_color.get(f['risk'],'#17a2b8')}'>{f['risk']}</span></td><td style='font-size:12px'>{f['note']}</td></tr>" for f in results.get('port_scan', {}).get('findings', []))}
            </table>
        </div>

    </div>
</body>
</html>"""
    return html


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="RedSim Simple - Web Security Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target domain/IP (contoh: example.com)")
    parser.add_argument("-o", "--output", default="./output", help="Folder output laporan")
    parser.add_argument("--no-paths", action="store_true", help="Skip pengecekan sensitive paths")
    parser.add_argument("--json-only", action="store_true", help="Hanya buat laporan JSON")
    args = parser.parse_args()

    target = args.target.replace("http://", "").replace("https://", "").rstrip("/")

    print("=" * 55)
    print(f"  RedSim Simple - Security Scanner")
    print(f"  Target : {target}")
    print(f"  Mulai  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 55)

    results = {"target": target}

    # 1. DNS Info
    results["dns"] = get_dns_info(target)

    # 2. Port Scan
    results["port_scan"] = scan_ports(target)

    # 3. HTTP Analysis
    results["http"] = analyze_http(target)

    # 4. Sensitive Paths
    if not args.no_paths:
        results["paths"] = check_sensitive_paths(target)

    # 5. Save report
    save_report(target, results, args.output)

    print("\n[+] Scan selesai!")


if __name__ == "__main__":
    main()
