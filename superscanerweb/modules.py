import json
import re
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import parse_qs, urljoin, urlparse

import requests

try:
    import dns.resolver
except Exception:
    dns = None

from .core import ModuleResult, ScanContext, result
from .utils import extract_emails, has_command, merge_emails, run_command, truncate


@dataclass(frozen=True)
class Module:
    module_id: str
    name: str
    category: str
    description: str
    runner: callable
    requires_active: bool = False
    requires_kali: bool = False


SENSITIVE_PATHS = [
    ".env",
    ".git/config",
    ".svn/entries",
    "backup.zip",
    "backup.tar.gz",
    "db.sql",
    "database.sql",
    "dump.sql",
    "config.php.bak",
    "wp-config.php.bak",
    "phpinfo.php",
    "server-status",
    "debug",
    "admin",
    "administrator",
    "login",
    "api/docs",
    "swagger",
    "swagger.json",
    "openapi.json",
]


RISKY_LINK_PATTERNS = [
    r"/admin\b",
    r"/administrator\b",
    r"/wp-admin\b",
    r"/phpmyadmin\b",
    r"/debug\b",
    r"/backup",
    r"\.bak\b",
    r"\.old\b",
    r"\.sql\b",
    r"\.env\b",
    r"/swagger",
    r"/openapi",
    r"/api-docs",
    r"/private",
    r"/internal",
    r"/staging",
    r"/dev",
    r"/test",
]


SECRET_PATTERNS = {
    "AWS access key": r"\bAKIA[0-9A-Z]{16}\b",
    "Google API key": r"\bAIza[0-9A-Za-z\-_]{35}\b",
    "Slack token": r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
    "GitHub token": r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b",
    "Private key marker": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "JWT": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "Password assignment": r"(?i)\b(passwd|password|pwd|secret|token|api_key)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
}


def get_home(ctx: ScanContext):
    if "home" not in ctx.cache:
        ctx.cache["home"] = ctx.http.fetch(ctx.base_url)
    return ctx.cache["home"]


def dns_query(ctx: ScanContext, record_type: str, name: str | None = None) -> list[str]:
    query_name = name or ctx.host
    key = f"dns:{query_name}:{record_type}"
    if key in ctx.cache:
        return ctx.cache[key]
    values = []
    if dns is not None:
        try:
            answers = dns.resolver.resolve(query_name, record_type, lifetime=ctx.config.timeout)
            values = sorted({str(answer).strip() for answer in answers})
        except Exception:
            values = []
    if not values and has_command("dig"):
        cmd = run_command(["dig", "+short", query_name, record_type], timeout=ctx.config.timeout)
        values = sorted({line.strip() for line in cmd.get("stdout", "").splitlines() if line.strip()})
    if not values and record_type in {"A", "AAAA"}:
        family = socket.AF_INET6 if record_type == "AAAA" else socket.AF_INET
        try:
            values = sorted({item[4][0] for item in socket.getaddrinfo(query_name, None, family, socket.SOCK_STREAM)})
        except Exception:
            values = []
    ctx.cache[key] = values
    return values


def mod_official_email(ctx: ScanContext) -> ModuleResult:
    sources = []
    emails = []
    home = get_home(ctx)
    page_emails = extract_emails(home.text, ctx.registered_domain)
    if page_emails:
        sources.append({"source": ctx.base_url, "emails": page_emails})
        emails.extend(page_emails)

    for href in re.findall(r"""href=["'](mailto:[^"']+)["']""", home.text, flags=re.I):
        mail = href.split(":", 1)[-1].split("?", 1)[0]
        found = extract_emails(mail, ctx.registered_domain)
        if found:
            sources.append({"source": "mailto link", "emails": found})
            emails.extend(found)

    for path in ["/.well-known/security.txt", "/security.txt", "/contact", "/contact-us"]:
        fetched = ctx.http.fetch(urljoin(ctx.base_url, path))
        found = extract_emails(fetched.text, ctx.registered_domain)
        if found:
            sources.append({"source": path, "status": fetched.status_code, "emails": found})
            emails.extend(found)

    whois = run_command(["whois", ctx.registered_domain], timeout=ctx.config.timeout)
    found = extract_emails(whois.get("stdout", ""), ctx.registered_domain)
    if found:
        sources.append({"source": "whois", "emails": found})
        emails.extend(found)

    emails = ctx.with_emails(emails)
    severity = "info" if emails else "low"
    summary = f"Ditemukan {len(emails)} kandidat email resmi." if emails else "Belum menemukan email resmi dari sumber umum."
    recs = ["Pastikan security@ atau kontak keamanan resmi tersedia di security.txt dan halaman kontak."]
    return result(ctx, "official_email", "Official Email Discovery", "OSINT", severity, summary, emails, sources, recs)


def mod_security_txt(ctx: ScanContext) -> ModuleResult:
    evidence = []
    emails = []
    findings = []
    for path in ["/.well-known/security.txt", "/security.txt"]:
        fetched = ctx.http.fetch(urljoin(ctx.base_url, path))
        evidence.append({"url": fetched.url, "status": fetched.status_code, "sample": truncate(fetched.text, 1200)})
        found = extract_emails(fetched.text, ctx.registered_domain)
        emails.extend(found)
        if fetched.status_code == 200 and "Contact:" in fetched.text:
            findings.append(f"{path} tersedia dan berisi Contact.")
    ctx.with_emails(emails)
    severity = "info" if findings else "low"
    summary = "security.txt tersedia." if findings else "security.txt tidak ditemukan atau belum berisi Contact yang jelas."
    recs = ["Tambahkan /.well-known/security.txt berisi Contact, Policy, dan Preferred-Languages sesuai RFC 9116."]
    return result(ctx, "security_txt", "security.txt Contact", "OSINT", severity, summary, findings, evidence, recs)


def mod_dns_records(ctx: ScanContext) -> ModuleResult:
    record_types = ["A", "AAAA", "NS", "SOA", "TXT"]
    evidence = [{"type": rt, "values": dns_query(ctx, rt)} for rt in record_types]
    findings = [f"{item['type']}: {len(item['values'])} record" for item in evidence if item["values"]]
    return result(ctx, "dns_records", "DNS Record Inventory", "OSINT", "info", "Inventaris DNS dasar selesai.", findings, evidence)


def mod_mx_records(ctx: ScanContext) -> ModuleResult:
    records = dns_query(ctx, "MX", ctx.registered_domain)
    severity = "info" if records else "low"
    summary = "MX record ditemukan." if records else "MX record tidak ditemukan pada host target."
    recs = ["Validasi konfigurasi email domain dan pastikan jalur abuse/security mailbox aktif."]
    return result(ctx, "mx_records", "Mail Server MX Check", "OSINT", severity, summary, records, [{"mx": records}], recs)


def mod_spf_dmarc(ctx: ScanContext) -> ModuleResult:
    txt = dns_query(ctx, "TXT", ctx.registered_domain)
    spf = [item for item in txt if "v=spf1" in item.lower()]
    try:
        dmarc = dns_query(ctx, "TXT", "_dmarc." + ctx.registered_domain)
    except Exception:
        dmarc = []
    findings = []
    if not spf:
        findings.append("SPF belum terlihat.")
    if not dmarc:
        findings.append("DMARC belum terlihat.")
    severity = "medium" if findings else "info"
    recs = ["Aktifkan SPF dan DMARC untuk mengurangi spoofing email domain."]
    return result(ctx, "spf_dmarc", "SPF and DMARC Posture", "OSINT", severity, "Pemeriksaan SPF/DMARC selesai.", findings, [{"spf": spf, "dmarc": dmarc}], recs)


def mod_caa(ctx: ScanContext) -> ModuleResult:
    caa = dns_query(ctx, "CAA", ctx.registered_domain)
    severity = "info" if caa else "low"
    summary = "CAA record ditemukan." if caa else "CAA record belum ditemukan."
    recs = ["Pertimbangkan CAA record agar penerbitan sertifikat dibatasi ke CA yang dipercaya."]
    return result(ctx, "dns_caa", "Certificate Authority Authorization", "OSINT", severity, summary, caa, [{"caa": caa}], recs)


def mod_tls_certificate(ctx: ScanContext) -> ModuleResult:
    findings = []
    evidence = []
    if ctx.scheme != "https":
        return result(ctx, "tls_certificate", "TLS Certificate Review", "OSINT", "medium", "Target tidak memakai HTTPS pada URL input.", ["URL target bukan HTTPS."], recommendations=["Gunakan HTTPS sebagai default."])
    try:
        with socket.create_connection((ctx.host, 443), timeout=ctx.config.timeout) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=ctx.host) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter", "")
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if not_after else None
        if expires:
            days = (expires - datetime.now(timezone.utc)).days
            if days < 15:
                findings.append(f"Sertifikat akan kedaluwarsa dalam {days} hari.")
        evidence.append({"subject": cert.get("subject"), "issuer": cert.get("issuer"), "notAfter": not_after, "sans": cert.get("subjectAltName")})
    except Exception as exc:
        findings.append(f"Gagal membaca sertifikat TLS: {exc}")
    severity = "medium" if findings else "info"
    return result(ctx, "tls_certificate", "TLS Certificate Review", "OSINT", severity, "Pemeriksaan sertifikat TLS selesai.", findings, evidence, ["Pantau masa berlaku sertifikat dan SAN agar sesuai aset resmi."])


def mod_http_headers(ctx: ScanContext) -> ModuleResult:
    home = get_home(ctx)
    headers = {k.lower(): v for k, v in home.headers.items()}
    required = {
        "strict-transport-security": "HSTS belum terlihat.",
        "x-content-type-options": "X-Content-Type-Options belum terlihat.",
        "x-frame-options": "X-Frame-Options belum terlihat.",
        "referrer-policy": "Referrer-Policy belum terlihat.",
        "permissions-policy": "Permissions-Policy belum terlihat.",
    }
    findings = [message for key, message in required.items() if key not in headers]
    severity = "medium" if len(findings) >= 3 else "low" if findings else "info"
    recs = ["Tambahkan header keamanan standar melalui reverse proxy atau aplikasi."]
    return result(ctx, "http_headers", "HTTP Security Headers", "OSINT Risk Audit", severity, "Audit header keamanan HTTP selesai.", findings, [{"headers": dict(home.headers)}], recs)


def mod_cookies(ctx: ScanContext) -> ModuleResult:
    home = get_home(ctx)
    raw = home.headers.get("Set-Cookie", "")
    findings = []
    if raw:
        for cookie in raw.split(","):
            lower = cookie.lower()
            name = cookie.split("=", 1)[0].strip()
            if "secure" not in lower:
                findings.append(f"Cookie {name} belum terlihat memakai Secure.")
            if "httponly" not in lower:
                findings.append(f"Cookie {name} belum terlihat memakai HttpOnly.")
            if "samesite" not in lower:
                findings.append(f"Cookie {name} belum terlihat memakai SameSite.")
    severity = "medium" if findings else "info"
    return result(ctx, "cookie_flags", "Cookie Security Flags", "OSINT Risk Audit", severity, "Audit atribut cookie selesai.", findings, [{"set_cookie": raw}], ["Gunakan Secure, HttpOnly, dan SameSite pada cookie sensitif."])


def mod_cors(ctx: ScanContext) -> ModuleResult:
    home = get_home(ctx)
    acao = home.headers.get("Access-Control-Allow-Origin", "")
    accred = home.headers.get("Access-Control-Allow-Credentials", "")
    findings = []
    if acao == "*":
        findings.append("Access-Control-Allow-Origin memakai wildcard.")
    if acao == "*" and accred.lower() == "true":
        findings.append("Kombinasi wildcard origin dan credentials berisiko.")
    severity = "high" if len(findings) > 1 else "medium" if findings else "info"
    return result(ctx, "cors_policy", "CORS Policy Review", "OSINT Risk Audit", severity, "Pemeriksaan CORS selesai.", findings, [{"acao": acao, "credentials": accred}], ["Batasi CORS hanya ke origin resmi."])


def mod_csp(ctx: ScanContext) -> ModuleResult:
    csp = get_home(ctx).headers.get("Content-Security-Policy", "")
    findings = []
    if not csp:
        findings.append("Content-Security-Policy belum terlihat.")
    if "'unsafe-inline'" in csp or "unsafe-eval" in csp:
        findings.append("CSP mengizinkan unsafe-inline atau unsafe-eval.")
    severity = "medium" if findings else "info"
    return result(ctx, "content_security_policy", "Content Security Policy", "OSINT Risk Audit", severity, "Pemeriksaan CSP selesai.", findings, [{"csp": csp}], ["Terapkan CSP bertahap untuk mengurangi dampak XSS."])


def mod_robots(ctx: ScanContext) -> ModuleResult:
    fetched = ctx.http.fetch(urljoin(ctx.base_url, "/robots.txt"))
    findings = []
    exposed = []
    if fetched.status_code == 200:
        for line in fetched.text.splitlines():
            if line.lower().startswith(("disallow:", "allow:")):
                path = line.split(":", 1)[1].strip()
                if any(re.search(pattern, path, re.I) for pattern in RISKY_LINK_PATTERNS):
                    exposed.append(path)
        if exposed:
            findings.append(f"robots.txt menyebut {len(exposed)} path sensitif/administratif.")
    severity = "medium" if exposed else "info"
    return result(ctx, "robots_txt", "robots.txt Exposure Review", "OSINT", severity, "Pemeriksaan robots.txt selesai.", findings, [{"status": fetched.status_code, "exposed_paths": exposed, "sample": truncate(fetched.text, 1500)}], ["Jangan jadikan robots.txt sebagai tempat menyembunyikan path sensitif."])


def mod_sitemap(ctx: ScanContext) -> ModuleResult:
    fetched = ctx.http.fetch(urljoin(ctx.base_url, "/sitemap.xml"))
    urls = re.findall(r"<loc>\s*([^<]+)\s*</loc>", fetched.text, flags=re.I)
    risky = [url for url in urls if any(re.search(pattern, url, re.I) for pattern in RISKY_LINK_PATTERNS)]
    severity = "medium" if risky else "info"
    findings = [f"Sitemap memuat {len(risky)} URL yang terlihat sensitif."] if risky else []
    return result(ctx, "sitemap_links", "Sitemap URL Exposure", "OSINT", severity, "Analisis sitemap selesai.", findings, [{"status": fetched.status_code, "url_count": len(urls), "risky": risky[:50]}], ["Pisahkan URL privat/admin dari sitemap publik."])


def collect_links(ctx: ScanContext) -> list[str]:
    if "links" in ctx.cache:
        return ctx.cache["links"]
    links = set()
    for value in re.findall(r"""(?:href|src|action)=["']([^"']+)["']""", get_home(ctx).text, flags=re.I):
        if not value:
            continue
        absolute = urljoin(ctx.base_url, value)
        if urlparse(absolute).netloc.endswith(ctx.host) or urlparse(absolute).netloc.endswith(ctx.registered_domain):
            links.add(absolute)
    ctx.cache["links"] = sorted(links)
    return ctx.cache["links"]


def mod_html_links(ctx: ScanContext) -> ModuleResult:
    links = collect_links(ctx)
    findings = [f"Ditemukan {len(links)} link internal/terkait pada halaman awal."]
    return result(ctx, "html_link_inventory", "HTML Link Inventory", "OSINT", "info", "Inventaris link halaman awal selesai.", findings, [{"links": links[:200]}])


def mod_exposed_links(ctx: ScanContext) -> ModuleResult:
    links = collect_links(ctx)
    risky = [link for link in links if any(re.search(pattern, link, re.I) for pattern in RISKY_LINK_PATTERNS)]
    severity = "medium" if risky else "info"
    findings = [f"Ditemukan {len(risky)} link yang tampak sensitif/administratif."] if risky else []
    recs = ["Review link admin, backup, debug, staging, dan dokumentasi API sebelum terindeks publik."]
    return result(ctx, "exposed_links", "Unexpected Public Link Finder", "OSINT", severity, "Pencarian link terekspos selesai.", findings, [{"risky_links": risky[:100]}], recs)


def mod_js_endpoints(ctx: ScanContext) -> ModuleResult:
    links = collect_links(ctx)
    js_links = [link for link in links if urlparse(link).path.endswith(".js")][: ctx.config.max_js]
    endpoints = set()
    evidence = []
    for js in js_links:
        fetched = ctx.http.fetch(js)
        matches = re.findall(r"['\"]((?:/|https?://)[A-Za-z0-9_./?&=%:-]{4,})['\"]", fetched.text)
        normalized = sorted({urljoin(ctx.base_url, match) for match in matches if not match.startswith("//")})
        endpoints.update(normalized)
        evidence.append({"js": js, "status": fetched.status_code, "endpoints": normalized[:40]})
    risky = [item for item in sorted(endpoints) if any(re.search(pattern, item, re.I) for pattern in RISKY_LINK_PATTERNS)]
    severity = "medium" if risky else "info"
    findings = [f"Endpoint JS berisiko: {len(risky)}"] if risky else [f"Endpoint dari JS: {len(endpoints)}"]
    return result(ctx, "javascript_endpoints", "JavaScript Endpoint Miner", "OSINT", severity, "Ekstraksi endpoint JavaScript selesai.", findings, evidence, ["Audit endpoint yang hanya muncul di JavaScript, terutama admin/internal/api docs."])


def mod_secret_patterns(ctx: ScanContext) -> ModuleResult:
    texts = [{"source": ctx.base_url, "text": get_home(ctx).text}]
    for link in [link for link in collect_links(ctx) if urlparse(link).path.endswith(".js")][: ctx.config.max_js]:
        texts.append({"source": link, "text": ctx.http.fetch(link).text})
    hits = []
    for item in texts:
        for label, pattern in SECRET_PATTERNS.items():
            for match in re.findall(pattern, item["text"]):
                hits.append({"source": item["source"], "type": label, "match": truncate(match, 120)})
    severity = "high" if hits else "info"
    findings = [f"Kandidat secret/token ditemukan: {len(hits)}"] if hits else []
    return result(ctx, "secret_patterns", "Public Secret Pattern Scanner", "OSINT Risk Audit", severity, "Pemindaian pola secret publik selesai.", findings, hits[:80], ["Cabut dan rotasi credential yang tidak sengaja muncul di HTML/JS publik."])


def mod_sensitive_paths(ctx: ScanContext) -> ModuleResult:
    evidence = []
    exposed = []
    for path in SENSITIVE_PATHS:
        url = urljoin(ctx.base_url + "/", path)
        fetched = ctx.http.fetch(url)
        if fetched.status_code in {200, 206, 401, 403}:
            item = {"url": url, "status": fetched.status_code, "sample": truncate(fetched.text, 500)}
            evidence.append(item)
            if fetched.status_code == 200:
                exposed.append(url)
    severity = "high" if exposed else "low" if evidence else "info"
    findings = [f"Path sensitif merespons 200: {len(exposed)}"] if exposed else []
    return result(ctx, "sensitive_paths", "Sensitive Path Exposure Check", "OSINT Risk Audit", severity, "Pemeriksaan path sensitif umum selesai.", findings, evidence, ["Hapus backup/config/debug dari web root dan batasi akses path administratif."])


def mod_directory_listing(ctx: ScanContext) -> ModuleResult:
    dirs = ["uploads/", "backup/", "backups/", "files/", "static/", "assets/", "logs/"]
    listings = []
    for path in dirs:
        fetched = ctx.http.fetch(urljoin(ctx.base_url + "/", path))
        if fetched.status_code == 200 and re.search(r"Index of /|Directory listing for", fetched.text, re.I):
            listings.append({"url": fetched.url, "status": fetched.status_code})
    severity = "high" if listings else "info"
    findings = [f"Directory listing terbuka: {len(listings)}"] if listings else []
    return result(ctx, "directory_listing", "Directory Listing Detector", "OSINT Risk Audit", severity, "Deteksi directory listing selesai.", findings, listings, ["Matikan autoindex/directory listing pada web server."])


def mod_technology(ctx: ScanContext) -> ModuleResult:
    home = get_home(ctx)
    tech = set()
    server = home.headers.get("Server")
    powered = home.headers.get("X-Powered-By")
    if server:
        tech.add("Server: " + server)
    if powered:
        tech.add("X-Powered-By: " + powered)
    for content in re.findall(r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']""", home.text, flags=re.I):
        tech.add("Generator: " + content)
    text = home.text.lower()
    for name, marker in {"WordPress": "wp-content", "Laravel": "laravel", "Drupal": "drupal", "Joomla": "joomla", "Next.js": "__next", "React": "react"}.items():
        if marker.lower() in text:
            tech.add(name)
    findings = sorted(tech)
    severity = "low" if any("X-Powered-By" in item or "Server:" in item for item in findings) else "info"
    return result(ctx, "technology_fingerprint", "Technology Fingerprint", "OSINT", severity, "Fingerprint teknologi selesai.", findings, [{"technologies": findings}], ["Kurangi banner/version disclosure jika tidak dibutuhkan."])


def mod_cms(ctx: ScanContext) -> ModuleResult:
    probes = {
        "WordPress login": "/wp-login.php",
        "WordPress admin": "/wp-admin/",
        "Joomla admin": "/administrator/",
        "Drupal user": "/user/login",
    }
    evidence = []
    findings = []
    for label, path in probes.items():
        fetched = ctx.http.fetch(urljoin(ctx.base_url, path))
        if fetched.status_code in {200, 301, 302, 401, 403}:
            evidence.append({"name": label, "url": fetched.url, "status": fetched.status_code})
            findings.append(f"{label} merespons status {fetched.status_code}.")
    severity = "low" if findings else "info"
    return result(ctx, "cms_admin_surface", "CMS Admin Surface Finder", "OSINT", severity, "Pemeriksaan permukaan CMS selesai.", findings, evidence, ["Batasi akses panel admin dengan kontrol akses tambahan bila memungkinkan."])


def mod_url_parameters(ctx: ScanContext) -> ModuleResult:
    links = collect_links(ctx)
    risky_names = re.compile(r"(?i)^(url|next|redirect|return|continue|dest|destination|file|path|debug|token|key|id)$")
    hits = []
    for link in links:
        parsed = urlparse(link)
        for name in parse_qs(parsed.query):
            if risky_names.search(name):
                hits.append({"url": link, "parameter": name})
    severity = "medium" if hits else "info"
    findings = [f"Parameter berisiko perlu review manual: {len(hits)}"] if hits else []
    return result(ctx, "url_parameters", "URL Parameter Risk Mapper", "OSINT", severity, "Analisis parameter URL selesai.", findings, hits[:100], ["Validasi redirect, file/path, debug, token, dan id parameter di sisi server."])


def mod_subdomain_ct(ctx: ScanContext) -> ModuleResult:
    if "ct_subdomains_result" in ctx.cache:
        cached = ctx.cache["ct_subdomains_result"]
        return result(ctx, "ct_subdomains", "Certificate Transparency Subdomains", "OSINT", cached["severity"], cached["summary"], cached["findings"], cached["evidence"], cached["recommendations"])
    url = f"https://crt.sh/?q=%25.{ctx.registered_domain}&output=json"
    try:
        response = requests.get(url, timeout=ctx.config.timeout, headers={"User-Agent": ctx.user_agent})
        data = response.json() if response.ok else []
        names = sorted({name.strip().lower() for item in data for name in item.get("name_value", "").splitlines() if name.strip()})
    except Exception as exc:
        names = []
        data = [{"error": str(exc)}]
    risky = [name for name in names if re.search(r"(?i)\b(dev|test|stage|staging|admin|internal|vpn|jira|git|old)\b", name)]
    severity = "medium" if risky else "info"
    findings = [f"Subdomain kandidat sensitif dari CT log: {len(risky)}"] if risky else [f"Subdomain dari CT log: {len(names)}"]
    payload = {
        "severity": severity,
        "summary": "Enumerasi subdomain CT log selesai.",
        "findings": findings,
        "evidence": [{"count": len(names), "risky": risky[:100], "sample": names[:100]}],
        "recommendations": ["Review subdomain dev/staging/internal yang muncul di sertifikat publik."],
    }
    ctx.cache["ct_subdomains_result"] = payload
    return result(ctx, "ct_subdomains", "Certificate Transparency Subdomains", "OSINT", payload["severity"], payload["summary"], payload["findings"], payload["evidence"], payload["recommendations"])


def mod_wayback(ctx: ScanContext) -> ModuleResult:
    api = f"https://web.archive.org/cdx?url={ctx.registered_domain}/*&output=json&fl=original&collapse=urlkey&limit=200"
    try:
        response = requests.get(api, timeout=ctx.config.timeout, headers={"User-Agent": ctx.user_agent})
        rows = response.json() if response.ok else []
        urls = sorted({row[0] for row in rows[1:] if row})
    except Exception as exc:
        urls = []
        rows = [["error", str(exc)]]
    risky = [url for url in urls if any(re.search(pattern, url, re.I) for pattern in RISKY_LINK_PATTERNS)]
    severity = "medium" if risky else "info"
    findings = [f"URL arsip yang terlihat sensitif: {len(risky)}"] if risky else [f"URL arsip ditemukan: {len(urls)}"]
    return result(ctx, "wayback_urls", "Wayback Public URL Review", "OSINT", severity, "Analisis URL dari arsip publik selesai.", findings, [{"risky": risky[:100], "sample": urls[:100]}], ["Review URL lama yang masih aktif atau membocorkan struktur internal."])


def mod_takeover(ctx: ScanContext) -> ModuleResult:
    subdomains = []
    ct_result = mod_subdomain_ct(ctx)
    for item in ct_result.evidence:
        subdomains.extend(item.get("sample", []))
        subdomains.extend(item.get("risky", []))
    signatures = ["github.io", "herokuapp.com", "azurewebsites.net", "cloudfront.net", "pages.dev", "netlify.app", "vercel.app"]
    hits = []
    for host in sorted(set(subdomains))[:80]:
        try:
            cnames = [answer.rstrip(".") for answer in dns_query(ctx, "CNAME", host)]
            if any(sig in cname for cname in cnames for sig in signatures):
                hits.append({"host": host, "cname": cnames})
        except Exception:
            continue
    severity = "medium" if hits else "info"
    findings = [f"Kandidat takeover CNAME perlu validasi manual: {len(hits)}"] if hits else []
    return result(ctx, "takeover_cname", "Subdomain Takeover CNAME Hints", "OSINT", severity, "Analisis CNAME takeover hint selesai.", findings, hits, ["Validasi ownership layanan pihak ketiga dan hapus CNAME yatim."])


def mod_whois_kali(ctx: ScanContext) -> ModuleResult:
    cmd = run_command(["whois", ctx.registered_domain], timeout=ctx.config.timeout)
    emails = extract_emails(cmd.get("stdout", ""), ctx.registered_domain)
    ctx.with_emails(emails)
    severity = "info" if cmd["available"] else "low"
    summary = "whois dijalankan." if cmd["available"] else "whois tidak tersedia."
    return result(ctx, "kali_whois", "Kali whois OSINT", "Kali Tool", severity, summary, emails, [cmd], ["Install paket whois jika belum tersedia: sudo apt install whois"])


def mod_whatweb(ctx: ScanContext) -> ModuleResult:
    cmd = run_command(["whatweb", "--color=never", "-a", "3", ctx.base_url], timeout=max(30, ctx.config.timeout * 3))
    severity = "info" if cmd["available"] else "low"
    return result(ctx, "kali_whatweb", "Kali WhatWeb Fingerprint", "Kali Tool", severity, "Integrasi whatweb selesai." if cmd["available"] else "whatweb tidak tersedia.", [], [cmd], ["Install whatweb di Kali jika belum ada: sudo apt install whatweb"])


def mod_wafw00f(ctx: ScanContext) -> ModuleResult:
    cmd = run_command(["wafw00f", ctx.base_url], timeout=max(30, ctx.config.timeout * 3))
    severity = "info" if cmd["available"] else "low"
    return result(ctx, "kali_wafw00f", "Kali WAFW00F WAF Detection", "Kali Tool", severity, "Integrasi wafw00f selesai." if cmd["available"] else "wafw00f tidak tersedia.", [], [cmd], ["Install wafw00f jika belum ada: sudo apt install wafw00f"])


def mod_nikto(ctx: ScanContext) -> ModuleResult:
    cmd = run_command(["nikto", "-h", ctx.base_url, "-nointeractive", "-ask", "no"], timeout=max(90, ctx.config.timeout * 8))
    findings = []
    if cmd["available"] and cmd["stdout"]:
        findings = [line for line in cmd["stdout"].splitlines() if line.strip().startswith("+")][:80]
    severity = "medium" if findings else "info" if cmd["available"] else "low"
    return result(ctx, "kali_nikto", "Kali Nikto Web Server Audit", "Kali Active Tool", severity, "Nikto selesai." if cmd["available"] else "nikto tidak tersedia.", findings, [cmd], ["Jalankan hanya pada aset berizin; review output Nikto secara manual sebelum tindakan."])


def mod_nmap(ctx: ScanContext) -> ModuleResult:
    scripts = "http-title,http-headers,http-server-header,ssl-cert"
    cmd = run_command(["nmap", "-Pn", "-T2", "--top-ports", "30", "--script", scripts, ctx.host], timeout=max(120, ctx.config.timeout * 10))
    severity = "info" if cmd["available"] else "low"
    return result(ctx, "kali_nmap_http", "Kali Nmap HTTP Surface", "Kali Active Tool", severity, "Nmap selesai." if cmd["available"] else "nmap tidak tersedia.", [], [cmd], ["Gunakan hasil port terbuka untuk hardening layanan yang memang publik."])


def mod_sslscan(ctx: ScanContext) -> ModuleResult:
    cmd = run_command(["sslscan", "--no-failed", ctx.host], timeout=max(90, ctx.config.timeout * 8))
    findings = []
    if cmd["available"]:
        for line in cmd["stdout"].splitlines():
            if any(word in line.lower() for word in ["ssl 2", "ssl 3", "tlsv1.0", "tlsv1.1", "weak", "expired"]):
                findings.append(line.strip())
    severity = "medium" if findings else "info" if cmd["available"] else "low"
    return result(ctx, "kali_sslscan", "Kali SSLScan TLS Audit", "Kali Active Tool", severity, "SSLScan selesai." if cmd["available"] else "sslscan tidak tersedia.", findings, [cmd], ["Nonaktifkan protokol/cipher lama dan monitor expiry sertifikat."])


def skip_result(ctx: ScanContext, module: Module, reason: str) -> ModuleResult:
    return result(ctx, module.module_id, module.name, module.category, "info", reason, skipped=True)


MODULES = [
    Module("official_email", "Official Email Discovery", "OSINT", "Mencari email resmi dari halaman, security.txt, kontak, dan whois.", mod_official_email),
    Module("security_txt", "security.txt Contact", "OSINT", "Memeriksa kontak keamanan RFC 9116.", mod_security_txt),
    Module("dns_records", "DNS Record Inventory", "OSINT", "Inventaris A/AAAA/NS/SOA/TXT.", mod_dns_records),
    Module("mx_records", "Mail Server MX Check", "OSINT", "Memeriksa MX domain.", mod_mx_records),
    Module("spf_dmarc", "SPF and DMARC Posture", "OSINT", "Memeriksa posture anti-spoofing email.", mod_spf_dmarc),
    Module("dns_caa", "Certificate Authority Authorization", "OSINT", "Memeriksa CAA record.", mod_caa),
    Module("tls_certificate", "TLS Certificate Review", "OSINT", "Membaca metadata sertifikat TLS.", mod_tls_certificate),
    Module("http_headers", "HTTP Security Headers", "OSINT Risk Audit", "Audit header keamanan umum.", mod_http_headers),
    Module("cookie_flags", "Cookie Security Flags", "OSINT Risk Audit", "Audit Secure/HttpOnly/SameSite.", mod_cookies),
    Module("cors_policy", "CORS Policy Review", "OSINT Risk Audit", "Mengecek CORS wildcard/credentials.", mod_cors),
    Module("content_security_policy", "Content Security Policy", "OSINT Risk Audit", "Memeriksa CSP dan directive berisiko.", mod_csp),
    Module("robots_txt", "robots.txt Exposure Review", "OSINT", "Mencari path sensitif di robots.txt.", mod_robots),
    Module("sitemap_links", "Sitemap URL Exposure", "OSINT", "Mencari URL sensitif di sitemap.", mod_sitemap),
    Module("html_link_inventory", "HTML Link Inventory", "OSINT", "Inventaris link halaman awal.", mod_html_links),
    Module("exposed_links", "Unexpected Public Link Finder", "OSINT", "Mencari link publik yang mencurigakan.", mod_exposed_links),
    Module("javascript_endpoints", "JavaScript Endpoint Miner", "OSINT", "Ekstraksi endpoint dari file JS publik.", mod_js_endpoints),
    Module("secret_patterns", "Public Secret Pattern Scanner", "OSINT Risk Audit", "Mencari pola token/secret di HTML dan JS publik.", mod_secret_patterns),
    Module("sensitive_paths", "Sensitive Path Exposure Check", "OSINT Risk Audit", "Probe ringan path sensitif umum.", mod_sensitive_paths),
    Module("directory_listing", "Directory Listing Detector", "OSINT Risk Audit", "Mendeteksi directory listing terbuka.", mod_directory_listing),
    Module("technology_fingerprint", "Technology Fingerprint", "OSINT", "Fingerprint teknologi dari header/HTML.", mod_technology),
    Module("cms_admin_surface", "CMS Admin Surface Finder", "OSINT", "Mendeteksi permukaan admin CMS umum.", mod_cms),
    Module("url_parameters", "URL Parameter Risk Mapper", "OSINT", "Memetakan parameter URL yang perlu review.", mod_url_parameters),
    Module("ct_subdomains", "Certificate Transparency Subdomains", "OSINT", "OSINT subdomain dari crt.sh.", mod_subdomain_ct),
    Module("wayback_urls", "Wayback Public URL Review", "OSINT", "OSINT URL publik dari Wayback.", mod_wayback),
    Module("takeover_cname", "Subdomain Takeover CNAME Hints", "OSINT", "Mencari hint CNAME pihak ketiga.", mod_takeover),
    Module("kali_whois", "Kali whois OSINT", "Kali Tool", "Integrasi whois bawaan Kali.", mod_whois_kali, requires_kali=True),
    Module("kali_whatweb", "Kali WhatWeb Fingerprint", "Kali Tool", "Integrasi whatweb.", mod_whatweb, requires_kali=True),
    Module("kali_wafw00f", "Kali WAFW00F WAF Detection", "Kali Tool", "Integrasi wafw00f.", mod_wafw00f, requires_kali=True),
    Module("kali_nikto", "Kali Nikto Web Server Audit", "Kali Active Tool", "Audit aktif dengan Nikto.", mod_nikto, requires_active=True, requires_kali=True),
    Module("kali_nmap_http", "Kali Nmap HTTP Surface", "Kali Active Tool", "Audit permukaan HTTP dengan Nmap.", mod_nmap, requires_active=True, requires_kali=True),
    Module("kali_sslscan", "Kali SSLScan TLS Audit", "Kali Active Tool", "Audit TLS dengan sslscan.", mod_sslscan, requires_active=True, requires_kali=True),
]


def get_modules() -> list[Module]:
    return MODULES


def run_modules(ctx: ScanContext) -> list[ModuleResult]:
    selected = set(ctx.config.selected_modules)
    results = []
    if selected and "official_email" not in selected:
        try:
            mod_official_email(ctx)
        except Exception:
            pass
    for module in MODULES:
        if selected and module.module_id not in selected:
            continue
        if module.requires_kali and not ctx.config.use_kali:
            results.append(skip_result(ctx, module, "Lewati: aktifkan --use-kali untuk menjalankan integrasi tool Kali."))
            continue
        if module.requires_active and not ctx.config.active:
            results.append(skip_result(ctx, module, "Lewati: aktifkan --active hanya untuk aset yang berizin."))
            continue
        if module.requires_kali and module.module_id.startswith("kali_"):
            tool_name = {
                "kali_whois": "whois",
                "kali_whatweb": "whatweb",
                "kali_wafw00f": "wafw00f",
                "kali_nikto": "nikto",
                "kali_nmap_http": "nmap",
                "kali_sslscan": "sslscan",
            }.get(module.module_id)
            if tool_name and not has_command(tool_name):
                results.append(module.runner(ctx))
                continue
        try:
            module_result = module.runner(ctx)
            if not module_result.official_emails:
                module_result.official_emails = ctx.official_emails.copy()
            results.append(module_result)
        except Exception as exc:
            results.append(result(ctx, module.module_id, module.name, module.category, "low", f"Modul gagal: {exc}", evidence=[{"error": repr(exc)}]))
    return results
