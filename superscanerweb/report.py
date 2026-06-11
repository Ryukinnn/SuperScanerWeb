import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

from . import __app_name__, __developer__, __version__
from .core import ScanContext
from .modules import get_modules
from .utils import markdown_escape, now_stamp, severity_rank, write_json


RISK_URL_PATTERNS = [
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


MODULE_GUIDE = {
    "official_email": {
        "function": "Mengumpulkan email resmi dari halaman publik, mailto, security.txt, contact page, dan whois.",
        "use": "Memastikan ada jalur kontak resmi untuk laporan kerentanan dan incident response.",
        "output": "Daftar email kandidat yang relevan dengan domain target.",
    },
    "security_txt": {
        "function": "Memeriksa /.well-known/security.txt dan /security.txt.",
        "use": "Menilai kesiapan disclosure keamanan sesuai RFC 9116.",
        "output": "Status security.txt, contact field, dan email keamanan.",
    },
    "dns_records": {
        "function": "Menginventaris A, AAAA, NS, SOA, dan TXT.",
        "use": "Memetakan permukaan DNS dasar yang bisa memengaruhi eksposur aset.",
        "output": "Record DNS utama dan jumlah record yang ditemukan.",
    },
    "mx_records": {
        "function": "Memeriksa MX record domain.",
        "use": "Melihat konfigurasi jalur email resmi dan potensi risiko salah konfigurasi mail routing.",
        "output": "Daftar mail exchanger domain.",
    },
    "spf_dmarc": {
        "function": "Memeriksa SPF dan DMARC.",
        "use": "Mengukur risiko spoofing email yang memakai domain target.",
        "output": "Status SPF, DMARC, dan rekomendasi hardening email.",
    },
    "dns_caa": {
        "function": "Memeriksa CAA record.",
        "use": "Menilai apakah penerbitan sertifikat sudah dibatasi ke CA yang dipercaya.",
        "output": "CAA record atau catatan jika belum tersedia.",
    },
    "tls_certificate": {
        "function": "Membaca subject, issuer, SAN, dan masa berlaku sertifikat TLS.",
        "use": "Mendeteksi sertifikat hampir kedaluwarsa atau tidak sesuai aset resmi.",
        "output": "Metadata sertifikat dan peringatan expiry.",
    },
    "http_headers": {
        "function": "Mengaudit header keamanan HTTP penting.",
        "use": "Menilai risiko clickjacking, MIME sniffing, downgrade, dan kebocoran referrer.",
        "output": "Header yang hilang atau perlu diperbaiki.",
    },
    "cookie_flags": {
        "function": "Memeriksa Secure, HttpOnly, dan SameSite pada Set-Cookie.",
        "use": "Mengurangi risiko pencurian cookie, CSRF, dan transport cookie lewat koneksi tidak aman.",
        "output": "Cookie yang belum memakai flag keamanan penting.",
    },
    "cors_policy": {
        "function": "Mengecek Access-Control-Allow-Origin dan credentials.",
        "use": "Mendeteksi CORS terlalu longgar yang bisa mengekspos data aplikasi.",
        "output": "Origin wildcard atau kombinasi CORS berisiko.",
    },
    "content_security_policy": {
        "function": "Memeriksa Content-Security-Policy.",
        "use": "Menilai perlindungan browser terhadap XSS dan injeksi script.",
        "output": "Status CSP dan directive berisiko seperti unsafe-inline.",
    },
    "robots_txt": {
        "function": "Menganalisis robots.txt untuk path sensitif.",
        "use": "Mencari petunjuk URL admin, backup, staging, atau area internal yang terekspos.",
        "output": "Daftar path sensitif dari robots.txt.",
    },
    "sitemap_links": {
        "function": "Membaca sitemap.xml dan mencari URL sensitif.",
        "use": "Mendeteksi URL private/admin/debug yang tidak seharusnya masuk sitemap publik.",
        "output": "URL sitemap yang cocok dengan pola risiko.",
    },
    "html_link_inventory": {
        "function": "Mengumpulkan link internal dari HTML halaman awal.",
        "use": "Membuat inventaris cepat permukaan link publik website.",
        "output": "Daftar link internal dan aset terkait.",
    },
    "exposed_links": {
        "function": "Memfilter link publik yang terlihat sensitif.",
        "use": "Menemukan admin panel, backup, API docs, staging, atau path debug dari halaman publik.",
        "output": "URL/link berisiko yang perlu review manual.",
    },
    "javascript_endpoints": {
        "function": "Mengekstrak endpoint dari file JavaScript publik.",
        "use": "Menemukan endpoint API, admin, internal, atau debug yang tidak tampak langsung di HTML.",
        "output": "Endpoint JS dan endpoint yang masuk kategori risiko.",
    },
    "secret_patterns": {
        "function": "Mencari pola token, key, JWT, private key marker, dan assignment secret.",
        "use": "Mendeteksi kredensial atau token yang tidak sengaja dipublikasikan.",
        "output": "Sumber file/URL dan tipe pola secret yang ditemukan.",
    },
    "sensitive_paths": {
        "function": "Melakukan probe ringan ke path sensitif umum seperti .env, backup, debug, dan API docs.",
        "use": "Mendeteksi file atau endpoint sensitif yang merespons dari web root.",
        "output": "URL, status HTTP, dan sample respons terbatas.",
    },
    "directory_listing": {
        "function": "Mendeteksi directory listing terbuka.",
        "use": "Menemukan folder publik yang membocorkan daftar file.",
        "output": "URL direktori yang menampilkan index/listing.",
    },
    "technology_fingerprint": {
        "function": "Fingerprint teknologi dari header dan HTML.",
        "use": "Mengidentifikasi framework/CMS/server untuk prioritas hardening.",
        "output": "Server, X-Powered-By, generator, dan marker teknologi.",
    },
}


def write_reports(ctx: ScanContext, results: list) -> tuple[Path, Path, dict]:
    stamp = now_stamp()
    safe_host = ctx.host.replace(":", "_")
    json_path = ctx.config.out_dir / f"{safe_host}-{stamp}.json"
    md_path = ctx.config.out_dir / f"{safe_host}-{stamp}.md"
    payload = build_payload(ctx, results)
    write_json(json_path, payload)
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    return json_path, md_path, payload


def build_payload(ctx: ScanContext, results: list) -> dict:
    result_dicts = [item.to_dict() for item in results]
    base_payload = {
        "tool": __app_name__,
        "version": __version__,
        "developer": __developer__,
        "target": ctx.target_url,
        "host": ctx.host,
        "registered_domain": ctx.registered_domain,
        "official_emails": ctx.official_emails,
        "active_modules_enabled": ctx.config.active,
        "kali_tools_enabled": ctx.config.use_kali,
        "module_catalog_20": build_module_catalog(limit=20),
        "results": result_dicts,
    }
    risky_urls = collect_risky_urls(base_payload)
    base_payload["risky_urls"] = risky_urls
    base_payload["security_summary"] = build_security_summary(base_payload, risky_urls)
    return base_payload


def build_module_catalog(limit: int = 20) -> list[dict]:
    catalog = []
    for idx, module in enumerate(get_modules()[:limit], start=1):
        guide = MODULE_GUIDE.get(module.module_id, {})
        catalog.append(
            {
                "number": idx,
                "module_id": module.module_id,
                "module_name": module.name,
                "category": module.category,
                "function": guide.get("function", module.description),
                "use": guide.get("use", "Mendukung audit keamanan website dari data publik dan respons non-destruktif."),
                "output": guide.get("output", "Temuan, evidence, rekomendasi, dan email resmi kandidat."),
            }
        )
    return catalog


def build_security_summary(payload: dict, risky_urls: list[dict]) -> dict:
    results = payload["results"]
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in results:
        severity_counts[item.get("severity", "info")] = severity_counts.get(item.get("severity", "info"), 0) + 1
    actionable = [item for item in results if item.get("findings") and item.get("severity") in {"critical", "high", "medium", "low"}]
    highest = "info"
    for severity in ["critical", "high", "medium", "low", "info"]:
        if severity_counts.get(severity):
            highest = severity
            break
    return {
        "highest_severity": highest,
        "severity_counts": severity_counts,
        "modules_executed": len(results),
        "modules_with_findings": len([item for item in results if item.get("findings")]),
        "actionable_modules": len(actionable),
        "skipped_modules": len([item for item in results if item.get("skipped")]),
        "risky_url_count": len(risky_urls),
        "official_email_count": len(payload.get("official_emails", [])),
    }


def collect_risky_urls(payload: dict) -> list[dict]:
    target = payload["target"]
    collected = []
    for item in payload["results"]:
        module_id = item["module_id"]
        module_name = item["module_name"]
        severity = item["severity"]
        for evidence in item.get("evidence") or []:
            collected.extend(extract_urls_from_evidence(target, module_id, module_name, severity, evidence))

    seen = set()
    unique = []
    for entry in sorted(collected, key=lambda row: (severity_rank(row["severity"]) * -1, row["url"])):
        key = (entry["module_id"], entry["url"], entry["reason"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(entry)
    return unique


def extract_urls_from_evidence(target: str, module_id: str, module_name: str, severity: str, evidence: dict) -> list[dict]:
    rows = []
    if not isinstance(evidence, dict):
        return rows

    def add(value: str, reason: str, status=None, force: bool = False) -> None:
        url = normalize_url(target, value)
        if not url:
            return
        if force or is_risky_url(url) or module_id in {"ct_subdomains", "takeover_cname", "directory_listing", "secret_patterns", "url_parameters", "cms_admin_surface"}:
            rows.append(
                {
                    "url": url,
                    "status": status,
                    "severity": severity,
                    "module_id": module_id,
                    "module_name": module_name,
                    "reason": reason,
                }
            )

    for key in ("risky_links", "risky", "exposed_paths"):
        values = evidence.get(key)
        if isinstance(values, list):
            for value in values:
                add(str(value), reason_for_key(module_id, key), force=True)

    if isinstance(evidence.get("url"), str):
        status = evidence.get("status")
        if module_id == "sensitive_paths" and status in {200, 206, 401, 403}:
            add(evidence["url"], "Path sensitif merespons dari web server.", status=status, force=True)
        elif module_id == "directory_listing":
            add(evidence["url"], "Directory listing terbuka.", status=status, force=True)
        elif module_id == "cms_admin_surface":
            add(evidence["url"], "Permukaan admin/CMS merespons dan perlu kontrol akses.", status=status, force=True)
        elif module_id == "url_parameters":
            parameter = evidence.get("parameter", "parameter")
            add(evidence["url"], f"Parameter URL berisiko perlu review: {parameter}.", status=status, force=True)
        else:
            add(evidence["url"], "URL pada evidence memenuhi pola risiko.", status=status)

    if isinstance(evidence.get("source"), str) and module_id == "secret_patterns":
        add(evidence["source"], f"Sumber mengandung kandidat secret/token: {evidence.get('type', 'unknown')}.", force=True)

    if isinstance(evidence.get("host"), str):
        add(evidence["host"], "Subdomain/CNAME kandidat risiko perlu validasi manual.", force=True)

    for endpoint in evidence.get("endpoints") or []:
        add(str(endpoint), "Endpoint JavaScript cocok dengan pola risiko.")

    return rows


def reason_for_key(module_id: str, key: str) -> str:
    reasons = {
        ("exposed_links", "risky_links"): "Link publik terlihat sensitif atau administratif.",
        ("sitemap_links", "risky"): "URL sensitif muncul di sitemap publik.",
        ("wayback_urls", "risky"): "URL sensitif ditemukan pada arsip publik.",
        ("ct_subdomains", "risky"): "Subdomain kandidat sensitif muncul di Certificate Transparency.",
        ("robots_txt", "exposed_paths"): "Path sensitif disebut di robots.txt.",
    }
    return reasons.get((module_id, key), "URL/path berisiko ditemukan oleh modul.")


def normalize_url(target: str, value: str) -> str:
    value = str(value).strip()
    if not value:
        return ""
    if value.startswith(("http://", "https://")):
        return value
    if value.startswith("/"):
        return urljoin(target.rstrip("/") + "/", value.lstrip("/"))
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc:
        return value
    if re.match(r"^[A-Za-z0-9*_.-]+\.[A-Za-z]{2,}(/.*)?$", value):
        return "https://" + value.lstrip("*.")
    return ""


def is_risky_url(url: str) -> bool:
    return any(re.search(pattern, url, re.I) for pattern in RISK_URL_PATTERNS)


def render_markdown(payload: dict) -> str:
    results = sorted(payload["results"], key=lambda item: severity_rank(item["severity"]), reverse=True)
    summary = payload["security_summary"]
    lines = [
        f"# {payload['tool']} Detailed Security Report",
        "",
        f"- Developer: {payload['developer']}",
        f"- Version: {payload['version']}",
        f"- Target: {payload['target']}",
        f"- Host: {payload['host']}",
        f"- Registered domain: {payload['registered_domain']}",
        f"- Official emails: {', '.join(payload['official_emails']) if payload['official_emails'] else 'Belum ditemukan'}",
        f"- Active modules: {payload['active_modules_enabled']}",
        f"- Kali tools: {payload['kali_tools_enabled']}",
        "",
        "## Ringkasan Keamanan",
        "",
        f"- Highest severity: {summary['highest_severity']}",
        f"- Modul dijalankan: {summary['modules_executed']}",
        f"- Modul dengan temuan: {summary['modules_with_findings']}",
        f"- Modul actionable: {summary['actionable_modules']}",
        f"- Modul dilewati: {summary['skipped_modules']}",
        f"- URL/path berisiko: {summary['risky_url_count']}",
        f"- Email resmi kandidat: {summary['official_email_count']}",
        f"- Severity counts: critical={summary['severity_counts'].get('critical', 0)}, high={summary['severity_counts'].get('high', 0)}, medium={summary['severity_counts'].get('medium', 0)}, low={summary['severity_counts'].get('low', 0)}, info={summary['severity_counts'].get('info', 0)}",
        "",
        "## URL dan Path Berisiko Prioritas",
        "",
    ]
    if payload["risky_urls"]:
        lines.extend(
            [
                "| No | Severity | URL/Path | Status | Module | Alasan |",
                "|---:|---|---|---|---|---|",
            ]
        )
        for idx, entry in enumerate(payload["risky_urls"], start=1):
            lines.append(
                "| {no} | {severity} | {url} | {status} | {module} | {reason} |".format(
                    no=idx,
                    severity=markdown_escape(entry["severity"]),
                    url=markdown_escape(entry["url"]),
                    status=markdown_escape(entry["status"] if entry["status"] is not None else "-"),
                    module=markdown_escape(entry["module_name"]),
                    reason=markdown_escape(entry["reason"]),
                )
            )
    else:
        lines.append("Tidak ada URL/path berisiko yang terkonfirmasi dari evidence modul yang berjalan.")

    lines.extend(
        [
            "",
            "## 20 Modul Utama dan Kegunaan",
            "",
            "| No | Module ID | Fungsi | Kegunaan | Output Keamanan |",
            "|---:|---|---|---|---|",
        ]
    )
    for module in payload["module_catalog_20"]:
        lines.append(
            "| {no} | {module_id} | {function} | {use} | {output} |".format(
                no=module["number"],
                module_id=markdown_escape(module["module_id"]),
                function=markdown_escape(module["function"]),
                use=markdown_escape(module["use"]),
                output=markdown_escape(module["output"]),
            )
        )

    lines.extend(["", "## Ringkasan Hasil Modul", "", "| No | Severity | Module | Category | Findings | Risk URLs | Summary | Official Email |", "|---:|---|---|---|---:|---:|---|---|"])
    for idx, item in enumerate(results, start=1):
        emails = ", ".join(item.get("official_emails") or payload["official_emails"]) or "Belum ditemukan"
        skipped = " (skipped)" if item.get("skipped") else ""
        risk_url_count = len([entry for entry in payload["risky_urls"] if entry["module_id"] == item["module_id"]])
        lines.append(
            "| {no} | {severity} | {module}{skipped} | {category} | {findings} | {risk_urls} | {summary} | {emails} |".format(
                no=idx,
                severity=markdown_escape(item["severity"]),
                module=markdown_escape(item["module_name"]),
                skipped=skipped,
                category=markdown_escape(item["category"]),
                findings=len(item.get("findings") or []),
                risk_urls=risk_url_count,
                summary=markdown_escape(item["summary"]),
                emails=markdown_escape(emails),
            )
        )

    lines.extend(["", "## Detail Temuan Per Modul", ""])
    for item in results:
        lines.append(f"### {item['module_name']} [{item['severity']}]")
        lines.append("")
        lines.append(item["summary"])
        lines.append("")
        emails = ", ".join(item.get("official_emails") or payload["official_emails"]) or "Belum ditemukan"
        lines.append(f"Official email: {emails}")
        lines.append("")
        module_risks = [entry for entry in payload["risky_urls"] if entry["module_id"] == item["module_id"]]
        if module_risks:
            lines.append("URL/path berisiko dari modul ini:")
            for entry in module_risks[:80]:
                status = f" status={entry['status']}" if entry["status"] is not None else ""
                lines.append(f"- [{entry['severity']}] {entry['url']}{status} - {entry['reason']}")
            lines.append("")
        if item.get("findings"):
            lines.append("Findings:")
            for finding in item["findings"][:80]:
                lines.append(f"- {finding}")
            lines.append("")
        if item.get("recommendations"):
            lines.append("Recommendations:")
            for rec in item["recommendations"]:
                lines.append(f"- {rec}")
            lines.append("")
        if item.get("evidence"):
            lines.append("Evidence sample:")
            lines.append("```json")
            lines.append(json.dumps(item["evidence"][:5], indent=2, ensure_ascii=False))
            lines.append("```")
            lines.append("")
    lines.append("> Gunakan hanya pada website/aset yang kamu miliki atau sudah diberi izin tertulis.")
    return "\n".join(lines)
