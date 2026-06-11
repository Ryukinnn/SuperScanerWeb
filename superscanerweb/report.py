from pathlib import Path

from .core import ScanContext
from .utils import markdown_escape, now_stamp, severity_rank, write_json
from . import __app_name__, __developer__, __version__


def write_reports(ctx: ScanContext, results: list) -> tuple[Path, Path]:
    stamp = now_stamp()
    safe_host = ctx.host.replace(":", "_")
    json_path = ctx.config.out_dir / f"{safe_host}-{stamp}.json"
    md_path = ctx.config.out_dir / f"{safe_host}-{stamp}.md"
    payload = {
        "tool": __app_name__,
        "version": __version__,
        "developer": __developer__,
        "target": ctx.target_url,
        "host": ctx.host,
        "registered_domain": ctx.registered_domain,
        "official_emails": ctx.official_emails,
        "active_modules_enabled": ctx.config.active,
        "kali_tools_enabled": ctx.config.use_kali,
        "results": [item.to_dict() for item in results],
    }
    write_json(json_path, payload)
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    return json_path, md_path


def render_markdown(payload: dict) -> str:
    results = sorted(payload["results"], key=lambda item: severity_rank(item["severity"]), reverse=True)
    lines = [
        f"# {payload['tool']} Report",
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
        "## Ringkasan Modul",
        "",
        "| Severity | Module | Category | Summary | Official email |",
        "|---|---|---|---|---|",
    ]
    for item in results:
        emails = ", ".join(item.get("official_emails") or payload["official_emails"]) or "Belum ditemukan"
        skipped = " (skipped)" if item.get("skipped") else ""
        lines.append(
            "| {severity} | {module}{skipped} | {category} | {summary} | {emails} |".format(
                severity=markdown_escape(item["severity"]),
                module=markdown_escape(item["module_name"]),
                skipped=skipped,
                category=markdown_escape(item["category"]),
                summary=markdown_escape(item["summary"]),
                emails=markdown_escape(emails),
            )
        )
    lines.extend(["", "## Detail Temuan", ""])
    for item in results:
        lines.append(f"### {item['module_name']} [{item['severity']}]")
        lines.append("")
        lines.append(item["summary"])
        lines.append("")
        emails = ", ".join(item.get("official_emails") or payload["official_emails"]) or "Belum ditemukan"
        lines.append(f"Official email: {emails}")
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
            import json

            lines.append(json.dumps(item["evidence"][:5], indent=2, ensure_ascii=False))
            lines.append("```")
            lines.append("")
    lines.append("> Gunakan hanya pada website/aset yang kamu miliki atau sudah diberi izin tertulis.")
    return "\n".join(lines)
