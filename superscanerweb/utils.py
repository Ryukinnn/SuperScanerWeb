import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]{1,80}@[A-Z0-9.-]{2,253}\.[A-Z]{2,24}\b", re.I)


ROLE_PREFIXES = (
    "security",
    "abuse",
    "admin",
    "administrator",
    "webmaster",
    "hostmaster",
    "postmaster",
    "contact",
    "info",
    "support",
    "it",
    "noc",
)


def now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def clean_domain(domain: str) -> str:
    return domain.lower().strip().strip(".")


def extract_emails(text: str, domain_hint: str | None = None) -> list[str]:
    if not text:
        return []
    emails = {email.lower().strip(".,;:()[]<>\"'") for email in EMAIL_RE.findall(text)}
    filtered = []
    for email in sorted(emails):
        local, _, host = email.partition("@")
        if len(local) < 2 or ".." in host:
            continue
        if domain_hint and not (host == domain_hint or host.endswith("." + domain_hint)):
            if local not in ROLE_PREFIXES:
                continue
        filtered.append(email)
    return filtered


def official_email_score(email: str, domain_hint: str) -> tuple[int, str]:
    local, _, host = email.partition("@")
    score = 0
    if host == domain_hint:
        score += 10
    elif host.endswith("." + domain_hint):
        score += 7
    if local in ROLE_PREFIXES:
        score += 8
    if local == "security":
        score += 5
    return (-score, email)


def merge_emails(*groups: Iterable[str], domain_hint: str = "") -> list[str]:
    merged = {email.lower() for group in groups for email in group if email}
    return sorted(merged, key=lambda email: official_email_score(email, domain_hint))


def truncate(value: str, limit: int = 800) -> str:
    if value is None:
        return ""
    value = str(value)
    return value if len(value) <= limit else value[: limit - 3] + "..."


def has_command(name: str) -> bool:
    return shutil.which(name) is not None


def run_command(args: list[str], timeout: int = 45) -> dict:
    if not args or not has_command(args[0]):
        return {
            "available": False,
            "command": args,
            "returncode": None,
            "stdout": "",
            "stderr": f"Command not found: {args[0] if args else ''}",
        }
    try:
        proc = subprocess.run(
            args,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return {
            "available": True,
            "command": args,
            "returncode": proc.returncode,
            "stdout": truncate(proc.stdout, 12000),
            "stderr": truncate(proc.stderr, 4000),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "available": True,
            "command": args,
            "returncode": None,
            "stdout": truncate(exc.stdout or "", 4000),
            "stderr": f"Timed out after {timeout}s",
        }


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def severity_rank(severity: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(severity, 0)


def markdown_escape(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", "<br>")
