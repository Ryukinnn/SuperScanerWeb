from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from .http_client import SafeHTTPClient
from .utils import merge_emails


@dataclass
class ScanConfig:
    target: str
    out_dir: Path
    timeout: int = 10
    rate_limit: float = 0.25
    max_pages: int = 25
    max_js: int = 12
    active: bool = False
    use_kali: bool = False
    selected_modules: list[str] = field(default_factory=list)


@dataclass
class ModuleResult:
    module_id: str
    module_name: str
    category: str
    severity: str
    summary: str
    findings: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    official_emails: list[str] = field(default_factory=list)
    skipped: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


class ScanContext:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.target_url = normalize_target(config.target)
        parsed = urlparse(self.target_url)
        self.host = parsed.netloc.split("@")[-1].split(":")[0].lower()
        self.registered_domain = registered_domain_from_host(self.host)
        self.scheme = parsed.scheme
        self.base_url = f"{self.scheme}://{parsed.netloc}"
        self.user_agent = "SuperScanerWeb/1.0 (+https://github.com/Ryukinnn/SuperScanerWeb; defensive OSINT scanner)"
        self.http = SafeHTTPClient(
            user_agent=self.user_agent,
            timeout=config.timeout,
            rate_limit=config.rate_limit,
        )
        self.cache: dict[str, object] = {}
        self.official_emails: list[str] = []

    def with_emails(self, *groups: list[str]) -> list[str]:
        self.official_emails = merge_emails(self.official_emails, *groups, domain_hint=self.registered_domain)
        return self.official_emails


def normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("Target tidak boleh kosong.")
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parsed = urlparse(target)
    if not parsed.netloc:
        raise ValueError("Target harus berupa domain atau URL yang valid.")
    return target.rstrip("/")


def registered_domain_from_host(host: str) -> str:
    parts = [part for part in host.lower().strip(".").split(".") if part]
    if len(parts) <= 2:
        return host.lower().strip(".")
    two_part_suffixes = {
        "ac.id",
        "co.id",
        "or.id",
        "go.id",
        "web.id",
        "sch.id",
        "co.uk",
        "org.uk",
        "gov.uk",
        "ac.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.jp",
        "com.br",
    }
    suffix = ".".join(parts[-2:])
    if suffix in two_part_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def result(
    ctx: ScanContext,
    module_id: str,
    module_name: str,
    category: str,
    severity: str,
    summary: str,
    findings: list[str] | None = None,
    evidence: list[dict] | None = None,
    recommendations: list[str] | None = None,
    skipped: bool = False,
) -> ModuleResult:
    return ModuleResult(
        module_id=module_id,
        module_name=module_name,
        category=category,
        severity=severity,
        summary=summary,
        findings=findings or [],
        evidence=evidence or [],
        recommendations=recommendations or [],
        official_emails=ctx.official_emails.copy(),
        skipped=skipped,
    )
