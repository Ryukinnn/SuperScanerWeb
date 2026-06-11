import time
from dataclasses import dataclass
from urllib.parse import urljoin

import requests


@dataclass
class FetchResult:
    url: str
    ok: bool
    status_code: int | None
    headers: dict
    text: str
    final_url: str
    error: str = ""


class SafeHTTPClient:
    def __init__(self, user_agent: str, timeout: int = 10, rate_limit: float = 0.25, max_body: int = 2_000_000):
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.max_body = max_body
        self._last_request = 0.0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})

    def absolute(self, base_url: str, path: str) -> str:
        return urljoin(base_url.rstrip("/") + "/", path)

    def fetch(self, url: str, method: str = "GET", allow_redirects: bool = True) -> FetchResult:
        elapsed = time.time() - self._last_request
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self._last_request = time.time()
        try:
            response = self.session.request(
                method,
                url,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
            )
            content = response.content[: self.max_body]
            encoding = response.encoding or response.apparent_encoding or "utf-8"
            text = content.decode(encoding, errors="replace")
            return FetchResult(
                url=url,
                ok=response.ok,
                status_code=response.status_code,
                headers=dict(response.headers),
                text=text,
                final_url=response.url,
            )
        except requests.RequestException as exc:
            return FetchResult(
                url=url,
                ok=False,
                status_code=None,
                headers={},
                text="",
                final_url=url,
                error=str(exc),
            )
