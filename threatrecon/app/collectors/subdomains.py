from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx
from loguru import logger

from threatrecon.app.core.config import Settings
from threatrecon.app.core.models import Page


SUBDOMAIN_RE_TEMPLATE = r"\b([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.{domain})\b"


class SubdomainCollector:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def collect(self, domain: str, pages: list[Page]) -> set[str]:
        discovered = {domain}
        discovered.update(self._from_pages(domain, pages))
        if self.settings.enable_crtsh:
            discovered.update(await self._from_crtsh(domain))
        return {item.lower().strip(".") for item in discovered if item.endswith(domain)}

    def _from_pages(self, domain: str, pages: list[Page]) -> set[str]:
        pattern = re.compile(SUBDOMAIN_RE_TEMPLATE.format(domain=re.escape(domain)), re.IGNORECASE)
        found: set[str] = set()

        for page in pages:
            hostname = urlparse(page.url).hostname
            if hostname and hostname.endswith(domain):
                found.add(hostname)
            found.update(match.group(1).lower() for match in pattern.finditer(page.html))

        return found

    async def _from_crtsh(self, domain: str) -> set[str]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        found: set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=self.settings.timeout_seconds) as client:
                response = await client.get(url, headers={"User-Agent": self.settings.user_agent})
                response.raise_for_status()
                for item in response.json():
                    name_value = str(item.get("name_value", ""))
                    for hostname in name_value.splitlines():
                        clean = hostname.lower().replace("*.", "").strip()
                        if clean.endswith(domain):
                            found.add(clean)
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("crt.sh lookup failed for {}: {}", domain, exc)
        return found
