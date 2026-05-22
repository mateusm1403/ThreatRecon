from __future__ import annotations

import asyncio
from collections import deque
from urllib.parse import urldefrag, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from loguru import logger

from threatrecon.app.core.config import Settings
from threatrecon.app.core.models import Page


class HttpCrawler:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def crawl(self, domain: str) -> tuple[list[Page], set[str]]:
        pages: list[Page] = []
        pdf_urls: set[str] = set()
        visited: set[str] = set()
        queue: deque[str] = deque([f"https://{domain}", f"http://{domain}"])

        async with httpx.AsyncClient(
            timeout=self.settings.timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": self.settings.user_agent},
        ) as client:
            while queue and len(pages) < self.settings.max_pages:
                url = queue.popleft()
                normalized = self._normalize_url(url)
                if not normalized or normalized in visited:
                    continue
                visited.add(normalized)

                try:
                    logger.info("Crawling {}", normalized)
                    response = await client.get(normalized)
                    await asyncio.sleep(self.settings.request_delay_seconds)
                except httpx.HTTPError as exc:
                    logger.warning("Could not fetch {}: {}", normalized, exc)
                    continue

                content_type = response.headers.get("content-type", "").lower()
                if "application/pdf" in content_type or normalized.lower().endswith(".pdf"):
                    pdf_urls.add(str(response.url))
                    continue
                if "text/html" not in content_type:
                    continue

                page = Page(
                    url=str(response.url),
                    status_code=response.status_code,
                    content_type=content_type,
                    html=response.text,
                    headers=dict(response.headers),
                )
                pages.append(page)

                links, pdf_links = self._extract_links(page.url, page.html, domain)
                pdf_urls.update(pdf_links)
                for link in links:
                    if link not in visited and len(visited) + len(queue) < self.settings.max_pages * 3:
                        queue.append(link)

        return pages, pdf_urls

    def _extract_links(self, base_url: str, html: str, domain: str) -> tuple[set[str], set[str]]:
        soup = BeautifulSoup(html, "html.parser")
        links: set[str] = set()
        pdf_links: set[str] = set()

        for tag in soup.find_all(["a", "link", "script"]):
            href = tag.get("href") or tag.get("src")
            if not href:
                continue
            absolute = self._normalize_url(urljoin(base_url, href))
            if not absolute:
                continue
            hostname = urlparse(absolute).hostname or ""
            if absolute.lower().endswith(".pdf"):
                pdf_links.add(absolute)
            if hostname == domain or hostname.endswith(f".{domain}"):
                links.add(absolute)

        return links, pdf_links

    @staticmethod
    def _normalize_url(url: str) -> str | None:
        parsed = urlparse(urldefrag(url).url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return None
        return parsed.geturl().rstrip("/")
