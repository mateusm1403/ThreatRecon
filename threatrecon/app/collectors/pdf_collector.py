from __future__ import annotations

import httpx
from loguru import logger

from threatrecon.app.core.config import Settings
from threatrecon.app.core.models import PdfDocument


class PdfCollector:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def fetch(self, urls: set[str]) -> list[PdfDocument]:
        documents: list[PdfDocument] = []
        selected_urls = list(urls)[: self.settings.max_pdfs]

        async with httpx.AsyncClient(
            timeout=self.settings.timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": self.settings.user_agent},
        ) as client:
            for url in selected_urls:
                try:
                    logger.info("Fetching PDF metadata source {}", url)
                    response = await client.get(url)
                    content_type = response.headers.get("content-type", "").lower()
                    if response.status_code < 400 and (
                        "application/pdf" in content_type or url.lower().endswith(".pdf")
                    ):
                        documents.append(PdfDocument(url=url, content=response.content, headers=dict(response.headers)))
                except httpx.HTTPError as exc:
                    logger.warning("Could not fetch PDF {}: {}", url, exc)

        return documents
