from __future__ import annotations

import re

from threatrecon.app.core.models import Finding, Page, PdfDocument


EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)


def extract_emails_from_pages(pages: list[Page]) -> list[Finding]:
    findings: dict[str, Finding] = {}
    for page in pages:
        for email in EMAIL_RE.findall(page.html):
            key = email.lower()
            findings[key] = Finding(
                type="email",
                value=key,
                source=page.url,
                severity="low",
                evidence="Email address exposed in public page",
            )
    return list(findings.values())


def extract_emails_from_pdfs(documents: list[PdfDocument]) -> list[Finding]:
    findings: dict[str, Finding] = {}
    for document in documents:
        text = document.content.decode("latin-1", errors="ignore")
        for email in EMAIL_RE.findall(text):
            key = email.lower()
            findings[key] = Finding(
                type="email",
                value=key,
                source=document.url,
                severity="low",
                evidence="Email address exposed in public PDF",
            )
    return list(findings.values())
