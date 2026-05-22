from __future__ import annotations

import re

from threatrecon.app.core.models import Finding, Page, PdfDocument


SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[0-9A-Za-z_]{36,255}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,100}\b"),
    "generic_api_secret": re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|client[_-]?secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-./+=]{20,})"
    ),
}


def extract_possible_secrets_from_pages(pages: list[Page]) -> list[Finding]:
    findings: dict[str, Finding] = {}
    for page in pages:
        _collect_from_text(page.html, page.url, findings)
    return list(findings.values())


def extract_possible_secrets_from_pdfs(documents: list[PdfDocument]) -> list[Finding]:
    findings: dict[str, Finding] = {}
    for document in documents:
        text = document.content.decode("latin-1", errors="ignore")
        _collect_from_text(text, document.url, findings)
    return list(findings.values())


def _collect_from_text(text: str, source: str, findings: dict[str, Finding]) -> None:
    for name, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(1) if match.lastindex else match.group(0)
            redacted = _redact(value)
            findings[f"{name}:{redacted}:{source}"] = Finding(
                type="possible_secret",
                value=redacted,
                source=source,
                severity="critical",
                evidence=f"Pattern matched: {name}",
                metadata={"pattern": name},
            )


def _redact(value: str) -> str:
    if len(value) <= 10:
        return "***"
    return f"{value[:4]}...{value[-4:]}"
