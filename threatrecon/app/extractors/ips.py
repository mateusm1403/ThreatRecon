from __future__ import annotations

import re

from threatrecon.app.core.models import Finding, Page


IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def extract_ips_from_pages(pages: list[Page]) -> list[Finding]:
    findings: dict[str, Finding] = {}
    for page in pages:
        for ip in IPV4_RE.findall(page.html):
            findings[ip] = Finding(
                type="ip",
                value=ip,
                source=page.url,
                severity="info",
                evidence="IPv4 address referenced in public content",
            )
    return list(findings.values())
