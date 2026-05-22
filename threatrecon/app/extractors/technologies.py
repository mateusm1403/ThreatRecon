from __future__ import annotations

from bs4 import BeautifulSoup

from threatrecon.app.core.models import Finding, Page


TECH_SIGNATURES: dict[str, tuple[str, ...]] = {
    "WordPress": ("wp-content", "wp-includes"),
    "React": ("react", "__REACT_DEVTOOLS_GLOBAL_HOOK__"),
    "Angular": ("ng-version", "angular"),
    "Vue.js": ("vue", "__vue__"),
    "jQuery": ("jquery",),
    "Bootstrap": ("bootstrap",),
    "Google Analytics": ("googletagmanager", "google-analytics"),
    "Next.js": ("_next/static", "__next_data__"),
}


def identify_technologies(pages: list[Page]) -> list[Finding]:
    findings: dict[str, Finding] = {}
    for page in pages:
        _from_headers(page, findings)
        _from_html(page, findings)
    return list(findings.values())


def _from_headers(page: Page, findings: dict[str, Finding]) -> None:
    for header in ("server", "x-powered-by", "cf-cache-status"):
        value = page.headers.get(header)
        if not value:
            continue
        tech = "Cloudflare" if header == "cf-cache-status" else value.split(";")[0].strip()
        findings[tech.lower()] = Finding(
            type="technology",
            value=tech,
            source=page.url,
            severity="info",
            evidence=f"HTTP header: {header}",
        )


def _from_html(page: Page, findings: dict[str, Finding]) -> None:
    soup = BeautifulSoup(page.html, "html.parser")
    searchable = " ".join(
        [
            page.html[:100_000].lower(),
            " ".join(tag.get("src", "") for tag in soup.find_all(["script", "img"])).lower(),
            " ".join(tag.get("href", "") for tag in soup.find_all("link")).lower(),
        ]
    )
    for tech, signatures in TECH_SIGNATURES.items():
        if any(signature.lower() in searchable for signature in signatures):
            findings[tech.lower()] = Finding(
                type="technology",
                value=tech,
                source=page.url,
                severity="info",
                evidence="Matched public HTML asset signature",
            )
