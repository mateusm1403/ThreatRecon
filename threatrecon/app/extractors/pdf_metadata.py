from __future__ import annotations

import re

from threatrecon.app.core.models import Finding, PdfDocument


PDF_META_FIELDS = ("Title", "Author", "Creator", "Producer", "CreationDate", "ModDate")


def extract_pdf_metadata(documents: list[PdfDocument]) -> list[Finding]:
    findings: list[Finding] = []
    for document in documents:
        text = document.content[:250_000].decode("latin-1", errors="ignore")
        metadata: dict[str, str] = {}
        for field in PDF_META_FIELDS:
            match = re.search(rf"/{field}\s*\((.*?)\)", text, flags=re.DOTALL)
            if match:
                metadata[field] = _clean_pdf_value(match.group(1))

        if metadata:
            findings.append(
                Finding(
                    type="pdf_metadata",
                    value=document.url,
                    source=document.url,
                    severity="medium" if {"Author", "Creator"} & metadata.keys() else "low",
                    evidence="Public PDF contains embedded metadata",
                    metadata=metadata,
                )
            )
    return findings


def _clean_pdf_value(value: str) -> str:
    return value.replace("\\)", ")").replace("\\(", "(").strip()[:300]
