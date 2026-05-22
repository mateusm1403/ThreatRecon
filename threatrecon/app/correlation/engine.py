from __future__ import annotations

from collections import Counter
from typing import Any

import pandas as pd

from threatrecon.app.core.models import Finding


class CorrelationEngine:
    def deduplicate(self, findings: list[Finding]) -> list[Finding]:
        deduped: dict[str, Finding] = {}
        for finding in findings:
            deduped.setdefault(finding.fingerprint, finding)
        return sorted(deduped.values(), key=lambda item: (item.type, item.value))

    def summarize(self, findings: list[Finding], pages_crawled: int, pdfs_analyzed: int) -> dict[str, Any]:
        counts = Counter(finding.type for finding in findings)
        critical = [finding.to_dict() for finding in findings if finding.severity in {"critical", "high"}]
        return {
            "pages_crawled": pages_crawled,
            "pdfs_analyzed": pdfs_analyzed,
            "total_findings": len(findings),
            "counts_by_type": dict(sorted(counts.items())),
            "critical_indicators": critical,
        }

    def compare(self, previous: list[Finding], current: list[Finding]) -> dict[str, list[dict[str, Any]]]:
        previous_map = {finding.fingerprint: finding for finding in previous}
        current_map = {finding.fingerprint: finding for finding in current}

        new_items = [
            finding.to_dict()
            for fingerprint, finding in current_map.items()
            if fingerprint not in previous_map
        ]
        resolved_items = [
            finding.to_dict()
            for fingerprint, finding in previous_map.items()
            if fingerprint not in current_map
        ]

        return {
            "new": sorted(new_items, key=lambda item: (item["type"], item["value"])),
            "resolved": sorted(resolved_items, key=lambda item: (item["type"], item["value"])),
        }

    def to_dataframe(self, findings: list[Finding]) -> pd.DataFrame:
        rows = [finding.to_dict() for finding in findings]
        if not rows:
            return pd.DataFrame(columns=["type", "value", "source", "severity", "evidence", "metadata"])
        frame = pd.DataFrame(rows)
        frame["metadata"] = frame["metadata"].apply(lambda value: str(value) if value else "")
        return frame.sort_values(by=["severity", "type", "value"])
