from __future__ import annotations

from collections import Counter

from threatrecon.app.core.models import Finding


TYPE_WEIGHTS = {
    "possible_secret": 25,
    "pdf_metadata": 8,
    "email": 4,
    "subdomain": 3,
    "ip": 2,
    "technology": 2,
}

SEVERITY_MULTIPLIERS = {
    "critical": 1.7,
    "high": 1.4,
    "medium": 1.1,
    "low": 0.8,
    "info": 0.5,
}


class ExposureScorer:
    def score(self, findings: list[Finding]) -> int:
        counts = Counter(finding.type for finding in findings)
        raw_score = 0.0

        for finding in findings:
            raw_score += TYPE_WEIGHTS.get(finding.type, 1) * SEVERITY_MULTIPLIERS.get(finding.severity, 1)

        if counts["subdomain"] > 10:
            raw_score += 8
        if counts["email"] > 5:
            raw_score += 6
        if counts["possible_secret"]:
            raw_score += 20

        return min(100, round(raw_score))
