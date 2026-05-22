from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class Finding:
    type: str
    value: str
    source: str
    severity: str = "info"
    evidence: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        return f"{self.type}:{self.value}".lower()

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "value": self.value,
            "source": self.source,
            "severity": self.severity,
            "evidence": self.evidence,
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class Page:
    url: str
    status_code: int
    content_type: str
    html: str
    headers: dict[str, str]


@dataclass(slots=True)
class PdfDocument:
    url: str
    content: bytes
    headers: dict[str, str]


@dataclass(slots=True)
class ScanArtifacts:
    html_report: str
    csv_path: str
    json_path: str

    def to_dict(self) -> dict[str, str]:
        return {
            "html_report": self.html_report,
            "csv_path": self.csv_path,
            "json_path": self.json_path,
        }


@dataclass(slots=True)
class ScanResult:
    scan_id: int | None
    domain: str
    started_at: datetime
    completed_at: datetime
    findings: list[Finding]
    exposure_score: int
    summary: dict[str, Any]
    changes: dict[str, list[dict[str, Any]]]
    artifacts: ScanArtifacts | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "domain": self.domain,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "exposure_score": self.exposure_score,
            "summary": self.summary,
            "changes": self.changes,
            "findings": [finding.to_dict() for finding in self.findings],
            "artifacts": self.artifacts.to_dict() if self.artifacts else None,
        }
