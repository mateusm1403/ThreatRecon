from datetime import UTC, datetime

from threatrecon.app.core.models import Finding, ScanArtifacts, ScanResult
from threatrecon.app.correlation.engine import CorrelationEngine
from threatrecon.app.correlation.scoring import ExposureScorer


def test_exposure_score_prioritizes_possible_secrets() -> None:
    score = ExposureScorer().score(
        [
            Finding(
                type="possible_secret",
                value="abcd...1234",
                source="https://example.com",
                severity="critical",
            )
        ]
    )

    assert score >= 60


def test_compare_marks_new_and_resolved_findings() -> None:
    engine = CorrelationEngine()
    previous = [Finding(type="email", value="old@example.com", source="x")]
    current = [Finding(type="email", value="new@example.com", source="x")]

    changes = engine.compare(previous, current)

    assert changes["new"][0]["value"] == "new@example.com"
    assert changes["resolved"][0]["value"] == "old@example.com"


def test_scan_result_serializes_slotted_artifacts() -> None:
    result = ScanResult(
        scan_id=1,
        domain="example.com",
        started_at=datetime(2026, 5, 22, tzinfo=UTC),
        completed_at=datetime(2026, 5, 22, tzinfo=UTC),
        findings=[],
        exposure_score=0,
        summary={},
        changes={"new": [], "resolved": []},
        artifacts=ScanArtifacts(
            html_report="reports/example.html",
            csv_path="reports/example.csv",
            json_path="reports/example.json",
        ),
    )

    assert result.to_dict()["artifacts"]["html_report"] == "reports/example.html"
