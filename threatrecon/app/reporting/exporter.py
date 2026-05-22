from __future__ import annotations

import json
import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from threatrecon.app.core.models import ScanArtifacts, ScanResult
from threatrecon.app.correlation.engine import CorrelationEngine


class ReportExporter:
    def __init__(self, reports_dir: Path, correlation_engine: CorrelationEngine) -> None:
        self.reports_dir = reports_dir
        self.correlation_engine = correlation_engine
        self.template_dir = Path(__file__).parent / "templates"

    def export(self, result: ScanResult) -> ScanArtifacts:
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        stem = self._build_stem(result)
        csv_path = self.reports_dir / f"{stem}.csv"
        json_path = self.reports_dir / f"{stem}.json"
        html_path = self.reports_dir / f"{stem}.html"

        frame = self.correlation_engine.to_dataframe(result.findings)
        frame.to_csv(csv_path, index=False, encoding="utf-8")

        artifacts = ScanArtifacts(
            html_report=str(html_path),
            csv_path=str(csv_path),
            json_path=str(json_path),
        )
        result.artifacts = artifacts

        json_path.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        html_path.write_text(self._render_html(result), encoding="utf-8")
        return artifacts

    def _render_html(self, result: ScanResult) -> str:
        env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=select_autoescape(["html", "xml"]),
        )
        template = env.get_template("report.html.j2")
        by_type: dict[str, list[dict[str, object]]] = {}
        for finding in result.findings:
            by_type.setdefault(finding.type, []).append(finding.to_dict())
        return template.render(result=result, by_type=by_type)

    @staticmethod
    def _build_stem(result: ScanResult) -> str:
        safe_domain = re.sub(r"[^a-zA-Z0-9_.-]+", "_", result.domain)
        timestamp = result.completed_at.strftime("%Y%m%d_%H%M%S")
        scan_id = result.scan_id or "pending"
        return f"threatrecon_{safe_domain}_{timestamp}_{scan_id}"
