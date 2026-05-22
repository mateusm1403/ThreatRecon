from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from threatrecon.app.core.models import Finding, ScanResult


class SQLiteStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True) if self.database_path.parent != Path(".") else None
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_schema(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    exposure_score INTEGER NOT NULL,
                    summary_json TEXT NOT NULL,
                    artifacts_json TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    source TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
                """
            )
            connection.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain, completed_at)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)")

    def save_scan(self, result: ScanResult) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO scans (domain, started_at, completed_at, exposure_score, summary_json, artifacts_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    result.domain,
                    result.started_at.isoformat(),
                    result.completed_at.isoformat(),
                    result.exposure_score,
                    json.dumps(result.summary, ensure_ascii=False),
                    json.dumps(result.artifacts.to_dict(), ensure_ascii=False) if result.artifacts else None,
                ),
            )
            scan_id = int(cursor.lastrowid)
            connection.executemany(
                """
                INSERT INTO findings (scan_id, type, value, source, severity, evidence, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_id,
                        finding.type,
                        finding.value,
                        finding.source,
                        finding.severity,
                        finding.evidence,
                        json.dumps(finding.metadata, ensure_ascii=False),
                    )
                    for finding in result.findings
                ],
            )
            return scan_id

    def update_artifacts(self, scan_id: int, artifacts: dict[str, str]) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE scans SET artifacts_json = ? WHERE id = ?",
                (json.dumps(artifacts, ensure_ascii=False), scan_id),
            )

    def get_latest_findings(self, domain: str) -> list[Finding]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id FROM scans
                WHERE domain = ?
                ORDER BY completed_at DESC, id DESC
                LIMIT 1
                """,
                (domain,),
            ).fetchone()
            if row is None:
                return []
            return self._findings_for_scan(int(row["id"]), connection)

    def list_scans(self, domain: str | None = None, limit: int = 10) -> list[dict[str, Any]]:
        query = "SELECT * FROM scans"
        params: tuple[Any, ...] = ()
        if domain:
            query += " WHERE domain = ?"
            params = (domain,)
        query += " ORDER BY completed_at DESC, id DESC LIMIT ?"
        params = (*params, limit)

        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
            return [dict(row) for row in rows]

    def _findings_for_scan(self, scan_id: int, connection: sqlite3.Connection) -> list[Finding]:
        rows = connection.execute(
            """
            SELECT type, value, source, severity, evidence, metadata_json
            FROM findings
            WHERE scan_id = ?
            """,
            (scan_id,),
        ).fetchall()
        return [
            Finding(
                type=row["type"],
                value=row["value"],
                source=row["source"],
                severity=row["severity"],
                evidence=row["evidence"],
                metadata=json.loads(row["metadata_json"] or "{}"),
            )
            for row in rows
        ]
