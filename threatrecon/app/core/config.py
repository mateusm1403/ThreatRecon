from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _load_env_file(path: Path) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


@dataclass(frozen=True)
class Settings:
    max_pages: int = 15
    max_pdfs: int = 5
    timeout_seconds: float = 10.0
    request_delay_seconds: float = 0.2
    user_agent: str = "ThreatRecon/0.1 OSINT Scanner"
    database_path: Path = Path("threatrecon.db")
    reports_dir: Path = Path("reports")
    enable_crtsh: bool = True

    @classmethod
    def from_env(cls, env_path: Path | None = None) -> "Settings":
        _load_env_file(env_path or Path(".env"))
        return cls(
            max_pages=int(os.getenv("THREATRECON_MAX_PAGES", "15")),
            max_pdfs=int(os.getenv("THREATRECON_MAX_PDFS", "5")),
            timeout_seconds=float(os.getenv("THREATRECON_TIMEOUT_SECONDS", "10")),
            request_delay_seconds=float(os.getenv("THREATRECON_REQUEST_DELAY_SECONDS", "0.2")),
            user_agent=os.getenv("THREATRECON_USER_AGENT", "ThreatRecon/0.1 OSINT Scanner"),
            database_path=Path(os.getenv("THREATRECON_DATABASE_PATH", "threatrecon.db")),
            reports_dir=Path(os.getenv("THREATRECON_REPORTS_DIR", "reports")),
            enable_crtsh=_bool_env("THREATRECON_ENABLE_CRTSH", True),
        )
