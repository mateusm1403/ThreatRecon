from __future__ import annotations

from urllib.parse import urlparse

from loguru import logger

from threatrecon.app.collectors.http_crawler import HttpCrawler
from threatrecon.app.collectors.pdf_collector import PdfCollector
from threatrecon.app.collectors.subdomains import SubdomainCollector
from threatrecon.app.core.config import Settings
from threatrecon.app.core.models import Finding, ScanResult, utc_now
from threatrecon.app.correlation.engine import CorrelationEngine
from threatrecon.app.correlation.scoring import ExposureScorer
from threatrecon.app.enrichers.dns import DnsEnricher
from threatrecon.app.extractors.emails import extract_emails_from_pages, extract_emails_from_pdfs
from threatrecon.app.extractors.ips import extract_ips_from_pages
from threatrecon.app.extractors.pdf_metadata import extract_pdf_metadata
from threatrecon.app.extractors.secrets import extract_possible_secrets_from_pages, extract_possible_secrets_from_pdfs
from threatrecon.app.extractors.technologies import identify_technologies
from threatrecon.app.reporting.exporter import ReportExporter
from threatrecon.app.storage.sqlite_store import SQLiteStore


class ScanOrchestrator:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.correlation = CorrelationEngine()
        self.scorer = ExposureScorer()
        self.store = SQLiteStore(settings.database_path)
        self.reporter = ReportExporter(settings.reports_dir, self.correlation)

    async def run(self, target: str) -> ScanResult:
        domain = normalize_domain(target)
        started_at = utc_now()
        logger.info("Starting passive scan for {}", domain)

        previous_findings = self.store.get_latest_findings(domain)

        crawler = HttpCrawler(self.settings)
        pages, pdf_urls = await crawler.crawl(domain)

        pdfs = await PdfCollector(self.settings).fetch(pdf_urls)
        subdomains = await SubdomainCollector(self.settings).collect(domain, pages)

        findings: list[Finding] = []
        findings.extend(
            Finding(
                type="subdomain",
                value=subdomain,
                source="passive discovery",
                severity="low" if subdomain != domain else "info",
                evidence="Found via crawl, certificate transparency, or target root",
            )
            for subdomain in sorted(subdomains)
        )
        findings.extend(extract_emails_from_pages(pages))
        findings.extend(extract_emails_from_pdfs(pdfs))
        findings.extend(extract_pdf_metadata(pdfs))
        findings.extend(identify_technologies(pages))
        findings.extend(extract_ips_from_pages(pages))
        findings.extend(extract_possible_secrets_from_pages(pages))
        findings.extend(extract_possible_secrets_from_pdfs(pdfs))
        findings.extend(await DnsEnricher().resolve(subdomains))

        findings = self.correlation.deduplicate(findings)
        exposure_score = self.scorer.score(findings)
        changes = self.correlation.compare(previous_findings, findings)
        summary = self.correlation.summarize(findings, pages_crawled=len(pages), pdfs_analyzed=len(pdfs))

        result = ScanResult(
            scan_id=None,
            domain=domain,
            started_at=started_at,
            completed_at=utc_now(),
            findings=findings,
            exposure_score=exposure_score,
            summary=summary,
            changes=changes,
        )

        scan_id = self.store.save_scan(result)
        result.scan_id = scan_id
        artifacts = self.reporter.export(result)
        self.store.update_artifacts(scan_id, artifacts.to_dict())

        logger.success("Scan completed for {} with exposure score {}", domain, exposure_score)
        return result


def normalize_domain(target: str) -> str:
    value = target.strip().lower()
    parsed = urlparse(value if "://" in value else f"https://{value}")
    hostname = parsed.hostname or value
    return hostname.strip(".")
