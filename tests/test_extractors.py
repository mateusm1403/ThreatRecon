from threatrecon.app.core.models import Page, PdfDocument
from threatrecon.app.extractors.emails import extract_emails_from_pages
from threatrecon.app.extractors.pdf_metadata import extract_pdf_metadata
from threatrecon.app.extractors.secrets import extract_possible_secrets_from_pages
from threatrecon.app.extractors.technologies import identify_technologies


def test_email_extraction_from_html() -> None:
    page = Page(
        url="https://example.com",
        status_code=200,
        content_type="text/html",
        html="Contact Security@Example.com for details",
        headers={},
    )

    findings = extract_emails_from_pages([page])

    assert findings[0].value == "security@example.com"


def test_pdf_metadata_extraction() -> None:
    pdf = PdfDocument(
        url="https://example.com/file.pdf",
        content=b"%PDF-1.4 /Author (Jane Doe) /Creator (Office) /Producer (PDF Engine)",
        headers={},
    )

    findings = extract_pdf_metadata([pdf])

    assert findings
    assert findings[0].metadata["Author"] == "Jane Doe"


def test_secret_redaction() -> None:
    page = Page(
        url="https://example.com",
        status_code=200,
        content_type="text/html",
        html="window.apiKey = 'abcdefghijklmnopqrstuvwxyz123456'",
        headers={},
    )

    findings = extract_possible_secrets_from_pages([page])

    assert findings
    assert "..." in findings[0].value


def test_technology_identification() -> None:
    page = Page(
        url="https://example.com",
        status_code=200,
        content_type="text/html",
        html='<script src="/wp-content/themes/site/jquery.js"></script>',
        headers={"server": "nginx"},
    )

    values = {finding.value for finding in identify_technologies([page])}

    assert {"WordPress", "jQuery", "nginx"} <= values
