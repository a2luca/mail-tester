"""Tests for build reply message and HTML escaping."""

from email import policy
from email.parser import BytesParser
from unittest.mock import patch

from mailtest.app import build_html, build_report, find_client, parse_received, send_reply
from tests.conftest import load_eml, make_config


def parse(raw: bytes):
    return BytesParser(policy=policy.default).parsebytes(raw)


def test_reply_structure():
    """Reply must be multipart/alternative with text + HTML, plus original.eml."""
    cfg = make_config()
    raw = load_eml("basic.eml")
    msg = parse(raw)
    hops = [parse_received(h) for h in (msg.get_all("Received") or [])]
    client = find_client(hops, cfg.my_hostname)

    with patch("mailtest.app.smtp_send") as mock_send:
        report, facts = build_report(cfg, msg, raw, hops, client, "INBOX")
        send_reply(cfg, msg, raw, "sender@example.com", report, facts)

    mock_send.assert_called_once()
    reply = mock_send.call_args[0][1]

    # Subject
    assert "Re:" in reply["Subject"]
    assert "Ergebnis" in reply["Subject"]

    # Reply-To and Auto-Submitted
    assert reply["Reply-To"] == cfg.contact_address
    assert reply["Auto-Submitted"] == "auto-replied"

    # In-Reply-To threading
    assert reply["In-Reply-To"] == "<test-basic@example.com>"

    # Multipart structure: text + HTML + attachment
    payloads = list(reply.iter_attachments())
    assert any(p.get_filename() == "original.eml" for p in payloads)

    parts = list(reply.walk())
    content_types = [p.get_content_type() for p in parts]
    assert "text/plain" in content_types
    assert "text/html" in content_types
    assert "application/octet-stream" in content_types


def test_html_escaping_in_report():
    """Headers with <script> tags must be escaped in HTML output."""
    cfg = make_config()
    raw = load_eml("xss.eml")
    msg = parse(raw)
    hops = [parse_received(h) for h in (msg.get_all("Received") or [])]
    client = find_client(hops, cfg.my_hostname)
    report, facts = build_report(cfg, msg, raw, hops, client, "INBOX")
    html_out = build_html(cfg, facts, report)

    assert "<script>" not in html_out
    assert "&lt;script&gt;" in html_out


def test_html_escaping_in_company_name():
    cfg = make_config(company_name='Test <b>"Co"</b>')
    raw = load_eml("basic.eml")
    msg = parse(raw)
    hops = [parse_received(h) for h in (msg.get_all("Received") or [])]
    client = find_client(hops, cfg.my_hostname)
    report, facts = build_report(cfg, msg, raw, hops, client, "INBOX")
    html_out = build_html(cfg, facts, report)

    # The company name must be escaped; unescaped tag must NOT appear as user content
    assert 'Test &lt;b&gt;' in html_out
    # The raw unescaped tag from company_name must not appear literally
    assert 'Test <b>' not in html_out


def test_reply_skips_attachment_when_too_large():
    cfg = make_config(max_attach_bytes=1)  # 1 byte limit → skip attachment
    raw = load_eml("basic.eml")
    msg = parse(raw)
    hops = [parse_received(h) for h in (msg.get_all("Received") or [])]
    client = find_client(hops, cfg.my_hostname)

    with patch("mailtest.app.smtp_send") as mock_send:
        report, facts = build_report(cfg, msg, raw, hops, client, "INBOX")
        send_reply(cfg, msg, raw, "sender@example.com", report, facts)

    reply = mock_send.call_args[0][1]
    payloads = list(reply.iter_attachments())
    assert not any(p.get_filename() == "original.eml" for p in payloads)


def test_junk_folder_flagged_in_report():
    cfg = make_config()
    raw = load_eml("basic.eml")
    msg = parse(raw)
    hops = [parse_received(h) for h in (msg.get_all("Received") or [])]
    client = find_client(hops, cfg.my_hostname)
    report, facts = build_report(cfg, msg, raw, hops, client, "Junk")
    assert "Junk" in report
    assert facts["folder"] == "Junk"
