"""Tests for auth_summary() including the Rspamd fallback."""

from email import policy
from email.parser import BytesParser

from mailtest.app import auth_summary
from tests.conftest import load_eml


def parse(eml_bytes: bytes):
    return BytesParser(policy=policy.default).parsebytes(eml_bytes)


def test_auth_results_header():
    msg = parse(load_eml("basic.eml"))
    results, headers, source = auth_summary(msg, "mail.example.com")
    assert source == "Authentication-Results"
    assert results["spf"] == ["pass"]
    assert results["dkim"] == ["pass"]
    assert results["dmarc"] == ["pass"]


def test_auth_filters_by_hostname():
    """Headers from a different host must be ignored when MY_HOSTNAME is set."""
    raw = b"""\
From: x@example.com\r\nTo: y@example.com\r\nSubject: t\r\n\
Authentication-Results: attacker.net; spf=pass\r\n\
Authentication-Results: mail.example.com; spf=fail\r\n\r\nbody"""
    msg = parse(raw)
    results, _, source = auth_summary(msg, "mail.example.com")
    assert results["spf"] == ["fail"]


def test_auth_rspamd_fallback():
    msg = parse(load_eml("rspamd.eml"))
    # No Authentication-Results header present in this fixture
    results, _, source = auth_summary(msg, "mail.example.com")
    assert source == "Rspamd symbols"
    assert results["spf"] == ["pass"]
    assert results["dkim"] == ["pass"]
    assert results["dmarc"] == ["pass"]


def test_auth_no_hostname_filter():
    """With empty MY_HOSTNAME all Authentication-Results headers are trusted."""
    raw = b"""\
From: x@example.com\r\nTo: y@example.com\r\nSubject: t\r\n\
Authentication-Results: someserver.net; spf=pass\r\n\r\nbody"""
    msg = parse(raw)
    results, _, source = auth_summary(msg, "")
    assert source == "Authentication-Results"
    assert results["spf"] == ["pass"]
