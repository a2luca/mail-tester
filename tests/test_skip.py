"""Tests for skip_reason()."""

from email import policy
from email.parser import BytesParser

from mailtest.app import skip_reason
from tests.conftest import load_eml

MY_ADDR = "mail-test@lucalutz.net"


def parse(raw: bytes):
    return BytesParser(policy=policy.default).parsebytes(raw)


def test_bounce():
    msg = parse(load_eml("bounce.eml"))
    assert skip_reason(msg, "MAILER-DAEMON@example.com", MY_ADDR) == "null Return-Path (bounce)"


def test_auto_reply():
    msg = parse(load_eml("auto_reply.eml"))
    reason = skip_reason(msg, "someone@example.com", MY_ADDR)
    assert reason is not None and "Auto-Submitted" in reason


def test_mailing_list():
    msg = parse(load_eml("list.eml"))
    assert skip_reason(msg, "list@example.com", MY_ADDR) == "mailing list"


def test_no_reply_localpart():
    raw = b"From: noreply@example.com\r\nSubject: t\r\n\r\n"
    msg = parse(raw)
    assert skip_reason(msg, "noreply@example.com", MY_ADDR) == "no-reply/system sender"


def test_mail_from_ourselves():
    raw = b"From: mail-test@lucalutz.net\r\nSubject: t\r\n\r\n"
    msg = parse(raw)
    assert skip_reason(msg, MY_ADDR, MY_ADDR) == "mail from ourselves"


def test_invalid_address():
    raw = b"From: notanemail\r\nSubject: t\r\n\r\n"
    msg = parse(raw)
    assert skip_reason(msg, "notanemail", MY_ADDR) == "no valid From address"


def test_normal_mail_passes():
    msg = parse(load_eml("basic.eml"))
    assert skip_reason(msg, "sender@example.com", MY_ADDR) is None


def test_precedence_bulk():
    raw = b"From: bulk@example.com\r\nPrecedence: bulk\r\n\r\n"
    msg = parse(raw)
    assert skip_reason(msg, "bulk@example.com", MY_ADDR) == "Precedence bulk/list/junk"
