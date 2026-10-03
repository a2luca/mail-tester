"""Shared fixtures for mailtest tests."""

from pathlib import Path
from unittest.mock import MagicMock
from zoneinfo import ZoneInfo

import dns.resolver

from mailtest.config import Config

FIXTURES = Path(__file__).parent / "fixtures"


def load_eml(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def make_config(**overrides) -> Config:
    resolver = MagicMock(spec=dns.resolver.Resolver)
    resolver.lifetime = 5

    defaults = dict(
        imap_host="mail.example.com",
        imap_port=993,
        smtp_host="mail.example.com",
        smtp_port=587,
        mail_user="mail-test@lucalutz.net",
        mail_password="secret",
        mail_address="mail-test@lucalutz.net",
        trigger_subject="Mailtest",
        alert_to="info@lucalutz.net",
        alert_threshold=5,
        per_sender_limit=5,
        folders=["INBOX", "Junk"],
        processed_folder="Processed",
        poll_seconds=30,
        my_hostname="mail.example.com",
        tz=ZoneInfo("Europe/Berlin"),
        db_path=":memory:",
        max_attach_bytes=5 * 1024 * 1024,
        company_name="Test Company",
        contact_address="info@lucalutz.net",
        logo_url="https://example.com/logo.png",
        website_url="https://example.com",
        resolver=resolver,
    )
    defaults.update(overrides)
    return Config(**defaults)
