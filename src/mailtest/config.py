"""Runtime configuration loaded from environment variables."""

import os
import sys
from dataclasses import dataclass, field
from zoneinfo import ZoneInfo

import dns.resolver


def _env(name: str, default: str | None = None, required: bool = False) -> str | None:
    value = os.environ.get(name, default)
    if required and not value:
        sys.exit(f"missing required environment variable {name}")
    return value


@dataclass
class Config:
    imap_host: str
    imap_port: int
    smtp_host: str
    smtp_port: int
    mail_user: str
    mail_password: str
    mail_address: str
    trigger_subject: str
    alert_to: str
    alert_threshold: int
    per_sender_limit: int
    folders: list[str]
    processed_folder: str
    poll_seconds: int
    my_hostname: str
    tz: ZoneInfo
    db_path: str
    max_attach_bytes: int
    company_name: str
    contact_address: str
    logo_url: str
    website_url: str
    resolver: dns.resolver.Resolver = field(repr=False)


def load_config() -> Config:
    imap_host = _env("IMAP_HOST", required=True)
    smtp_host = _env("SMTP_HOST", imap_host)
    mail_user = _env("MAIL_USER", required=True)
    mail_address = _env("MAIL_ADDRESS", mail_user)
    dns_server = _env("DNS_SERVER", "")

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5
    if dns_server:
        resolver.nameservers = [s.strip() for s in dns_server.split(",") if s.strip()]

    return Config(
        imap_host=imap_host,
        imap_port=int(_env("IMAP_PORT", "993")),
        smtp_host=smtp_host,
        smtp_port=int(_env("SMTP_PORT", "587")),
        mail_user=mail_user,
        mail_password=_env("MAIL_PASSWORD", required=True),
        mail_address=mail_address,
        trigger_subject=_env("TRIGGER_SUBJECT", "Mailtest"),
        alert_to=_env("ALERT_TO", "info@lucalutz.net"),
        alert_threshold=int(_env("ALERT_THRESHOLD", "5")),
        per_sender_limit=int(_env("PER_SENDER_LIMIT_PER_HOUR", "5")),
        folders=[f.strip() for f in _env("FOLDERS", "INBOX,Junk").split(",") if f.strip()],
        processed_folder=_env("PROCESSED_FOLDER", "Processed"),
        poll_seconds=int(_env("POLL_SECONDS", "30")),
        my_hostname=(_env("MY_HOSTNAME", "") or "").lower().rstrip("."),
        tz=ZoneInfo(_env("TZ", "Europe/Berlin")),
        db_path=_env("DB_PATH", "/data/state.db"),
        max_attach_bytes=int(_env("MAX_ATTACH_BYTES", str(5 * 1024 * 1024))),
        company_name=_env("COMPANY_NAME", "Luca Lutz Networks"),
        contact_address=_env("CONTACT_ADDRESS", "info@lucalutz.net"),
        logo_url=_env("LOGO_URL", "https://lucalutz.net/logo-llwn.png"),
        website_url=_env("WEBSITE_URL", "https://lucalutz.net"),
        resolver=resolver,
    )
