"""Tests for per-sender rate limit and daily alert using a temp SQLite DB."""

import sqlite3
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from mailtest.app import db_connect, maybe_alert, record_use, replies_last_hour
from tests.conftest import make_config


def make_db() -> sqlite3.Connection:
    return db_connect(":memory:")


def test_rate_limit_within_window():
    db = make_db()
    cfg = make_config(per_sender_limit=2)
    for _ in range(2):
        record_use(db, cfg.tz, "sender@example.com", "1.2.3.4", "replied")
    assert replies_last_hour(db, "sender@example.com") == 2


def test_rate_limit_case_insensitive():
    db = make_db()
    cfg = make_config()
    record_use(db, cfg.tz, "Sender@Example.COM", "1.2.3.4", "replied")
    assert replies_last_hour(db, "sender@example.com") == 1


def test_rate_limit_outside_window():
    db = make_db()
    old_ts = (datetime.now(UTC) - timedelta(hours=2)).isoformat(timespec="seconds")
    db.execute(
        "INSERT INTO uses (ts, day, sender, client_ip, status) VALUES (?,?,?,?,?)",
        (old_ts, "2024-01-01", "sender@example.com", "1.2.3.4", "replied"),
    )
    db.commit()
    assert replies_last_hour(db, "sender@example.com") == 0


def test_daily_alert_sent():
    db = make_db()
    cfg = make_config(alert_threshold=2)

    # Record 3 uses to exceed threshold of 2
    for i in range(3):
        record_use(db, cfg.tz, f"u{i}@example.com", "1.2.3.4", "replied")

    with patch("mailtest.app.smtp_send") as mock_send:
        maybe_alert(cfg, db)
        mock_send.assert_called_once()
        alert_msg = mock_send.call_args[0][1]
        assert "[mailtest]" in str(alert_msg["Subject"])

    # Second call must NOT send again
    with patch("mailtest.app.smtp_send") as mock_send2:
        maybe_alert(cfg, db)
        mock_send2.assert_not_called()


def test_daily_alert_not_sent_below_threshold():
    db = make_db()
    cfg = make_config(alert_threshold=5)

    for i in range(3):
        record_use(db, cfg.tz, f"u{i}@example.com", "1.2.3.4", "replied")

    with patch("mailtest.app.smtp_send") as mock_send:
        maybe_alert(cfg, db)
        mock_send.assert_not_called()
