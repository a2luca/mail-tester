"""Tests for Received header parsing and find_client()."""


from mailtest.app import find_client, parse_received


def test_parse_basic():
    raw = (
        "from mail.example.com (mail.example.com [1.2.3.4])"
        " by mail.example.com with ESMTPS id abc;"
        " Mon, 01 Jan 2024 10:00:00 +0000"
    )
    hop = parse_received(raw)
    assert hop["helo"] == "mail.example.com"
    assert hop["ip"] == "1.2.3.4"
    assert hop["rdns"] == "mail.example.com"
    assert hop["by"] == "mail.example.com"
    assert hop["with"] == "ESMTPS"
    assert "date" in hop


def test_parse_tls():
    raw = (
        "from smtp.sender.net (smtp.sender.net [5.6.7.8])"
        " by mail.example.com with ESMTPS id xyz"
        " using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384;"
        " Mon, 01 Jan 2024 12:00:00 +0000"
    )
    hop = parse_received(raw)
    assert hop["tls"] == "TLSv1.3 TLS_AES_256_GCM_SHA384"
    assert hop["ip"] == "5.6.7.8"


def test_parse_ipv6():
    raw = (
        "from host6.example.com (host6.example.com [IPv6:2600:1:2:3::1])"
        " by mail.example.com with ESMTP id aaa;"
        " Mon, 01 Jan 2024 10:00:00 +0000"
    )
    hop = parse_received(raw)
    assert hop["ip"] == "2600:1:2:3::1"


def test_find_client_matches_hostname():
    hops = [
        parse_received(
            "from mail.example.com (mail.example.com [1.2.3.4])"
            " by mail.example.com with ESMTP id a;"
            " Mon, 01 Jan 2024 10:00:00 +0000"
        ),
        parse_received(
            "from localhost (localhost [127.0.0.1])"
            " by mail.example.com with ESMTP id b;"
            " Mon, 01 Jan 2024 09:59:00 +0000"
        ),
    ]
    client = find_client(hops, "mail.example.com")
    assert client is not None
    assert client["ip"] == "1.2.3.4"


def test_find_client_skips_private():
    hops = [
        parse_received(
            "from localhost (localhost [127.0.0.1])"
            " by mail.example.com with ESMTP id a;"
            " Mon, 01 Jan 2024 10:00:00 +0000"
        ),
    ]
    client = find_client(hops, "mail.example.com")
    assert client is None


def test_find_client_fallback_warns_when_no_mx_hop(caplog):
    """Fallback must only trigger when NO hop was received by MY_HOSTNAME."""
    import logging

    hops = [
        parse_received(
            "from relay.other.net (relay.other.net [9.10.11.12])"
            " by someother.net with ESMTP id a;"
            " Mon, 01 Jan 2024 10:00:00 +0000"
        ),
    ]
    with caplog.at_level(logging.WARNING, logger="mailtest"):
        client = find_client(hops, "mail.example.com")
    assert client is not None
    assert client["ip"] == "9.10.11.12"
    assert "fallback" in caplog.text.lower()


def test_find_client_no_fallback_when_mx_hop_exists():
    """When a hop was received by MY_HOSTNAME, do NOT fall back to other hops."""
    hops = [
        # Newest first: the hop received by our MX
        parse_received(
            "from mail.example.com (mail.example.com [1.2.3.4])"
            " by mail.example.com with ESMTP id a;"
            " Mon, 01 Jan 2024 10:00:00 +0000"
        ),
        # An older hop received by a different host — must NOT be chosen
        parse_received(
            "from evil.net (evil.net [13.14.15.16])"
            " by relay.other.net with ESMTP id b;"
            " Mon, 01 Jan 2024 09:58:00 +0000"
        ),
    ]
    client = find_client(hops, "mail.example.com")
    assert client["ip"] == "1.2.3.4"


def test_find_client_tls_hop():
    raw = (
        "from smtp.sender.net (smtp.sender.net [5.6.7.8])"
        " by mail.example.com with ESMTPS id xyz"
        " using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384;"
        " Mon, 01 Jan 2024 12:00:00 +0000"
    )
    hops = [parse_received(raw)]
    client = find_client(hops, "mail.example.com")
    assert client is not None
    assert client["tls"] == "TLSv1.3 TLS_AES_256_GCM_SHA384"
