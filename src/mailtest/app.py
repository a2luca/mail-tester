"""Core logic: parsing, report building, sending, IMAP polling."""

import html
import imaplib
import ipaddress
import logging
import re
import smtplib
import sqlite3
import ssl
import time
from datetime import UTC, datetime, timedelta
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import formatdate, make_msgid, parseaddr, parsedate_to_datetime

import dns.reversename

from .config import Config

log = logging.getLogger("mailtest")

ADDR_RE = re.compile(r"^[^@\s<>\"]+@[^@\s<>\"]+\.[^@\s<>\"]+$")
NO_REPLY_LOCALPARTS = {
    "mailer-daemon",
    "postmaster",
    "noreply",
    "no-reply",
    "do-not-reply",
    "donotreply",
    "bounce",
    "bounces",
}

GOOD = ("#1e7e34", "#e6f4ea")
WARN = ("#8a5a00", "#fef3d6")
BAD = ("#b3261e", "#fce8e6")
NEUTRAL = ("#5f6368", "#f1f3f4")
BRAND = "#032d41"

RESULT_DE = {
    "pass": "bestanden",
    "fail": "nicht bestanden",
    "softfail": "nicht bestanden (softfail)",
    "neutral": "neutral",
    "none": "nicht eingerichtet",
    "temperror": "vorübergehender Fehler",
    "permerror": "fehlerhaft eingerichtet",
    "policy": "durch Richtlinie abgelehnt",
}

SPF_MAP = {
    "R_SPF_ALLOW": "pass",
    "R_SPF_FAIL": "fail",
    "R_SPF_SOFTFAIL": "softfail",
    "R_SPF_NEUTRAL": "neutral",
    "R_SPF_NA": "none",
    "R_SPF_DNSFAIL": "temperror",
    "R_SPF_PERMFAIL": "permerror",
}
DKIM_MAP = {
    "R_DKIM_ALLOW": "pass",
    "R_DKIM_REJECT": "fail",
    "R_DKIM_NA": "none",
    "R_DKIM_TEMPFAIL": "temperror",
    "R_DKIM_PERMFAIL": "permerror",
}
DMARC_MAP = {
    "DMARC_POLICY_ALLOW": "pass",
    "DMARC_POLICY_ALLOW_WITH_FAILURES": "pass (with failures)",
    "DMARC_POLICY_REJECT": "fail (p=reject)",
    "DMARC_POLICY_QUARANTINE": "fail (p=quarantine)",
    "DMARC_POLICY_SOFTFAIL": "fail (p=none)",
    "DMARC_NA": "none",
    "DMARC_BAD_POLICY": "bad policy",
    "DMARC_DNSFAIL": "temperror",
}

IP_IN_BRACKETS = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]")


# ----------------------------------------------------------------- helpers


def norm(value) -> str:
    return " ".join(str(value).split()) if value is not None else ""


def is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def parse_tags(value: str) -> dict[str, str]:
    tags = {}
    for part in value.split(";"):
        if "=" in part:
            key, val = part.split("=", 1)
            tags[key.strip().lower()] = "".join(val.split())
    return tags


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[1].lower() if addr and "@" in addr else ""


# --------------------------------------------------------------------- DNS


def _dns_query(resolver, name: str, rtype: str):
    import dns.resolver

    try:
        return list(resolver.resolve(name, rtype)), None
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return [], "no record"
    except Exception as exc:
        return [], f"lookup error ({exc.__class__.__name__})"


def txt_records(resolver, name: str):
    recs, err = _dns_query(resolver, name, "TXT")
    return [b"".join(r.strings).decode("utf-8", "replace") for r in recs], err


def rdns_info(resolver, ip: str):
    try:
        rev = dns.reversename.from_address(ip)
    except Exception:
        return [], False, "invalid IP"
    ptrs, err = _dns_query(resolver, rev, "PTR")
    names = [str(p.target).rstrip(".") for p in ptrs]
    if not names:
        return [], False, err
    rtype = "AAAA" if ipaddress.ip_address(ip).version == 6 else "A"
    confirmed = False
    for name in names:
        addrs, _ = _dns_query(resolver, name, rtype)
        if any(ipaddress.ip_address(a.address) == ipaddress.ip_address(ip) for a in addrs):
            confirmed = True
    return names, confirmed, None


def tagged_records(resolver, name: str, prefix: str):
    recs, err = txt_records(resolver, name)
    hits = [r for r in recs if r.lower().startswith(prefix.lower())]
    return hits, (err if not hits else None)


def dns_section(resolver, domain: str) -> list[str]:
    out = [f"Domain: {domain}"]

    mx, err = _dns_query(resolver, domain, "MX")
    if mx:
        for r in sorted(mx, key=lambda r: r.preference):
            out.append(f"  MX       {r.preference:>3} {str(r.exchange).rstrip('.')}")
    else:
        out.append(f"  MX       none ({err})")

    spf, err = tagged_records(resolver, domain, "v=spf1")
    if not spf:
        out.append(f"  SPF      none ({err or 'no v=spf1 record'})")
    for rec in spf:
        out.append(f"  SPF      {rec}")
    if len(spf) > 1:
        out.append("  SPF      WARNING: more than one SPF record -> permerror")

    dmarc, err = tagged_records(resolver, f"_dmarc.{domain}", "v=DMARC1")
    out.append(
        f"  DMARC    {dmarc[0]}" if dmarc else f"  DMARC    none ({err or 'no v=DMARC1 record'})"
    )

    sts, _ = tagged_records(resolver, f"_mta-sts.{domain}", "v=STSv1")
    out.append(f"  MTA-STS  {sts[0] if sts else 'none'}")

    rpt, _ = tagged_records(resolver, f"_smtp._tls.{domain}", "v=TLSRPTv1")
    out.append(f"  TLS-RPT  {rpt[0] if rpt else 'none'}")

    bimi, _ = tagged_records(resolver, f"default._bimi.{domain}", "v=BIMI1")
    out.append(f"  BIMI     {bimi[0] if bimi else 'none'}")
    return out


# --------------------------------------------------------- Received parsing


def parse_received(value: str) -> dict:
    v = norm(value)
    hop = {"raw": v}
    body, sep, date = v.rpartition(";")
    if not sep:
        body, date = v, ""

    m = re.match(r"from\s+(\S+)(?:\s+\(([^()]*)\))?", body, re.I)
    if m:
        hop["helo"] = m.group(1)
        info = m.group(2) or ""
        ipm = IP_IN_BRACKETS.search(info)
        if ipm:
            hop["ip"] = ipm.group(1)
        claimed = info.split("[")[0].strip()
        if claimed:
            hop["rdns"] = claimed
    if "ip" not in hop:
        ipm = IP_IN_BRACKETS.search(body)
        if ipm:
            hop["ip"] = ipm.group(1)

    by = re.search(r"\bby\s+(\S+)", body, re.I)
    if by:
        hop["by"] = by.group(1)
        w = re.search(r"\bwith\s+(\S+)", body[by.end() :], re.I)
        if w:
            hop["with"] = w.group(1)

    tls = re.search(r"\busing\s+((?:TLS|SSL)v?[\d.]+)\s+with\s+cipher\s+(\S+)", body, re.I)
    if tls:
        hop["tls"] = f"{tls.group(1)} {tls.group(2)}"

    if date.strip():
        try:
            hop["date"] = parsedate_to_datetime(date.strip())
        except Exception:
            pass
    return hop


def find_client(hops: list[dict], my_hostname: str) -> dict | None:
    """Return the first hop (newest first) where a public IP connected to our MX."""
    for hop in hops:
        if not is_public(hop.get("ip", "")):
            continue
        if my_hostname and not hop.get("by", "").lower().rstrip(".").startswith(my_hostname):
            continue
        return hop
    if my_hostname:
        # Fall back only when no hop matched MY_HOSTNAME at all
        for hop in hops:
            if is_public(hop.get("ip", "")):
                log.warning(
                    "find_client fallback: no hop received by %s, using %s",
                    my_hostname,
                    hop.get("ip"),
                )
                return hop
    return None


# ---------------------------------------------------------- authentication


def rspamd_symbols(msg) -> list[str]:
    value = norm(msg.get("X-Spamd-Result", ""))
    return re.findall(r"\b([A-Z][A-Z0-9_]+)\(", value)


def auth_summary(msg, my_hostname: str):
    all_headers = [norm(h) for h in (msg.get_all("Authentication-Results") or [])]
    trusted = all_headers
    if my_hostname:
        trusted = [
            h
            for h in all_headers
            if h.split(";", 1)[0].strip().lower().rstrip(".").startswith(my_hostname)
        ]
    if not trusted and all_headers:
        trusted = all_headers[:1]

    results = {}
    for h in trusted:
        for key, res in re.findall(r"\b(spf|dkim|dmarc|arc)=([a-z]+)", h, re.I):
            results.setdefault(key.lower(), []).append(res.lower())
    if results:
        return results, trusted, "Authentication-Results"

    symbols = rspamd_symbols(msg)
    for key, mapping in (("spf", SPF_MAP), ("dkim", DKIM_MAP), ("dmarc", DMARC_MAP)):
        hits = [mapping[s] for s in symbols if s in mapping]
        if hits:
            results[key] = hits
    return results, trusted, "Rspamd symbols" if results else "none found"


def spam_score(msg) -> str:
    score = norm(msg.get("X-Rspamd-Score", ""))
    if score:
        return score
    m = re.search(r"\[\s*(-?[\d.]+)\s*/\s*(-?[\d.]+)\s*\]", norm(msg.get("X-Spamd-Result", "")))
    return f"{m.group(1)} / {m.group(2)}" if m else ""


def aligned(a: str, b: str) -> bool:
    return bool(a and b) and (a == b or a.endswith("." + b) or b.endswith("." + a))


# ------------------------------------------------------------------- report


def mime_tree(part, depth: int = 0) -> list[str]:
    extra = []
    charset = part.get_content_charset()
    if charset:
        extra.append(f"charset={charset}")
    cte = part.get("Content-Transfer-Encoding")
    if cte:
        extra.append(f"cte={norm(cte)}")
    filename = part.get_filename()
    if filename:
        extra.append(f'filename="{filename}"')
    if not part.is_multipart():
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        extra.append(f"{len(payload)} bytes")
    lines = [
        "  " * (depth + 1)
        + "- "
        + part.get_content_type()
        + (f" ({', '.join(extra)})" if extra else "")
    ]
    if part.is_multipart():
        for sub in part.get_payload():
            lines += mime_tree(sub, depth + 1)
    return lines


def build_report(cfg: Config, msg, raw: bytes, hops: list[dict], client: dict | None, folder: str):
    out = []
    add = out.append

    def section(title):
        add("")
        add(title)
        add("-" * len(title))

    from_addr = parseaddr(norm(msg.get("From", "")))[1]
    from_domain = domain_of(from_addr)
    rp_addr = parseaddr(norm(msg.get("Return-Path", "")))[1]
    rp_domain = domain_of(rp_addr)
    facts = {
        "folder": folder,
        "from": from_addr,
        "ip": None,
        "ptr": [],
        "fcrdns": False,
        "tls": None,
    }

    add("MAILTEST REPORT")
    add("=" * 60)
    add(f"Generated:     {datetime.now(cfg.tz):%Y-%m-%d %H:%M:%S %Z}")
    folder_note = (
        "  <-- the spam filter put this mail into Junk!" if folder.lower() == "junk" else ""
    )
    add(f"Delivered to:  {folder}{folder_note}")

    section("Message")
    for name in (
        "From",
        "Sender",
        "Reply-To",
        "Return-Path",
        "To",
        "Cc",
        "Date",
        "Message-ID",
        "Subject",
        "User-Agent",
        "X-Mailer",
    ):
        if msg.get(name):
            add(f"  {name + ':':<14} {norm(msg[name])}")
    add(f"  {'Size:':<14} {len(raw)} bytes")

    section("Connecting server (as seen by our MX)")
    if client:
        ip = client["ip"]
        names, confirmed, err = rdns_info(cfg.resolver, ip)
        facts.update(ip=ip, ptr=names, fcrdns=confirmed, tls=client.get("tls"))
        add(f"  IP:           {ip}")
        if names:
            add(f"  PTR (rDNS):   {', '.join(names)}")
            add(
                f"  FCrDNS:       {'OK (PTR resolves back to the IP)' if confirmed else 'FAIL (PTR does not resolve back to the IP)'}"
            )
        else:
            add(f"  PTR (rDNS):   none ({err})  <-- many receivers reject mail without rDNS")
        add(f"  HELO/EHLO:    {client.get('helo', '-')}")
        if client.get("rdns"):
            add(f"  MTA logged:   {client['rdns']}")
        add(f"  TLS:          {client.get('tls', 'none / not recorded')}")
        add(f"  Protocol:     {client.get('with', '-')}")
        add(f"  Received by:  {client.get('by', '-')}")
        if client.get("date"):
            add(f"  Received at:  {client['date'].astimezone(cfg.tz):%Y-%m-%d %H:%M:%S %Z}")
    else:
        add("  could not be determined (no public IP in the Received headers)")

    section("Authentication")
    results, auth_headers, source = auth_summary(msg, cfg.my_hostname)
    for key in ("spf", "dkim", "dmarc", "arc"):
        add(f"  {key.upper():<6} {', '.join(results.get(key, ['-']))}")
    add(f"  (source: {source})")
    dkim_domains = [
        parse_tags(norm(s)).get("d", "").lower() for s in (msg.get_all("DKIM-Signature") or [])
    ]
    add(f"  From domain:         {from_domain or '-'}")
    add(
        f"  Return-Path domain:  {rp_domain or '-'}"
        + (
            f"  (SPF alignment: {'yes' if aligned(from_domain, rp_domain) else 'NO'})"
            if rp_domain
            else ""
        )
    )
    if dkim_domains:
        add(
            f"  DKIM d= domains:     {', '.join(d or '?' for d in dkim_domains)}"
            f"  (DKIM alignment: {'yes' if any(aligned(from_domain, d) for d in dkim_domains) else 'NO'})"
        )
    score = spam_score(msg)
    facts.update(auth=results, score=score)
    if score:
        add(f"  Spam score:          {score}")
    for h in auth_headers:
        add(f"  Authentication-Results: {h}")

    section("DKIM signatures")
    sigs = msg.get_all("DKIM-Signature") or []
    if not sigs:
        add("  none - the message is not DKIM-signed")
    for sig in sigs:
        tags = parse_tags(norm(sig))
        d, s = tags.get("d"), tags.get("s")
        add(f"  d={d} s={s} a={tags.get('a')} c={tags.get('c', 'simple/simple')}")
        if d and s:
            recs, err = txt_records(cfg.resolver, f"{s}._domainkey.{d}")
            keys = [r for r in recs if "p=" in r]
            if keys:
                ktags = parse_tags(keys[0])
                if not ktags.get("p"):
                    add(f"    {s}._domainkey.{d}: key REVOKED (empty p=)")
                else:
                    add(
                        f"    {s}._domainkey.{d}: key found "
                        f"(k={ktags.get('k', 'rsa')}, {len(ktags['p'])} base64 chars)"
                    )
            else:
                add(f"    {s}._domainkey.{d}: no key record ({err or 'no p= tag'})")

    section("DNS records")
    domains = [d for d in dict.fromkeys([from_domain, rp_domain]) if d]
    if not domains:
        add("  no sender domain found")
    for d in domains:
        out.extend("  " + line for line in dns_section(cfg.resolver, d))

    section("Received path (oldest first)")
    if not hops:
        add("  no Received headers")
    prev_date = None
    for i, hop in enumerate(reversed(hops), 1):
        src = hop.get("helo", "?")
        if hop.get("ip"):
            src += f" [{hop['ip']}]"
        line = f"  {i:>2}. {src} -> {hop.get('by', '?')}"
        if hop.get("with"):
            line += f"  with {hop['with']}"
        if hop.get("tls"):
            line += f"  ({hop['tls']})"
        add(line)
        if hop.get("date"):
            when = f"{hop['date'].astimezone(cfg.tz):%Y-%m-%d %H:%M:%S %Z}"
            if prev_date:
                when += f"  (+{int((hop['date'] - prev_date).total_seconds())}s)"
            add(f"      {when}")
            prev_date = hop["date"]

    spamd = norm(msg.get("X-Spamd-Result", ""))
    if spamd:
        section("Rspamd result")
        for part in spamd.split("; "):
            add(f"  {part}")

    section("MIME structure")
    out.extend(mime_tree(msg))

    section("Full headers (as stored in the mailbox)")
    sep = re.search(rb"\r?\n\r?\n", raw)
    header_block = raw[: sep.start()] if sep else raw
    add(header_block.decode("utf-8", "replace").replace("\r\n", "\n"))

    add("")
    add("-- ")
    add(
        f"Automated reply from {cfg.mail_address}. The original message is attached as original.eml."
    )
    return "\n".join(out), facts


# --------------------------------------------------------------- HTML mail


def classify(result):
    r = (result or "").lower()
    if r.startswith("pass"):
        return GOOD
    if r in ("", "-", "none"):
        return NEUTRAL
    if r.startswith(("neutral", "temperror")):
        return WARN
    return BAD


def to_german(result: str) -> str:
    if not result or result == "-":
        return "nicht vorhanden"
    word = result.split()[0].lower()
    return RESULT_DE.get(word, result)


def check_rows(facts: dict) -> list:
    auth = facts.get("auth", {})
    rows = []
    for key, title, question in (
        (
            "spf",
            "Absender-Berechtigung (SPF)",
            "Darf dieser Server für Ihre Domain E-Mails versenden?",
        ),
        ("dkim", "Digitale Signatur (DKIM)", "Ist die E-Mail unterwegs unverändert geblieben?"),
        ("dmarc", "Domain-Richtlinie (DMARC)", "Passt alles zusammen mit Ihrer Absender-Domain?"),
    ):
        value = (auth.get(key) or ["-"])[0]
        rows.append((title, question, to_german(value), classify(value)))

    if not facts.get("ip"):
        rows.append(
            (
                "Server-Name (rDNS)",
                "Hat der sendende Server einen gültigen Namen?",
                "nicht ermittelbar",
                NEUTRAL,
            )
        )
    elif not facts.get("ptr"):
        rows.append(
            (
                "Server-Name (rDNS)",
                "Hat der sendende Server einen gültigen Namen?",
                "kein Name hinterlegt",
                BAD,
            )
        )
    elif facts.get("fcrdns"):
        rows.append(
            (
                "Server-Name (rDNS)",
                "Hat der sendende Server einen gültigen Namen?",
                f"in Ordnung ({facts['ptr'][0]})",
                GOOD,
            )
        )
    else:
        rows.append(
            (
                "Server-Name (rDNS)",
                "Hat der sendende Server einen gültigen Namen?",
                f"passt nicht zusammen ({facts['ptr'][0]})",
                WARN,
            )
        )

    tls = facts.get("tls")
    rows.append(
        (
            "Verschlüsselung (TLS)",
            "Wurde die E-Mail verschlüsselt übertragen?",
            f"ja ({tls.split()[0]})" if tls else "nicht erkannt",
            GOOD if tls else WARN,
        )
    )

    junk = facts.get("folder", "").lower() == "junk"
    score_txt = facts.get("score") or ""
    try:
        score = float(score_txt.split("/")[0])
    except ValueError:
        score = None
    if junk:
        rows.append(
            (
                "Spam-Bewertung",
                "Wird Ihre E-Mail als normale Post erkannt?",
                f"als Spam eingestuft ({score_txt})",
                BAD,
            )
        )
    elif score is None:
        rows.append(
            (
                "Spam-Bewertung",
                "Wird Ihre E-Mail als normale Post erkannt?",
                "keine Bewertung",
                NEUTRAL,
            )
        )
    else:
        rows.append(
            (
                "Spam-Bewertung",
                "Wird Ihre E-Mail als normale Post erkannt?",
                f"unauffällig ({score_txt})" if score < 5 else f"grenzwertig ({score_txt})",
                GOOD if score < 5 else WARN,
            )
        )
    return rows


def build_html(cfg: Config, facts: dict, report_text: str) -> str:
    e = html.escape
    rows = check_rows(facts)
    problems = any(colors in (BAD, WARN) for *_, colors in rows)
    if problems:
        verdict = (
            "Es gibt Punkte, die Ihr IT-Betreuer sich ansehen sollte. "
            "Für Sie besteht kein Handlungsbedarf."
        )
        verdict_colors = WARN
    else:
        verdict = "Alles in Ordnung – Ihre E-Mails werden korrekt zugestellt."
        verdict_colors = GOOD

    row_html = ""
    for title, question, value, (fg, bg) in rows:
        row_html += f"""
          <tr>
            <td style="padding:12px 0;border-bottom:1px solid #e8eaed;">
              <div style="font-size:15px;font-weight:600;color:#202124;">{e(title)}</div>
              <div style="font-size:13px;color:#5f6368;padding-top:2px;">{e(question)}</div>
            </td>
            <td align="right" style="padding:12px 0 12px 12px;border-bottom:1px solid #e8eaed;white-space:nowrap;">
              <span style="display:inline-block;padding:4px 10px;border-radius:12px;background:{bg};color:{fg};font-size:13px;font-weight:600;">{e(value)}</span>
            </td>
          </tr>"""

    report = (
        report_text if len(report_text) <= 80000 else report_text[:80000] + "\n[... gekürzt ...]"
    )
    company = e(cfg.company_name)
    contact = e(cfg.contact_address)

    return f"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>Ihre Test-E-Mail ist angekommen</title>
</head>
<body style="margin:0;padding:0;background:#f1f3f4;font-family:Segoe UI,Helvetica,Arial,sans-serif;color:#202124;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f1f3f4;">
  <tr><td align="center" style="padding:24px 12px;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;background:#ffffff;border-radius:8px;overflow:hidden;">

      <tr><td style="padding:24px 32px 16px 32px;border-bottom:4px solid {BRAND};">
        <a href="{e(cfg.website_url)}" style="text-decoration:none;">
          <img src="{e(cfg.logo_url)}" width="240" alt="{company}" style="display:block;border:0;width:240px;max-width:100%;height:auto;">
        </a>
      </td></tr>

      <tr><td style="padding:28px 32px 8px 32px;">
        <h1 style="margin:0 0 12px 0;font-size:22px;color:{BRAND};">Ihre Test-E-Mail ist angekommen</h1>
        <p style="margin:0 0 12px 0;font-size:15px;line-height:1.55;">Guten Tag,</p>
        <p style="margin:0 0 12px 0;font-size:15px;line-height:1.55;">
          vielen Dank für Ihre Nachricht an <b>{e(cfg.mail_address)}</b>. Diese Adresse ist ein automatischer
          Prüfdienst von {company}. Er schaut sich an, wie Ihre E-Mail bei einem fremden Mailserver
          angekommen ist – so ähnlich wie ein Einschreiben mit Rückschein.
        </p>
      </td></tr>

      <tr><td style="padding:8px 32px;">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eef4f7;border-left:4px solid {BRAND};border-radius:4px;">
          <tr><td style="padding:16px 20px;font-size:14px;line-height:1.6;">
            <div style="font-size:15px;font-weight:700;color:{BRAND};padding-bottom:6px;">Kein Grund zur Sorge</div>
            &#10003;&nbsp; Dies ist eine automatische Antwort – Sie müssen nichts weiter tun.<br>
            &#10003;&nbsp; Ihre Nachricht wurde nur technisch ausgewertet und nicht an Dritte weitergegeben.<br>
            &#10003;&nbsp; An Ihrem Computer und Ihrem Postfach wurde nichts verändert.<br>
            &#10003;&nbsp; Die technischen Angaben weiter unten sind für Ihren IT-Betreuer gedacht.
          </td></tr>
        </table>
      </td></tr>

      <tr><td style="padding:24px 32px 0 32px;">
        <h2 style="margin:0 0 12px 0;font-size:17px;color:{BRAND};">Ergebnis auf einen Blick</h2>
        <div style="padding:12px 16px;border-radius:6px;background:{verdict_colors[1]};color:{verdict_colors[0]};font-size:14px;font-weight:600;">{e(verdict)}</div>
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:8px;">{row_html}
        </table>
      </td></tr>

      <tr><td style="padding:28px 32px 8px 32px;">
        <h2 style="margin:0 0 6px 0;font-size:17px;color:{BRAND};">Technischer Bericht</h2>
        <p style="margin:0 0 10px 0;font-size:13px;color:#5f6368;">Für Ihren IT-Betreuer. Die Original-E-Mail liegt als Anhang <i>original.eml</i> bei.</p>
        <pre style="margin:0;padding:14px;background:#f6f8fa;border:1px solid #e1e4e8;border-radius:6px;font-family:Consolas,Menlo,monospace;font-size:12px;line-height:1.45;color:#24292e;white-space:pre-wrap;word-break:break-all;">{e(report)}</pre>
      </td></tr>

      <tr><td style="padding:24px 32px 28px 32px;font-size:14px;line-height:1.55;">
        Fragen? Schreiben Sie einfach an <a href="mailto:{contact}" style="color:{BRAND};font-weight:600;">{contact}</a>
        – Antworten auf diese E-Mail kommen dort ebenfalls an.
      </td></tr>

      <tr><td style="padding:16px 32px;background:{BRAND};color:#ffffff;font-size:12px;line-height:1.5;">
        {company} &middot; <a href="{e(cfg.website_url)}" style="color:#ffffff;">{e(cfg.website_url.replace("https://", ""))}</a><br>
        Diese Nachricht wurde automatisch erstellt.
      </td></tr>

    </table>
  </td></tr>
</table>
</body>
</html>"""


# --------------------------------------------------------------------- state


def db_connect(db_path: str) -> sqlite3.Connection:
    con = sqlite3.connect(db_path)
    con.execute("""CREATE TABLE IF NOT EXISTS uses (
        id INTEGER PRIMARY KEY, ts TEXT, day TEXT, sender TEXT, client_ip TEXT, status TEXT)""")
    con.execute("CREATE TABLE IF NOT EXISTS alerts (day TEXT PRIMARY KEY, ts TEXT)")
    con.commit()
    return con


def utcnow() -> datetime:
    return datetime.now(UTC)


def today(tz) -> str:
    return datetime.now(tz).date().isoformat()


def record_use(db: sqlite3.Connection, tz, sender: str | None, client_ip: str | None, status: str):
    db.execute(
        "INSERT INTO uses (ts, day, sender, client_ip, status) VALUES (?,?,?,?,?)",
        (utcnow().isoformat(timespec="seconds"), today(tz), sender, client_ip, status),
    )
    db.commit()


def replies_last_hour(db: sqlite3.Connection, sender: str) -> int:
    since = (utcnow() - timedelta(hours=1)).isoformat(timespec="seconds")
    row = db.execute(
        "SELECT COUNT(*) FROM uses WHERE lower(sender)=lower(?) AND status='replied' AND ts>=?",
        (sender, since),
    ).fetchone()
    return row[0]


# ------------------------------------------------------------------ sending


def smtp_send(cfg: Config, message, recipients: list[str]):
    ctx = ssl.create_default_context()
    if cfg.smtp_port == 465:
        with smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port, context=ctx, timeout=30) as s:
            s.login(cfg.mail_user, cfg.mail_password)
            s.send_message(message, from_addr=cfg.mail_address, to_addrs=recipients)
    else:
        with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=30) as s:
            s.starttls(context=ctx)
            s.login(cfg.mail_user, cfg.mail_password)
            s.send_message(message, from_addr=cfg.mail_address, to_addrs=recipients)


def send_reply(cfg: Config, msg, raw: bytes, recipient: str, report: str, facts: dict):
    reply = EmailMessage()
    reply["From"] = f"{cfg.company_name} Mailtest <{cfg.mail_address}>"
    reply["To"] = recipient
    reply["Reply-To"] = cfg.contact_address
    reply["Subject"] = f"Re: {cfg.trigger_subject} – Ihr Ergebnis"
    reply["Date"] = formatdate(localtime=True)
    reply["Message-ID"] = make_msgid(domain=domain_of(cfg.mail_address) or None)
    orig_id = norm(msg.get("Message-ID", ""))
    if orig_id:
        reply["In-Reply-To"] = orig_id
        reply["References"] = orig_id
    reply["Auto-Submitted"] = "auto-replied"
    reply["X-Auto-Response-Suppress"] = "All"
    reply.set_content(
        "Ihre Test-E-Mail ist angekommen.\n\n"
        f"Diese Adresse ist ein automatischer Prüfdienst von {cfg.company_name}. "
        "Kein Grund zur Sorge: Sie müssen nichts tun, Ihre Nachricht wurde nur technisch "
        "ausgewertet, und an Ihrem Computer wurde nichts verändert.\n"
        f"Fragen? {cfg.contact_address}\n\n"
        "Technischer Bericht für Ihren IT-Betreuer:\n\n" + report
    )
    reply.add_alternative(build_html(cfg, facts, report), subtype="html")
    if len(raw) <= cfg.max_attach_bytes:
        reply.add_attachment(
            raw, maintype="application", subtype="octet-stream", filename="original.eml"
        )
    smtp_send(cfg, reply, [recipient])


def maybe_alert(cfg: Config, db: sqlite3.Connection):
    day = today(cfg.tz)
    rows = db.execute(
        "SELECT ts, sender, client_ip, status FROM uses WHERE day=? ORDER BY ts", (day,)
    ).fetchall()
    if len(rows) <= cfg.alert_threshold:
        return
    if db.execute("SELECT 1 FROM alerts WHERE day=?", (day,)).fetchone():
        return

    lines = [
        f"The mailtest service ({cfg.mail_address}) was used {len(rows)} times today ({day}).",
        f"Alert threshold: more than {cfg.alert_threshold} uses per day. "
        "This alert is sent once per day.",
        "",
        f"{'Time':<9} {'Sender':<40} {'Client IP':<40} Status",
    ]
    for ts, sender, ip, status in rows:
        local = datetime.fromisoformat(ts).astimezone(cfg.tz).strftime("%H:%M:%S")
        lines.append(f"{local:<9} {sender or '-':<40} {ip or '-':<40} {status}")

    alert = EmailMessage()
    alert["From"] = f"Mailtest <{cfg.mail_address}>"
    alert["To"] = cfg.alert_to
    alert["Subject"] = f"[mailtest] used {len(rows)} times today ({day})"
    alert["Date"] = formatdate(localtime=True)
    alert["Message-ID"] = make_msgid(domain=domain_of(cfg.mail_address) or None)
    alert["Auto-Submitted"] = "auto-generated"
    alert.set_content("\n".join(lines))
    smtp_send(cfg, alert, [cfg.alert_to])

    db.execute(
        "INSERT INTO alerts (day, ts) VALUES (?,?)", (day, utcnow().isoformat(timespec="seconds"))
    )
    db.commit()
    log.warning("usage alert sent to %s (%d uses today)", cfg.alert_to, len(rows))


# --------------------------------------------------------------------- IMAP


def quote(name: str) -> str:
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def skip_reason(msg, sender: str, mail_address: str) -> str | None:
    if not sender or not ADDR_RE.match(sender):
        return "no valid From address"
    if sender.lower() == mail_address.lower():
        return "mail from ourselves"
    # Null Return-Path is a definitive bounce signal — check before localpart list
    if msg.get("Return-Path") is not None and norm(msg.get("Return-Path")) in ("<>", ""):
        return "null Return-Path (bounce)"
    if sender.split("@")[0].lower() in NO_REPLY_LOCALPARTS:
        return "no-reply/system sender"
    auto = norm(msg.get("Auto-Submitted", "no")).lower()
    if auto and auto != "no":
        return f"Auto-Submitted: {auto}"
    if norm(msg.get("Precedence", "")).lower() in ("bulk", "list", "junk"):
        return "Precedence bulk/list/junk"
    if msg.get("List-Id") or msg.get("List-Unsubscribe"):
        return "mailing list"
    return None


def move(imap, uid: str, dest: str):
    try:
        typ, _ = imap.uid("MOVE", uid, quote(dest))
        if typ == "OK":
            return
    except imaplib.IMAP4.error:
        pass
    imap.uid("COPY", uid, quote(dest))
    imap.uid("STORE", uid, "+FLAGS", r"(\Deleted)")
    imap.expunge()


def process(cfg: Config, db: sqlite3.Connection, imap, folder: str, uid: str, raw: bytes):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    subject = norm(msg.get("Subject", ""))
    if subject.casefold() != cfg.trigger_subject.casefold():
        imap.uid("STORE", uid, "+FLAGS", r"(\Seen)")
        log.info("ignored uid %s in %s (subject %r)", uid, folder, subject[:60])
        return

    sender = parseaddr(norm(msg.get("From", "")))[1].strip()
    hops = [parse_received(h) for h in (msg.get_all("Received") or [])]
    client = find_client(hops, cfg.my_hostname)
    client_ip = client.get("ip") if client else None

    reason = skip_reason(msg, sender, cfg.mail_address)
    if reason:
        status = f"skipped ({reason})"
    elif replies_last_hour(db, sender) >= cfg.per_sender_limit:
        status = "rate-limited"
    else:
        report, facts = build_report(cfg, msg, raw, hops, client, folder)
        send_reply(cfg, msg, raw, sender, report, facts)
        status = "replied"

    log.info("uid %s in %s from %s (%s): %s", uid, folder, sender, client_ip, status)
    record_use(db, cfg.tz, sender, client_ip, status)
    move(imap, uid, cfg.processed_folder)
    try:
        maybe_alert(cfg, db)
    except Exception:
        log.exception("sending usage alert failed, will retry with the next use")


def poll_folder(cfg: Config, db: sqlite3.Connection, imap, folder: str):
    typ, _ = imap.select(quote(folder))
    if typ != "OK":
        log.warning("cannot select folder %s", folder)
        return
    typ, data = imap.uid("SEARCH", None, "UNSEEN")
    uids = data[0].split() if typ == "OK" and data and data[0] else []
    for uid in uids:
        uid = uid.decode()
        try:
            typ, fetched = imap.uid("FETCH", uid, "(BODY.PEEK[])")
            raw = next((p[1] for p in fetched if isinstance(p, tuple)), None)
            if raw is None:
                continue
            process(cfg, db, imap, folder, uid, raw)
        except (imaplib.IMAP4.abort, OSError):
            raise
        except Exception:
            log.exception("failed to process uid %s in %s - marking as seen", uid, folder)
            try:
                record_use(db, cfg.tz, None, None, "error")
                imap.uid("STORE", uid, "+FLAGS", r"(\Seen)")
            except Exception:
                pass


def connect(cfg: Config):
    imap = imaplib.IMAP4_SSL(
        cfg.imap_host,
        cfg.imap_port,
        ssl_context=ssl.create_default_context(),
        timeout=60,
    )
    imap.login(cfg.mail_user, cfg.mail_password)
    imap.create(quote(cfg.processed_folder))
    return imap


def run(cfg: Config):
    db = db_connect(cfg.db_path)
    log.info(
        "mailtest started for %s (subject %r, folders %s)",
        cfg.mail_address,
        cfg.trigger_subject,
        cfg.folders,
    )
    while True:
        imap = None
        try:
            imap = connect(cfg)
            while True:
                for folder in cfg.folders:
                    poll_folder(cfg, db, imap, folder)
                time.sleep(cfg.poll_seconds)
                imap.noop()
        except KeyboardInterrupt:
            break
        except Exception:
            log.exception("IMAP connection problem, reconnecting in 30s")
            time.sleep(30)
        finally:
            if imap is not None:
                try:
                    imap.logout()
                except Exception:
                    pass
