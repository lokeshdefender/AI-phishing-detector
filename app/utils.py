import re
from urllib.parse import urlparse

SHORTENERS = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","buff.ly","is.gd"]

_ip_re = re.compile(r"^https?://(\d{1,3}\.){3}\d{1,3}")

def extract_urls(text: str):
    url_regex = r"(https?://[^\s'\)\]\">]+)"
    raw = re.findall(url_regex, text)
    cleaned = [u.rstrip('.,;:)"]') for u in raw]
    return cleaned


def is_ip_url(url: str) -> bool:
    return bool(_ip_re.match(url))


def is_shortener(url: str) -> bool:
    try:
        host = urlparse(url).netloc.lower()
    except Exception:
        return False
    for s in SHORTENERS:
        if s in host:
            return True
    return False


def domain_from_url(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def extract_sender(text: str) -> str:
    """Try to extract a sender email address from raw email text (From: header)."""
    m = re.search(r"^From:\s*(.*)$", text, re.MULTILINE | re.IGNORECASE)
    if not m:
        return ""
    s = m.group(1).strip()
    # try <email>
    em = re.search(r"<([^>]+)>", s)
    if em:
        return em.group(1).strip()
    # try plain email
    em2 = re.search(r"([\w.+-]+@[\w-]+\.[\w.-]+)", s)
    if em2:
        return em2.group(1).strip()
    return s


FREE_EMAIL_PROVIDERS = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "protonmail.com"]


def is_free_email_address(email: str) -> bool:
    try:
        domain = email.split('@')[-1].lower()
    except Exception:
        return False
    return any(domain.endswith(p) for p in FREE_EMAIL_PROVIDERS)


# WHOIS and DNS helpers
import whois
import dns.resolver
import threading
from datetime import datetime, timezone

SUSPICIOUS_TLDS = ["xyz","top","info","club","ru","cn","tk","ml","ga","cf","gq"]


def get_whois_creation_date(domain: str):
    """Return creation datetime for a domain, or None. Hard timeout of 8 seconds.
    
    Uses a daemon thread instead of signal.alarm() so this works on both
    Windows (dev) and Linux (Docker/production).
    """
    result = [None]
    error = [None]

    def _do_whois():
        try:
            w = whois.whois(domain)
            cd = w.creation_date
            if isinstance(cd, list):
                cd = cd[0]
            if isinstance(cd, datetime):
                result[0] = cd
            elif isinstance(cd, str):
                try:
                    result[0] = datetime.fromisoformat(cd)
                except Exception:
                    pass
        except Exception as e:
            error[0] = e

    t = threading.Thread(target=_do_whois, daemon=True)
    t.start()
    t.join(timeout=8)  # 8-second hard limit

    if t.is_alive():
        # Thread still blocked = WHOIS server unresponsive; give up cleanly
        return None

    if error[0]:
        return None

    return result[0]


def get_domain_age_days(domain: str):
    cd = get_whois_creation_date(domain)
    if not cd:
        return None
    now = datetime.now(timezone.utc)
    if cd.tzinfo is None:
        cd = cd.replace(tzinfo=timezone.utc)
    delta = now - cd
    return max(0, delta.days)


def get_dns_records(domain: str):
    """Return dict with A, MX, NS lists (may be empty)."""
    res = {"A": [], "MX": [], "NS": []}
    try:
        answers = dns.resolver.resolve(domain, 'A', lifetime=5)
        res['A'] = [r.to_text() for r in answers]
    except Exception:
        res['A'] = []
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=5)
        res['MX'] = [r.to_text() for r in answers]
    except Exception:
        res['MX'] = []
    try:
        answers = dns.resolver.resolve(domain, 'NS', lifetime=5)
        res['NS'] = [r.to_text() for r in answers]
    except Exception:
        res['NS'] = []
    return res


def is_suspicious_tld(domain: str) -> bool:
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    tld = parts[-1].lower()
    return tld in SUSPICIOUS_TLDS


def is_newly_registered(domain: str, days_threshold: int = 90) -> bool:
    try:
        age = get_domain_age_days(domain)
        if age is None:
            return False
        return age <= days_threshold
    except Exception:
        return False


# .eml file parsing
import email
from email.parser import BytesParser


def parse_eml_file(file_bytes: bytes) -> dict:
    """Parse .eml file and extract sender, subject, and body."""
    try:
        parser = BytesParser()
        msg = parser.parsebytes(file_bytes)

        sender = msg.get('From', '')
        subject = msg.get('Subject', '')

        # Extract body (prefer plain text, fall back to HTML)
        body = ''
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain':
                    body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    break
            if not body:
                for part in msg.walk():
                    if part.get_content_type() == 'text/html':
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        break
        else:
            body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')

        return {
            'sender': sender.strip(),
            'subject': subject.strip(),
            'body': body.strip(),
            'full_text': f"From: {sender}\nSubject: {subject}\n\n{body}"
        }
    except Exception as e:
        return {
            'sender': '',
            'subject': '',
            'body': '',
            'full_text': '',
            'error': str(e)
        }