"""
backend/services/dns_service.py
==================================
WHOIS and passive DNS lookups.
Functions match the plan spec exactly:
  get_domain_age(domain) -> int (days, or -1 if unknown)
  get_a_records(domain)  -> list of IP strings
  has_mx_record(domain)  -> bool

These are synchronous — run them in FastAPI's threadpool via
  asyncio.get_event_loop().run_in_executor(None, fn, arg)
to avoid blocking the event loop.
"""

import socket
from datetime import datetime
from urllib.parse import urlparse

try:
    import whois as python_whois
    _WHOIS_OK = True
except ImportError:
    _WHOIS_OK = False

try:
    import dns.resolver
    _DNS_OK = True
except ImportError:
    _DNS_OK = False


def extract_root_domain(domain: str) -> str:
    """Strips subdomains and port. google.com from mail.google.com:8080."""
    domain = domain.split(":")[0].lower().strip()
    parts  = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def get_domain_age(domain: str) -> int:
    """
    Returns days since domain registration via WHOIS.
    Returns -1 if lookup fails or date unavailable.
    """
    if not _WHOIS_OK:
        return -1
    try:
        root = extract_root_domain(domain)
        w    = python_whois.whois(root)

        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return -1

        if isinstance(created, str):
            # Try common date formats
            for fmt in ("%Y-%m-%d", "%d-%b-%Y", "%Y-%m-%dT%H:%M:%SZ"):
                try:
                    created = datetime.strptime(created[:10], fmt[:10])
                    break
                except ValueError:
                    continue

        if isinstance(created, datetime):
            return max((datetime.utcnow() - created).days, 0)
        return -1
    except Exception:
        return -1


def get_whois_info(domain: str) -> dict:
    """
    Full WHOIS record: registrar, country, creation date, age.
    Used for the threat report WHOIS section.
    """
    if not _WHOIS_OK:
        return {"registrar": None, "country": None,
                "creation_date": None, "domain_age_days": -1}
    try:
        root = extract_root_domain(domain)
        w    = python_whois.whois(root)

        created = w.creation_date
        if isinstance(created, list):
            created = created[0]

        age = -1
        if created:
            try:
                if isinstance(created, str):
                    created = datetime.strptime(created[:10], "%Y-%m-%d")
                age = max((datetime.utcnow() - created).days, 0)
            except Exception:
                pass

        return {
            "registrar":      str(w.registrar)[:200]     if w.registrar      else None,
            "country":        str(w.country)[:100]        if w.country        else None,
            "creation_date":  str(created)[:100]          if created          else None,
            "domain_age_days": age,
            "is_new_domain":  (age >= 0 and age < 30),
        }
    except Exception:
        return {"registrar": None, "country": None,
                "creation_date": None, "domain_age_days": -1, "is_new_domain": False}


def get_a_records(domain: str) -> list:
    """Returns list of A record IP strings for the domain."""
    bare = domain.split(":")[0].lower()
    if _DNS_OK:
        try:
            answers = dns.resolver.resolve(bare, "A", lifetime=2)
            return [str(r.address) for r in answers]
        except Exception:
            pass
    # Fallback: socket
    try:
        info = socket.getaddrinfo(bare, None, socket.AF_INET)
        return list({i[4][0] for i in info})
    except Exception:
        return []


def has_mx_record(domain: str) -> bool:
    """Returns True if the domain has a valid MX record."""
    bare = domain.split(":")[0].lower()
    if not _DNS_OK:
        return False
    try:
        dns.resolver.resolve(bare, "MX", lifetime=2)
        return True
    except Exception:
        return False


def get_all_dns_info(domain: str) -> dict:
    """Returns all DNS info bundled for the threat report."""
    return {
        "a_records":    get_a_records(domain),
        "has_mx_record": has_mx_record(domain),
    }
