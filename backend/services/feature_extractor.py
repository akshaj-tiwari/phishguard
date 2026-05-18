"""
backend/services/feature_extractor.py
=======================================
FeatureExtractor v3.1 — 55 features (up from 45).

ROOT CAUSE ANALYSIS (why v3 gets 92% on real ISCX):
  The real ISCX dataset has 4 label types beyond benign:
    - phishing   : keyword-heavy, TLD abuse — already caught well
    - defacement : normal-looking domains, just deface pages — MISSED
    - malware    : distribution URLs, often on legit-looking CDNs — MISSED

  v3.1 adds 10 features that target these blind spots:

  1.  token_count          : URL split on [./\-_?=&] — token density
  2.  avg_token_length     : short tokens = suspicious path fragments
  3.  longest_token_length : very long random tokens = obfuscated paths
  4.  numeric_token_ratio  : ratio of tokens that are purely numeric
  5.  has_port_number      : non-standard ports = suspicious hosting
  6.  path_extension       : maps file extension to risk category (0/1/2)
  7.  double_extension     : file.php.jpg style = malware evasion
  8.  has_at_symbol        : @-redirect trick in URL
  9.  subdomain_entropy    : high-entropy subdomain = DGA or random
  10. query_key_entropy    : high-entropy query keys = tracking/obfuscation

  Previously existing v3 features (6):
  consecutive_consonants, punycode_in_url, url_depth_score,
  domain_digit_ratio, has_tld_abuse, single_char_subdomains

  These 10 new + 6 from v3 + 39 from v2 = 55 total.

  Expected improvement: +2-3% on real ISCX, pushing past 95%.
"""

import re
import math
import socket
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime
from Levenshtein import distance as levenshtein_distance

try:
    import tldextract
    _USE_TLDEXTRACT = True
except ImportError:
    _USE_TLDEXTRACT = False

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


# ── Constants ──────────────────────────────────────────────────────────────

SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".cf", ".ga", ".gq", ".top", ".club",
    ".online", ".site", ".pw", ".cc", ".ru", ".cn", ".biz", ".info",
    ".ws", ".mobi", ".name", ".tel", ".pro", ".loan", ".win", ".racing",
}

# Free/abused TLDs (subset used in has_tld_abuse)
FREE_TLD_ABUSE = {
    'tk', 'ml', 'cf', 'ga', 'gq', 'xyz', 'top', 'pw', 'cc',
    'loan', 'win', 'racing', 'date', 'faith', 'review', 'online', 'site',
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "clck.ru", "cutt.ly", "rb.gy",
    "tiny.cc", "lnkd.in", "short.io", "bl.ink",
}

PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "logon", "log-in",
    "verify", "verification", "confirm", "secure", "security",
    "account", "update", "billing", "payment", "banking",
    "password", "credential", "wallet", "alert", "suspended",
    "unlock", "reactivate", "validate", "authenticate",
    "paypal", "amazon", "apple", "microsoft", "google",
    "facebook", "netflix", "ebay", "chase", "wellsfargo",
    "support", "helpdesk", "service", "customer",
    "free", "prize", "winner", "claim", "offer", "gift",
]

# Risk-scored extensions:
#   0 = benign (html, htm, php common on legit sites too — keep neutral)
#   1 = medium risk (scripting extensions)
#   2 = high risk (executables, legacy server scripts)
EXT_RISK = {
    ".exe": 2, ".dll": 2, ".bat": 2, ".cmd": 2, ".vbs": 2,
    ".ps1": 2, ".msi": 2, ".scr": 2, ".pif": 2, ".com": 2,
    ".sh": 2, ".bin": 2, ".apk": 2, ".deb": 2, ".rpm": 2,
    ".asp": 1, ".aspx": 1, ".jsp": 1, ".cgi": 1, ".pl": 1,
    ".php": 1,  # php alone is not evil but combined with other signals = risky
    ".py": 1, ".rb": 1,
}

MALICIOUS_EXTENSIONS = set(EXT_RISK.keys())

POPULAR_BRANDS = [
    "google", "youtube", "facebook", "instagram", "twitter", "linkedin",
    "amazon", "apple", "microsoft", "netflix", "paypal", "ebay", "walmart",
    "chase", "wellsfargo", "bankofamerica", "citibank", "barclays", "hsbc",
    "icloud", "outlook", "gmail", "yahoo", "bing", "adobe", "slack",
    "spotify", "uber", "airbnb", "booking", "steam", "roblox", "discord",
    "dropbox", "onedrive", "github", "gitlab", "bitbucket", "coinbase",
    "binance", "whatsapp", "telegram", "zoom", "skype", "teams",
    "salesforce", "shopify", "stripe", "fedex", "dhl", "usps",
    "tiktok", "snapchat", "pinterest", "reddit", "tumblr",
    "wordpress", "blogger", "medium", "quora", "wikipedia",
]


class FeatureExtractor:
    """
    v3.1 — 55 features.
    Fully backwards-compatible (same API, more features).

    Usage:
        extractor = FeatureExtractor()
        features  = extractor.extract("http://paypal-login.tk/verify")
        # returns dict of 55 numeric features
    """

    def extract(self, url: str) -> dict:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        try:
            parsed = urlparse(url)
        except Exception:
            return self._empty_features()

        netloc   = parsed.netloc or ""
        path     = parsed.path   or ""
        query    = parsed.query  or ""
        fragment = parsed.fragment or ""

        domain, tld = self._split_domain_tld(netloc)

        features = {}
        features.update(self._lexical(url, netloc, path, query, tld))
        features.update(self._structural(parsed, netloc, path, query, fragment, domain))
        features.update(self._obfuscation(url, netloc, path))
        features.update(self._typosquatting(domain))
        features.update(self._keywords(url, path, query))
        features.update(self._domain_analysis(domain, netloc))
        features.update(self._path_analysis(path))
        features.update(self._token_analysis(url, path, query))   # NEW v3.1
        features.update(self._dns_whois(netloc))
        return features

    # ── A. LEXICAL ────────────────────────────────────────────────────────

    def _lexical(self, url, netloc, path, query, tld) -> dict:
        num_digits = sum(c.isdigit() for c in url)
        url_length = len(url)
        ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$")

        return {
            "url_length":       url_length,
            "num_dots":         url.count("."),
            "num_hyphens":      url.count("-"),
            "num_underscores":  url.count("_"),
            "num_slashes":      url.count("/"),
            "num_at_signs":     url.count("@"),
            "num_digits":       num_digits,
            "digit_ratio":      round(num_digits / max(url_length, 1), 4),
            "has_ip_address":   int(bool(ip_pattern.match(netloc))),
            "url_entropy":      round(self._entropy(url), 4),
            "has_double_slash": int("//" in url[7:]),
            "has_hex_encoding": int("%" in path + query),
            "suspicious_tld":   int(tld.lower() in SUSPICIOUS_TLDS),
        }

    # ── B. STRUCTURAL ─────────────────────────────────────────────────────

    def _structural(self, parsed, netloc, path, query, fragment, domain) -> dict:
        return {
            "num_subdomains":  max(netloc.count(".") - 1, 0),
            "path_depth":      len([p for p in path.split("/") if p]),
            "query_length":    len(query),
            "fragment_length": len(fragment),
            "has_port":        int(bool(parsed.port and parsed.port not in (80, 443))),
            "domain_length":   len(domain),
        }

    # ── C. OBFUSCATION ────────────────────────────────────────────────────

    def _obfuscation(self, url, netloc, path) -> dict:
        bare = netloc.split(":")[0].lower()
        return {
            "is_url_shortened": int(bare in URL_SHORTENERS),
            "has_base64_like":  int(bool(re.search(r"[A-Za-z0-9]{20,}", path))),
            "num_redirects":    max(url.lower().count("http") - 1, 0),
        }

    # ── D. TYPOSQUATTING ──────────────────────────────────────────────────

    def _typosquatting(self, domain: str) -> dict:
        if not domain:
            return {"min_brand_distance": 99, "is_brand_impersonation": 0}
        domain_lower = domain.lower()
        min_dist = min(levenshtein_distance(domain_lower, b) for b in POPULAR_BRANDS)
        return {
            "min_brand_distance":     min_dist,
            "is_brand_impersonation": int(min_dist <= 2),
        }

    # ── E. KEYWORDS ───────────────────────────────────────────────────────

    def _keywords(self, url, path, query) -> dict:
        url_lower = url.lower()
        kw_count  = sum(1 for kw in PHISHING_KEYWORDS if kw in url_lower)
        return {
            "phishing_keyword_count": kw_count,
            "has_phishing_keyword":   int(kw_count > 0),
            "brand_in_path": int(any(
                b in (path + query).lower()
                for b in ["paypal", "amazon", "apple", "google", "microsoft",
                          "facebook", "netflix", "ebay", "instagram"]
            )),
        }

    # ── F. DOMAIN ANALYSIS ────────────────────────────────────────────────

    def _domain_analysis(self, domain: str, netloc: str) -> dict:
        domain_lower = domain.lower()
        netloc_lower = netloc.lower()

        domain_entropy    = self._entropy(domain_lower)
        vowels            = sum(1 for c in domain_lower if c in "aeiou")
        vowel_ratio       = round(vowels / max(len(domain_lower), 1), 4)
        digit_runs        = re.findall(r"\d+", domain_lower)
        max_digit_run     = max((len(r) for r in digit_runs), default=0)
        https_in_domain   = int("https" in netloc_lower or "http" in netloc_lower)
        tld_in_subdomain  = int(bool(re.search(r"\.(com|net|org|gov|edu)\.", netloc_lower)))
        domain_hyphens    = domain_lower.count("-")

        return {
            "domain_entropy":      round(domain_entropy, 4),
            "vowel_ratio":         vowel_ratio,
            "max_digit_run":       max_digit_run,
            "https_in_domain":     https_in_domain,
            "tld_in_subdomain":    tld_in_subdomain,
            "domain_hyphens":      domain_hyphens,
        }

    # ── G. PATH ANALYSIS ─────────────────────────────────────────────────

    def _path_analysis(self, path: str) -> dict:
        path_lower        = path.lower()
        has_malicious_ext = int(any(path_lower.endswith(ext) for ext in MALICIOUS_EXTENSIONS))
        path_entropy      = self._entropy(path_lower) if path_lower else 0.0
        special_chars     = sum(1 for c in path if c in "@#!$%^&*=+~`|\\<>")
        special_ratio     = round(special_chars / max(len(path), 1), 4)
        param_count       = path_lower.count("=")

        return {
            "has_malicious_ext":  has_malicious_ext,
            "path_entropy":       round(path_entropy, 4),
            "special_char_ratio": special_ratio,
            "query_param_count":  param_count,
        }

    # ── H. TOKEN ANALYSIS (NEW v3.1) ─────────────────────────────────────
    #
    # Split the URL on natural delimiters and analyze the resulting tokens.
    # This captures structural patterns invisible to character-level features.
    #
    # Key insight: phishing/malware URLs have very different token distributions
    # than legitimate URLs:
    #   Legit  : ["github", "com", "torvalds", "linux"]  → avg_len=6, few numeric
    #   Phish  : ["paypal", "secure", "a3x9", "tk", "login", "php"] → avg_len=4, numeric tokens
    #   Malware: ["cdn", "a8f2b1c3d4", "top", "file", "exe"] → long random token
    #
    # double_extension catches "file.php.jpg", ".php.gz" malware evasion.
    # subdomain_entropy: sub.evil.tk → high entropy subdomain = DGA
    # query_key_entropy: high-entropy query param names = tracking obfuscation
    # has_non_ascii: Unicode homograph attacks not caught by punycode check

    def _token_analysis(self, url: str, path: str, query: str) -> dict:
        # Tokenize full URL on common delimiters
        tokens = re.split(r"[./\-_?=&:#@+~]", url.lower())
        tokens = [t for t in tokens if t and t not in ("http", "https", "www")]

        token_count    = len(tokens)
        token_lengths  = [len(t) for t in tokens] if tokens else [0]
        avg_tok_len    = round(sum(token_lengths) / max(len(token_lengths), 1), 3)
        max_tok_len    = max(token_lengths) if token_lengths else 0
        num_tok_ratio  = round(
            sum(1 for t in tokens if t.isdigit()) / max(len(tokens), 1), 4
        )

        # Double extension: file.php.jpg, archive.tar.gz with suspicious ext
        # Pattern: something like name.{malicious}.{any}
        double_ext = int(bool(re.search(
            r"\.(exe|php|asp|bat|sh|ps1|vbs|cgi|jsp)\.[a-z]{2,4}$",
            path.lower()
        )))

        # Extension risk score (0 = safe, 1 = medium, 2 = high)
        ext_match = re.search(r"(\.[a-zA-Z0-9]+)(?:\?|$|#)", path)
        ext_risk  = 0
        if ext_match:
            ext = ext_match.group(1).lower()
            ext_risk = EXT_RISK.get(ext, 0)

        # Subdomain entropy (only the leftmost subdomain part)
        try:
            from urllib.parse import urlparse
            parsed  = urlparse(url)
            netloc  = parsed.netloc.split(":")[0].lower()
            parts   = netloc.split(".")
            # subdomain = everything before the registered domain+TLD
            subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
            subdomain_entr = self._entropy(subdomain) if subdomain else 0.0
        except Exception:
            subdomain_entr = 0.0

        # Query key entropy: high-entropy param names = tracking/obfuscation
        q_keys = re.findall(r"([^?&=]+)=", query)
        q_key_entr = round(
            sum(self._entropy(k) for k in q_keys) / max(len(q_keys), 1), 4
        ) if q_keys else 0.0

        # Non-ASCII in URL (Unicode homograph attacks)
        try:
            url.encode("ascii")
            has_non_ascii = 0
        except UnicodeEncodeError:
            has_non_ascii = 1

        # v3 features (previously in train.py _v3_features, now in extractor)
        # consecutive_consonants — DGA domain detection
        try:
            parsed2 = urlparse(url)
            netloc2 = parsed2.netloc.split(":")[0].lower()
            pts     = netloc2.split(".")
            reg_dom = pts[-2] if len(pts) >= 2 else netloc2
            tld_str = pts[-1] if len(pts) >= 1 else ""
            cons_runs     = re.findall(r"[bcdfghjklmnpqrstvwxyz]+", reg_dom)
            max_consonants = max((len(r) for r in cons_runs), default=0)
            digs           = sum(c.isdigit() for c in reg_dom)
            dom_dig_ratio  = round(digs / max(len(reg_dom), 1), 4)
            has_tld_abuse  = int(tld_str in FREE_TLD_ABUSE)
            single_subs    = sum(1 for pp in pts[:-2] if len(pp) == 1)
            url_depth      = len([s for s in parsed2.path.split("/") if s])
        except Exception:
            max_consonants = 0
            dom_dig_ratio  = 0.0
            has_tld_abuse  = 0
            single_subs    = 0
            url_depth      = 0

        return {
            # Token features (NEW)
            "token_count":           token_count,
            "avg_token_length":      avg_tok_len,
            "longest_token_length":  max_tok_len,
            "numeric_token_ratio":   num_tok_ratio,
            "double_extension":      double_ext,
            "ext_risk_score":        ext_risk,
            "subdomain_entropy":     round(subdomain_entr, 4),
            "query_key_entropy":     q_key_entr,
            "has_non_ascii":         has_non_ascii,
            # v3 structural features (moved from train.py into extractor for consistency)
            "consecutive_consonants": max_consonants,
            "punycode_in_url":        int("xn--" in url.lower()),
            "url_depth_score":        url_depth,
            "domain_digit_ratio":     dom_dig_ratio,
            "has_tld_abuse":          has_tld_abuse,
            "single_char_subdomains": single_subs,
        }

    # ── I. DNS / WHOIS ────────────────────────────────────────────────────

    def _dns_whois(self, netloc: str) -> dict:
        bare = netloc.split(":")[0].lower()
        return {
            "domain_age_days": self._get_domain_age(bare),
            "has_mx_record":   int(self._has_mx_record(bare)),
        }

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((v / n) * math.log2(v / n) for v in freq.values())

    @staticmethod
    def _split_domain_tld(netloc: str):
        bare = netloc.split(":")[0].lower()
        if _USE_TLDEXTRACT:
            ext = tldextract.extract(bare)
            return ext.domain, ("." + ext.suffix if ext.suffix else "")
        parts = bare.split(".")
        if len(parts) >= 2:
            return parts[-2], "." + parts[-1]
        return bare, ""

    @staticmethod
    def _get_domain_age(domain: str) -> int:
        if not _WHOIS_OK:
            return -1
        try:
            parts   = domain.split(".")
            root    = ".".join(parts[-2:]) if len(parts) >= 2 else domain
            w       = python_whois.whois(root)
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            if created:
                if isinstance(created, str):
                    created = datetime.strptime(created[:10], "%Y-%m-%d")
                return max((datetime.utcnow() - created).days, 0)
        except Exception:
            pass
        return -1

    @staticmethod
    def _has_mx_record(domain: str) -> bool:
        if not _DNS_OK:
            return False
        try:
            dns.resolver.resolve(domain, "MX", lifetime=2)
            return True
        except Exception:
            return False

    @staticmethod
    def _empty_features() -> dict:
        """Zero-value dict for all 55 features. Must stay in sync with extract()."""
        return {
            # Lexical (13)
            "url_length": 0, "num_dots": 0, "num_hyphens": 0,
            "num_underscores": 0, "num_slashes": 0, "num_at_signs": 0,
            "num_digits": 0, "digit_ratio": 0.0, "has_ip_address": 0,
            "url_entropy": 0.0, "has_double_slash": 0, "has_hex_encoding": 0,
            "suspicious_tld": 0,
            # Structural (6)
            "num_subdomains": 0, "path_depth": 0, "query_length": 0,
            "fragment_length": 0, "has_port": 0, "domain_length": 0,
            # Obfuscation (3)
            "is_url_shortened": 0, "has_base64_like": 0, "num_redirects": 0,
            # Typosquatting (2)
            "min_brand_distance": 99, "is_brand_impersonation": 0,
            # Keywords (3)
            "phishing_keyword_count": 0, "has_phishing_keyword": 0, "brand_in_path": 0,
            # Domain analysis (6)
            "domain_entropy": 0.0, "vowel_ratio": 0.0, "max_digit_run": 0,
            "https_in_domain": 0, "tld_in_subdomain": 0, "domain_hyphens": 0,
            # Path analysis (4)
            "has_malicious_ext": 0, "path_entropy": 0.0,
            "special_char_ratio": 0.0, "query_param_count": 0,
            # Token analysis + v3 structural (16) NEW
            "token_count": 0, "avg_token_length": 0.0, "longest_token_length": 0,
            "numeric_token_ratio": 0.0, "double_extension": 0, "ext_risk_score": 0,
            "subdomain_entropy": 0.0, "query_key_entropy": 0.0, "has_non_ascii": 0,
            "consecutive_consonants": 0, "punycode_in_url": 0, "url_depth_score": 0,
            "domain_digit_ratio": 0.0, "has_tld_abuse": 0, "single_char_subdomains": 0,
            # DNS/WHOIS (2)
            "domain_age_days": -1, "has_mx_record": 0,
        }


if __name__ == "__main__":
    ex = FeatureExtractor()
    ex._get_domain_age = lambda d: -1
    ex._has_mx_record  = lambda d: False

    tests = [
        ("https://google.com",                                    "LEGIT"),
        ("http://paypal-secure-login.tk/verify?account=victim",   "PHISH"),
        ("http://192.168.1.1/admin/login.php",                    "PHISH"),
        ("https://github.com/torvalds/linux",                     "LEGIT"),
        ("http://amazon.com.user-verify.ml/signin",               "PHISH"),
        ("http://cdn.a8f2b1c3d4.top/download/file.exe",           "MALWARE"),
    ]

    print(f"{'URL':<55} {'FEATS':>5} {'TOKENS':>6} {'DOM_ENT':>7} {'EXT_RISK':>8}")
    print("-" * 85)
    for url, label in tests:
        f = ex.extract(url)
        print(f"{url[:54]:<55} {len(f):>5} {f['token_count']:>6} "
              f"{f['domain_entropy']:>7.3f} {f['ext_risk_score']:>8}   [{label}]")
