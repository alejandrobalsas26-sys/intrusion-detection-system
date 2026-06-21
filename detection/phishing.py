"""Local, explainable phishing / scam URL analysis.

Deterministic heuristics only — no machine learning, no external API, no network
calls. Every point added to a URL's risk score carries a human-readable reason,
so an analyst can see *why* a link was flagged and defend or dismiss the verdict.
This is the right tool for triaging a suspicious link from a phishing/smishing
report, or for scoring domains that surface elsewhere in the IDS.

Design goals (per the platform's detection philosophy): low false positives, low
complexity, fully offline, and explainable. The signals are intentionally
conservative — a single weak signal lands a URL in "suspicious", never "high";
"high" requires corroborating evidence.

Usage:
    from detection.phishing import analyze_url
    verdict = analyze_url("http://paypal.secure-login.ru/verify")
    print(verdict.risk, verdict.score, verdict.reasons)

    # or the CLI:
    python -m detection.phishing http://example.com/login
"""

import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# Curated, high-value brand list kept deliberately short to minimize false
# positives. Extend at runtime via PHISHING_PROTECTED_BRANDS (comma-separated).
_DEFAULT_BRANDS = frozenset(
    {
        "paypal", "google", "microsoft", "apple", "amazon", "facebook",
        "instagram", "whatsapp", "netflix", "linkedin", "outlook", "office365",
        "icloud", "coinbase", "binance", "metamask", "wellsfargo", "chase",
        "bankofamerica", "citibank", "hsbc", "santander", "dhl", "fedex",
        "ups", "usps", "irs", "steam", "dropbox", "adobe", "github",
    }
)

# TLDs disproportionately abused for phishing / malware staging.
_SUSPICIOUS_TLDS = frozenset(
    {
        "zip", "mov", "xyz", "top", "gq", "tk", "ml", "cf", "ga", "work",
        "click", "link", "country", "kim", "loan", "download", "review",
        "rest", "fit", "host", "support", "icu", "cam", "quest",
    }
)

# URL shorteners can mask the true destination — informational, not damning.
_SHORTENERS = frozenset(
    {
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
        "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly",
    }
)

_SCAM_KEYWORDS = frozenset(
    {
        "verify", "account", "secure", "security", "login", "signin", "update",
        "confirm", "suspend", "suspended", "unlock", "billing", "invoice",
        "payment", "password", "wallet", "recover", "bonus", "prize", "gift",
        "free", "winner", "urgent", "alert", "validate", "restricted",
        "limited", "support", "service",
    }
)

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_RISK_HIGH = 60
_RISK_SUSPICIOUS = 30


@dataclass
class PhishingVerdict:
    """Explainable risk verdict for a single URL or domain."""

    target: str
    host: str
    score: int
    risk: str  # "low" / "suspicious" / "high"
    reasons: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "host": self.host,
            "score": self.score,
            "risk": self.risk,
            "reasons": self.reasons,
            "techniques": self.techniques,
        }


def _protected_brands(extra: set[str] | None = None) -> frozenset[str]:
    brands = set(_DEFAULT_BRANDS)
    env = os.getenv("PHISHING_PROTECTED_BRANDS", "").strip()
    if env:
        brands |= {b.strip().lower() for b in env.split(",") if b.strip()}
    if extra:
        brands |= {b.lower() for b in extra}
    return frozenset(brands)


def _levenshtein(a: str, b: str) -> int:
    """Classic edit distance (stdlib only); used for typosquat detection."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _split_host(url: str) -> tuple[str, str]:
    """Returns (host, userinfo) from a URL, tolerating a missing scheme."""
    candidate = url.strip()
    if "://" not in candidate:
        candidate = "http://" + candidate
    parts = urlsplit(candidate)
    netloc = parts.netloc
    userinfo = ""
    if "@" in netloc:
        userinfo, netloc = netloc.rsplit("@", 1)
    host = netloc.split(":", 1)[0].rstrip(".").lower()
    return host, userinfo


def _brand_at_boundary(haystack: str, brand: str) -> bool:
    """True if `brand` appears in `haystack` at a label/word boundary.

    Boundaries are any non-letter (dot, hyphen, digit, start/end), so
    'paypal-login' and 'paypal.evil' match but 'googleblog' and 'mypaypal' do
    not — which is what keeps legitimate brand-substring domains from flagging.
    """
    return re.search(rf"(?<![a-z]){re.escape(brand)}(?![a-z])", haystack) is not None


def analyze_url(url: str, extra_brands: set[str] | None = None) -> PhishingVerdict:
    """Scores a URL (or bare domain) for phishing indicators. Always explainable."""
    brands = _protected_brands(extra_brands)
    host, userinfo = _split_host(url)
    reasons: list[str] = []
    score = 0

    if not host:
        return PhishingVerdict(url, "", 0, "low", ["No host could be parsed."], [])

    labels = host.split(".")
    tld = labels[-1] if len(labels) > 1 else ""
    main_label = labels[-2] if len(labels) >= 2 else labels[0]
    # Everything except the final TLD label — where we hunt for impersonation.
    host_wo_tld = ".".join(labels[:-1]) if len(labels) > 1 else host

    # --- Host-shape signals ---
    if _IPV4_RE.match(host):
        score += 35
        reasons.append("Host is a raw IP address (legitimate brands use names).")

    if userinfo:
        score += 30
        reasons.append(
            f"URL embeds userinfo before '@' ('{userinfo}@...') - a classic trick to "
            "make the real host look trusted."
        )

    punycode_labels = [lbl for lbl in labels if lbl.startswith("xn--")]
    if punycode_labels:
        score += 30
        reasons.append(
            f"Internationalized (punycode) label(s) {punycode_labels} - common in "
            "homoglyph look-alike domains."
        )
    elif any(ord(ch) > 127 for ch in host):
        score += 25
        reasons.append("Host contains non-ASCII characters (possible homoglyph attack).")

    # --- Brand abuse signals (skipped when the registrable label IS the brand) ---
    main_is_brand = main_label in brands
    if not main_is_brand:
        typo_hit = next(
            (
                b
                for b in brands
                if len(main_label) >= 4 and 1 <= _levenshtein(main_label, b) <= 2
            ),
            None,
        )
        if typo_hit:
            score += 40
            reasons.append(
                f"Registrable label '{main_label}' is one or two edits from the brand "
                f"'{typo_hit}' (typosquatting)."
            )
            if any(c.isdigit() for c in main_label):
                score += 10
                reasons.append(
                    "Typosquat uses digit-for-letter substitution (e.g. '1'->'l', '0'->'o')."
                )
        else:
            impersonated = next(
                (b for b in brands if _brand_at_boundary(host_wo_tld, b)), None
            )
            if impersonated:
                score += 30
                reasons.append(
                    f"Brand '{impersonated}' appears in the host but the registrable "
                    f"domain is '{main_label}.{tld}', not the brand's own domain "
                    "(impersonation)."
                )

    # --- Lexical / structural signals ---
    if tld in _SUSPICIOUS_TLDS:
        score += 15
        reasons.append(f"Uses a frequently-abused TLD ('.{tld}').")

    registrable = f"{main_label}.{tld}" if tld else host
    if registrable in _SHORTENERS or host in _SHORTENERS:
        score += 12
        reasons.append("URL shortener host - the true destination is hidden.")

    is_ip = bool(_IPV4_RE.match(host))
    # Structural signals below only make sense for name-based hosts.
    subdomain_count = max(0, len(labels) - 2)
    if not is_ip and subdomain_count >= 3:
        score += 12
        reasons.append(f"Deeply nested subdomains ({subdomain_count}) - often used to bury intent.")
    elif not is_ip and subdomain_count == 2:
        score += 6
        reasons.append("Multiple subdomain levels.")

    if not is_ip and host.count("-") >= 3:
        score += 8
        reasons.append("Host crowded with hyphens (look-alike construction).")

    if sum(c.isdigit() for c in host) >= 4 and not _IPV4_RE.match(host):
        score += 8
        reasons.append("Host packed with digits (uncommon for legitimate brand domains).")

    if len(host) > 40:
        score += 6
        reasons.append("Unusually long hostname.")

    # Scam-y vocabulary across the whole URL (host + path + query).
    lowered = url.lower()
    hits = sorted({kw for kw in _SCAM_KEYWORDS if kw in lowered})
    if hits:
        bonus = min(len(hits) * 5, 20)
        score += bonus
        reasons.append(f"Contains alarm/credential keywords: {', '.join(hits)}.")

    score = max(0, min(100, score))
    if score >= _RISK_HIGH:
        risk = "high"
    elif score >= _RISK_SUSPICIOUS:
        risk = "suspicious"
    else:
        risk = "low"

    techniques: list[str] = []
    if risk != "low":
        # T1566.002 — Phishing: Spearphishing Link.
        techniques = ["T1566.002"]

    if not reasons:
        reasons.append("No phishing indicators found.")

    return PhishingVerdict(url, host, score, risk, reasons, techniques)


def analyze_domain(domain: str, extra_brands: set[str] | None = None) -> PhishingVerdict:
    """Convenience wrapper to score a bare domain (no scheme/path)."""
    return analyze_url(domain, extra_brands=extra_brands)


def _main(argv: list[str] | None = None) -> int:
    import sys

    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("usage: python -m detection.phishing <url> [<url> ...]", file=sys.stderr)
        return 2
    worst = "low"
    rank = {"low": 0, "suspicious": 1, "high": 2}
    for url in args:
        v = analyze_url(url)
        print(f"[{v.risk.upper():10}] score={v.score:3}  {v.target}")
        for r in v.reasons:
            print(f"    - {r}")
        if v.techniques:
            print(f"    techniques: {', '.join(v.techniques)}")
        if rank[v.risk] > rank[worst]:
            worst = v.risk
    # Non-zero exit when anything looked suspicious, for scripting.
    return 0 if worst == "low" else 1


if __name__ == "__main__":
    raise SystemExit(_main())
