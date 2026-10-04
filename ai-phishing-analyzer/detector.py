"""
detector.py
Rule-based phishing detection logic for the AI Phishing Email Analyzer.

No external services required — pure Python heuristics over the email's
raw text, headers (if provided) and extracted links.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Signal definitions
# ---------------------------------------------------------------------------

URGENCY_PHRASES = [
    "urgent", "immediately", "verify your account", "account suspended",
    "action required", "confirm your identity", "unusual activity",
    "limited time", "your account will be closed", "final notice",
    "click here now", "within 24 hours", "payment failed",
    "security alert", "unauthorized access", "update your payment",
    "reset your password now", "confirm your password",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear account holder", "dear valued customer",
    "dear sir/madam", "valued member",
]

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "support", "fit", "gq", "tk", "ml", "cf",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
}

SENSITIVE_REQUEST_WORDS = [
    "social security", "ssn", "credit card", "bank account", "routing number",
    "password", "login credentials", "one-time code", "otp", "cvv", "pin number",
    "wire transfer", "gift card",
]

IP_URL_RE = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
URL_RE = re.compile(r"https?://[^\s<>\")]+")
EMAIL_RE = re.compile(r"[\w\.-]+@[\w\.-]+\.\w+")


@dataclass
class Indicator:
    name: str
    description: str
    weight: int
    matched: bool = False
    evidence: list[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    score: int                 # 0-100, higher = more suspicious
    risk_level: str            # Low / Medium / High / Critical
    indicators: list[Indicator]
    links: list[str]

    def matched_indicators(self) -> list[Indicator]:
        return [i for i in self.indicators if i.matched]


def _extract_links(text: str) -> list[str]:
    return URL_RE.findall(text)


def _risk_level(score: int) -> str:
    if score >= 70:
        return "Critical"
    if score >= 45:
        return "High"
    if score >= 20:
        return "Medium"
    return "Low"


def analyze_email(
    body: str,
    sender: str | None = None,
    display_name: str | None = None,
    subject: str | None = None,
) -> AnalysisResult:
    """
    Run all heuristics over the given email and return a scored result.

    Parameters
    ----------
    body: full plain-text body of the email
    sender: the sender's actual email address (From: header), if known
    display_name: the sender's display name, if known (e.g. "PayPal Support")
    subject: the email subject line, if known
    """
    text = body or ""
    full_text = f"{subject or ''}\n{text}".lower()
    links = _extract_links(text)

    indicators: list[Indicator] = []

    # 1. Urgency / pressure language -----------------------------------
    hits = [p for p in URGENCY_PHRASES if p in full_text]
    indicators.append(Indicator(
        name="Urgency language",
        description="Phrases designed to pressure quick, unverified action.",
        weight=15,
        matched=bool(hits),
        evidence=hits,
    ))

    # 2. Requests for sensitive data -------------------------------------
    hits = [p for p in SENSITIVE_REQUEST_WORDS if p in full_text]
    indicators.append(Indicator(
        name="Sensitive data request",
        description="Asks for credentials, financial or personal data by email.",
        weight=20,
        matched=bool(hits),
        evidence=hits,
    ))

    # 3. Generic greeting (no personalization) ---------------------------
    hits = [p for p in GENERIC_GREETINGS if p in full_text]
    indicators.append(Indicator(
        name="Generic greeting",
        description="Impersonal greeting instead of the recipient's real name.",
        weight=8,
        matched=bool(hits),
        evidence=hits,
    ))

    # 4. IP-address based links -------------------------------------------
    ip_links = IP_URL_RE.findall(text)
    indicators.append(Indicator(
        name="IP-address link",
        description="Links to a raw IP address instead of a domain name.",
        weight=20,
        matched=bool(ip_links),
        evidence=ip_links,
    ))

    # 5. URL shorteners ----------------------------------------------------
    shortener_hits = [l for l in links if urlparse(l).netloc.lower() in URL_SHORTENERS]
    indicators.append(Indicator(
        name="URL shortener",
        description="Shortened links hide the real destination domain.",
        weight=12,
        matched=bool(shortener_hits),
        evidence=shortener_hits,
    ))

    # 6. Suspicious top-level domains --------------------------------------
    tld_hits = []
    for l in links:
        netloc = urlparse(l).netloc.lower()
        tld = netloc.split(".")[-1] if "." in netloc else ""
        if tld in SUSPICIOUS_TLDS:
            tld_hits.append(l)
    indicators.append(Indicator(
        name="Suspicious TLD",
        description="Link domain uses a TLD commonly abused for phishing.",
        weight=10,
        matched=bool(tld_hits),
        evidence=tld_hits,
    ))

    # 7. Display name / sender domain mismatch -----------------------------
    mismatch = False
    evidence = []
    if sender and display_name:
        sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""
        known_brands = ["paypal", "microsoft", "apple", "amazon", "google", "bank", "netflix"]
        for brand in known_brands:
            if brand in display_name.lower() and brand not in sender_domain:
                mismatch = True
                evidence.append(f'"{display_name}" <{sender}>')
    indicators.append(Indicator(
        name="Sender / display name mismatch",
        description="Display name claims a known brand but the sending domain doesn't match.",
        weight=25,
        matched=mismatch,
        evidence=evidence,
    ))

    # 8. Excessive urgency punctuation / shouting --------------------------
    shouting = bool(re.search(r"[A-Z]{6,}", text)) or text.count("!") >= 3
    indicators.append(Indicator(
        name="Excessive punctuation / caps",
        description="Heavy use of exclamation marks or ALL CAPS to create alarm.",
        weight=5,
        matched=shouting,
        evidence=["detected"] if shouting else [],
    ))

    # 9. Mismatched link text vs href (e.g. "paypal.com" text, different href)
    link_text_pairs = re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>', body or "", re.I)
    mismatched = []
    for href, link_text in link_text_pairs:
        shown_domains = EMAIL_RE.findall(link_text) or re.findall(r"[\w-]+\.\w{2,}", link_text)
        if shown_domains and shown_domains[0] not in href:
            mismatched.append(f"{link_text!r} -> {href}")
    indicators.append(Indicator(
        name="Link text / destination mismatch",
        description="Visible link text shows one domain, actual link goes elsewhere.",
        weight=20,
        matched=bool(mismatched),
        evidence=mismatched,
    ))

    score = sum(i.weight for i in indicators if i.matched)
    score = min(score, 100)

    return AnalysisResult(
        score=score,
        risk_level=_risk_level(score),
        indicators=indicators,
        links=links,
    )
