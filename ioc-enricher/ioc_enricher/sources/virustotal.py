"""
VirusTotal source — covers IPs, domains, URLs, and file hashes, which is
why it's the one source queried for almost every IOC type here.

Free tier (as of this writing): 4 requests/minute, 500/day. Get a key at
https://www.virustotal.com/gui/my-apikey and set it as VIRUSTOTAL_API_KEY.

API docs: https://docs.virustotal.com/reference/overview
"""

import base64
import requests

from .base import SourceResult
from ..classify import IOCType, is_hash, is_ip

SOURCE_NAME = "virustotal"
API_BASE = "https://www.virustotal.com/api/v3"
TIMEOUT_SECONDS = 10


def supports(ioc_type):
    return True  # VirusTotal has an endpoint for every IOC type this tool handles


def _endpoint_for(ioc_value, ioc_type):
    if is_ip(ioc_type):
        return f"{API_BASE}/ip_addresses/{ioc_value}"
    if ioc_type == IOCType.DOMAIN:
        return f"{API_BASE}/domains/{ioc_value}"
    if ioc_type == IOCType.URL:
        # VT identifies URLs by the base64 of the URL itself, no padding
        url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip("=")
        return f"{API_BASE}/urls/{url_id}"
    if is_hash(ioc_type):
        return f"{API_BASE}/files/{ioc_value}"
    return None


def query(ioc_value, ioc_type, api_key):
    if not api_key:
        return SourceResult.skipped(SOURCE_NAME, "no API key configured (VIRUSTOTAL_API_KEY)")

    endpoint = _endpoint_for(ioc_value, ioc_type)
    if endpoint is None:
        return SourceResult.skipped(SOURCE_NAME, f"does not support IOC type '{ioc_type}'")

    try:
        response = requests.get(
            endpoint,
            headers={"x-apikey": api_key},
            timeout=TIMEOUT_SECONDS,
        )
    except requests.exceptions.RequestException as exc:
        return SourceResult.failed(SOURCE_NAME, f"network error: {exc}")

    if response.status_code == 404:
        return SourceResult(SOURCE_NAME, ok=True, risk_score=None, summary="not found in VirusTotal")
    if response.status_code == 429:
        return SourceResult.failed(SOURCE_NAME, "rate limited (4 req/min on the free tier)")
    if response.status_code == 401:
        return SourceResult.failed(SOURCE_NAME, "authentication failed — check API key")
    if response.status_code != 200:
        return SourceResult.failed(SOURCE_NAME, f"unexpected HTTP {response.status_code}")

    try:
        attributes = response.json()["data"]["attributes"]
    except (KeyError, ValueError) as exc:
        return SourceResult.failed(SOURCE_NAME, f"unexpected response shape: {exc}")

    stats = attributes.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total_engines = sum(stats.values()) if stats else 0

    # Normalize "N engines flagged this out of M" to a 0-100 score.
    risk_score = round(((malicious + suspicious) / total_engines) * 100) if total_engines else None

    summary = (
        f"{malicious} malicious / {suspicious} suspicious of {total_engines} engines"
        if total_engines else "no analysis data available"
    )

    return SourceResult(
        source=SOURCE_NAME,
        ok=True,
        risk_score=risk_score,
        summary=summary,
        details={
            "malicious_engines": malicious,
            "suspicious_engines": suspicious,
            "total_engines": total_engines,
            "reputation": attributes.get("reputation"),
            "last_analysis_date": attributes.get("last_analysis_date"),
        },
    )
