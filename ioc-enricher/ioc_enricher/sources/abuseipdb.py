"""
AbuseIPDB source — IP reputation only.

Free tier: 1,000 checks/day as of this writing. Get a key at
https://www.abuseipdb.com/account/api and set it as ABUSEIPDB_API_KEY.

API docs: https://docs.abuseipdb.com/
"""

import requests

from .base import SourceResult
from ..classify import IOCType, is_ip

SOURCE_NAME = "abuseipdb"
API_URL = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT_SECONDS = 10


def supports(ioc_type):
    return is_ip(ioc_type)


def query(ioc_value, ioc_type, api_key):
    if not api_key:
        return SourceResult.skipped(SOURCE_NAME, "no API key configured (ABUSEIPDB_API_KEY)")

    if not supports(ioc_type):
        return SourceResult.skipped(SOURCE_NAME, f"does not support IOC type '{ioc_type}'")

    try:
        response = requests.get(
            API_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ioc_value, "maxAgeInDays": 90, "verbose": True},
            timeout=TIMEOUT_SECONDS,
        )
    except requests.exceptions.RequestException as exc:
        return SourceResult.failed(SOURCE_NAME, f"network error: {exc}")

    if response.status_code == 429:
        return SourceResult.failed(SOURCE_NAME, "rate limited (daily quota likely exhausted)")
    if response.status_code == 401:
        return SourceResult.failed(SOURCE_NAME, "authentication failed — check API key")
    if response.status_code != 200:
        return SourceResult.failed(SOURCE_NAME, f"unexpected HTTP {response.status_code}")

    try:
        data = response.json()["data"]
    except (KeyError, ValueError) as exc:
        return SourceResult.failed(SOURCE_NAME, f"unexpected response shape: {exc}")

    abuse_score = data.get("abuseConfidenceScore", 0)  # AbuseIPDB already scores 0-100
    total_reports = data.get("totalReports", 0)
    country = data.get("countryCode", "?")
    is_tor = data.get("isTor", False)
    usage_type = data.get("usageType", "unknown")

    summary_parts = [f"{abuse_score}/100 confidence"]
    if total_reports:
        summary_parts.append(f"{total_reports} report(s)")
    if is_tor:
        summary_parts.append("Tor exit node")
    summary = ", ".join(summary_parts)

    return SourceResult(
        source=SOURCE_NAME,
        ok=True,
        risk_score=abuse_score,
        summary=summary,
        details={
            "total_reports": total_reports,
            "country_code": country,
            "is_tor": is_tor,
            "usage_type": usage_type,
            "domain": data.get("domain"),
            "last_reported_at": data.get("lastReportedAt"),
        },
    )
