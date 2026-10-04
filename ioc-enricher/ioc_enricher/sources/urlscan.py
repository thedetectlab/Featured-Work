"""
urlscan.io source — URL and domain search only. Unlike AbuseIPDB and
VirusTotal, urlscan's public search API works without an API key for
read-only queries against already-submitted scans, so this source
degrades gracefully (lower rate limit, same data) rather than being
skipped entirely when no key is configured.

API docs: https://urlscan.io/docs/api/
"""

import requests

from .base import SourceResult
from ..classify import IOCType

SOURCE_NAME = "urlscan"
SEARCH_URL = "https://urlscan.io/api/v1/search/"
TIMEOUT_SECONDS = 10


def supports(ioc_type):
    return ioc_type in (IOCType.URL, IOCType.DOMAIN)


def query(ioc_value, ioc_type, api_key):
    if not supports(ioc_type):
        return SourceResult.skipped(SOURCE_NAME, f"does not support IOC type '{ioc_type}'")

    # Search for prior scans of this domain/URL rather than submitting a
    # fresh scan — submitting is a write operation with its own quota and
    # makes the target aware it's being investigated, which isn't
    # appropriate for a passive triage tool.
    query_field = "page.domain" if ioc_type == IOCType.DOMAIN else "page.url"
    headers = {"API-Key": api_key} if api_key else {}

    try:
        response = requests.get(
            SEARCH_URL,
            headers=headers,
            params={"q": f'{query_field}:"{ioc_value}"', "size": 5},
            timeout=TIMEOUT_SECONDS,
        )
    except requests.exceptions.RequestException as exc:
        return SourceResult.failed(SOURCE_NAME, f"network error: {exc}")

    if response.status_code == 429:
        return SourceResult.failed(SOURCE_NAME, "rate limited")
    if response.status_code != 200:
        return SourceResult.failed(SOURCE_NAME, f"unexpected HTTP {response.status_code}")

    try:
        results = response.json().get("results", [])
    except ValueError as exc:
        return SourceResult.failed(SOURCE_NAME, f"unexpected response shape: {exc}")

    if not results:
        return SourceResult(SOURCE_NAME, ok=True, risk_score=None, summary="no prior scans found")

    malicious_count = sum(1 for r in results if r.get("page", {}).get("status") == "malicious")
    # urlscan's search doesn't give a numeric verdict the way AbuseIPDB/VT do;
    # treat any prior scan flagged malicious as a strong signal, otherwise
    # report presence without asserting a score this source can't back up.
    risk_score = 90 if malicious_count else None

    summary = (
        f"{malicious_count} of {len(results)} prior scan(s) flagged malicious"
        if malicious_count else f"{len(results)} prior scan(s), none flagged malicious"
    )

    return SourceResult(
        source=SOURCE_NAME,
        ok=True,
        risk_score=risk_score,
        summary=summary,
        details={
            "scan_count": len(results),
            "malicious_count": malicious_count,
            "latest_scan_url": results[0].get("result") if results else None,
        },
    )
