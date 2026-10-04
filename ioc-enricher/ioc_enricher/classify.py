"""
Classifies a raw string as one of the IOC types this tool knows how to
enrich: ipv4, ipv6, domain, url, or a hash (md5/sha1/sha256). This
decides which threat-intel sources get queried for a given indicator —
there's no point sending a domain to AbuseIPDB (IP-only) or a hash to
urlscan.io (URL/domain-only).
"""

import re
import ipaddress

HASH_PATTERNS = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}

# Deliberately conservative: requires at least one dot and a plausible TLD,
# so it doesn't accidentally classify a bare word as a domain.
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

URL_PATTERN = re.compile(r"^https?://", re.IGNORECASE)


class IOCType:
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    UNKNOWN = "unknown"


def classify(raw_value):
    """Returns one of the IOCType constants for the given string."""
    value = raw_value.strip()

    if not value:
        return IOCType.UNKNOWN

    if URL_PATTERN.match(value):
        return IOCType.URL

    try:
        ip = ipaddress.ip_address(value)
        return IOCType.IPV4 if ip.version == 4 else IOCType.IPV6
    except ValueError:
        pass

    for hash_type, pattern in HASH_PATTERNS.items():
        if pattern.match(value):
            return {
                "md5": IOCType.HASH_MD5,
                "sha1": IOCType.HASH_SHA1,
                "sha256": IOCType.HASH_SHA256,
            }[hash_type]

    if DOMAIN_PATTERN.match(value):
        return IOCType.DOMAIN

    return IOCType.UNKNOWN


def is_hash(ioc_type):
    return ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256)


def is_ip(ioc_type):
    return ioc_type in (IOCType.IPV4, IOCType.IPV6)
