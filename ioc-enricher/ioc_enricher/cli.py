"""
ioc-enricher CLI entry point.

Usage:
    ioc-enricher 8.8.8.8 evil.example.com
    ioc-enricher --file iocs.txt
    ioc-enricher --file iocs.txt --json --output report.json
    ioc-enricher 8.8.8.8 --no-cache
"""

import argparse
import os
import sys

from . import classify, report
from .aggregator import aggregate
from .cache import Cache
from .sources import abuseipdb, virustotal, urlscan

SOURCE_MODULES = [abuseipdb, virustotal, urlscan]


def build_parser():
    parser = argparse.ArgumentParser(
        prog="ioc-enricher",
        description="Enrich a list of indicators of compromise (IPs, domains, URLs, hashes) "
                     "against AbuseIPDB, VirusTotal, and urlscan.io, and produce one consolidated report.",
    )
    parser.add_argument("iocs", nargs="*", help="One or more IOCs to check, given directly on the command line")
    parser.add_argument("--file", metavar="FILE", help="Read IOCs from a file, one per line")
    parser.add_argument("--json", action="store_true", help="Output as JSON instead of a terminal report")
    parser.add_argument("--csv", action="store_true", help="Output as CSV instead of a terminal report")
    parser.add_argument("--output", metavar="FILE", help="Write output to a file instead of stdout")
    parser.add_argument("--no-cache", action="store_true", help="Bypass the local cache and query sources fresh")
    parser.add_argument(
        "--cache-ttl", type=int, default=None, metavar="SECONDS",
        help="Override the cache TTL in seconds (default: 6 hours)",
    )
    return parser


def _read_iocs(args):
    """Returns the deduplicated IOC list, or None if the given --file couldn't be read."""
    iocs = list(args.iocs)
    if args.file:
        try:
            with open(args.file) as fh:
                iocs.extend(line.strip() for line in fh if line.strip() and not line.startswith("#"))
        except FileNotFoundError:
            print(f"error: file not found: {args.file}", file=sys.stderr)
            return None
    # de-duplicate while preserving order, so the same IP listed twice
    # doesn't burn quota twice or appear twice in the report
    seen = set()
    deduped = []
    for ioc in iocs:
        if ioc not in seen:
            seen.add(ioc)
            deduped.append(ioc)
    return deduped


def _query_ioc(ioc_value, ioc_type, api_keys, cache):
    results = []
    for module in SOURCE_MODULES:
        if not module.supports(ioc_type):
            continue

        api_key = api_keys.get(module.SOURCE_NAME)
        cached = None if cache is None else cache.get(module.SOURCE_NAME, ioc_value)

        if cached is not None:
            from .sources.base import SourceResult
            results.append(SourceResult(**cached))
            continue

        result = module.query(ioc_value, ioc_type, api_key)
        results.append(result)

        if cache is not None and result.ok:
            cache.set(module.SOURCE_NAME, ioc_value, {
                "source": result.source, "ok": result.ok, "risk_score": result.risk_score,
                "summary": result.summary, "details": result.details, "error": result.error,
            })

    return results


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    iocs = _read_iocs(args)
    if iocs is None:
        return 1  # _read_iocs already printed the specific error (e.g. file not found)
    if not iocs:
        print("error: no IOCs given — pass them as arguments or use --file", file=sys.stderr)
        return 1

    api_keys = {
        "abuseipdb": os.environ.get("ABUSEIPDB_API_KEY"),
        "virustotal": os.environ.get("VIRUSTOTAL_API_KEY"),
        "urlscan": os.environ.get("URLSCAN_API_KEY"),  # optional — urlscan search works without one
    }

    cache = None
    if not args.no_cache:
        cache_kwargs = {}
        if args.cache_ttl is not None:
            cache_kwargs["ttl_seconds"] = args.cache_ttl
        cache = Cache(**cache_kwargs)

    ioc_reports = []
    for raw_ioc in iocs:
        ioc_type = classify.classify(raw_ioc)
        if ioc_type == classify.IOCType.UNKNOWN:
            print(f"warning: could not classify '{raw_ioc}', skipping", file=sys.stderr)
            continue

        source_results = _query_ioc(raw_ioc, ioc_type, api_keys, cache)
        ioc_reports.append(aggregate(raw_ioc, ioc_type, source_results))

    if not ioc_reports:
        print("error: no valid IOCs to report on", file=sys.stderr)
        return 1

    if args.json:
        output = report.to_json(ioc_reports)
    elif args.csv:
        output = report.to_csv(ioc_reports)
    else:
        output = report.to_terminal(ioc_reports)

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(output)
        print(f"Report written to {args.output}")
    else:
        print(output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
