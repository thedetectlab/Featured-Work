"""
Formats a list of IOCReport objects as a colored terminal summary, JSON,
or CSV — JSON/CSV for feeding into a SIEM or spreadsheet, terminal for
reading during a shift.
"""

import csv
import io
import json
from datetime import datetime, timezone

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
GRAY = "\033[90m"

VERDICT_COLOR = {"malicious": RED, "suspicious": YELLOW, "clean": GREEN, "unknown": GRAY}


def to_terminal(ioc_reports):
    lines = [f"{BOLD}ioc-enricher{RESET} — {len(ioc_reports)} indicator(s)", GRAY + "-" * 60 + RESET]

    counts = {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0}
    for r in ioc_reports:
        counts[r.verdict] += 1

    summary = ", ".join(
        f"{VERDICT_COLOR[v]}{count} {v}{RESET}" for v, count in counts.items() if count
    )
    lines.append(summary)
    lines.append("")

    # Worst-first: an analyst scanning the output should see the thing
    # that needs action before the things that don't.
    verdict_rank = {"malicious": 0, "suspicious": 1, "unknown": 2, "clean": 3}
    for r in sorted(ioc_reports, key=lambda r: (verdict_rank[r.verdict], -r.overall_score)):
        color = VERDICT_COLOR[r.verdict]
        lines.append(f"{color}{BOLD}[{r.verdict.upper()}]{RESET} {r.ioc_value} "
                      f"{GRAY}({r.ioc_type}){RESET} — score: {r.overall_score}/100")

        for sr in r.source_results:
            if sr.ok:
                score_str = f"{sr.risk_score}/100" if sr.risk_score is not None else "n/a"
                lines.append(f"  {GRAY}{sr.source}:{RESET} {score_str} — {sr.summary}")
            else:
                lines.append(f"  {GRAY}{sr.source}:{RESET} {GRAY}skipped/failed — {sr.error}{RESET}")
        lines.append("")

    return "\n".join(lines)


def _report_to_dict(r):
    return {
        "ioc": r.ioc_value,
        "ioc_type": r.ioc_type,
        "overall_score": r.overall_score,
        "verdict": r.verdict,
        "sources": [
            {
                "source": sr.source,
                "ok": sr.ok,
                "risk_score": sr.risk_score,
                "summary": sr.summary,
                "details": sr.details,
                "error": sr.error,
            }
            for sr in r.source_results
        ],
    }


def to_json(ioc_reports):
    payload = {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "indicator_count": len(ioc_reports),
        "indicators": [_report_to_dict(r) for r in ioc_reports],
    }
    return json.dumps(payload, indent=2, default=str)


def to_csv(ioc_reports):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["ioc", "ioc_type", "overall_score", "verdict", "sources_queried", "sources_with_data"])

    for r in ioc_reports:
        writer.writerow([
            r.ioc_value,
            r.ioc_type,
            r.overall_score,
            r.verdict,
            len(r.queried_sources),
            len(r.scored_sources),
        ])

    return buffer.getvalue()
