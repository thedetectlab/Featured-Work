"""
Combines SourceResult objects from multiple threat-intel sources into one
overall verdict for an IOC. The logic is deliberately simple and
auditable — an analyst reading a report should be able to see exactly
why an IOC got the score it did, not trust a black box.
"""

from dataclasses import dataclass, field
from typing import List

from .sources.base import SourceResult

VERDICT_THRESHOLDS = (
    (75, "malicious"),
    (40, "suspicious"),
    (0, "clean"),
)


@dataclass
class IOCReport:
    ioc_value: str
    ioc_type: str
    overall_score: int  # 0-100, 0 when no source had an opinion
    verdict: str        # "malicious" | "suspicious" | "clean" | "unknown"
    source_results: List[SourceResult] = field(default_factory=list)

    @property
    def queried_sources(self):
        return [r for r in self.source_results if r.ok or r.error]

    @property
    def scored_sources(self):
        return [r for r in self.source_results if r.ok and r.risk_score is not None]

    @property
    def failed_sources(self):
        return [r for r in self.source_results if not r.ok]


def _verdict_for_score(score):
    for threshold, label in VERDICT_THRESHOLDS:
        if score >= threshold:
            return label
    return "clean"


def aggregate(ioc_value, ioc_type, source_results):
    """
    Combines per-source results into a single IOCReport.

    Overall score is the mean of every source that returned a numeric
    risk_score (i.e. it had the IOC and an opinion about it). Sources that
    were skipped, failed, or simply had no data on this IOC don't pull the
    average down — "not found" is not the same signal as "found and clean".
    If no source produced a score at all, the verdict is "unknown" rather
    than defaulting to "clean", so an analyst doesn't mistake silence for
    a clean bill of health.
    """
    scores = [r.risk_score for r in source_results if r.ok and r.risk_score is not None]

    if not scores:
        return IOCReport(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            overall_score=0,
            verdict="unknown",
            source_results=source_results,
        )

    overall_score = round(sum(scores) / len(scores))

    return IOCReport(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        overall_score=overall_score,
        verdict=_verdict_for_score(overall_score),
        source_results=source_results,
    )
