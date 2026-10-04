"""
ai_analyst.py
Optional: turn the rule-based triage output into a Tier-1 SOC analyst
style narrative using a locally running Ollama model. Fully optional —
the triage engine works standalone; this module just degrades gracefully
when Ollama isn't available.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error

from triage_engine import TriageResult, IncidentCluster

OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "llama3.2"


def is_ollama_available(url: str = OLLAMA_URL) -> bool:
    try:
        base = url.rsplit("/api/", 1)[0]
        req = urllib.request.Request(base + "/api/tags")
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return resp.status == 200
    except Exception:
        return False


def _cluster_prompt(cluster: IncidentCluster) -> str:
    lines = []
    for r in cluster.triages:
        for f in r.findings:
            lines.append(
                f"- [{r.alert.timestamp.isoformat()}] {f.rule.mitre_id} "
                f"({f.rule.mitre_name}): {f.rule.name} — user={r.alert.user}, "
                f"details={json.dumps(r.alert.details)}"
            )
    timeline = "\n".join(lines)

    return f"""You are a Tier-1 SOC analyst writing a shift-handoff note.

Host: {cluster.host}
Distinct MITRE ATT&CK techniques observed: {', '.join(sorted(cluster.distinct_techniques))}

Chronological findings:
{timeline}

Write a concise incident summary (4-6 sentences) in plain language for a
Tier-2 analyst picking this up: what likely happened, in what order, how
confident you are it's malicious vs. benign, and the single next
investigative step you'd take first. Do not just restate the technique
list — synthesize a narrative."""


def _single_alert_prompt(result: TriageResult) -> str:
    rule_lines = "\n".join(
        f"- {f.rule.mitre_id} ({f.rule.mitre_name}): {f.rule.name}" for f in result.findings
    ) or "- No rules matched."
    return f"""You are a Tier-1 SOC analyst. Explain this single alert for a
non-expert reader in 2-3 short sentences: what happened, why it matters,
and the recommended next action.

Host: {result.alert.host}
User: {result.alert.user}
Event type: {result.alert.event_type}
Details: {json.dumps(result.alert.details)}
Matched rules:
{rule_lines}
Severity: {result.severity}"""


def _call_ollama(prompt: str, model: str, url: str, timeout: float) -> str:
    payload = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("response", "").strip()
    except urllib.error.URLError as e:
        raise RuntimeError(f"Could not reach Ollama at {url}: {e}") from e
    except Exception as e:
        raise RuntimeError(f"Ollama request failed: {e}") from e


def explain_cluster(cluster: IncidentCluster, model: str = DEFAULT_MODEL, url: str = OLLAMA_URL, timeout: float = 45.0) -> str:
    return _call_ollama(_cluster_prompt(cluster), model, url, timeout)


def explain_alert(result: TriageResult, model: str = DEFAULT_MODEL, url: str = OLLAMA_URL, timeout: float = 30.0) -> str:
    return _call_ollama(_single_alert_prompt(result), model, url, timeout)
