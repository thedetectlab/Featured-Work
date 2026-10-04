"""
ai_explainer.py
Optional natural-language explanation of the heuristic result, generated
by a locally running Ollama model. Fully optional — the app works fine
without Ollama installed; this module just degrades gracefully.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error

from detector import AnalysisResult

OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "llama3.2"


def is_ollama_available(url: str = OLLAMA_URL) -> bool:
    """Quick check whether a local Ollama server is reachable."""
    try:
        base = url.rsplit("/api/", 1)[0]
        req = urllib.request.Request(base + "/api/tags")
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return resp.status == 200
    except Exception:
        return False


def _build_prompt(result: AnalysisResult, email_excerpt: str) -> str:
    matched = result.matched_indicators()
    signal_lines = "\n".join(
        f"- {i.name} (weight {i.weight}): {i.description}"
        + (f" Evidence: {', '.join(i.evidence[:3])}" if i.evidence else "")
        for i in matched
    ) or "- No heuristic signals matched."

    return f"""You are a security analyst assistant. Explain, in plain language
for a non-technical employee, why an email was scored {result.score}/100
({result.risk_level} risk) by an automated phishing detector.

Matched signals:
{signal_lines}

Email excerpt (truncated):
\"\"\"{email_excerpt[:800]}\"\"\"

Write 3-5 short sentences: what looks suspicious, what the likely goal of
the attacker is (if any), and one concrete recommended action for the
recipient. Do not repeat the raw signal list verbatim; synthesize it."""


def explain_with_ollama(
    result: AnalysisResult,
    email_body: str,
    model: str = DEFAULT_MODEL,
    url: str = OLLAMA_URL,
    timeout: float = 30.0,
) -> str:
    """
    Ask a local Ollama model to explain the result in plain language.
    Raises RuntimeError if Ollama is unreachable or returns an error.
    """
    prompt = _build_prompt(result, email_body)
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
    }).encode("utf-8")

    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("response", "").strip()
    except urllib.error.URLError as e:
        raise RuntimeError(f"Could not reach Ollama at {url}: {e}") from e
    except Exception as e:
        raise RuntimeError(f"Ollama request failed: {e}") from e
