# 🛡️ AI SOC Analyst Lab

> One-machine project: Python app + MITRE ATT&CK-mapped triage logic + optional local AI incident narrative
>
> `Python` · `Streamlit` · `MITRE ATT&CK` · `Ollama (optional)` · Portfolio-ready

A Streamlit dashboard that does first-pass triage on raw security events the
way a Tier-1 SOC analyst would: score each alert against a small rule
library mapped to MITRE ATT&CK, then correlate events on the same host to
flag candidate **multi-stage incidents** instead of a pile of isolated
noise. An optional local LLM (via [Ollama](https://ollama.com)) can turn the
findings into a plain-language shift-handoff narrative — nothing leaves
your machine.

## Features

- Ingests SIEM-style JSON events (`authentication`, `process_creation`,
  `process_access`, `network_connection`, `file_write`)
- 10 detection rules mapped to MITRE ATT&CK, covering:
  brute force, encoded PowerShell, LSASS access (credential dumping),
  C2-style outbound connections, scheduled task persistence, defense
  evasion (disabling AV/firewall), malicious document execution, mass
  file modification (ransomware pattern), new admin account creation,
  and recon commands
- Per-alert severity score (Informational → Critical) with a recommended
  next action for each matched rule
- **Correlation engine**: groups matched alerts by host and flags hosts
  with ≥3 distinct ATT&CK techniques as a likely multi-stage attack chain
  — so a brute-force login + encoded PowerShell + LSASS access on the same
  box gets surfaced as one incident, not three disconnected alerts
- Optional AI-written incident narrative and per-alert explanations via a
  local Ollama model
- Three ready-to-load sample alert sets (`sample_alerts/`): a full
  multi-stage attack chain, benign noise, and a standalone ransomware spike

## Project structure

```
.
├── app.py                 # Streamlit dashboard
├── triage_engine.py         # rule library, MITRE mapping, scoring, correlation
├── ai_analyst.py            # optional local AI narrative via Ollama
├── sample_alerts/
│   ├── attack_chain.json     # 7 correlated events, one host, one intrusion
│   ├── benign_noise.json     # normal activity, should score Informational
│   └── ransomware_spike.json # single high-severity, non-correlated alert
├── requirements.txt
└── README.md
```

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
streamlit run app.py
```

Open the local URL Streamlit prints (usually http://localhost:8501),
pick **"Multi-stage attack chain"** from the sample dropdown, and click
**Run triage** to see the full correlated incident view.

## Optional: local AI incident narrative

Works fully without any setup. To also get a plain-language shift-handoff
summary of a correlated incident:

1. Install [Ollama](https://ollama.com)
2. Pull a small model: `ollama pull llama3.2`
3. In the app, toggle **"AI incident narrative (local Ollama)"**

If Ollama isn't running, the app just skips this with a friendly message —
rule-based triage and correlation still work fully.

## Detection rules

| Rule | MITRE ATT&CK | Severity weight |
|---|---|---|
| Mass file modification (ransomware pattern) | T1486 | 40 |
| LSASS memory access | T1003.001 | 35 |
| Successful login after repeated failures | T1110 | 30 |
| Security tooling disabled | T1562.001 | 30 |
| Encoded/obfuscated PowerShell | T1059.001 | 25 |
| Outbound to flagged destination/port | T1071 | 25 |
| Office app spawning a shell | T1204/T1059 | 20 |
| New local admin account | T1136 | 20 |
| Scheduled task persistence | T1053.005 | 15 |
| Recon command (whoami, net group, ...) | T1087/T1018 | 10 |

`0` Informational · `1–14` Low · `15–34` Medium · `35–59` High · `60+` Critical

A host is flagged as a **candidate multi-stage incident** when ≥3 distinct
technique IDs appear on it (configurable correlation window, default 30 min).

## Bring your own data

Export real events from your SIEM/EDR as a JSON list with this shape and
paste or upload it — no code changes needed:

```json
{
  "id": "A-1001",
  "timestamp": "2026-02-10T14:02:00Z",
  "host": "WKS-FIN-07",
  "user": "jdoe",
  "event_type": "process_creation",
  "details": { "process_name": "...", "parent_process": "...", "command_line": "..." }
}
```

## License

MIT — do whatever you want with it.
