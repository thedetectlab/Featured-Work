# home-soc-lab

Spin up a minimal SOC detection lab — Elasticsearch + Kibana, pre-loaded with
synthetic (but realistic) security events — in under 5 minutes, with one command.

Built as a companion to the [Home SOC Lab Setup Guide](https://thedetectlab.gumroad.com)
and the [SOC Detection Playbook](https://thedetectlab.gumroad.com) — this repo gives you
somewhere to actually practice queries instead of just reading about them.

## What's included

- `docker-compose.yml` — single-node Elasticsearch + Kibana, no security setup friction
- `scripts/generate_sample_logs.py` — generates synthetic Windows-style security events
  (failed logons, process creation) with a realistic mix of normal and suspicious activity
- `scripts/ingest_logs.sh` — bulk-loads the generated logs into Elasticsearch
- `sample-logs/events.ndjson` — a pre-generated sample set (300 events) so you can start
  immediately without generating your own

## Quick start

```bash
# 1. Start Elasticsearch + Kibana
docker compose up -d

# 2. (Optional) Generate a fresh batch of synthetic logs
python3 scripts/generate_sample_logs.py --count 500 --out sample-logs/events.ndjson

# 3. Load the logs into Elasticsearch
chmod +x scripts/ingest_logs.sh
./scripts/ingest_logs.sh

# 4. Open Kibana
open http://localhost:5601
```

In Kibana: **Stack Management → Data Views → Create data view**, pattern `soc-lab-events*`,
timestamp field `@timestamp`. Then go to **Discover** to start exploring.

## Example queries to try (KQL, in Kibana Discover)

```
# All suspicious-tagged events
tags: "suspicious"

# Failed logons from a specific host
event.code: "4625" and host.name: "WIN-SRV-DB01"

# Process creation events involving PowerShell
event.code: "4688" and process.command_line: *powershell*

# Suspicious process spawned from an Office app (classic phishing macro pattern)
process.parent.name: "winword.exe" and tags: "suspicious"
```

## Practice ideas

- Build a Kibana visualization showing failed logon count per host, per hour
- Find every "suspicious"-tagged event and manually verify why it was flagged
- Write a query that finds process creation events NOT in a normal baseline list
- Delete the index, regenerate logs with `--count 2000`, and see how your queries hold up
  at higher volume

## Cleanup

```bash
docker compose down -v   # removes containers and the Elasticsearch data volume
```

## Notes

- This is a **detection practice environment**, not a production SIEM setup — security
  features are disabled on Elasticsearch for simplicity. Never run this configuration
  outside an isolated lab network.
- All log data is synthetically generated — no real hostnames, users, or IPs are involved.

---

Part of [The Detect Lab](https://thedetectlab.gumroad.com) — practical playbooks for
developers and SOC analysts.
