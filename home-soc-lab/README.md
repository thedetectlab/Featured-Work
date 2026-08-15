<div align="center">

```
r o o t @ s n i f f e r : ~ / f e a t u r e d - w o r k / h o m e - s o c - l a b #  d o c k e r  c o m p o s e  u p
```

# 🧪 Home SOC Lab

**A minimal SOC detection lab — Elasticsearch + Kibana, pre-loaded with synthetic security events — in under 5 minutes, one command.**

<img src="https://img.shields.io/badge/status-active-33FF66?style=for-the-badge&labelColor=0A0F0A" />
<img src="https://img.shields.io/badge/stack-elasticsearch%20%2B%20kibana-33FF66?style=for-the-badge&labelColor=0A0F0A" />

</div>

---

Somewhere to actually run queries instead of just reading about them. Companion to the SOC detection field guides — same Event IDs, same query patterns, but on real infrastructure you control.

## 📦 What's included

| File | Purpose |
|---|---|
| `docker-compose.yml` | Single-node Elasticsearch + Kibana, no security setup friction |
| `scripts/generate_sample_logs.py` | Generates synthetic Windows-style security events — failed logons, process creation — with a realistic mix of normal and suspicious activity |
| `scripts/ingest_logs.sh` | Bulk-loads the generated logs into Elasticsearch |
| `sample-logs/events.ndjson` | Pre-generated set (300 events) — start immediately without generating your own |

## ⚡ Quick Start

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

In Kibana: **Stack Management → Data Views → Create data view**, pattern `soc-lab-events*`, timestamp field `@timestamp`. Then go to **Discover** to start exploring.

## 🔍 Example Queries (KQL, in Kibana Discover)

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

## 🎯 Practice Ideas

- Build a Kibana visualization showing failed logon count per host, per hour
- Find every `suspicious`-tagged event and manually verify why it was flagged
- Write a query that finds process creation events NOT in a normal baseline list
- Delete the index, regenerate logs with `--count 2000`, and see how your queries hold up at higher volume

## 🧹 Cleanup

```bash
docker compose down -v   # removes containers and the Elasticsearch data volume
```

## ⚠️ Notes

- This is a **detection practice environment**, not a production SIEM setup — security features are disabled on Elasticsearch for simplicity. Never run this configuration outside an isolated lab network.
- All log data is synthetically generated — no real hostnames, users, or IPs are involved.

---

<div align="center">

```
TYPE      PRACTICE LAB
STATUS    ACTIVE
```

⭐ Star this repo if you use it — practice ideas and query examples get added as they come up.

</div>
