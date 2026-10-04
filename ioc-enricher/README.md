<div align="center">

```
r o o t @ s n i f f e r : ~ / i o c - e n r i c h e r #
```

# 🔎 ioc-enricher

</div>

<p align="center">
  <img src="https://img.shields.io/badge/status-active-33FF66?style=for-the-badge&labelColor=0A0F0A" />
  <img src="https://img.shields.io/badge/language-python-33FF66?style=for-the-badge&labelColor=0A0F0A" />
  <img src="https://img.shields.io/badge/tests-44%20passing-33FF66?style=for-the-badge&labelColor=0A0F0A" />
</p>

<p align="center">
  Give it a list of IOCs. Get back one report instead of four open tabs.
</p>

---

## What it does

The part of a SOC shift that's simple but slow: taking an indicator — an IP, a domain, a URL, a
file hash — and checking it against AbuseIPDB, VirusTotal, and urlscan.io one by one, then
mentally averaging three different verdicts into "is this actually bad." This automates that
whole loop for a list of indicators at once and outputs one consolidated score per IOC instead
of three browser tabs per IOC.

```
$ ioc-enricher --file examples/iocs.txt

ioc-enricher — 4 indicator(s)
------------------------------------------------------------
1 malicious, 1 suspicious, 1 clean, 1 unknown

[MALICIOUS] 185.220.101.45 (ipv4) — score: 85/100
  abuseipdb: 98/100 — 98/100 confidence, 340 report(s), Tor exit node
  virustotal: 72/100 — 40 malicious / 15 suspicious of 76 engines

[SUSPICIOUS] evil-test-domain.example.com (domain) — score: 68/100
  virustotal: 45/100 — 12 malicious / 22 suspicious of 76 engines
  urlscan: 90/100 — 2 of 3 prior scan(s) flagged malicious
...
```

Full sample output in [`examples/sample_output.txt`](./examples/sample_output.txt).

---

## Install

```bash
git clone https://github.com/thedetectlab/ioc-enricher
cd ioc-enricher
pip install -e .
```

Requires Python 3.8+. The only runtime dependency is `requests`.

## API keys

Each source is independently optional — the tool runs with zero, one, two, or all three keys
configured, and just reports which sources it could actually query for each IOC.

| Source | Env var | Free tier | Covers |
|---|---|---|---|
| [AbuseIPDB](https://www.abuseipdb.com/account/api) | `ABUSEIPDB_API_KEY` | 1,000 checks/day | IPv4, IPv6 |
| [VirusTotal](https://www.virustotal.com/gui/my-apikey) | `VIRUSTOTAL_API_KEY` | 4 req/min, 500/day | IPs, domains, URLs, hashes |
| [urlscan.io](https://urlscan.io/user/signup) | `URLSCAN_API_KEY` | works **without a key** for search | Domains, URLs |

```bash
export ABUSEIPDB_API_KEY="your-key-here"
export VIRUSTOTAL_API_KEY="your-key-here"
# urlscan.io works unauthenticated for search queries — the key is optional
```

## Usage

```bash
# Check indicators directly
ioc-enricher 8.8.8.8 evil.example.com d41d8cd98f00b204e9800998ecf8427e

# Check a list from a file (one IOC per line, # comments supported)
ioc-enricher --file examples/iocs.txt

# JSON — for piping into a SIEM or another script
ioc-enricher --file iocs.txt --json --output report.json

# CSV — for a spreadsheet
ioc-enricher --file iocs.txt --csv --output report.csv

# Skip the local cache and query sources fresh
ioc-enricher 8.8.8.8 --no-cache
```

IOC type is auto-detected (IPv4, IPv6, domain, URL, MD5/SHA1/SHA256 hash), and each indicator is
only sent to the sources that actually support that type — a domain never gets sent to AbuseIPDB,
a hash never gets sent to urlscan.

---

## How the scoring works

Every source returns its own 0–100 risk score (or no score at all, if it has no data on that
IOC). The overall score is the **mean of every source that actually had an opinion** — a source
with no data on an IOC doesn't drag the average toward "clean," because "not found" and "found
and verified clean" are different signals and treating them the same would be misleading.

| Score | Verdict |
|---|---|
| 75–100 | `malicious` |
| 40–74 | `suspicious` |
| 0–39 | `clean` |
| no source had data | `unknown` |

A rate-limited or failed source is excluded from the average entirely rather than silently
counting as a 0 — a quota error should never make an indicator look safer than it is.

---

## Caching

Results are cached locally (`~/.cache/ioc-enricher/cache.json`) for 6 hours by default, so
re-running a report against the same IOC list doesn't burn through AbuseIPDB's 1,000/day or
VirusTotal's 4/minute quota for indicators you already checked an hour ago. Override with
`--cache-ttl SECONDS` or skip it entirely with `--no-cache`.

---

## Project structure

```
ioc-enricher/
├── ioc_enricher/
│   ├── cli.py              ← argument parsing, orchestration
│   ├── classify.py         ← IOC type detection (IP/domain/URL/hash)
│   ├── aggregator.py        ← combines per-source scores into one verdict
│   ├── cache.py             ← local JSON cache with TTL
│   ├── report.py            ← terminal / JSON / CSV output
│   └── sources/
│       ├── abuseipdb.py
│       ├── virustotal.py
│       └── urlscan.py
├── tests/                   ← 44 tests, all HTTP calls mocked
└── examples/
    ├── iocs.txt
    └── sample_output.txt
```

Adding a new source means writing one module with a `supports(ioc_type)` function and a
`query(ioc_value, ioc_type, api_key)` function that returns a `SourceResult`, then registering
it in `cli.py`'s `SOURCE_MODULES` list.

## Running the tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

All 44 tests run offline — every HTTP call to AbuseIPDB, VirusTotal, and urlscan.io is mocked,
so the suite verifies this project's own classification, scoring, caching, and error-handling
logic without depending on live API quota or network access.

---

## Limitations

This tool reports what public reputation sources say about an indicator — it doesn't replace
judgment. A "clean" verdict means no source had anything negative on file, not that the
indicator is proven safe; a freshly-registered malicious domain can be clean everywhere simply
because no one's reported it yet. Treat every output as a lead, the same way
[pcap-triage](https://github.com/thedetectlab/pcap-triage) findings are leads, not verdicts.

---

<div align="center">

```
TYPE      TOOL
STATUS    ACTIVE
```

Part of [thedetectlab](https://github.com/thedetectlab) — see also
[pcap-triage](https://github.com/thedetectlab/pcap-triage) and
[SOC Detection Queries](https://github.com/thedetectlab/Featured-Work/tree/main/soc-detection-queries).

</div>
