"""
triage_engine.py
Rule-based SOC alert triage engine. Takes raw security events (the kind a
SIEM would emit) and scores each one against a small library of detection
rules mapped to MITRE ATT&CK techniques, then correlates events on the
same host into a candidate incident.

No external services required — pure Python, works on synthetic or real
exported alert data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    id: str
    timestamp: datetime
    host: str
    user: str
    event_type: str
    details: dict = field(default_factory=dict)

    @staticmethod
    def from_dict(d: dict) -> "Alert":
        ts = d["timestamp"]
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return Alert(
            id=str(d.get("id", "")),
            timestamp=ts,
            host=d.get("host", "unknown"),
            user=d.get("user", "unknown"),
            event_type=d.get("event_type", "unknown"),
            details=d.get("details", {}),
        )


@dataclass
class Rule:
    id: str
    name: str
    mitre_id: str
    mitre_name: str
    severity: str          # Low / Medium / High / Critical
    weight: int
    match_fn: callable
    recommended_action: str


@dataclass
class Finding:
    alert: Alert
    rule: Rule


@dataclass
class TriageResult:
    alert: Alert
    findings: list[Finding]
    score: int
    severity: str

    @property
    def matched(self) -> bool:
        return bool(self.findings)


@dataclass
class IncidentCluster:
    host: str
    triages: list[TriageResult]
    distinct_techniques: set
    window_minutes: int

    @property
    def is_multi_stage(self) -> bool:
        return len(self.distinct_techniques) >= 3


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

def _cmd(alert: Alert) -> str:
    return str(alert.details.get("command_line", "") or alert.details.get("command", "")).lower()


def _match_brute_force(a: Alert) -> bool:
    return (
        a.event_type == "authentication"
        and str(a.details.get("result", "")).lower() == "success"
        and int(a.details.get("prior_failed_attempts", 0)) >= 5
    )


def _match_encoded_powershell(a: Alert) -> bool:
    cmd = _cmd(a)
    return a.event_type == "process_creation" and "powershell" in cmd and (
        "-encodedcommand" in cmd or "-enc " in cmd or "frombase64string" in cmd
    )


def _match_lsass_access(a: Alert) -> bool:
    return (
        a.event_type == "process_access"
        and "lsass" in str(a.details.get("target_process", "")).lower()
        and str(a.details.get("source_process", "")).lower() not in ("wininit.exe", "csrss.exe", "services.exe")
    )


def _match_suspicious_outbound(a: Alert) -> bool:
    if a.event_type != "network_connection":
        return False
    port = int(a.details.get("dest_port", 0) or 0)
    reputation = str(a.details.get("dest_reputation", "")).lower()
    return reputation in ("malicious", "suspicious") or port in (4444, 1337, 8443, 6667)


def _match_scheduled_task(a: Alert) -> bool:
    cmd = _cmd(a)
    return a.event_type == "process_creation" and ("schtasks" in cmd and "/create" in cmd)


def _match_defense_impair(a: Alert) -> bool:
    cmd = _cmd(a)
    patterns = ["set-mppreference", "disablerealtimemonitoring", "netsh advfirewall set", "stop-service -name windefend"]
    return a.event_type == "process_creation" and any(p in cmd for p in patterns)


def _match_office_spawns_shell(a: Alert) -> bool:
    parent = str(a.details.get("parent_process", "")).lower()
    child = str(a.details.get("process_name", "")).lower()
    office = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
    shells = ("cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe")
    return a.event_type == "process_creation" and any(o in parent for o in office) and any(s in child for s in shells)


def _match_mass_file_rename(a: Alert) -> bool:
    return (
        a.event_type == "file_write"
        and int(a.details.get("files_modified_last_minute", 0)) >= 50
    )


def _match_new_admin_account(a: Alert) -> bool:
    cmd = _cmd(a)
    return a.event_type == "process_creation" and "net localgroup administrators" in cmd and "/add" in cmd


def _match_recon_commands(a: Alert) -> bool:
    cmd = _cmd(a)
    recon_cmds = ["whoami /all", "net group", "net user /domain", "nltest /domain_trusts", "ipconfig /all"]
    return a.event_type == "process_creation" and any(r in cmd for r in recon_cmds)


RULES: list[Rule] = [
    Rule("brute_force", "Successful login after repeated failures", "T1110", "Brute Force",
         "High", 30, _match_brute_force,
         "Verify login source/geo with the user; force password reset; check for follow-on activity from this session."),
    Rule("encoded_ps", "Obfuscated/encoded PowerShell execution", "T1059.001", "PowerShell",
         "High", 25, _match_encoded_powershell,
         "Decode the command, isolate the host, and inspect parent process lineage."),
    Rule("lsass_access", "Non-system process accessing LSASS memory", "T1003.001", "OS Credential Dumping: LSASS Memory",
         "Critical", 35, _match_lsass_access,
         "Isolate the host immediately; assume credential theft; rotate affected credentials."),
    Rule("susp_outbound", "Outbound connection to flagged destination/port", "T1071", "Application Layer Protocol (C2)",
         "High", 25, _match_suspicious_outbound,
         "Block destination at the firewall/proxy; capture pcap; check for beaconing pattern."),
    Rule("scheduled_task", "Scheduled task created for persistence", "T1053.005", "Scheduled Task/Job",
         "Medium", 15, _match_scheduled_task,
         "Review the task's target binary/script and remove if unauthorized."),
    Rule("defense_impair", "Security tooling disabled or modified", "T1562.001", "Impair Defenses",
         "Critical", 30, _match_defense_impair,
         "Re-enable protections, investigate why they were disabled, check for concurrent payload drop."),
    Rule("office_shell", "Office application spawned a script interpreter", "T1204/T1059", "User Execution -> Command Interpreter",
         "High", 20, _match_office_spawns_shell,
         "Treat as likely malicious document execution; collect the originating file/email."),
    Rule("mass_file_rename", "High-volume file modification (possible ransomware)", "T1486", "Data Encrypted for Impact",
         "Critical", 40, _match_mass_file_rename,
         "Isolate host from the network immediately; do not power off; engage IR process."),
    Rule("new_admin", "New local administrator account created", "T1136", "Create Account",
         "High", 20, _match_new_admin_account,
         "Verify change was authorized via change management; disable account if not."),
    Rule("recon", "Reconnaissance command executed", "T1087/T1018", "Account/Network Discovery",
         "Medium", 10, _match_recon_commands,
         "Correlate with other activity on the host; recon alone is often a precursor, not an isolated incident."),
]


def _severity_from_score(score: int) -> str:
    if score >= 60:
        return "Critical"
    if score >= 35:
        return "High"
    if score >= 15:
        return "Medium"
    if score > 0:
        return "Low"
    return "Informational"


def triage_alert(alert: Alert) -> TriageResult:
    findings = [Finding(alert, rule) for rule in RULES if rule.match_fn(alert)]
    score = min(sum(f.rule.weight for f in findings), 100)
    return TriageResult(alert=alert, findings=findings, score=score, severity=_severity_from_score(score))


def triage_batch(alerts: list[Alert]) -> list[TriageResult]:
    return [triage_alert(a) for a in alerts]


def correlate_by_host(results: list[TriageResult], window_minutes: int = 30) -> list[IncidentCluster]:
    """
    Group matched triage results by host. Within each host, find the
    tightest time window containing >=3 distinct MITRE techniques — a
    signal of a multi-stage attack chain rather than isolated noise.
    """
    by_host: dict[str, list[TriageResult]] = {}
    for r in results:
        if not r.matched:
            continue
        by_host.setdefault(r.alert.host, []).append(r)

    clusters: list[IncidentCluster] = []
    for host, host_results in by_host.items():
        host_results.sort(key=lambda r: r.alert.timestamp)
        techniques = set()
        for r in host_results:
            for f in r.findings:
                techniques.add(f.rule.mitre_id)
        clusters.append(IncidentCluster(
            host=host,
            triages=host_results,
            distinct_techniques=techniques,
            window_minutes=window_minutes,
        ))
    return clusters
