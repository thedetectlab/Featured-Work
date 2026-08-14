<div align="center">

```
r o o t @ s n i f f e r : ~ / f e a t u r e d - w o r k / s o c - d e t e c t i o n - q u e r i e s #
```

# 🛡 SOC Detection Queries

**Real Event IDs, real queries, mapped to MITRE ATT&CK — ten attacks, ready to adapt.**

</div>

---

## 🔑 Brute Force Login — T1110.001

**Event ID 4625 — Failed Logon.** A handful from the same user/IP in a workday is normal. Dozens/hundreds from one source IP in a short window, especially followed by a successful logon (4624), means the attacker found the right password.

```spl
index=security EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 10
```

**First response:** lock/reset the affected account, block the source IP, check for a follow-up successful logon from the same source.

---

## 🎫 Kerberoasting — T1558.003

**Event ID 4769 — Kerberos Service Ticket requested.** Watch for a high volume of ticket requests using RC4 encryption (`0x17`) for service accounts — modern environments should be using AES, so RC4 requests are a red flag.

```spl
index=security EventCode=4769 Ticket_Encryption_Type=0x17
| stats count by Account_Name, Service_Name
| where count > 5
```

**First response:** identify the requesting account, check if it's expected behavior, rotate the service account password if compromise is suspected.

---

## 📡 C2 Beaconing — T1071

Regular, low-variance intervals between outbound connections to the same external host are the signature of beaconing malware — not the payload itself, the *rhythm*.

```spl
index=network
| stats count, avg(bytes_out) by dest_ip, src_ip
| eventstats stdev(_time) as time_variance by dest_ip, src_ip
| where time_variance < 5 AND count > 20
```

**First response:** isolate the host, block the destination IP/domain, capture traffic for further analysis before remediation.

---

## 🌐 DNS Exfiltration — T1071.004

Abnormally long DNS queries, high query volume to a single domain, or high-entropy subdomains (random-looking strings) are common exfiltration indicators.

```spl
index=dns
| eval qlen=len(query)
| where qlen > 50
| stats count by src_ip, query
| where count > 20
```

**First response:** block the domain, isolate the host, check what data may have left before detection.

---

## 🖥 Lateral Movement — T1021

**Event ID 4624 (Logon Type 3)** across multiple hosts from the same account in a short window suggests lateral movement, especially outside normal working hours.

```spl
index=security EventCode=4624 Logon_Type=3
| stats dc(dest) as host_count by Account_Name
| where host_count > 5
```

**First response:** confirm whether the activity is expected (admin, scheduled job), isolate affected hosts if not.

---

## Reference Table

| Attack | Severity | MITRE ATT&CK |
|---|---|---|
| Brute Force Login | High | T1110.001 |
| Kerberoasting | Critical | T1558.003 |
| C2 Beaconing | Critical | T1071 |
| DNS Exfiltration | High | T1071.004 |
| Lateral Movement | High | T1021 |
| Pass-the-Hash | Critical | T1550.002 |
| Privilege Escalation | Critical | T1068 |
| Malicious PowerShell | High | T1059.001 |
| Persistence | High | T1547 |
| Password Spraying | High | T1110.003 |

*Full write-ups with normal-vs-suspicious pattern breakdowns and MITRE mapping for all ten in the linked field guide.*

---

<div align="center">

```
TYPE      DETECTION REFERENCE
STATUS    ACTIVE
```

⚠️ Queries are SPL-style — adapt syntax for Sentinel (KQL) or Elastic (EQL) as needed.

</div>
