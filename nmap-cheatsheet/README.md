<div align="center">

```
r o o t @ s n i f f e r : ~ / f e a t u r e d - w o r k / n m a p - c h e a t s h e e t #
```

# 🎯 Nmap Cheat Sheet

**Every flag that actually matters. Nothing you'll never use.**

</div>

---

## 📡 Host Discovery

```bash
# Ping scan — no port scan, just "is it alive"
nmap -sn 192.168.1.0/24

# Skip ping entirely — useful when ICMP is blocked
nmap -Pn 192.168.1.10

# ARP scan — fastest and most reliable on a local subnet
nmap -PR 192.168.1.0/24
```

## 🔍 Scan Types

| Flag | Scan | Notes |
|---|---|---|
| `-sS` | TCP SYN (Stealth) | Default for privileged users, doesn't complete the handshake |
| `-sT` | TCP Connect | Full handshake, used when SYN isn't available |
| `-sU` | UDP | Slow, but necessary for DNS/SNMP/DHCP recon |
| `-sA` | TCP ACK | Maps firewall rules, not open ports |
| `-sV` | Version Detection | Identifies the service, not just the port |

```bash
# Stealth SYN scan on specific ports
nmap -sS -p 22,80,443 192.168.1.10

# Every port, version detection, OS fingerprint
nmap -sV -O -p- 192.168.1.10
```

## 🚦 Port States

```
OPEN            → service is listening
CLOSED          → reachable, nothing listening
FILTERED        → firewall is dropping probes
UNFILTERED      → reachable, but state unknown
OPEN|FILTERED   → nmap genuinely can't tell
```

## 🧠 NSE Scripts

```bash
# Run the default safe script set
nmap -sC 192.168.1.10

# Vulnerability scanning
nmap --script vuln 192.168.1.10

# Specific category
nmap --script discovery 192.168.1.10
```

| Category | Purpose |
|---|---|
| `auth` | Authentication bypass checks |
| `default` | Safe, general-purpose scripts |
| `discovery` | Host/service discovery |
| `exploit` | Active exploitation attempts |
| `vuln` | Vulnerability detection |

## 💾 Output Formats

```bash
# Normal (human-readable)
nmap -oN scan.txt 192.168.1.10

# XML (for parsing/tooling)
nmap -oX scan.xml 192.168.1.10

# Grepable (for scripts)
nmap -oG scan.gnmap 192.168.1.10

# All formats at once
nmap -oA full_scan 192.168.1.10
```

## ⚡ Quick Combos

```bash
# Aggressive — OS detection, version, scripts, traceroute
nmap -A 192.168.1.10

# Fast scan — top 100 ports only
nmap -F 192.168.1.10

# Full recon, real-world default
nmap -sV -O -sC -p- -oA recon 192.168.1.10
```

---

<div align="center">

```
TYPE      TOOL CHEAT SHEET
STATUS    ACTIVE
```

⚠️ For authorized testing and educational use only.

</div>
