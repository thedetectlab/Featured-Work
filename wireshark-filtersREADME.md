<div align="center">

```
r o o t @ s n i f f e r : ~ / f e a t u r e d - w o r k / w i r e s h a r k - f i l t e r s #
```

# 🔍 Wireshark Filters Reference

**The filters that come up in real troubleshooting — not the whole manual rewritten.**

</div>

---

## 🎯 Capture Filters (BPF syntax — applied before capture)

```
host 192.168.1.10          → traffic to/from a specific IP
net 192.168.1.0/24         → all traffic on a subnet
port 443                   → traffic on port 443 (HTTPS)
tcp                        → TCP packets only
not arp and not dns        → exclude ARP and DNS noise
src host 10.0.0.5          → only packets where source is this IP
```

## 🔎 Display Filters (applied after capture)

| Filter | What it shows |
|---|---|
| `ip.addr == 192.168.1.1` | All traffic to/from a specific IP |
| `tcp.port == 443` | Traffic on TCP port 443 |
| `http` | HTTP requests/responses only |
| `dns` | DNS traffic only |
| `tcp.flags.syn == 1` | Packets with the SYN flag set |
| `tcp.analysis.retransmission` | Lost/retransmitted packets |
| `http.request.method == "POST"` | POST requests only |
| `ip.src == 10.0.0.1 && tcp` | Combine conditions with `&&` |
| `!(arp \|\| icmp)` | Everything except ARP and ICMP |

## 🤝 TCP Handshake & Flags

```
[SYN]           → connection request
[SYN, ACK]      → request accepted
[ACK]           → handshake complete
[RST]           → forced connection reset
[FIN, ACK]      → graceful close
[TCP Retransmission]  → packet didn't arrive, resending
[TCP Dup ACK]          → sign of packet loss
[TCP ZeroWindow]       → receiver overwhelmed, asking sender to pause
```

A `[SYN]` with no reply means the port is closed or blocked by a firewall.

## 🕵️ Finding Trouble Fast

```
tcp.analysis.retransmission        → packet loss / unstable link
tcp.analysis.duplicate_ack         → same signal, different symptom
tcp.flags.reset == 1               → connections being killed
dns.flags.rcode != 0               → failed DNS lookups
http.response.code >= 400          → failed HTTP requests
tls.handshake.type == 1            → TLS Client Hello (see SNI here)
```

## 🧵 Follow Streams

```
Right-click a TCP packet → Follow → TCP Stream
```

Reassembles the full client/server conversation in one window. Auto-applies a filter like:

```
tcp.stream eq 5
```

so you can jump back to individual packets of that same connection later.

---

<div align="center">

```
TYPE      TOOL CHEAT SHEET
STATUS    ACTIVE
```

⚠️ For authorized testing and educational use only.

</div>
