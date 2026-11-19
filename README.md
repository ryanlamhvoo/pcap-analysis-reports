# Pcap Analysis Reports

Network forensics write-ups from real malware traffic captures, written the way a SOC analyst writes an incident report: **what happened, which host, which user, the evidence, and what to do next.**

Exercises come from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/training-exercises.html). All analysis is done inside an isolated Ubuntu VM with `tshark` / Wireshark — no malware is ever executed. Pcaps are **not** stored in this repo.

## Reports

| Date | Exercise | Threat | Key skills | Report |
|---|---|---|---|---|
| 2026-02-28 | Easy As 123 | NetSupport Manager RAT | Host identification (DHCP, NBNS, Kerberos, LDAP), C2 traffic | [report](reports/2026-02-28-easy-as-123/report.md) |

## Method

1. **Scope** — read the alert (SIEM hit, IP, time) and the network details (LAN range, DC, gateway).
2. **Triage** — `capinfos`, protocol hierarchy, top conversations.
3. **Identify the victim** — IP → MAC (Ethernet/DHCP) → host name (DHCP / NBNS) → user (Kerberos `CNameString`) → full name (LDAP).
4. **Find the malicious activity** — traffic to the alerted IP, DNS lookups, HTTP requests, TLS SNI.
5. **Report** — timeline, IOCs (defanged), MITRE ATT&CK mapping, containment and detection recommendations.

## Tools

`tshark` · `capinfos` · Wireshark · Ubuntu Server VM (VirtualBox) · VirusTotal / AbuseIPDB for IOC lookups

## Safety

- Pcaps and zips are handled only inside the VM and never committed (`.gitignore`).
- IOCs are written **defanged** (`45.131.214[.]85`, `hxxp://`) so nothing in this repo is clickable.
