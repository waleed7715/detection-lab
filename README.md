# Detection Engineering Lab

Hands-on detection engineering against a purpose-built Active Directory environment. Each project runs a technique, attempts to detect it, and documents what the telemetry actually showed.

The emphasis is on detection logic and its limits, not on tool deployment.

---

## Projects

| # | Project | Techniques |
|---|---------|-----------|
| 01 | [AD Telemetry Pipeline & Discovery Detection](./01-ad-telemetry-discovery/) | T1087.002, T1069.002 |
| 02 | Adversary Emulation & Attack Path Mapping | Atomic Red Team, BloodHound |
| 03 | False Positive Tuning | Baseline analysis, rule refinement |
| 04 | Malware Analysis & Rule Authoring | YARA, Sigma, static/dynamic analysis |
| 05 | Network Detection | Zeek, Suricata, C2 identification |

---

## Environment

**Domain:** `soc.lab` — one DC, two workstations, five users, two nested groups  
**Endpoint telemetry:** Sysmon (SwiftOnSecurity config), Windows Security / System / PowerShell channels  
**Policy:** PowerShell Script Block Logging, command-line auditing in 4688, and advanced audit subcategories enforced by GPO at the domain root  
**SIEM:** Splunk Enterprise with `Splunk_TA_windows` and `Splunk_TA_microsoft_sysmon`  

The SIEM runs on **separate physical hardware** rather than as a VM on the same host. Forwarders therefore cross a real network boundary, which matches production topology and surfaces connectivity failures that a same-host setup hides.

---

## Detection rules

Portable [Sigma](https://github.com/SigmaHQ/sigma) rules live in [`/sigma`](./sigma/). Backend-specific searches appear in each project writeup.

| Rule | Technique | Level |
|------|-----------|-------|
| [`net_domain_discovery.yml`](./sigma/net_domain_discovery.yml) | T1087.002, T1069.002 | low |

---
