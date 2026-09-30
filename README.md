# Detection Engineering Lab

Hands-on detection engineering against a purpose-built Active Directory environment. Each project runs a technique, attempts to detect it, and documents what the telemetry actually showed.

The emphasis is on detection logic and its limits, not on tool deployment.

---

## Projects

| # | Project | Techniques |
|---|---------|-----------|
| 01 | [AD Telemetry Pipeline & Discovery Detection](./01-ad-telemetry-discovery/) | T1087.002, T1069.002 |
| 02 | [Adversary Emulation & Attack Path Mapping](./02-adversary-emulation/) | T1558.003, T1087.002, T1098 |
| 03 | [Malware Analysis & Rule Authoring](./03-malware-analysis/) | YARA, RC4/AES config extraction, static/dynamic RE |
| 04 | Network Detection | Zeek, Suricata, C2 identification |

Project 02 covers three related techniques:
- [Kerberoasting: Detection Across Encryption States](./02-adversary-emulation/kerberoasting/) — T1558.003
- [BloodHound Collection Detection](./02-adversary-emulation/bloodhound/) — T1087.002, T1069.002
- [ACL Attack Path: Delegated Password Reset](./02-adversary-emulation/bloodhound/ACL-attack-path/) — T1098

Project 03 covers two malware families across managed and native code:
- [AsyncRAT / XWorm (.NET)](./03-malware-analysis/asyncrat-xworm/) — AES config extraction, obfuscation and packer handling, YARA authoring
- [Remcos (native C++)](./03-malware-analysis/remcos/) — RC4 config decryption reversed in IDA, YARA authoring

---

## Environment

**Domain:** `soc.lab` — one DC, two workstations, five users, two nested groups  
**Endpoint telemetry:** Sysmon (SwiftOnSecurity config), Windows Security / System / PowerShell channels  
**Policy:** PowerShell Script Block Logging, command-line auditing in 4688, and advanced audit subcategories enforced by GPO at the domain root  
**SIEM:** Splunk Enterprise with `Splunk_TA_windows` and `Splunk_TA_microsoft_sysmon`  

The SIEM runs on **separate physical hardware** rather than as a VM on the same host. Forwarders therefore cross a real network boundary, which matches production topology and surfaces connectivity failures that a same-host setup hides.

---

## Detection rules

Portable [Sigma](https://github.com/SigmaHQ/sigma) rules live in [`/sigma`](./sigma/) and [YARA](https://github.com/virustotal/yara) rules live in [`/yara`](./yara/). Backend-specific searches appear in each project writeup.

| Rule | Technique / Family | Type |
|------|-----------|-------|
| [`net_domain_discovery.yml`](./sigma/net_domain_discovery.yml) | T1087.002, T1069.002 | Sigma |
| [`xworm.yar`](./03-malware-analysis/asyncrat-xworm/xworm.yar) | XWorm | YARA |
| [`asyncrat.yar`](./03-malware-analysis/asyncrat-xworm/asyncrat.yar) | AsyncRAT | YARA |
| [`remcos.yar`](./03-malware-analysis/remcos/remcos.yar) | Remcos | YARA |

---

