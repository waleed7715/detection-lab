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
| 04 | [EDR Detection & Automated Containment (Wazuh)](./04-edr-wazuh/) | T1486, T1204.002, T1562.001, T1110.003, T1078 |
| 05 | Network Detection | Zeek, Suricata, C2 identification |

Project 02 covers three related techniques:
- [Kerberoasting: Detection Across Encryption States](./02-adversary-emulation/kerberoasting/) — T1558.003
- [BloodHound Collection Detection](./02-adversary-emulation/bloodhound/) — T1087.002, T1069.002
- [ACL Attack Path: Delegated Password Reset](./02-adversary-emulation/bloodhound/ACL-attack-path/) — T1098

Project 03 covers two malware families across managed and native code:
- [AsyncRAT / XWorm (.NET)](./03-malware-analysis/asyncrat-xworm/) — AES config extraction, obfuscation and packer handling, YARA authoring
- [Remcos (native C++)](./03-malware-analysis/remcos/) — RC4 config decryption reversed in IDA, YARA authoring

Project 04 pairs five Wazuh detections with an automated validation harness that measures per-rule detection latency, and three self-reverting containment actions:
- Ransomware-style mass encryption (FIM who-data), malware drop with VirusTotal enrichment, Defender tampering, and password-spray-to-logon correlation
- Account disable, host isolation and attacker-IP block, with an OU allowlist that makes disabling a DC or admin account impossible
- A CIS hardening cycle scored by Wazuh SCA and remediated via Group Policy

---

## Environment

**Domain:** `soc.lab` — one DC, two workstations, five users, two nested groups (project 04 adds a `TestUsers` OU of spray-target accounts)  
**Endpoint telemetry:** Sysmon (SwiftOnSecurity config), Windows Security / System / PowerShell channels  
**Policy:** PowerShell Script Block Logging, command-line auditing in 4688, and advanced audit subcategories enforced by GPO at the domain root  
**SIEM:** Splunk Enterprise with `Splunk_TA_windows` and `Splunk_TA_microsoft_sysmon`  
**EDR/XDR:** Wazuh 4.14 all-in-one on a dedicated Ubuntu VM, with agents on all three Windows hosts (project 04)  

The SIEM runs on **separate physical hardware** rather than as a VM on the same host. Forwarders therefore cross a real network boundary, which matches production topology and surfaces connectivity failures that a same-host setup hides.

---

## Detection rules

Portable [Sigma](https://github.com/SigmaHQ/sigma) rules live in [`/sigma`](./sigma/) and [YARA](https://github.com/virustotal/yara) rules live in [`/yara`](./yara/). Wazuh rules for project 04 live with that project. Backend-specific searches appear in each project writeup.

| Rule | Technique / Family | Type |
|------|-----------|-------|
| [`net_domain_discovery.yml`](./sigma/net_domain_discovery.yml) | T1087.002, T1069.002 | Sigma |
| [`xworm.yar`](./03-malware-analysis/asyncrat-xworm/xworm.yar) | XWorm | YARA |
| [`asyncrat.yar`](./03-malware-analysis/asyncrat-xworm/asyncrat.yar) | AsyncRAT | YARA |
| [`remcos.yar`](./03-malware-analysis/remcos/remcos.yar) | Remcos | YARA |
| [`local_rules.xml`](./04-edr-wazuh/rules/local_rules.xml) | T1486, T1204.002, T1562.001, T1110.003 → T1078 | Wazuh |

---
