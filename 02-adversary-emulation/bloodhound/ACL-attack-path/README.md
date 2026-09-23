# ACL Attack Path: Delegated Password Reset to Privilege Escalation

**Technique:** Abuse of ACL / delegated rights (ForceChangePassword) —
[T1098](https://attack.mitre.org/techniques/T1098/) (Account Manipulation),
[T1078.002](https://attack.mitre.org/techniques/T1078/002/) (Valid Accounts: Domain Accounts)
**Tactic:** Privilege Escalation / Persistence
**Attacker position:** Unprivileged domain user (`SOC\jsmith`), member of Helpdesk
**Tooling:** BloodHound (discovery), net rpc / Samba (exploitation), Splunk (detection)

---

## Summary

A misconfigured delegation — the Helpdesk group granted `ForceChangePassword`
over another account — lets an unprivileged helpdesk user reset that account's
password without knowing the current one, and log in as it. This lab plants
that misconfiguration, discovers the resulting attack path in BloodHound,
exploits it, and detects the exploitation in Splunk.

**Two findings, and the second is the more interesting one:**

1. **The path works against a normal account.** jsmith (Helpdesk, unprivileged)
   → `ForceChangePassword` → `svc-report` → password reset → account takeover.
   Detected via event 4724.

2. **The same path was DENIED against a Domain Admin — and BloodHound didn't
   know.** The identical misconfiguration was first planted on a Domain Admin
   account (`dadmin`). BloodHound displayed the path to it, but the exploit was
   refused (`Access is denied`). Root cause: `dadmin` is protected by
   **AdminSDHolder / SDProp** (`adminCount=1`), which overrides delegated rights
   on privileged accounts. BloodHound reads the ACE and draws the edge, but the
   domain does not honour it. **A path in the graph is not proof the path is
   walkable.**

---

## Why this technique

Active Directory lets rights be delegated at the object level — e.g. a helpdesk
team given the ability to reset passwords. `ForceChangePassword` is the extended
right that permits resetting an account's password *without* knowing the current
one. When such delegation is scoped too broadly (a very common real-world
misconfiguration), a low-privilege group ends up able to take over accounts it
should not — and if one of those accounts is privileged, that is a direct
escalation path. BloodHound exists precisely to surface these relationships as
graph edges.

---

## The misconfiguration (plant)

Granted the **Helpdesk group** the `ForceChangePassword` extended right
(GUID `00299570-246d-11d0-a768-00aa006e0529`) over a target account. Because
`jsmith` is a Helpdesk member, jsmith inherits the right.

Two targets were used, deliberately:
- `dadmin` — a Domain Admin (to test the path to full domain compromise)
- `svc-report` — a non-privileged service account (the working demonstration)

---

## Discovery (BloodHound)

Before the plant, BloodHound showed **no path** from jsmith to Domain Admins —
a correctly configured baseline. *(`clean-baseline.png`, `domain-topology.png`)*

After the plant and re-collection (`bloodhound-python -c All,ACL`), the path
rendered:

```
jsmith --MemberOf--> Helpdesk --ForceChangePassword--> [target]
```
*(`attack-path.png`)* BloodHound's Linux abuse panel documents the exploitation
method directly. *(`linux-abuse-info.png`)*

> Collection note: `-c All` alone did not reliably include ACL edges; ACLs had
> to be requested explicitly (`-c All,ACL`), and the database cleared and
> re-imported, before the `ForceChangePassword` edge appeared. A stale import
> silently shows nodes without their ACL relationships.

---

## Exploitation

### Against the Domain Admin (`dadmin`) — DENIED

```
net rpc password dadmin '<newpass>' -U 'soc.lab/jsmith%<pw>' -S dc01.soc.lab
# Failed to set password for 'dadmin' with error: Access is denied.
```
*(`dadmin-denied.png`)*

BloodHound showed this path, but it does not work. **Root cause — AdminSDHolder /
SDProp.** `dadmin` is a member of Domain Admins, a protected group. The SDProp
process periodically stamps a locked-down ACL template onto all protected
accounts, sets `adminCount=1`, and disables ACL inheritance. Confirmed on the
DC:
```
Get-ADUser dadmin -Properties adminCount   ->   adminCount : 1
```
The delegated `ForceChangePassword` ACE remains *visible* on the object (so
BloodHound reads it and draws the edge), but it is not *effective* — the
protected-account machinery overrides it. This is a genuine limitation of
graph-based path analysis: **the graph reflects the DACL as written, not the
effective permission after AdminSDHolder.**

### Against a normal account (`svc-report`) — SUCCEEDS

The identical right over a non-protected account is honoured:
```
net rpc password svc-report '<newpass>' -U 'soc.lab/jsmith%<pw>' -S dc01.soc.lab
# success
```
*(`password-reset.png`)* jsmith — an unprivileged helpdesk user — has taken
over `svc-report` using only the delegated right, without knowing its previous
password. Kill chain complete for the non-protected case.

---

## Detection

The password reset generates **event 4724** ("An attempt was made to reset an
account's password") on the DC — distinct from 4723 (a user changing their own
password). The signal is *who reset whom*:

```
index=wineventlog EventCode=4724
| table _time, Account_Name, Target_User_Name
```
Shows `jsmith` resetting `svc-report`. *(`4724-detection.png`)*

**The detection logic:** a 4724 where the actor is not a legitimate
password-reset operator, or where the target is a privileged/service account,
is the anomaly. Helpdesk staff reset ordinary user passwords routinely — so raw
4724 volume is noisy — but the *pairing* (which account resets which) is where
the signal lives. See `sigma/acl_forcechangepassword_reset.yml`.

**Coverage note:** the *denied* attempt against `dadmin` also warrants
detection — a failed privileged-target reset is itself suspicious. Depending on
audit configuration this appears as a 4724 failure or an access-denied audit
event; detecting attempts (not just successes) widens coverage.

---

## Attack-to-telemetry mapping

| Activity | Log source | Event ID | Key fields | Status |
|---|---|---|---|---|
| Delegated password reset (success) | DC Security | 4724 | `Account_Name=jsmith`, `Target_User_Name=svc-report` | **Detected** — `sigma/acl_forcechangepassword_reset.yml` |
| Reset attempt vs. protected acct (denied) | DC Security | 4724 (fail) / access-denied | actor=jsmith, target=dadmin | Design — detect attempts, not just successes |
| Attack-path discovery | (BloodHound, offline) | — | ForceChangePassword edge | N/A — attacker-side |

---

## Findings

1. **Over-scoped delegation = escalation.** A helpdesk group with
   `ForceChangePassword` over the wrong account gives an unprivileged user
   account-takeover. Realistic and common; the fix is tightly scoped delegation
   (only over the specific OUs/accounts helpdesk should manage).

2. **AdminSDHolder protects privileged accounts from this — and BloodHound does
   not reflect it.** The path to `dadmin` appeared in the graph but was not
   exploitable, because SDProp overrides delegated ACEs on protected accounts.
   Lesson: validate BloodHound paths against protected-account status
   (`adminCount=1`) before assuming exploitability. This is also a defensive
   control — keeping privileged accounts in protected groups blunts ACL-based
   escalation against them directly.

3. **Detection is about the pairing, not the event.** 4724 is common (helpdesk
   resets passwords all day); the signal is anomalous actor/target pairs, not
   the event alone.

---

## Remediation

- Scope Helpdesk delegation to specific OUs of standard user accounts; never
  over admin, service, or protected accounts.
- Audit `ForceChangePassword` / `GenericAll` / `WriteDacl` grants over
  privileged and service accounts (BloodHound, or `Get-Acl` sweeps).
- Keep privileged accounts in protected groups (AdminSDHolder coverage).
- Alert on 4724 where the target is a service/privileged account.

---

## Build notes

- Misconfiguration planted via `Set-Acl` adding an `ExtendedRight` ACE
  (ForceChangePassword GUID) for the Helpdesk group SID on the target object.
- `dadmin` was made a Domain Admin, which triggered SDProp to set
  `adminCount=1` and protect it — the reason the exploit against it failed.
- ACL edges required explicit `-c All,ACL` collection + a cleared/re-imported
  BloodHound database to appear.
- Lab changes to revert after writeup: `dadmin`, `svc-report`, and both
  ForceChangePassword ACEs (snapshot `07-pre-misconfiguration`).

---

## References

- [MITRE ATT&CK T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [Microsoft — 4724: An attempt was made to reset an account's password](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4724)
- [Microsoft — AdminSDHolder, SDProp, and adminCount](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [The Hacker Recipes — ForceChangePassword](https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword)