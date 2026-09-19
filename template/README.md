# Project NN — <Title>

**Techniques:** [TXXXX.XXX — Name](https://attack.mitre.org/techniques/TXXXX/XXX/)
**Data sources:** <event IDs and log channels>
**Outcome:** <one line — what was detected, and what was not>

---

## Summary

Three to five sentences. Lead with the **finding**, not the setup.

A reader who stops here should know what you ran, what the telemetry showed,
and what was surprising about it. If nothing was surprising, say what the
detection cost in false positives instead.

---

## Why this technique

Two or three sentences on where this sits in an intrusion and why a defender
should care. Not a definition of the technique — the ATT&CK link covers that.

---

## Attack

What was executed, on which host, as which user, with what privileges.

```powershell
<commands>
```

Include real output when it makes the point. Trim it — paste what a reader
needs to see the result, not the whole scrollback.

State plainly whether anything failed, and whether it needed privileges it
should not have had.

---

## Detection

### Query

```spl
<the search>
```

### Result

| Time | Host | User | ... |
|------|------|------|-----|
|      |      |      |     |

### What the events show

Call out anything non-obvious in the telemetry: duplicated events, misleading
field values, parent/child relationships that change how a rule must be written.

This is where technical depth shows. "The search returned results" is not a
finding; "this binary re-executes itself and produces two events, so a naive
rule double-counts" is.

---

## Findings

The core of the writeup.

Each finding gets a heading and evidence. Negative results count and are often
more interesting than positive ones — but **verify them** before publishing.
If something logged nothing, prove it is a real gap and not a misconfiguration
on your side, and show the verification.

### Visibility matrix

| Activity | Source A | Source B |
|----------|----------|----------|
|          |          |          |

### Implications

What a defender should do differently. Be concrete: which data source, which
control, which compensating detection. Name the limitation if there is no
clean answer.

---

## Tuning

Every detection has a false positive profile. Document it or the rule is not
finished.

```spl
<baseline query>
```

| Tuning option | Cost |
|---------------|------|
|               |      |

State which option was chosen and what blind spot it creates. A rule with an
acknowledged blind spot is honest engineering; a rule presented as complete
coverage is not.

---

## Build notes

Environment detail needed to reproduce, plus any failure worth recording.

Include failures that taught something — especially ones where the symptom
appeared in a different subsystem than the cause. Skip the ones that were
just typos.

<details>
<summary>Configuration</summary>

Collapse long config blocks so they do not bury the analysis.

</details>

---

## References

- ATT&CK technique pages
- Vendor documentation for any behavior claimed
- Tools used

---

<!--
CHECKLIST BEFORE PUBLISHING

[ ] Finding is in the first paragraph, not the last
[ ] Every claim about product behavior is backed by output or a vendor doc link
[ ] Negative results are verified, with the verification shown
[ ] False positives are named, not hand-waved
[ ] Real hostnames, home network ranges, and credentials are removed
[ ] Screenshots cropped to the search bar and results, not the whole browser
[ ] Sigma rule committed to /sigma and linked from here
[ ] Root README table updated
-->
