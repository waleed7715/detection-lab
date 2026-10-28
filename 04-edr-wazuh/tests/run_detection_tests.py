#!/usr/bin/env python3
"""
Wazuh detection test harness.

Runs each lab attack simulation, then polls the Wazuh indexer for the expected
rule IDs on the target host. Prints a PASS/FAIL table with detection latency and
writes a timestamped CSV.

Run from WS01 (where the PowerShell simulations and the SSH client live), with the
SSH tunnel to the indexer open:
    ssh -N -L 9200:127.0.0.1:9200 wazuh01@10.10.10.20     # separate window
    python run_detection_tests.py

Requires: Python 3.8+, `pip install requests`.
"""

import csv
import os
import getpass
import subprocess
import sys
import time
from datetime import datetime, timezone

try:
    import requests
    from requests.auth import HTTPBasicAuth
    import urllib3
except ImportError:
    sys.exit("Missing dependency. Run:  pip install requests")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Config — edit these for your lab
# ---------------------------------------------------------------------------
INDEXER     = "https://127.0.0.1:9200"   # via the SSH tunnel
TESTS_DIR   = r"C:\LabTests"             # where the .ps1 simulations live
KALI        = "waleed@10.10.10.102"       # user@host for the spray launch  <-- set Kali IP
DC_IP       = "10.10.10.10"
DOMAIN      = "soc.lab"
THIS_HOST   = subprocess.check_output("hostname", text=True).strip().upper()

TIMEOUT_SEC = 150   # how long to wait for every expected alert of one test
POLL_SEC    = 10    # gap between indexer polls
COOLDOWN    = 30    # gap between tests so one test's rule windows can't bleed in

# ---------------------------------------------------------------------------
# Test table. One entry per detection.
#   host    : agent.name to query (defaults to this host)
#   setup   : ("local", script, arg) run before timing starts, or None
#   wait    : seconds to wait after setup (clears a rule's ignore window)
#   fire    : ("local", script, arg) or ("remote", "shell command")
#   cleanup : ("local", script, arg) run after polling, or None
#   expect  : rule IDs that must all appear for a PASS
# ---------------------------------------------------------------------------
TESTS = [
    {
        "name": "T1486 mass encryption",
        "fire": ("local", "T1486_mass_encrypt.ps1", "-Run"),
        "setup": ("local", "T1486_mass_encrypt.ps1", "-Reset"), "wait": 130,
        "expect": ["100110"],
    },
    {
        "name": "T1204.002 malware drop",
        "fire": ("local", "T1204_eicar_drop.ps1", ""),
        "expect": ["100120", "87105"],
    },
    {
        "name": "T1562.001 Defender tamper",
        "fire": ("local", "T1562.001_defender_tamper.ps1", "-Run"),
        "setup": ("local", "T1562.001_defender_tamper.ps1", "-Reset"), "wait": 10,
        "cleanup": ("local", "T1562.001_defender_tamper.ps1", "-Reset"),
        "expect": ["100130", "100132"],
    },
    {
        "name": "T1110.003 password spray",
        "host": "DC01",
        "fire": ("remote", f"ssh {KALI} ./spray.sh {DC_IP} {DOMAIN}"),
        "expect": ["100140", "100141"],
    },
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def run_step(step):
    """Run a ('local', script, arg) or ('remote', command) step."""
    if step is None:
        return
    kind = step[0]
    if kind == "local":
        _, script, arg = step
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
               "-File", rf"{TESTS_DIR}\{script}"]
        if arg:
            cmd.append(arg)
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    elif kind == "remote":
        print(f"    remote: {step[1]}")
        r = subprocess.run(step[1], shell=True, capture_output=True, text=True)
        print(f"    exit={r.returncode}")
        if r.stdout.strip(): print("    stdout:", r.stdout.strip()[-400:])
        if r.stderr.strip(): print("    stderr:", r.stderr.strip()[-400:])

def parse_ts(ts):
    """Wazuh timestamp -> aware datetime. Handles +0000 and +00:00, with/without ms."""
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    raise ValueError(f"unparseable timestamp: {ts}")


def first_hit(auth, rule_id, agent, since_ms):
    """Earliest alert for this rule on this host since start. Returns datetime or None."""
    body = {
        "size": 1, "track_total_hits": True,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {"bool": {"filter": [
            {"term": {"rule.id": rule_id}},
            {"term": {"agent.name": agent}},
            {"range": {"timestamp": {"gte": since_ms, "format": "epoch_millis"}}},
        ]}},
    }
    r = requests.post(f"{INDEXER}/wazuh-alerts-*/_search",
                      auth=auth, json=body, verify=False, timeout=30)
    r.raise_for_status()
    hits = r.json()["hits"]
    if hits["total"]["value"] > 0:
        return parse_ts(hits["hits"][0]["_source"]["timestamp"])
    return None


def run_test(t, auth):
    agent = t.get("host", THIS_HOST)
    expect = t["expect"]

    run_step(t.get("setup"))
    if t.get("wait"):
        time.sleep(t["wait"])

    start = datetime.now(timezone.utc)
    since_ms = int(start.timestamp() * 1000)
    run_step(t["fire"])

    found = {}
    deadline = time.time() + TIMEOUT_SEC
    while time.time() < deadline and len(found) < len(expect):
        for rid in expect:
            if rid not in found:
                hit = first_hit(auth, rid, agent, since_ms)
                if hit:
                    found[rid] = round((hit - start).total_seconds(), 1)
        if len(found) < len(expect):
            time.sleep(POLL_SEC)

    run_step(t.get("cleanup"))

    return [{"Test": t["name"], "Host": agent, "RuleID": rid,
             "Result": "PASS" if rid in found else "FAIL",
             "LatencyS": found.get(rid, "-")} for rid in expect]


def main():
    cred_user = "[WAZUH USERNAME]"
    cred_pass = "[WAZUH PASSWORD]"
    auth = HTTPBasicAuth(cred_user, cred_pass)

    # Fail fast on bad creds / unreachable indexer rather than per-test
    try:
        requests.get(f"{INDEXER}/_cluster/health", auth=auth,
                     verify=False, timeout=15).raise_for_status()
    except Exception as e:
        sys.exit(f"Cannot reach indexer at {INDEXER}: {e}\n"
                 f"Is the SSH tunnel open and the password correct?")

    results = []
    for i, t in enumerate(TESTS):
        print(f"[*] {t['name']} ...", flush=True)
        results.extend(run_test(t, auth))
        if i < len(TESTS) - 1:
            time.sleep(COOLDOWN)

    # Print table
    cols = ["Test", "Host", "RuleID", "Result", "LatencyS"]
    widths = {c: max(len(c), max(len(str(r[c])) for r in results)) for c in cols}
    line = "  ".join(c.ljust(widths[c]) for c in cols)
    print("\n" + line)
    print("  ".join("-" * widths[c] for c in cols))
    for r in results:
        print("  ".join(str(r[c]).ljust(widths[c]) for c in cols))

    passed = sum(1 for r in results if r["Result"] == "PASS")
    print(f"\n{passed}/{len(results)} checks passed")

    out = f"results_{datetime.now():%Y%m%d_%H%M}.csv"
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(results)
    print(f"Wrote {out}")

    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
