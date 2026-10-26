#!/usr/bin/env python3
"""Regression test for a verification race: a verification that overlaps an approval must never report INVALID.

The credential row and its approvals used to be read in separate queries, so a verification landing between them
saw the new approval next to the old status and reported INVALID for a perfectly good credential. Verification
now reads everything in one database snapshot.

Usage: scripts/verify-race-test.py [credentials]   (dev stack running on http://localhost:3000; run from any directory)

Everything that has to be fast runs inside the backend container (so the per-IP rate limit does not throttle it):
six loops verify whichever credential is being approved at that moment while its three approvals are made.
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import uuid

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
B = "http://localhost:3000/api/v1"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 40
PASS = os.environ.get("PASS") or re.search(r"^SEED_DEMO_PASSWORD=(.*)$", open(f"{ROOT}/.env").read(), re.M).group(1)


def req(method, path, token=None, body=None):
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = "Bearer " + token
    if method == "POST":
        h["X-Nonce"] = str(uuid.uuid4())
        h["X-Timestamp"] = str(int(time.time()))
    for attempt in range(4):
        r = urllib.request.Request(B + path, method=method, headers=h, data=json.dumps(body).encode() if body is not None else None)
        try:
            return json.load(urllib.request.urlopen(r))
        except urllib.error.HTTPError as e:
            # Request limits are counted in the database and survive restarts, so a test that follows another
            # one on the same stack may have to wait out the rest of a window. The server says how long.
            if e.code != 429 or attempt == 3:
                raise
            time.sleep(int(e.headers.get("Retry-After", "5")) + 1)
            if method == "POST":
                h["X-Nonce"] = str(uuid.uuid4())
                h["X-Timestamp"] = str(int(time.time()))


def token(user):
    return req("POST", "/auth/login", body={"email": user + "@university.edu", "password": PASS})["token"]


# Runs inside the container: $1,$2,$3 are the exam cell, registrar and admin tokens, the rest are credential ids.
DRIVER = r"""
EXC=$1; REG=$2; ADM=$3; shift 3
rm -f /tmp/out.* ; echo none > /tmp/cur; touch /tmp/run
verify_loop() {
  n=0
  while [ -f /tmp/run ]; do
    id=$(cat /tmp/cur); n=$((n+1)); [ "$id" = none ] && continue
    curl -s -H "X-Forwarded-For: 100.$1.$((n/250%250)).$((n%250))" http://localhost:8000/api/v1/verify/$id
    echo
  done > /tmp/out.$1
}
for k in 1 2 3 4 5 6; do verify_loop $k & done
sleep 1
for id in "$@"; do
  echo $id > /tmp/cur; sleep 0.1
  for t in $EXC $REG $ADM; do
    curl -s -o /dev/null -X POST -H "Authorization: Bearer $t" -H "X-Nonce: $(cat /proc/sys/kernel/random/uuid)" \
      -H "X-Timestamp: $(date +%s)" -H "X-Forwarded-For: 100.200.0.1" http://localhost:8000/api/v1/credentials/$id/approve
  done
done
sleep 0.2; rm -f /tmp/run; wait
cat /tmp/out.*
"""


def main():
    fac, exc, reg, adm = token("faculty"), token("examcell"), token("registrar"), token("admin")
    ids = [
        req("POST", "/credentials", fac, {"student_id": f"R{n}", "student_name": "Race", "program": "BSc", "graduation_date": "2025-05-15"})["id"]
        for n in range(N)
    ]
    out = subprocess.run(
        ["docker", "compose", "exec", "-T", "backend", "sh", "-c", DRIVER, "sh", exc, reg, adm, *ids],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    bad, total = {}, 0
    for line in out.splitlines():
        try:
            v = json.loads(line)
        except ValueError:
            continue
        total += 1
        if v["verdict"] == "INVALID":
            k = f"status {v['credential']['status']} but signed by {','.join(s['role'] for s in v['signatures'])}"
            bad[k] = bad.get(k, 0) + 1
    print(f"{total} verifications of credentials while they were being approved; spurious INVALID verdicts: {sum(bad.values())}")
    for k, c in bad.items():
        print(f"   {c}x {k}")
    approved = sum(1 for i in ids if req("GET", f"/verify/{i}")["verdict"] == "VALID")
    print(f"{approved}/{N} credentials ended VALID")
    if total < 1000 or approved != N:
        sys.exit("the test did not run properly (too few verifications, or approvals failed)")
    sys.exit(1 if bad else 0)


main()
