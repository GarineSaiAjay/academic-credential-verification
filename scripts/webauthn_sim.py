#!/usr/bin/env python3
"""TEST ONLY: a software WebAuthn authenticator built on the `openssl` command line.

It makes the same bytes a real passkey or security key would, so scripts/personal-sig-test.sh can exercise the
server's verification end to end, and it can forge each kind of mistake on request.

  new     DIR NAME                         make a P-256 key; print its credential id and public key (base64url SPKI)
  create  DIR NAME CHALLENGE ORIGIN        clientDataJSON for a registration (base64url)
  get     DIR NAME CHALLENGE RP ORIGIN     an assertion as JSON; options:
            --flags 0x05      authenticator flags (default 0x05 = user present + verified)
            --counter N       signature counter (default: previous + 1)
            --tamper sig|auth|client        corrupt that part after signing
            --rp-override X / --origin-override Y / --challenge-override Z   sign for different values
  challenge CREDENTIAL_ID STAGE HASH       the challenge the server asks to be signed for an approval
  check   FILE.json                        verify every personal signature in a /verify response using only
                                           the data in that response (no server code)
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, check=True).stdout


def paths(d, name):
    return {k: f"{d}/{name}.{k}" for k in ("pem", "cid", "counter")}


def cmd_new(d, name):
    p = paths(d, name)
    openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", p["pem"])
    cid = os.urandom(32)
    open(p["cid"], "w").write(b64u(cid))
    open(p["counter"], "w").write("0")
    spki = openssl("ec", "-in", p["pem"], "-pubout", "-outform", "DER")
    print(json.dumps({"credential_id": b64u(cid), "public_key": b64u(spki)}))


def client_data(kind, challenge_b64u, origin):
    return json.dumps(
        {"type": kind, "challenge": challenge_b64u, "origin": origin, "crossOrigin": False}, separators=(",", ":")
    ).encode()


def cmd_create(d, name, challenge, origin):
    print(b64u(client_data("webauthn.create", challenge, origin)))


def cmd_get(d, name, challenge, rp, origin, opts):
    p = paths(d, name)
    flags = int(opts.get("--flags", "0x05"), 16)
    prev = int(open(p["counter"]).read())
    counter = int(opts["--counter"]) if "--counter" in opts else prev + 1
    open(p["counter"], "w").write(str(counter))
    rp = opts.get("--rp-override", rp)
    origin = opts.get("--origin-override", origin)
    challenge = opts.get("--challenge-override", challenge)
    auth = hashlib.sha256(rp.encode()).digest() + bytes([flags]) + counter.to_bytes(4, "big")
    cdata = client_data("webauthn.get", challenge, origin)
    signed = auth + hashlib.sha256(cdata).digest()
    with tempfile.NamedTemporaryFile() as f:
        f.write(signed)
        f.flush()
        sig = openssl("dgst", "-sha256", "-sign", p["pem"], f.name)
    tamper = opts.get("--tamper")
    if tamper == "sig":
        sig = sig[:-1] + bytes([sig[-1] ^ 1])
    elif tamper == "auth":
        auth = auth[:34] + bytes([auth[34] ^ 1]) + auth[35:]
    elif tamper == "client":
        cdata = cdata.replace(b"webauthn.get", b"webauthn.get ", 1)
    print(
        json.dumps(
            {
                "credential_id": open(p["cid"]).read(),
                "authenticator_data": b64u(auth),
                "client_data_json": b64u(cdata),
                "signature": b64u(sig),
            }
        )
    )


def cmd_challenge(cred_id, stage, h):
    print(b64u(hashlib.sha256(f"ACVS-APPROVAL-v1|{cred_id}|{stage}|{h}".encode()).digest()))


def cmd_check(path):
    v = json.load(open(path))
    cid, h = v["credential"]["id"], v["credential"]["credential_hash"]
    checked = 0
    for s in v["signatures"]:
        pv = s.get("personal")
        if not pv:
            continue
        auth, cdata, sig = unb64u(pv["authenticator_data"]), unb64u(pv["client_data_json"]), unb64u(pv["signature"])
        want = b64u(hashlib.sha256(f"ACVS-APPROVAL-v1|{cid}|{s['role']}|{h}".encode()).digest())
        cd = json.loads(cdata)
        assert cd["type"] == "webauthn.get", "wrong ceremony"
        assert cd["challenge"] == want, f"{s['role']}: challenge is not this approval"
        assert auth[:32] == hashlib.sha256(pv["rp_id"].encode()).digest(), f"{s['role']}: wrong relying party"
        assert cd["origin"] == pv["origin"], f"{s['role']}: wrong origin"
        assert auth[32] & 0x05 == 0x05, f"{s['role']}: presence/verification flags missing"
        with tempfile.TemporaryDirectory() as t:
            open(f"{t}/pub.der", "wb").write(unb64u(pv["public_key"]))
            open(f"{t}/sig", "wb").write(sig)
            open(f"{t}/msg", "wb").write(auth + hashlib.sha256(cdata).digest())
            openssl("ec", "-pubin", "-inform", "DER", "-in", f"{t}/pub.der", "-out", f"{t}/pub.pem")
            out = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", f"{t}/pub.pem", "-signature", f"{t}/sig", f"{t}/msg"],
                capture_output=True, text=True,
            )
        assert "Verified OK" in out.stdout, f"{s['role']}: openssl says {out.stdout.strip()} {out.stderr.strip()}"
        checked += 1
    print(f"independently verified {checked} personal signature(s)")


def main():
    a = sys.argv[1:]
    if a[0] == "new":
        cmd_new(a[1], a[2])
    elif a[0] == "create":
        cmd_create(*a[1:5])
    elif a[0] == "get":
        opts = {k: v for k, v in zip(a[6::2], a[7::2])}
        cmd_get(a[1], a[2], a[3], a[4], a[5], opts)
    elif a[0] == "challenge":
        cmd_challenge(*a[1:4])
    elif a[0] == "check":
        cmd_check(a[1])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
