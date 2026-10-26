"""TEST ONLY: a minimal RFC 3161 time-stamping authority built on `openssl ts -reply`.

It makes two throwaway CAs, "good" and "evil", each with a TSA signing certificate, and writes the good
CA to /tsa/ca.pem (the file the backend trusts) and the evil one to /tsa/evil-ca.pem. What it answers with is
chosen per request by the content of /tsa/mode: ok | evil | garbage | down.
"""
import http.server
import os
import subprocess
import tempfile

ROOT = "/tsa"


def run(*cmd):
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def make_authority(name):
    d = f"{ROOT}/{name}"
    os.makedirs(d, exist_ok=True)
    with open(f"{d}/ext.cnf", "w") as f:
        f.write("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\n")
    with open(f"{d}/serial", "w") as f:
        f.write("01\n")
    with open(f"{d}/tsa.cnf", "w") as f:
        f.write(
            f"[tsa]\ndefault_tsa=t\n[t]\nserial={d}/serial\ncrypto_device=builtin\nsigner_cert={d}/tsa.crt\n"
            f"certs={d}/ca.pem\nsigner_key={d}/tsa.key\nsigner_digest=sha256\ndefault_policy=1.2.3.4.1\n"
            "digests=sha256\naccuracy=secs:1\nordering=yes\ntsa_name=yes\ness_cert_id_chain=no\ness_cert_id_alg=sha256\n"
        )
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-keyout", f"{d}/ca.key",
        "-out", f"{d}/ca.pem", "-subj", f"/CN=ACVS Test TSA Root ({name})")
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{d}/tsa.key", "-out", f"{d}/tsa.csr",
        "-subj", f"/CN=ACVS Test TSA ({name})")
    run("openssl", "x509", "-req", "-in", f"{d}/tsa.csr", "-CA", f"{d}/ca.pem", "-CAkey", f"{d}/ca.key",
        "-CAcreateserial", "-out", f"{d}/tsa.crt", "-days", "30", "-extfile", f"{d}/ext.cnf")
    return d


def reply(authority, query):
    with tempfile.TemporaryDirectory() as t:
        q, r = f"{t}/q.tsq", f"{t}/r.tsr"
        with open(q, "wb") as f:
            f.write(query)
        run("openssl", "ts", "-reply", "-config", f"{ROOT}/{authority}/tsa.cnf", "-section", "t",
            "-queryfile", q, "-out", r)
        with open(r, "rb") as f:
            return f.read()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        query = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            mode = open(f"{ROOT}/mode").read().strip()
        except OSError:
            mode = "ok"
        if mode == "down":
            self.send_response(503); self.end_headers(); return
        try:
            body = os.urandom(300) if mode == "garbage" else reply("evil" if mode == "evil" else "good", query)
        except subprocess.CalledProcessError:
            self.send_response(400); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    good, evil = make_authority("good"), make_authority("evil")
    for src, dst in ((f"{good}/ca.pem", f"{ROOT}/ca.pem"), (f"{evil}/ca.pem", f"{ROOT}/evil-ca.pem")):
        with open(src) as a, open(dst, "w") as b:
            b.write(a.read())
    # This runs as root, but the test script runs as the host user: it must be able to write "mode" and delete everything
    # afterwards (on Linux hosts bind-mounted files keep their owner; Docker Desktop hides this).
    for dirpath, dirnames, filenames in os.walk(ROOT):
        for name in dirnames:
            os.chmod(os.path.join(dirpath, name), 0o777)
        for name in filenames:
            os.chmod(os.path.join(dirpath, name), 0o666)
    os.chmod(ROOT, 0o777)
    mode = f"{ROOT}/mode"
    open(mode, "w").close()
    os.chmod(mode, 0o666)
    open(mode, "w").write("ok\n")
    http.server.ThreadingHTTPServer(("0.0.0.0", 8318), Handler).serve_forever()
