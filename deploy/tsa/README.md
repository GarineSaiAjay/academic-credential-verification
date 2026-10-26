# Timestamp authority CA

Put the PEM certificate(s) your time-stamping authority (TSA) signs with in a file named `ca.pem` here, then set in `.env`:

```
TSA_URL=https://freetsa.org/tsr
TSA_CA_FILE=/etc/acvs/tsa/ca.pem
```

This directory is mounted read-only into the backend. `ca.pem` must hold the TSA's **root** certificate (add intermediates too
if the TSA does not send them). Get it from the TSA's own website over HTTPS and check its fingerprint against what the TSA
publishes: whoever controls this file decides which timestamps are trusted. See the README ("Anchoring the ledger to an
external timestamp authority").
