# Security Policy

ACVS signs and verifies academic credentials, so security reports are taken seriously.

## Reporting a vulnerability

**Please do not open a public issue, PR, or discussion for security problems.**

Report privately using either:

1. GitHub's [private vulnerability reporting](../../security/advisories/new)
   (repository **Security** tab -> **Report a vulnerability**), or
2. Email garinesaiajay@gmail.com with the subject `ACVS security`.

Include what you found, the affected component/endpoint, steps to reproduce, and the impact you see.

## What to expect

- Acknowledgement within 5 days.
- An initial assessment and plan within 14 days.
- Credit in the fix/advisory if you want it, once a fix is released.

Please give us reasonable time to fix the issue before any public disclosure.

## Scope

In scope: the backend API, signing/ledger logic, auth and session handling, the front end, and the Docker setup.
Out of scope: the demo users and `SEED_DEMO_PASSWORD` (demo only; leave it empty in real deployments),
and the limits already documented in the README ("Limits you should know about").

## Supported versions

This is a pre-1.0 project; only the latest `main` receives security fixes.
