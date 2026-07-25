# Security Policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub Security Advisories: https://github.com/nc1107/slim-m-relay/security/advisories/new
Do not open a public issue for a security report.
Include steps to reproduce, the affected version or commit, and the impact you believe it has.
Expect an acknowledgement within a few days.

## Scope

In scope: the relay binary and its HTTP API (`/v1/register`, `/v1/send`, `/admin/*`, `/healthz`), the SQLite key store, and how the relay handles the APNs and FCM credentials it holds.
Out of scope: slim-m's home server and client apps, and the security of Apple's or Google's own push infrastructure.

## What the relay sees

The relay never sees plaintext.
Every payload it forwards is already encrypted by the home server before it ever reaches the relay; the relay only ever forwards that ciphertext, plus a coarse `kind` (`message`, `mention`, `call`, or `wake`), to APNs or FCM.
It does not log tokens or payload content, only counts and error codes.

## Primary risk: credential compromise

The relay holds one Apple APNs `.p8` token key and one Firebase service account, shared across every self-hosted slim-m server that registers with it.
Compromise of either credential is the most serious outcome for this project: it would let an attacker push to any device on any slim-m deployment that uses the relay.
Registration keys are stored only as SHA-256 hashes, so a leak of the SQLite database alone does not expose a usable key.
A compromised or misbehaving registered server can be cut off with `POST /admin/keys/{id}/revoke`.

## Baseline, not maximal, security

This project targets Discord-level baseline security, not end-to-end or nation-state-resistant guarantees.
The relay is a transport hop, not a party to slim-m's encryption: the payload it forwards is opaque ciphertext the home server already produced, and the relay itself never has the means to decrypt it.
Reports asking for user-facing cryptography changes to the relay itself are out of scope; the payload encryption boundary lives in the home server, not here.
