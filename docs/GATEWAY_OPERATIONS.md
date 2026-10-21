# BPC Gateway operations

`bpc-gateway` is the deployable HTTP product built from this repository’s BPC v2 library. It exposes:

| Route | Purpose | Authentication |
| --- | --- | --- |
| `GET /healthz` | Process liveness | None; returns `204` only when the process is running. |
| `GET /readyz` | Replay continuity readiness | None; returns `204` only after Redis, its marker/config, and the independent continuity anchor reconcile. |
| `GET, POST /v1/echo` | Reference protected route showing the verified BPC identity | Complete BPC v2 five-header envelope. |

The intended integration is to add BPC’s Axum middleware to protected application routes. The echo route is deliberately small and proves the executable authorization path without placing application business logic inside the security gateway.

## Build

```bash
cargo build --locked --release --features gateway --bin bpc-gateway
# or build the pinned non-root image
podman build --pull=never -t bpc-gateway:local .
```

Copy [`gateway.env.example`](../gateway.env.example) to a mode-600 deployment-secret file managed outside Git. Every listed setting is mandatory. Do not place the data-encryption key, registration secret, private key, or approval token in source control, Docker build arguments, a Kubernetes ConfigMap, CI logs, or shell history.

## Required production topology

Use a TLS-terminating load balancer in front of at least two stateless gateway instances. Use these separate managed services:

1. **Authority PostgreSQL** with `sslmode=verify-full`, a synchronous standby, a least-privilege runtime role, and a separate migration role.
2. **Replay Redis** over `rediss://`, ACL authentication, `noeviction`, persistence, and at least one required replica acknowledgement.
3. **Continuity-anchor PostgreSQL** with `sslmode=verify-full`, synchronous replication, an independent backup/restore policy from Redis, and a tightly controlled recovery role. Its URL must differ from the authority URL; it must not share Redis’s restore domain.
4. **Secret manager/KMS** supplying one 32-byte base64url data key and its non-secret key ID at process start. Rotate through an approved re-encryption deployment procedure.

The gateway rejects production plain PostgreSQL, production zero-replica replay durability, identical authority/anchor URLs, missing replay generations, and unreconciled replay state. It cannot determine whether two separately named managed services really have independent operators, backups, or root accounts; that is a required deployment control.

## Initial deployment

Run these commands from a privileged migration/recovery environment, with the configuration exported from the protected file. Never run `migrate`, `initialize-replay`, or `advance-replay` from the gateway runtime service account.

```bash
set -a; . /secure/path/bpc-gateway.env; set +a
./bpc-gateway migrate
# Drain/fence every gateway instance for this namespace first.
./bpc-gateway initialize-replay --fenced
```

The last command deliberately returns a quarantine error on a new/changed Redis generation. This is correct: do not serve BPC traffic for the complete reported replay quarantine horizon. After that horizon, start the service:

```bash
./bpc-gateway serve
curl --fail --silent --show-error http://127.0.0.1:8080/healthz
curl --fail --silent --show-error http://127.0.0.1:8080/readyz
```

An unhealthy `readyz` must be removed from the load balancer; do not bypass it with a static Redis epoch, retry loop, or an in-memory fallback.

## Redis recovery, restore, or promotion

1. Fence/drain all gateway verifiers for the affected Redis namespace.
2. Verify the affected gateway pods are no longer accepting BPC-authenticated requests.
3. Use the controlled recovery role to run `./bpc-gateway advance-replay --fenced`.
4. Keep the namespace quarantined for the full returned/derived horizon.
5. Run/allow `reconcile`; only return instances reporting `204 /readyz` to service.

This intentionally favors a bounded authentication outage over authorization of a replay after lost Redis nonce state.

## Credential lifecycle

Enrollment is an offline privileged control-plane operation. Prepare a mode-600 JSON file containing the client-derived `request_hmac_key`, public JWK, policy fields, and the exact gateway audience/mode. Submit and approve it only from a privileged session:

```bash
./bpc-gateway enroll --input /secure/enrollment.json
./bpc-gateway approve --token 'approval_...'
./bpc-gateway list-pairs
./bpc-gateway revoke --pair-id 'pair_...'
```

The input file must be at most 16 KiB and non-readable by group/other users on Unix. The command rejects an audience or mode that differs from the runtime gateway policy, creates only BPC v2 registrations, prints only redacted pair inventory, and revokes successor lineage atomically. Rotate through BPC’s signed dual-factor rotation API/control-plane integration; do not mutate database rows manually.

## Release proof

The repository’s CI template builds the real gateway, applies migrations, proves a fresh replay domain begins in quarantine, waits the required horizon, starts the binary, verifies liveness/readiness, enrolls a pair through the durable authority, and sends a real signed BPC v2 HTTP request to `/v1/echo`. It also runs the Rust library, real Redis/PostgreSQL, CA-signed PostgreSQL TLS, Node WebCrypto interoperability, dependency, secret, package, and static-analysis gates.
