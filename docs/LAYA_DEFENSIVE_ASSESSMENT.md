# Laya defensive-use assessment

Reviewed source: [convaiinnovations/laya model card](https://huggingface.co/convaiinnovations/laya), reviewed 2026-10-20.

## Decision

Laya may be useful as an **advisory, offline security-operations classifier**. It is not a cryptographic primitive and must not be inserted into BPC request verification, pair authorization, replay handling, secret/key processing, database migration, policy enforcement, or any other availability/security control path.

The model card describes a multilingual non-autoregressive typed-decision model that returns choices and calibrated probabilities rather than generated prose. That shape can be useful for prioritization, but neither a probability nor a model claim is security proof. An attacker can manipulate natural-language inputs, model serving can fail or be compromised, model weights can change, and model decisions are not a deterministic authorization policy.

## Appropriate bounded uses

A separately isolated service may use a pinned Laya model revision to classify **sanitized copies** of protected telemetry after BPC has made its deterministic decision. Examples include labeling a ghost-pair incident for analyst queueing, grouping repeated generic authentication failures into likely operational categories, ranking review of enrollment requests that already passed deterministic policy checks, and summarizing a redacted incident queue for a human responder.

Every output must remain advisory. A deterministic rule and a trained human/operator process decide whether to revoke a pair, page an on-call responder, change a rate limit, or open an incident. A Laya outage, timeout, low confidence, malformed response, or suspected model compromise must leave BPC authorization behavior unchanged and fail to a safe operational fallback such as “send to human review.”

## Non-negotiable isolation and supply-chain controls

Do not send registration secrets, verifier HMAC material, private P-256 keys, bearer tokens, raw signed payloads, request bodies, raw JWKs, database URLs, or unredacted customer PII to Laya. Supply only a strict allowlisted event schema with bounded fields and stable opaque IDs. Keep the inference service on a separate identity, network segment, container/runtime, and log-retention policy from BPC.

The model card says the self-hosted `laya-serve` service binds `0.0.0.0` and has no authentication unless `LAYA_API_KEY` is configured. If evaluated, bind it to a private interface or service mesh, require authentication and network policy, apply request limits/timeouts, protect its API key in a secret manager, and prohibit direct public exposure.

Pin the exact Hugging Face revision by immutable commit hash, record model/config/tokenizer artifact hashes, prefer reviewed `safetensors` artifacts, scan the serving image/dependencies, and require code review for any weight or runtime upgrade. Benchmark calibration and adversarial behavior on the organization’s own sanitized event corpus before deployment; model-card latency and accuracy statements are not independent assurance.

## Recommended first experiment

Run an offline replay-only pilot on previously sanitized audit events. Measure false negatives for known critical events, false positives that create analyst load, calibration by confidence bucket, multilingual behavior, latency, resource cost, prompt/input manipulation resistance, and failure behavior. Do not connect the pilot to PagerDuty, credential rotation, network controls, or authorization until its evaluation report and threat model are reviewed.
