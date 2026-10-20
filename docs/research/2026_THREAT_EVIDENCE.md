# 2026 threat evidence used for BPC hardening

## OpenCode credential exposure

On October 19, 2026, TechCrunch reported that OpenCode said attackers entered an older Console system, affecting 1.4% of Console users. Some users stored AI-provider API keys in workspaces; reported consequences included unauthorized usage/charges. The reporting says the open-source application/CLI was not affected, that providers blocked affected keys, and that OpenCode urged affected users to revoke and replace keys. The technical root cause and storage details were not publicly detailed at publication time.[1]

**Applied lesson:** protocol software must never create a hosted “console” tier that collects long-lived provider, deployment, or signing credentials without explicit secret isolation, envelope encryption/KMS, scoped short-lived credentials, access logging, revocation automation, and incident-ready key rotation. BPC itself must avoid logging or returning request HMAC material, raw signatures, signed payloads, or JWKs.

## OpenCode unauthenticated local-server vulnerability

CVE-2026-22812 records that versions of OpenCode before 1.0.216 automatically started an unauthenticated HTTP server that allowed local processes, or websites via permissive CORS, to execute shell commands with the user’s privilege. The record classifies the issue as missing authentication, exposed dangerous functionality, and permissive cross-domain policy.[2]

**Applied lesson:** no BPC test, administration, verification, or future bridge component may bind a management/debug endpoint without authentication and an explicit loopback/private deployment policy. The Rust crate remains HTTP-framework-agnostic except for its Axum adapter and must not introduce process-control endpoints.

## Supply-chain and CI/CD compromises

CISA’s May 28, 2026 alert describes attacks through a poisoned VS Code extension and malicious GitHub Action workflows that harvested CI/CD secrets, cloud credentials, and tokens. CISA recommends auditing workflow files/contributor activity, rotating accessible secrets after compromise, delaying package intake, and pinning trusted versions.[3]

OpenAI’s May 13, 2026 response to the TanStack npm compromise says affected employee devices accessed limited credential material in repositories. Its response included isolation, session revocation, credential and certificate rotation, deployment workflow restrictions, provenance controls, and package-manager minimum-release-age controls; the source says devices without the strengthened configuration were exposed during the rollout.[4]

**Applied lesson:** BPC needs a supply-chain posture in its repository and release process: locked Rust dependency graph, advisory scanning, provenance-aware release/CI policy, no unreviewed workflow modifications, least-privileged GitHub/CI credentials, and no secrets in test fixtures, logs, or version control. Any future GitHub Actions workflow must be reviewed and pinned before activation.

## References

[1]: https://techcrunch.com/2026/10/19/hackers-hit-ai-coding-tool-opencode-running-up-charges-on-users-ai-accounts/ "OpenCode Console breach report"
[2]: https://www.cve.org/CVERecord?id=CVE-2026-22812 "CVE-2026-22812"
[3]: https://www.cisa.gov/news-events/alerts/2026/05/28/supply-chain-compromises-impact-nx-console-and-github-repositories "CISA supply-chain compromises alert"
[4]: https://openai.com/index/our-response-to-the-tanstack-npm-supply-chain-attack/ "OpenAI TanStack supply-chain response"
