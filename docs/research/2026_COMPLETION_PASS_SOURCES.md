# Completion-pass sources — 2026-10-21

This evidence was collected for the final BPC Rust high-assurance hardening pass.

NIST SP 800-218 SSDF version 1.1 groups secure development outcomes into preparing the organization, protecting software from tampering and unauthorized access, producing well-secured releases, and responding to residual vulnerabilities. Its PS.3.1 and PS.3.2 practices call for protected release integrity/provenance data and maintained, safeguarded, standards-based component provenance such as an SBOM. Its PW.1 guidance specifically calls for threat modeling and more rigorous assessment around credentials and authentication. [1]

OWASP API2:2023 identifies authentication endpoints and flows as exposed assets and recommends strict brute-force controls beyond ordinary API limits, weak-secret rejection, reauthentication for sensitive operations, and systematic coverage of every authentication flow. [2]

NIST NCCoE’s PQC migration guidance recommends starting with cryptographic asset discovery/inventory. It identifies a CBOM as an inventory of algorithms, libraries, protocols, keys, systems, and protected data that supports risk management and PQC transition planning. [3]

OpenAI’s May 2026 TanStack incident response describes containment through isolation of affected identities, credential rotation, restricted deployment workflows, scrutiny of credentials, controls such as minimum package release age, and provenance validation. [4]

Microsoft’s August 2026 ChainDrop incident analysis reports a self-propagating package attack that searched developer and CI/CD environments for GitHub, cloud, Kubernetes, and secret-store credentials. It recommends pinning known-good versions, purging compromised caches, rotating credentials from a clean host, reviewing workflow token scopes/protected environments/release provenance, and rebuilding affected artifacts from trusted sources. [5]

## References

[1]: https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-218.pdf "NIST SP 800-218 Secure Software Development Framework"
[2]: https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/ "OWASP API2 2023 Broken Authentication"
[3]: https://pages.nist.gov/nccoe-migration-post-quantum-cryptography/ "NIST NCCoE Migration to Post-Quantum Cryptography"
[4]: https://openai.com/index/our-response-to-the-tanstack-npm-supply-chain-attack/ "OpenAI response to the TanStack npm supply chain attack"
[5]: https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/ "Microsoft ChainDrop supply-chain compromise analysis"
