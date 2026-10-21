# Cryptographic assurance sources for BPC evolution

Retrieved 2026-10-20 for BPC v1 work-factor analysis and a future versioned post-quantum design.

NIST SP 800-186 states that elliptic-curve security strength is approximately one half the bit length of the basepoint order. Its Table 1 assigns P-256 128-bit strength, P-384 192-bit strength, and P-521 256-bit strength. It permits these curves for ECDSA and EC key establishment.[1]

NIST SP 800-57 Part 1 Rev. 5 defines security strength as work measured in operations and lists its standardized values as 80, 112, 128, 192, and 256 bits. Its Table 2 maps ECC orders of 256–383 bits to 128-bit strength and 512+ bit orders to 256-bit strength; it also warns that quantum computing materially affects asymmetric estimates.[2]

FIPS 204 defines the finalized ML-DSA signature standard. It assigns ML-DSA-44, ML-DSA-65, and ML-DSA-87 to NIST security categories 2, 3, and 5 respectively. Its Table 2 lists ML-DSA-87 as a 4,896-byte private key, 2,592-byte public key, and 4,627-byte signature.[3]

NSA’s October 2026 CNSA 2.0 FAQ lists FIPS 204 ML-DSA-87 for digital signatures at all classification levels. It describes a hybrid as multiple algorithms performing the same function in a way that requires an adversary to break every component, while warning that hybrid format, negotiation, API, and interoperability complexity can itself create risk.[4]

RustCrypto’s current `ml-dsa` documentation says its implementation follows final FIPS 204 and supports ML-DSA-87, but explicitly warns that it has never been independently audited. This means it is appropriate for controlled interoperability/research evaluation, not an automatic production dependency for BPC’s high-assurance profile.[5]

The linked Laya model card says Laya is a typed-decision classifier, not a cryptographic primitive. Its self-hosted server binds to `0.0.0.0` without authentication unless an API key is configured; it may be used only in a segregated, advisory security-operations role, never in BPC authorization or key/replay processing.[6]

## References

[1]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf "NIST SP 800-186 discrete logarithm cryptography"
[2]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf "NIST SP 800-57 Part 1 Revision 5"
[3]: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf "FIPS 204 Module-Lattice-Based Digital Signature Standard"
[4]: https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/1/CSI_CNSA_2.0_FAQ_.PDF "NSA CNSA Suite 2.0 and Quantum Computing FAQ"
[5]: https://docs.rs/ml-dsa/latest/ml_dsa/ "RustCrypto ML-DSA crate documentation"
[6]: https://huggingface.co/convaiinnovations/laya "Laya model card"
