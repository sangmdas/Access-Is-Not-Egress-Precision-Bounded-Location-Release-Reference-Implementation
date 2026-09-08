# Limitations and non-claims

This document is intentionally strict. Passing tests are evidence of implementability of the modeled semantics, not proof of real-world non-bypassability.

## 1. Software PED is not a hardware trust boundary

The PED is a Python object. It is not a TEE, secure enclave, HSM, protected OS service or other hardware-backed enforcement domain. A privileged attacker controlling the process or interpreter can violate assumptions.

## 2. Software activation state is only a model of non-bearer authority

`ActivationStore` means a copied authority object alone is insufficient in the demo. It does not make the authority physically non-exportable. Production designs require protected state/non-exportability appropriate to the platform.

## 3. Payload inspection is deliberately incomplete

The sink detects common structured latitude/longitude fields recursively and in headers. It does not understand every media type, serialization, compressed body, encrypted tunnel, steganographic encoding, free-text coordinate representation, image metadata, protobuf field, vendor binary format or application-specific encoding.

The Internet-Draft itself leaves a complete media-type inspection algorithm unspecified. Production deployment must either inspect every consequence-bearing plaintext representation or make unsupported paths technically incapable of exporting protected data.

## 4. Encryption boundary matters

If end-to-end encryption hides payload content before the Finality Sink can validate it, precision cannot be established there. The sink must be placed before encryption, participate in a protected encryption boundary, or validate a trustworthy transformed object before ciphertext leaves the domain.

## 5. Alternate-path closure is not automatically achieved

Protecting HTTPS upload while leaving telemetry, clipboard, file export, WebRTC, analytics SDK, crash reporting, DNS encoding, custom sockets or another channel unrestricted does not satisfy full egress finality for that data class.

## 6. Policy mappings are illustrative

`weather -> CITY`, `analytics -> REGION`, `advertising -> NONE`, retention limits and cumulative-disclosure thresholds are reference policy choices. They are not mandated by the Internet-Draft, GDPR, Indian law, US law or any regulator.

## 7. Precision transformations are demonstrations

Decimal rounding is not a rigorous geospatial privacy guarantee. `GRID` is a simple quantization identifier. The randomization helper is deterministic for reproducible tests and is **not differential privacy**. Production systems need geodetically and privacy-appropriate transformation methods.

## 8. CITY/REGION labels require trustworthy local resolution

The reference RawLocation carries city/region/country labels. It does not implement a secure offline reverse-geocoder or prove the labels correspond to the coordinate.

## 9. Cumulative disclosure remains difficult

Release count and finest prior precision are crude indicators. Real movement-history inference depends on time spacing, geography, uniqueness, auxiliary datasets, recipients and correlation. The accumulator is a testable placeholder, not a complete privacy-risk model.

## 10. Metadata can itself leak

Candidate/authority metadata reveals application, purpose, destination, jurisdiction and precision class. A production system should minimize or protect these descriptors.

## 11. No real OS integration

There is no Android Binder, iOS entitlement, browser engine, socket layer, VPN, eBPF, enterprise DLP, API gateway or kernel hook in this repository.

## 12. No live network enforcement

The code returns a release decision and payload model. It does not physically prevent a real NIC from transmitting bytes.

## 13. No remote attestation

The repository does not validate TPM/TEE/EAT/RATS evidence.

## 14. No distributed consensus or rollback-resistant persistence

In-memory stores disappear on restart. There is no secure monotonic counter, sealed storage, Byzantine quorum or anti-rollback hardware.

## 15. Time is OS supplied

Freshness/expiry rely on system time. A production deployment may require protected time or monotonic state.

## 16. No formal verification

The implementation has unit/adversarial tests but no TLA+, Tamarin, ProVerif, Coq, Lean or equivalent proof.

## 17. Benchmark is not device/network latency

The benchmark is local Python execution. It excludes app/OS IPC, TLS, Wi-Fi/5G transport, DNS, server RTT, TEE transitions, HSM operations, reverse geocoding, remote policy calls and production contention.

## 18. No legal determination

The code does not determine which precision is legally required or permitted. Jurisdiction is a policy input, not legal advice.

## 19. No standards endorsement

This repository does not imply IETF, W3C, 3GPP, O-RAN, ITU, ENISA, European Commission or other endorsement.

## 20. Patent/licensing status is separate

The source Internet-Draft notes pending patent applications and says its IPR section does not define licensing terms. Repository publication should not be read as an automatic patent license.
