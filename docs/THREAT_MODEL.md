# Threat model

## Security objective

Protected location must not become externally effective at a precision finer than current act-specific authority permits.

## Adversaries exercised by tests

- Compromised/over-permissive application or SDK with legitimate local location access.
- Caller that changes the outbound payload after PED approval.
- Caller that lies about `declared_precision`.
- Recipient/destination/jurisdiction substitution.
- Authority replay.
- Authority copying without sink-local activation.
- Stale policy/revocation state.
- Signature modification.
- Candidate mutation.

## Trusted components in this software model

- PED process and its signing key.
- Finality Sink process and verifier.
- EvidenceStore / ActivationStore integrity.
- CurrentState inputs.
- Structured payload inspector for supported formats.

## Out of scope / not solved

- Fully compromised kernel/hypervisor unless PED/sink are separately protected.
- Side channels.
- Malicious firmware.
- Covert encoding of coordinates in arbitrary text/images/audio.
- End-to-end inspection of encrypted payloads when plaintext is unavailable at the sink.
- Exfiltration over an alternate path not covered by a sink.
- Formal proof of policy correctness.
- Byzantine distributed state.
