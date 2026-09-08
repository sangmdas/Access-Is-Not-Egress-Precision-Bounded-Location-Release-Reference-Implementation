# Architecture

The reference follows the draft's two-boundary chain:

```text
Exact location exists locally
        |
        v
Location-Release Candidate Act
        |
        v
NON-EFFECTIVE STATE
        |
        v
Protected Enforcement Domain (PED)
        |  requester / component / purpose
        |  destination / recipient / jurisdiction
        |  requested vs necessary precision
        |  policy / revocation epochs
        |  cumulative disclosure
        |  sink identity / freshness
        v
Protected Validation Evidence (committed first)
        |
        v
Scoped Finality Authority + sink-local activation
        |
        v
Egress Finality Sink
        |  signature + act digest + evidence
        |  current epochs + nonce + sink
        |  actual fields + observed payload precision
        |  destination / recipient / jurisdiction
        v
    PASS / FAIL
      |      |
      |      +--> remain non-effective
      v
atomic consumption
      |
      v
external release
```

## Non-bearer demonstration

The serialized authority is insufficient by itself in this reference. The sink also requires an activation commitment held in `ActivationStore`. Copying the authority to a sink with no corresponding activation record is rejected. This is a software model of non-bearer semantics; it is not hardware non-exportability.

## Evidence-before-authority

`EvidenceStore.commit()` occurs before the authority is constructed, signed and activated. The authority binds the evidence digest and protected-state reference.

## Sink-side payload inspection

The sink derives observed precision from structured JSON fields and common headers rather than trusting `declared_precision`. A CITY-labeled body containing latitude/longitude therefore fails.
