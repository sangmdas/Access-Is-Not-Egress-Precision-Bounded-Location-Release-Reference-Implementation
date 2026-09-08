# Access Is Not Egress — Precision-Bounded Location Release
## Runnable Reference Implementation

**Reference implementation for `draft-das-precision-bounded-egress-01`: precision-bounded location/data egress using execution finality.**

> Core rule: **Precise location access is not precise location-release authority.**

A device may legitimately hold an exact location while an application, SDK, AI agent, analytics component or remote endpoint only needs a city, region, coarse grid, randomized representation—or no location at all. This repository makes that distinction executable.

The implementation keeps the proposed release **non-effective** until a Protected Enforcement Domain (PED) evaluates the exact release context, commits protected evidence, issues scoped finality authority, and an independent egress Finality Sink verifies the **actual outbound payload** immediately before release.

---

## What this repository demonstrates

```text
Exact location exists locally
            |
            v
Location-Release Candidate Act
            |
            v
      NON-EFFECTIVE
            |
            v
Protected Enforcement Domain
 requester / component / purpose
 recipient / destination / jurisdiction
 requested vs necessary precision
 policy / revocation / freshness
 cumulative disclosure / sink
            |
            v
Protected Evidence (committed first)
            |
            v
Scoped Finality Authority
+ sink-local activation state
            |
            v
Independent Egress Finality Sink
            |
     inspect actual payload
            |
      +-----+-----+
      |           |
    FAIL        PASS
      |           |
 NO RELEASE   consume authority
                  |
                  v
               RELEASE
```

### Important distinction

This is not ordinary “permission to read location.” It is a later control: **may this particular representation leave this protected environment, for this purpose, recipient, destination, jurisdiction and current policy state?**

---

# 1. Source basis

The implementation is derived from the uploaded Internet-Draft:

`Access Is Not Egress: Precision-Bounded Location Release`

`draft-das-precision-bounded-egress-01`

The draft defines a location-release Candidate Act, explicit non-effective state, PED evaluation, protected evidence, scoped non-bearer finality authority, sink-side comparison against the actual payload, cumulative-disclosure state and a precision ladder.

The original XML is included under `ietf/` for traceability.

---

# 2. Language and implementation stack

## Language

**Python 3**

Supported package versions:

```text
Python 3.11
Python 3.12
Python 3.13
```

Why Python?

- makes the protocol state machine readable;
- supports strict typed models;
- makes adversarial tests easy to audit;
- gives deterministic reference vectors;
- keeps the implementation vendor-neutral;
- is suitable for semantic/protocol experimentation.

Python is **not** being proposed as the mandatory production enforcement language.

Possible production realizations include:

```text
Rust / C / C++
Android/iOS protected OS services
browser network stack
enterprise proxy / API gateway
TEE / secure enclave
HSM
SmartNIC / DPU
eBPF / kernel enforcement
secure network function
hardware-backed data broker
```

## Main dependencies

```text
Pydantic 2.x      strict object/schema validation
cryptography      Ed25519 implementation
pytest            automated/adversarial testing
```

The standard library supplies JSON canonicalization, hashing, timing, concurrency primitives and the reference in-memory state stores.

---

# 3. Verified development environment

The package was generated and tested in the following isolated environment:

```text
OS:             Linux
Kernel:         6.18.35
Architecture:   x86_64
Hypervisor:     KVM
Visible CPUs:   5 logical CPUs
CPU model:      AMD EPYC 9V74 80-Core Processor
Visible RAM:    approximately 5.8 GiB
Swap:           0
Python:         3.13.5
Pydantic:       2.13.4
cryptography:   46.0.4
```

The processor model string names the underlying EPYC SKU; only **5 CPUs** were exposed to this execution environment. The RAM figure is environment capacity, **not application memory consumption**.

Run:

```bash
python scripts/environment_report.py
```

on another system to record its actual environment.

---

# 4. Installation

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e '.[dev]'
```

If running in an offline environment where build isolation cannot download build dependencies, and compatible `setuptools`/`wheel` are already installed, use:

```bash
pip install --no-build-isolation -e '.[dev]'
```

Run tests:

```bash
pytest
```

Run a scenario:

```bash
precision-egress weather
```

or:

```bash
python -m precision_egress weather
```

---

# 5. Example — exact GPS requested, CITY released

Reference input:

```text
local coordinate:
21.494321, 86.932145
accuracy: 4.2 m

purpose:
local-weather

requested:
EXACT

remote recipient:
weather/service provider
```

Reference policy decision:

```text
ALLOW_WITH_TRANSFORMATION
requested precision: EXACT
authorized precision: CITY
```

Transformed outbound object:

```json
{
  "city": "Balasore",
  "region": "Odisha",
  "country": "IN"
}
```

Exact latitude/longitude remain inside the protected domain.

---

# 6. Precision ladder

The executable model includes:

| Class | Reference representation |
|---|---|
| EXACT | latitude + longitude + accuracy |
| METER_10 | rounded coordinate demonstration |
| METER_100 | rounded coordinate demonstration |
| GRID | quantized grid identifier |
| GEOHASH | geohash prefix |
| CITY | city/region/country labels |
| REGION | region/country labels |
| COUNTRY | country label |
| NONE | no location egress |

**Important:** the transformation algorithms are demonstrations. Decimal rounding and deterministic jitter are not complete geospatial privacy guarantees.

---

# 7. Varying runnable scenarios

Generated example JSON is under `examples/`.

| Scenario | Request | Reference outcome |
|---|---|---|
| `weather` | exact for local forecast | transform to CITY |
| `pharmacy` | exact for nearby pharmacy | transform to CITY |
| `emergency` | exact for emergency-services | EXACT in reference policy |
| `advertising` | exact for ad use | DENY |
| `analytics` | exact for analytics | REGION |
| `ai-agent` | exact to AI provider | CITY |
| `high-cumulative` | repeated-release high risk | REGION downgrade |
| `critical-cumulative` | critical movement-history risk | DENY |
| `continuous-trace` | continuous fine trace | ESCALATE |

Examples:

```bash
precision-egress advertising
precision-egress analytics
precision-egress emergency
precision-egress high-cumulative
precision-egress continuous-trace
```

Use HMAC variation:

```bash
precision-egress weather --backend hmac
```

---

# 8. Why the authority is modeled as non-bearer

A serialized authority object is **not enough** to release data in this reference.

The sink also requires a corresponding activation commitment in sink-visible protected state.

```text
copied signed authority
        +
no activation state
        =
DENY
```

This is tested explicitly.

The implementation demonstrates the semantic property. It does **not** claim software memory provides hardware non-exportability. A production realization may require a TEE, HSM, protected OS service, DPU or equivalent.

---

# 9. Evidence before authority

The sequence in code is deliberately:

```text
validate
  ↓
commit ProtectedEvidence
  ↓
construct authority bound to evidence digest
  ↓
sign authority
  ↓
activate authority
```

not:

```text
release
  ↓
write audit log later
```

The evidence is therefore pre-effectuation state, not merely post-event logging.

---

# 10. Sink-side inspection: declared precision is not trusted

An application can lie:

```json
{
  "declared_precision": "CITY",
  "fields": {
    "city": "Balasore",
    "latitude": 21.494321,
    "longitude": 86.932145
  }
}
```

The sink inspects the actual structured body and detects the coordinate fields.

Result:

```text
EF-023 PRECISION_MISMATCH
NO RELEASE
```

The inspector also walks nested JSON fields and common headers.

This matters because a system that trusts only a metadata label has not made precision load-bearing.

---

# 11. Component identity variation

The policy model distinguishes the application from embedded or delegated components:

```text
APPLICATION
SDK
AI_AGENT
ANALYTICS
ADVERTISING
BROWSER
CLOUD_SERVICE
SYSTEM_SERVICE
OTHER
```

This lets a first-party app have a legitimate local reason to access exact location while an advertising SDK in the same process receives no egress authority.

The specific caps in `ReferencePolicy` are illustrative, not standardized.

---

# 12. Recipient and processor variations

Supported reference processor classes include:

```text
FIRST_PARTY
PROCESSOR
SDK_VENDOR
AI_PROVIDER
ANALYTICS
AD_NETWORK
PUBLIC_AUTHORITY
OTHER
```

Authority is bound to both `destination_id` and `recipient_id`.

Changing either after issuance fails at the sink.

---

# 13. Sink placement variations

The same finality role is exercised with multiple functional sink types:

```text
NETWORK_EGRESS
OS_DATA_BROKER
BROWSER_UPLOAD
API_GATEWAY
CLOUD_SYNC
TELEMETRY
ANALYTICS_SDK
AD_SDK
FILE_EXPORT
DATABASE_EXPORT
```

A sink type is not sufficient by name. In a real deployment it qualifies only if the protected release is technically non-completable without its verification.

---

# 14. Cumulative disclosure

A single city-level disclosure may appear low-risk while hundreds of timed disclosures can form a movement history.

`ExposureStore` therefore records protected release events and derives an **illustrative** risk state for demonstrations.

The reference logic can:

```text
LOW      -> ordinary purpose cap
MEDIUM   -> at least CITY
HIGH     -> at least REGION
CRITICAL -> DENY
```

These thresholds are **not protocol requirements** and must not be treated as privacy law.

The draft's key architectural idea is that prior disclosure can become a current PED input; it does not mandate this repository's threshold function.

---

# 15. Cryptographic variations

## Ed25519 (default)

```text
PED:  private signing capability
Sink: public verification capability
```

This provides cleaner issuer/verifier key separation.

## HMAC-SHA256

Included to demonstrate that the finality semantics are not tied to one signature primitive.

HMAC shares secret material between issuer and verifier and therefore has a different trust model. It is not automatically interchangeable with Ed25519 in a production architecture.

---

# 16. Canonical binding

Authority is bound to a deterministic SHA-256 digest of the Candidate Act.

Changing a load-bearing attribute after issuance—such as:

```text
purpose
destination
recipient
jurisdiction
requested precision
component
policy state
nonce
sink
```

changes the digest and causes sink rejection.

The payload is separately inspected and digested for release/audit semantics.

---

# 17. Fail-closed behavior

The reference denies rather than silently releases on:

```text
missing authority
invalid signature
candidate mismatch
missing evidence
missing activation
expired authority
policy epoch mismatch
revocation mismatch
sink mismatch
nonce mismatch
destination mismatch
recipient mismatch
jurisdiction mismatch
field-scope mismatch
precision mismatch
uninspectable structured payload (strict mode)
replay / already used authority
```

---

# 18. Adversarial test coverage

The test suite covers more than the normal allow path.

Representative cases:

- exact-to-city successful transformation;
- emergency exact release under the reference policy;
- ad-network denial;
- analytics and AI-provider minimization;
- unknown-purpose escalation;
- jurisdiction denial;
- user-authorization denial;
- policy/authority/revocation epoch mismatches;
- stale Candidate Act;
- unauthorized sink;
- replay;
- candidate mutation;
- destination substitution;
- recipient substitution;
- jurisdiction substitution;
- sink substitution;
- nonce substitution;
- sequence substitution;
- policy/revocation change after authority issuance;
- authority expiry;
- signature tampering;
- missing protected evidence;
- missing activation state;
- copied authority without sink-local activation;
- exact coordinates hidden in a CITY-labelled body;
- exact location hidden in a header;
- disallowed extra payload fields;
- structured-inspector behavior;
- Ed25519/HMAC variants;
- multiple sink roles;
- concurrent single-use consumption;
- cumulative disclosure states.

Run:

```bash
pytest -q
```

---

# 19. Performance and target latency

This repository includes a **local software benchmark**, not a network-latency benchmark.

Run:

```bash
python scripts/benchmark.py --iterations 5000
```

and optionally:

```bash
python scripts/benchmark.py --iterations 5000 --backend hmac
```

The benchmark separately measures:

1. PED validation/evidence/authority issuance.
2. Finality Sink verification/payload inspection/consumption.

## Engineering target

For an on-device or edge-local hot path, a reasonable research goal is to keep common bounded egress checks in the **sub-millisecond to low-millisecond local processing range** on modern hardware where policy state is local and no remote attestation/policy service is needed.

This is **not** an IETF requirement and **not** a current guarantee.

Exact performance depends heavily on:

```text
OS integration
serialization
payload size
inspection complexity
TEE/HSM transition cost
policy engine
reverse-geocoding method
state backend
content type
concurrency
hardware
```

The current benchmark must not be quoted as end-to-end mobile/network latency.

---

# 20. Data/system variations a production implementation should test

The supplied package is intentionally extensible. A production evaluation should add matrices such as:

## Data class

```text
LOCATION
MOBILITY_TRACE
PROXIMITY
SENSOR_DERIVED_LOCATION
```

## Payload format

```text
JSON
CBOR
protobuf
form-data
HTTP headers
WebSocket messages
gRPC
binary telemetry
file metadata
```

## Egress channel

```text
HTTPS
QUIC
WebRTC
SDK telemetry
cloud sync
browser fetch/beacon
file upload
clipboard/share sheet
enterprise gateway
AI tool call
```

## Platform

```text
Android
iOS
browser
Linux endpoint
enterprise agent
API gateway
edge device
```

## Trust realization

```text
software-only
TEE
HSM
secure OS service
SmartNIC/DPU
eBPF/kernel
hardware data broker
```

## Policy state

```text
current
stale
revoked
unknown
unavailable
changed between PED and sink
```

## Disclosure history

```text
first release
repeated coarse releases
multiple destinations
fine repeated releases
cross-jurisdiction release
continuous trace
```

---

# 21. Limitations — read before making security claims

The full detailed list is in [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md). The most important limitations are summarized below.

### 21.1 No real hardware PED

The Python PED is not a TEE/HSM/secure enclave.

### 21.2 No physical egress enforcement

The software returns an allow/deny result. It does not itself stop a real NIC, modem or OS socket from sending bytes.

### 21.3 Payload inspection is incomplete

The reference inspector handles common structured JSON/header location fields. It cannot discover arbitrary encoded, encrypted, compressed, steganographic or custom representations.

### 21.4 Encryption must be placed after inspectable finality or integrated with it

A sink that sees only opaque ciphertext cannot independently determine location precision.

### 21.5 Every equivalent egress path must be closed

Protecting one API while leaving another channel unrestricted is not execution-finality protection of the data class.

### 21.6 Reference policy is not law

Purpose-to-precision rules and cumulative-risk thresholds are illustrative.

### 21.7 Coarsening is not automatically privacy-safe

Repeated CITY or REGION releases can still reveal movement patterns.

### 21.8 Metadata is sensitive

Purpose, app identity, destination and precision class can themselves leak behavior.

### 21.9 No formal proof

Passing tests are not proof of security or non-bypassability.

### 21.10 No standards endorsement

The repository does not imply endorsement or adoption by IETF, W3C, 3GPP, O-RAN, ITU or regulators.

---

# 22. Repository structure

```text
.
├── README.md
├── pyproject.toml
├── src/precision_egress/
│   ├── models.py          strict semantic objects
│   ├── canonical.py       deterministic binding/hashing
│   ├── crypto.py          Ed25519 + HMAC variations
│   ├── policy.py          illustrative reference policy
│   ├── transform.py       precision transformations
│   ├── inspector.py       actual structured payload inspection
│   ├── state.py           evidence/activation/exposure/current state
│   ├── ped.py             first-boundary validation + authority issuance
│   ├── sink.py            independent final egress verification
│   ├── factory.py         deterministic/demo object builders
│   ├── scenarios.py       runnable scenarios
│   └── cli.py             command-line interface
├── tests/
├── examples/
├── scripts/
│   ├── benchmark.py
│   ├── environment_report.py
│   └── generate_examples.py
├── docs/
│   ├── ARCHITECTURE.md
│   ├── DATA_MODEL.md
│   ├── VARIATIONS.md
│   ├── THREAT_MODEL.md
│   ├── LIMITATIONS.md
│   └── PERFORMANCE.md
└── ietf/
    └── draft-das-precision-bounded-egress-01.xml
```

---

# 23. What the implementation proves—and what it does not

## It demonstrates

- the draft can be expressed as executable state transitions;
- exact location can remain local while a coarser representation is authorized;
- evidence can be committed before authority;
- authority can be act/recipient/destination/jurisdiction/sink/epoch/nonce bound;
- a sink can inspect the actual structured payload rather than trusting a label;
- replay and tested substitutions can be rejected;
- cumulative disclosure can influence current authorization;
- the same semantic contract can be exercised across different sink/component/processor types.

## It does not prove

- carrier/mobile-OS production readiness;
- hardware non-bypassability;
- complete media-type inspection;
- correctness of the illustrative policy;
- compliance with any privacy law;
- resistance to every covert channel;
- formal protocol security;
- patent novelty, validity or freedom to operate.

---

# 24. Research invariant

```text
LOCAL ACCESS != EGRESS AUTHORITY

AVAILABLE PRECISION != AUTHORIZED PRECISION

DECLARED PRECISION != OBSERVED PAYLOAD PRECISION

UPSTREAM ALLOW != EXTERNAL RELEASE

NO CURRENT FINALITY AUTHORITY = NO PROTECTED EGRESS
```

The implementation is designed around those distinctions.

# 25. Persistence variation

The default state stores are in-memory for deterministic testing. The package also includes `SQLiteEvidenceStore` and `SQLiteActivationStore` to demonstrate that protected evidence and single-use consumption semantics can survive store/process reopen.

The SQLite tests verify both:

```text
issue -> reopen stores -> legitimate first use succeeds
```

and:

```text
use once -> reopen stores -> replay remains denied
```

**SQLite is not a security boundary.** It provides ordinary durability, not tamper resistance, sealed state or hardware rollback protection. A privileged attacker able to replace or roll back the database can violate the security assumptions.

# 26. Verified result snapshot

On the documented reference environment, the final verification run produced:

```text
98 tests passed
0 failed
```

A 5,000-iteration local Ed25519 benchmark measured:

```text
Combined PED + sink:
mean  500.7 microseconds
p50   457.7 microseconds
p95   662.7 microseconds
p99   882.0 microseconds
```

The HMAC-SHA256 variation measured a combined mean of 297.7 microseconds and p99 of 652.3 microseconds.

These are **synthetic local reference-code measurements**, not end-to-end device/network latency. See [`docs/VERIFIED_RESULTS.md`](docs/VERIFIED_RESULTS.md) and [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md).
