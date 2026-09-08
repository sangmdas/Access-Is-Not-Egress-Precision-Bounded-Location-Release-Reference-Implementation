# Implemented variations and scenarios

## Precision classes

- EXACT
- METER_10
- METER_100
- GRID
- GEOHASH
- CITY
- REGION
- COUNTRY
- NONE

Transformations include exact pass-through, decimal rounding, grid identifier, geohash, city/region/country labels and a deterministic demonstration randomization helper.

## Requester/component variations

- APPLICATION
- SDK
- AI_AGENT
- ANALYTICS
- ADVERTISING
- BROWSER
- CLOUD_SERVICE
- SYSTEM_SERVICE

## Destination/processor variations

- FIRST_PARTY
- PROCESSOR
- SDK_VENDOR
- AI_PROVIDER
- ANALYTICS
- AD_NETWORK
- PUBLIC_AUTHORITY

## Sink placement variations

- NETWORK_EGRESS
- OS_DATA_BROKER
- BROWSER_UPLOAD
- API_GATEWAY
- CLOUD_SYNC
- TELEMETRY
- ANALYTICS_SDK
- AD_SDK
- FILE_EXPORT
- DATABASE_EXPORT

## Positive scenarios

1. Weather app requests exact GPS; CITY is released.
2. Nearby-pharmacy search requests exact GPS; CITY is released.
3. Emergency-services reference policy can authorize EXACT.
4. Analytics is reduced to REGION.
5. AI-provider request is reduced to CITY.
6. Browser/API/telemetry/file sink roles can enforce the same semantic contract.
7. Ed25519 and HMAC signing backends demonstrate cryptographic-pluggability.

## Adversarial scenarios

- Exact coordinates hidden in a CITY-labeled JSON object.
- Exact coordinates in headers.
- Destination substitution.
- Recipient substitution.
- Jurisdiction substitution.
- Sink substitution.
- Candidate mutation after issuance.
- Nonce/sequence mismatch.
- Signature tampering.
- Missing evidence.
- Missing sink-local activation.
- Copying authority to a fresh sink state.
- Replay / already-consumed authority.
- Policy epoch change after issuance.
- Revocation epoch change after issuance.
- Expiration.
- Extra non-authorized payload fields.
- Uninspectable payload fails closed in strict mode.
- High/critical cumulative-disclosure state.
- Continuous fine-grained trace escalation.

## State backend variation

- In-memory evidence/activation state for fast unit tests.
- SQLite evidence/activation state demonstrating persistence across process/store reopen and durable single-use replay rejection.

SQLite is **not** a protected monotonic store; privileged rollback or database replacement remains a limitation.
