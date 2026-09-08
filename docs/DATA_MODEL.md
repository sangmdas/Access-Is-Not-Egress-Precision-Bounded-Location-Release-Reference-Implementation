# Data model and parameter origin

The executable models track the Internet-Draft JSON profile and its named predicates.

| Implementation field | Role | Source/rationale |
|---|---|---|
| `candidate_act_id` | One proposed release | Draft Candidate Act schema |
| `requester.application_id` | Requesting app | Draft requester object |
| `component_id/type` | SDK/agent/analytics distinction | Draft makes component identity a predicate |
| `purpose_id` | Necessity/minimization decision | Draft PED predicate |
| `available_precision` | Finest data held locally | Draft terminology |
| `requested_precision` | What caller asks to export | Draft JSON profile |
| `authorized_precision` | Maximum/fineness ceiling actually permitted | Draft terminology/decision object |
| `destination_id` | Destination binding | Draft schema |
| `recipient_id` | Recipient binding | Draft schema |
| `jurisdiction` | Sovereignty/policy input | Draft schema |
| `retention_seconds` | Requested retention | Draft schema |
| `continuous` | One-shot versus continuous | Draft PED predicate |
| `policy_epoch` | Policy freshness | Draft schema |
| `authority_epoch` | Authority/key-generation state | Draft authority binding |
| `revocation_epoch` | Revocation freshness | Draft schema |
| `nonce`/`sequence` | Replay/freshness | Draft schema |
| `sink_id/type` | Exact egress boundary | Draft schema |
| `cumulative_disclosure` | Prior-release risk | Draft extension |

## Reference-policy additions

The draft deliberately does **not** standardize which purpose gets which precision. Therefore `ReferencePolicy` contains illustrative mappings such as weather -> CITY and advertising -> NONE. Those are demo policy choices, not protocol requirements or legal interpretations.

Similarly, the exposure thresholds used by `ExposureStore` are explicitly illustrative. They exist to make cumulative-disclosure behavior executable and testable, not to define acceptable privacy risk.
