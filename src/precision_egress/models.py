from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator

class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=False)

class Precision(str, Enum):
    EXACT="EXACT"; METER_10="METER_10"; METER_100="METER_100"; GRID="GRID"; GEOHASH="GEOHASH"; CITY="CITY"; REGION="REGION"; COUNTRY="COUNTRY"; NONE="NONE"

PRECISION_RANK = {p:i for i,p in enumerate(Precision)}

def within_ceiling(observed: Precision, authorized: Precision) -> bool:
    return PRECISION_RANK[observed] >= PRECISION_RANK[authorized]

def coarser(a: Precision, b: Precision) -> Precision:
    return a if PRECISION_RANK[a] >= PRECISION_RANK[b] else b

class ComponentType(str, Enum):
    APPLICATION="APPLICATION"; SDK="SDK"; AI_AGENT="AI_AGENT"; ANALYTICS="ANALYTICS"; ADVERTISING="ADVERTISING"; BROWSER="BROWSER"; CLOUD_SERVICE="CLOUD_SERVICE"; SYSTEM_SERVICE="SYSTEM_SERVICE"; OTHER="OTHER"
class DataClass(str, Enum):
    LOCATION="LOCATION"; MOBILITY_TRACE="MOBILITY_TRACE"; PROXIMITY="PROXIMITY"; SENSOR_DERIVED_LOCATION="SENSOR_DERIVED_LOCATION"
class ProcessorType(str, Enum):
    FIRST_PARTY="FIRST_PARTY"; PROCESSOR="PROCESSOR"; SDK_VENDOR="SDK_VENDOR"; AI_PROVIDER="AI_PROVIDER"; ANALYTICS="ANALYTICS"; AD_NETWORK="AD_NETWORK"; PUBLIC_AUTHORITY="PUBLIC_AUTHORITY"; OTHER="OTHER"
class SinkType(str, Enum):
    NETWORK_EGRESS="NETWORK_EGRESS"; OS_DATA_BROKER="OS_DATA_BROKER"; BROWSER_UPLOAD="BROWSER_UPLOAD"; API_GATEWAY="API_GATEWAY"; CLOUD_SYNC="CLOUD_SYNC"; TELEMETRY="TELEMETRY"; ANALYTICS_SDK="ANALYTICS_SDK"; AD_SDK="AD_SDK"; FILE_EXPORT="FILE_EXPORT"; DATABASE_EXPORT="DATABASE_EXPORT"; OTHER="OTHER"
class Risk(str, Enum): LOW="LOW"; MEDIUM="MEDIUM"; HIGH="HIGH"; CRITICAL="CRITICAL"
class Decision(str, Enum): ALLOW="ALLOW"; ALLOW_WITH_TRANSFORMATION="ALLOW_WITH_TRANSFORMATION"; DELAY="DELAY"; RANDOMIZE="RANDOMIZE"; ESCALATE="ESCALATE"; DENY="DENY"
class TransformType(str, Enum): NONE="NONE"; PRECISION_REDUCTION="PRECISION_REDUCTION"; RANDOMIZATION="RANDOMIZATION"; DELAY="DELAY"

class Requester(StrictModel):
    application_id: str
    component_id: str | None = None
    component_type: ComponentType = ComponentType.APPLICATION
class Purpose(StrictModel):
    purpose_id: str
    declared_purpose: str
    purpose_epoch: int = Field(default=0, ge=0)
    user_intent_reference: str | None = None
class SourceData(StrictModel):
    data_class: DataClass = DataClass.LOCATION
    available_precision: Precision
    local_only: bool = True
    source_reference: str | None = None
class RequestedRelease(StrictModel):
    requested_precision: Precision
    fields: list[str]
    retention_seconds: int = Field(default=0, ge=0)
    continuous: bool = False
class Destination(StrictModel):
    destination_id: str
    endpoint: str | None = None
    recipient_id: str
    processor_type: ProcessorType = ProcessorType.OTHER
    jurisdiction: str
    cloud_region: str | None = None
class CumulativeDisclosure(StrictModel):
    window_seconds: int = Field(default=86400, ge=0)
    prior_release_count: int = Field(default=0, ge=0)
    prior_precision_max: Precision | None = None
    distinct_destinations: int = Field(default=0, ge=0)
    movement_history_risk: Risk = Risk.LOW
    subject_scope: str | None = None
class PolicyState(StrictModel):
    policy_epoch: int = Field(ge=0)
    authority_epoch: int = Field(default=0, ge=0)
    revocation_epoch: int = Field(ge=0)
    policy_profile_id: str = "reference-v1"
    regulatory_profile_id: str | None = None
class Freshness(StrictModel):
    nonce: str = Field(min_length=16)
    sequence: int = Field(default=0, ge=0)
    session_id: str | None = None
class SinkRef(StrictModel):
    sink_id: str
    sink_type: SinkType

class LocationReleaseCandidate(StrictModel):
    version: Literal["1.0"] = "1.0"
    object_type: Literal["location_release_candidate"] = "location_release_candidate"
    candidate_act_id: str = Field(min_length=16)
    act_type: Literal["LOCATION_RELEASE"] = "LOCATION_RELEASE"
    created_at: datetime
    expires_at: datetime
    requester: Requester
    purpose: Purpose
    source_data: SourceData
    requested_release: RequestedRelease
    destination: Destination
    cumulative_disclosure: CumulativeDisclosure | None = None
    policy_state: PolicyState
    freshness: Freshness
    finality_sink: SinkRef
    @model_validator(mode="after")
    def validate_time(self):
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        return self

class Transformation(StrictModel):
    type: TransformType
    method: str
    parameters: dict[str, Any] = Field(default_factory=dict)
class PrecisionDecision(StrictModel):
    version: Literal["1.0"]="1.0"
    object_type: Literal["precision_policy_decision"]="precision_policy_decision"
    decision_id: str
    candidate_act_id: str
    decision: Decision
    requested_precision: Precision
    authorized_precision: Precision
    transformation: Transformation | None = None
    validated_predicates: dict[str,bool] = Field(default_factory=dict)
    reason_codes: list[str] = Field(default_factory=list)
class ProtectedEvidence(StrictModel):
    evidence_id: str
    candidate_act_id: str
    decision_id: str
    candidate_digest: str
    decision_digest: str
    previous_evidence_digest: str | None = None
    evidence_digest: str
    committed_at: datetime
    protected_state_reference: str
class AuthorityScope(StrictModel):
    data_class: DataClass
    authorized_precision: Precision
    permitted_fields: list[str]
    recipient_id: str
    destination_id: str
    jurisdiction: str
    retention_seconds_max: int = Field(ge=0)
    transformation_method: str | None = None
class AuthorityBinding(StrictModel):
    candidate_act_digest: str
    evidence_digest: str
    nonce: str
    sequence: int
    policy_epoch: int
    authority_epoch: int
    revocation_epoch: int
    finality_sink_id: str
    protected_state_reference: str
    activation_commitment: str
class AuthorityLifetime(StrictModel):
    issued_at: datetime
    expires_at: datetime
    single_use: bool=True
class Issuer(StrictModel):
    ped_id: str
    key_id: str
    algorithm: str
    signature: str
class EgressFinalityAuthority(StrictModel):
    version: Literal["1.0"]="1.0"
    object_type: Literal["egress_finality_authority"]="egress_finality_authority"
    authority_id: str
    candidate_act_id: str
    decision_id: str
    evidence_id: str
    scope: AuthorityScope
    binding: AuthorityBinding
    lifetime: AuthorityLifetime
    issuer: Issuer
class RawLocation(StrictModel):
    latitude: float
    longitude: float
    accuracy_meters: float = Field(default=5.0, ge=0)
    city: str | None=None
    region: str | None=None
    country: str | None=None
class OutboundPayload(StrictModel):
    content_type: str="application/json"
    data_class: DataClass=DataClass.LOCATION
    declared_precision: Precision
    fields: dict[str, Any]
    headers: dict[str, Any] = Field(default_factory=dict)
    payload_digest: str | None=None
class SinkVerifyRequest(StrictModel):
    operation: Literal["EgressSinkVerify"]="EgressSinkVerify"
    request_id: str
    candidate_act_id: str
    authority_id: str
    sink: SinkRef
    outbound_payload: OutboundPayload
    destination: Destination
    freshness: Freshness
class SinkResult(StrictModel):
    operation: Literal["EgressSinkVerify"]="EgressSinkVerify"
    request_id: str
    decision: Decision
    verification: dict[str,str]
    authority_id: str
    consumed: bool=False
    released_precision: Precision | None=None
    release_id: str | None=None
    error_code: str | None=None
    error_message: str | None=None

class ReleaseEvent(StrictModel):
    at: datetime
    subject_scope: str
    destination_id: str
    precision: Precision
    fields: list[str]
