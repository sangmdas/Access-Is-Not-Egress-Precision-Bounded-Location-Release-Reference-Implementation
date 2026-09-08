from __future__ import annotations
from dataclasses import dataclass, field
from .models import *

@dataclass
class ReferencePolicy:
    """Illustrative policy choices. These are NOT requirements of the Internet-Draft."""
    purpose_caps: dict[str,Precision] = field(default_factory=lambda:{
        'local-weather':Precision.CITY,
        'nearby-pharmacy':Precision.CITY,
        'local-search':Precision.CITY,
        'navigation':Precision.EXACT,
        'emergency-services':Precision.EXACT,
        'fraud-prevention':Precision.METER_100,
        'analytics':Precision.REGION,
        'ai-inference':Precision.CITY,
        'personalization':Precision.REGION,
        'advertising':Precision.NONE,
    })
    component_caps: dict[ComponentType,Precision] = field(default_factory=lambda:{
        ComponentType.ADVERTISING:Precision.NONE,
        ComponentType.ANALYTICS:Precision.REGION,
        ComponentType.SDK:Precision.CITY,
        ComponentType.AI_AGENT:Precision.CITY,
    })
    processor_caps: dict[ProcessorType,Precision] = field(default_factory=lambda:{
        ProcessorType.AD_NETWORK:Precision.NONE,
        ProcessorType.ANALYTICS:Precision.REGION,
        ProcessorType.AI_PROVIDER:Precision.CITY,
    })
    max_retention: dict[Precision,int] = field(default_factory=lambda:{
        Precision.EXACT:300, Precision.METER_10:600, Precision.METER_100:1800,
        Precision.GRID:3600, Precision.GEOHASH:3600, Precision.CITY:3600,
        Precision.REGION:86400, Precision.COUNTRY:86400, Precision.NONE:0,
    })

class PolicyEngine:
    def __init__(self, policy=None): self.policy=policy or ReferencePolicy()
    def decide(self,c:LocationReleaseCandidate,current, exposure_snapshot=None)->tuple[Decision,Precision,list[str]]:
        reasons=[]
        if not current.user_authorized: return Decision.DENY,Precision.NONE,['USER_AUTHORIZATION_MISSING']
        if c.destination.jurisdiction not in current.allowed_jurisdictions:
            return Decision.DENY,Precision.NONE,['JURISDICTION_NOT_ALLOWED']
        cap=self.policy.purpose_caps.get(c.purpose.purpose_id)
        if cap is None: return Decision.ESCALATE,Precision.NONE,['UNKNOWN_PURPOSE']
        # Component/processor caps can only coarsen, never widen.
        for maybe in (self.policy.component_caps.get(c.requester.component_type), self.policy.processor_caps.get(c.destination.processor_type)):
            if maybe is not None: cap=coarser(cap,maybe)
        cumulative = c.cumulative_disclosure
        risk=(cumulative.movement_history_risk if cumulative else None)
        if exposure_snapshot and exposure_snapshot.get('movement_history_risk'):
            rr=exposure_snapshot['movement_history_risk']
            if risk is None or list(Risk).index(rr)>list(Risk).index(risk): risk=rr
        if risk==Risk.CRITICAL: return Decision.DENY,Precision.NONE,['CUMULATIVE_DISCLOSURE_CRITICAL']
        if risk==Risk.HIGH:
            cap=coarser(cap,Precision.REGION); reasons.append('CUMULATIVE_DISCLOSURE_DOWNGRADE')
        elif risk==Risk.MEDIUM:
            cap=coarser(cap,Precision.CITY); reasons.append('CUMULATIVE_DISCLOSURE_LIMIT')
        # High-consequence continuous fine traces require explicit escalation in reference policy.
        if c.requested_release.continuous and PRECISION_RANK[c.requested_release.requested_precision] <= PRECISION_RANK[Precision.METER_100]:
            return Decision.ESCALATE,Precision.NONE,['CONTINUOUS_FINE_TRACE_REQUIRES_ESCALATION']
        authorized=coarser(c.requested_release.requested_precision,cap)
        if authorized==Precision.NONE: return Decision.DENY,authorized,reasons+['NO_EGRESS_AUTHORIZED']
        if c.requested_release.retention_seconds > self.policy.max_retention[authorized]:
            reasons.append('RETENTION_CLAMP_REQUIRED')
        if authorized==c.requested_release.requested_precision:
            return Decision.ALLOW,authorized,reasons or ['REQUEST_WITHIN_POLICY']
        return Decision.ALLOW_WITH_TRANSFORMATION,authorized,reasons+['MINIMIZATION_REQUIRED','REQUESTED_PRECISION_EXCEEDS_NECESSITY']
