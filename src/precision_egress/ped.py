from __future__ import annotations
import secrets
from datetime import datetime, timezone, timedelta
from .models import *
from .canonical import digest
from .policy import PolicyEngine
from .state import EvidenceStore, ActivationStore, ExposureStore, CurrentState
from .errors import *

class ProtectedEnforcementDomain:
    def __init__(self, ped_id, signer, current_state:CurrentState, evidence_store=None, activation_store=None, exposure_store=None, policy_engine=None, authority_ttl_seconds=10):
        self.ped_id=ped_id; self.signer=signer; self.current=current_state
        self.evidence_store=evidence_store if evidence_store is not None else EvidenceStore(); self.activation_store=activation_store if activation_store is not None else ActivationStore(); self.exposure_store=exposure_store if exposure_store is not None else ExposureStore(); self.policy_engine=policy_engine if policy_engine is not None else PolicyEngine(); self.authority_ttl_seconds=authority_ttl_seconds
    def _check_epochs(self,c):
        if c.policy_state.policy_epoch!=self.current.policy_epoch: raise EgressError(POLICY_EPOCH_MISMATCH,'policy epoch is not current')
        if c.policy_state.authority_epoch!=self.current.authority_epoch: raise EgressError(POLICY_EPOCH_MISMATCH,'authority epoch is not current')
        if c.policy_state.revocation_epoch!=self.current.revocation_epoch: raise EgressError(REVOCATION_MISMATCH,'revocation epoch is not current')
    def validate_and_issue(self,c:LocationReleaseCandidate, now=None):
        now=now or datetime.now(timezone.utc)
        if c.created_at.tzinfo is None or c.expires_at.tzinfo is None: raise EgressError(MALFORMED,'timezone-aware timestamps required')
        if now>=c.expires_at: raise EgressError(STALE_AUTHORITY,'candidate expired')
        self._check_epochs(c)
        if c.finality_sink.sink_id not in self.current.authorized_sinks: raise EgressError(SINK_MISMATCH,'sink is not authorized')
        subject=(c.cumulative_disclosure.subject_scope if c.cumulative_disclosure and c.cumulative_disclosure.subject_scope else c.freshness.session_id or c.source_data.source_reference or c.requester.application_id)
        snap=self.exposure_store.snapshot(subject, c.cumulative_disclosure.window_seconds if c.cumulative_disclosure else 86400, now)
        decision,authorized,reasons=self.policy_engine.decide(c,self.current,snap)
        preds={'application_valid':True,'component_valid':True,'purpose_valid':decision not in {Decision.ESCALATE,Decision.DENY},'destination_valid':True,'recipient_valid':True,'jurisdiction_valid':c.destination.jurisdiction in self.current.allowed_jurisdictions,'user_authorization_valid':self.current.user_authorized,'policy_epoch_valid':True,'revocation_state_valid':True,'cumulative_disclosure_acceptable':decision!=Decision.DENY,'sink_binding_valid':True}
        transformation=None
        if decision==Decision.ALLOW_WITH_TRANSFORMATION:
            method={Precision.CITY:'CITY_LABEL',Precision.REGION:'REGION_LABEL',Precision.COUNTRY:'COUNTRY_LABEL',Precision.GEOHASH:'GEOHASH',Precision.GRID:'GRID_SNAP',Precision.METER_100:'ROUND_100M',Precision.METER_10:'ROUND_10M'}.get(authorized,'PRECISION_REDUCTION')
            transformation=Transformation(type=TransformType.PRECISION_REDUCTION,method=method,parameters={})
        pd=PrecisionDecision(decision_id='ppd-'+secrets.token_hex(8),candidate_act_id=c.candidate_act_id,decision=decision,requested_precision=c.requested_release.requested_precision,authorized_precision=authorized,transformation=transformation,validated_predicates=preds,reason_codes=reasons)
        if decision not in {Decision.ALLOW,Decision.ALLOW_WITH_TRANSFORMATION,Decision.RANDOMIZE,Decision.DELAY}:
            return pd,None,None
        candidate_digest=digest(c); decision_digest=digest(pd); state_ref='ped-location-state-'+secrets.token_hex(8)
        ev=self.evidence_store.commit({'evidence_id':'pve-location-'+secrets.token_hex(8),'candidate_act_id':c.candidate_act_id,'decision_id':pd.decision_id,'candidate_digest':candidate_digest,'decision_digest':decision_digest,'committed_at':now,'protected_state_reference':state_ref})
        authority_id='efa-'+secrets.token_hex(8); activation=secrets.token_urlsafe(24); activation_commit=digest({'authority_id':authority_id,'activation':activation,'state':state_ref})
        # Clamp authority life to candidate expiry.
        expires=min(c.expires_at, now+timedelta(seconds=self.authority_ttl_seconds))
        maxret=self.policy_engine.policy.max_retention[authorized]
        scope=AuthorityScope(data_class=c.source_data.data_class,authorized_precision=authorized,permitted_fields=_fields_for(authorized,c.requested_release.fields),recipient_id=c.destination.recipient_id,destination_id=c.destination.destination_id,jurisdiction=c.destination.jurisdiction,retention_seconds_max=min(c.requested_release.retention_seconds,maxret),transformation_method=transformation.method if transformation else None)
        bind=AuthorityBinding(candidate_act_digest=candidate_digest,evidence_digest=ev.evidence_digest,nonce=c.freshness.nonce,sequence=c.freshness.sequence,policy_epoch=self.current.policy_epoch,authority_epoch=self.current.authority_epoch,revocation_epoch=self.current.revocation_epoch,finality_sink_id=c.finality_sink.sink_id,protected_state_reference=state_ref,activation_commitment=activation_commit)
        life=AuthorityLifetime(issued_at=now,expires_at=expires,single_use=True)
        unsigned={'version':'1.0','object_type':'egress_finality_authority','authority_id':authority_id,'candidate_act_id':c.candidate_act_id,'decision_id':pd.decision_id,'evidence_id':ev.evidence_id,'scope':scope,'binding':bind,'lifetime':life,'issuer':{'ped_id':self.ped_id,'key_id':self.signer.key_id,'algorithm':self.signer.algorithm}}
        sig=self.signer.sign(unsigned)
        authority=EgressFinalityAuthority(**{**unsigned,'issuer':Issuer(**unsigned['issuer'],signature=sig)})
        self.activation_store.activate(authority_id,activation_commit,c.freshness.nonce)
        return pd,ev,authority

def _fields_for(p:Precision,requested:list[str])->list[str]:
    mapping={
      Precision.EXACT:['latitude','longitude','accuracy_meters'],
      Precision.METER_10:['latitude','longitude','precision_class'],
      Precision.METER_100:['latitude','longitude','precision_class','randomized'],
      Precision.GRID:['grid_id'], Precision.GEOHASH:['geohash'],
      Precision.CITY:['city','region','country'], Precision.REGION:['region','country'], Precision.COUNTRY:['country'], Precision.NONE:[]}
    return mapping[p]
