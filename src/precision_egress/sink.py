from __future__ import annotations
import secrets
from datetime import datetime, timezone
from .models import *
from .canonical import digest
from .inspector import inspect_structured_payload
from .errors import *

class EgressFinalitySink:
    def __init__(self,sink_id,verifier,current_state,evidence_store,activation_store,exposure_store=None,fail_on_uninspectable=True):
        self.sink_id=sink_id; self.verifier=verifier; self.current=current_state; self.evidence_store=evidence_store; self.activation_store=activation_store; self.exposure_store=exposure_store; self.fail_on_uninspectable=fail_on_uninspectable
    def _unsigned(self,a:EgressFinalityAuthority):
        return {'version':a.version,'object_type':a.object_type,'authority_id':a.authority_id,'candidate_act_id':a.candidate_act_id,'decision_id':a.decision_id,'evidence_id':a.evidence_id,'scope':a.scope,'binding':a.binding,'lifetime':a.lifetime,'issuer':{'ped_id':a.issuer.ped_id,'key_id':a.issuer.key_id,'algorithm':a.issuer.algorithm}}
    def verify_and_release(self,c:LocationReleaseCandidate,a:EgressFinalityAuthority,req:SinkVerifyRequest,now=None):
        now=now or datetime.now(timezone.utc); ver={}
        def deny(code,msg):
            return SinkResult(request_id=req.request_id,decision=Decision.DENY,verification=ver,authority_id=a.authority_id,error_code=code,error_message=msg)
        if a.authority_id!=req.authority_id: return deny(INVALID_AUTHORITY,'authority id mismatch')
        if not self.verifier.verify(self._unsigned(a),a.issuer.signature): ver['authority_signature']='INVALID'; return deny(INVALID_AUTHORITY,'signature invalid')
        ver['authority_signature']='VALID'
        if a.candidate_act_id!=c.candidate_act_id or a.candidate_act_id!=req.candidate_act_id: return deny(ACT_MISMATCH,'candidate id mismatch')
        if digest(c)!=a.binding.candidate_act_digest: return deny(ACT_MISMATCH,'candidate digest mismatch')
        ver['candidate_act_binding']='MATCH'
        ev=self.evidence_store.get(a.evidence_id)
        if not ev or ev.evidence_digest!=a.binding.evidence_digest or ev.candidate_digest!=a.binding.candidate_act_digest: return deny(EVIDENCE_MISSING,'protected evidence missing or mismatched')
        ver['protected_evidence']='MATCH'
        if not self.activation_store.check(a.authority_id,a.binding.activation_commitment):
            return deny(ALREADY_USED if self.activation_store.is_used(a.authority_id) else ACTIVATION_MISSING,'activation unavailable or authority consumed')
        ver['activation_state']='ACTIVE'
        if now>=a.lifetime.expires_at: return deny(STALE_AUTHORITY,'authority expired')
        if a.binding.policy_epoch!=self.current.policy_epoch or a.binding.authority_epoch!=self.current.authority_epoch: return deny(POLICY_EPOCH_MISMATCH,'policy/authority epoch stale')
        if a.binding.revocation_epoch!=self.current.revocation_epoch: return deny(REVOCATION_MISMATCH,'revocation epoch stale')
        ver['epochs']='CURRENT'
        if self.sink_id!=a.binding.finality_sink_id or req.sink.sink_id!=self.sink_id: return deny(SINK_MISMATCH,'finality sink mismatch')
        ver['sink_binding']='MATCH'
        if req.freshness.nonce!=a.binding.nonce or req.freshness.sequence!=a.binding.sequence: return deny(NONCE_FAILURE,'nonce/sequence mismatch')
        ver['nonce']='FRESH'
        if req.destination.destination_id!=a.scope.destination_id: return deny(DESTINATION_MISMATCH,'destination mismatch')
        if req.destination.recipient_id!=a.scope.recipient_id: return deny(DESTINATION_MISMATCH,'recipient mismatch')
        if req.destination.jurisdiction!=a.scope.jurisdiction: return deny(JURISDICTION_MISMATCH,'jurisdiction mismatch')
        ver['destination']='MATCH'; ver['jurisdiction']='MATCH'
        fields=set(req.outbound_payload.fields.keys())
        if not fields.issubset(set(a.scope.permitted_fields)): return deny(FIELD_SCOPE_MISMATCH,'payload fields exceed permitted field set')
        observed,suspicious=inspect_structured_payload(req.outbound_payload.fields,req.outbound_payload.headers)
        if observed==Precision.NONE and req.outbound_payload.fields and self.fail_on_uninspectable:
            return deny(PAYLOAD_UNINSPECTABLE,'payload precision cannot be established by structured inspector')
        if not within_ceiling(observed,a.scope.authorized_precision):
            ver['payload_precision']=f'{observed.value}_EXCEEDS_{a.scope.authorized_precision.value}'
            if suspicious: ver['precision_evidence']=';'.join(suspicious)
            return deny(PRECISION_MISMATCH,'outbound payload exceeds authorized precision')
        # Declared precision may be coarser than observed; observed wins.
        if not within_ceiling(req.outbound_payload.declared_precision,a.scope.authorized_precision): return deny(PRECISION_MISMATCH,'declared precision exceeds authorized precision')
        ver['payload_precision']=f'{observed.value}_WITHIN_{a.scope.authorized_precision.value}'
        if not self.activation_store.consume(a.authority_id,a.binding.activation_commitment): return deny(ALREADY_USED,'authority already consumed')
        ver['consumption_state']='CONSUMED'
        release_id='release-'+secrets.token_hex(8)
        if self.exposure_store:
            subject=(c.cumulative_disclosure.subject_scope if c.cumulative_disclosure and c.cumulative_disclosure.subject_scope else c.freshness.session_id or c.source_data.source_reference or c.requester.application_id)
            self.exposure_store.record(ReleaseEvent(at=now,subject_scope=subject,destination_id=req.destination.destination_id,precision=observed,fields=list(fields)))
        return SinkResult(request_id=req.request_id,decision=Decision.ALLOW,verification=ver,authority_id=a.authority_id,consumed=True,released_precision=observed,release_id=release_id)
