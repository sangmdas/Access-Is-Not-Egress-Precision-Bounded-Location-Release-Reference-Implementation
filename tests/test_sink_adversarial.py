from copy import deepcopy
from datetime import datetime,timezone,timedelta
import pytest
from precision_egress.models import *
from precision_egress.factory import base_candidate,request_for
from precision_egress.transform import transform_location
from precision_egress.scenarios import RAW,stack
from precision_egress.sink import EgressFinalitySink
from precision_egress.crypto import Ed25519Signer


def issued(env,purpose='local-weather'):
 st,es,ac,ex,ped,sink=env; c=base_candidate(purpose=purpose); pd,ev,a=ped.validate_and_issue(c); return st,es,ac,ex,ped,sink,c,pd,ev,a

def allow_req(c,a,pd): return request_for(c,a,transform_location(RAW,pd.authorized_precision),pd.authorized_precision)

def test_replay_rejected(env):
 *_,sink,c,pd,ev,a=issued(env); req=allow_req(c,a,pd); assert sink.verify_and_release(c,a,req).decision==Decision.ALLOW; r=sink.verify_and_release(c,a,req); assert r.error_code=='EF-005'

def test_candidate_substitution_rejected(env):
 *_,sink,c,pd,ev,a=issued(env); req=allow_req(c,a,pd); c.purpose.declared_purpose='changed'; r=sink.verify_and_release(c,a,req); assert r.error_code=='EF-010'

def test_destination_substitution(env):
 *_,sink,c,pd,ev,a=issued(env); d=c.destination.model_copy(update={'destination_id':'other.example'}); r=sink.verify_and_release(c,a,request_for(c,a,transform_location(RAW,pd.authorized_precision),destination=d)); assert r.error_code=='EF-020'

def test_recipient_substitution(env):
 *_,sink,c,pd,ev,a=issued(env); d=c.destination.model_copy(update={'recipient_id':'other'}); r=sink.verify_and_release(c,a,request_for(c,a,transform_location(RAW,pd.authorized_precision),destination=d)); assert r.error_code=='EF-020'

def test_jurisdiction_substitution(env):
 *_,sink,c,pd,ev,a=issued(env); d=c.destination.model_copy(update={'jurisdiction':'US'}); r=sink.verify_and_release(c,a,request_for(c,a,transform_location(RAW,pd.authorized_precision),destination=d)); assert r.error_code=='EF-021'

def test_sink_substitution(env):
 st,es,ac,ex,ped,sink,c,pd,ev,a=issued(env); req=allow_req(c,a,pd); req.sink.sink_id='other-sink'; r=sink.verify_and_release(c,a,req); assert r.error_code=='EF-040'

def test_nonce_substitution(env):
 *_,sink,c,pd,ev,a=issued(env); req=allow_req(c,a,pd); req.freshness.nonce='A'*32; r=sink.verify_and_release(c,a,req); assert r.error_code=='EF-007'

def test_sequence_substitution(env):
 *_,sink,c,pd,ev,a=issued(env); req=allow_req(c,a,pd); req.freshness.sequence+=1; r=sink.verify_and_release(c,a,req); assert r.error_code=='EF-007'

def test_policy_epoch_change_after_issue(env):
 st,es,ac,ex,ped,sink,c,pd,ev,a=issued(env); st.policy_epoch+=1; r=sink.verify_and_release(c,a,allow_req(c,a,pd)); assert r.error_code=='EF-030'

def test_revocation_change_after_issue(env):
 st,es,ac,ex,ped,sink,c,pd,ev,a=issued(env); st.revocation_epoch+=1; r=sink.verify_and_release(c,a,allow_req(c,a,pd)); assert r.error_code=='EF-031'

def test_expired_authority(env):
 *_,sink,c,pd,ev,a=issued(env); later=a.lifetime.expires_at+timedelta(microseconds=1); r=sink.verify_and_release(c,a,allow_req(c,a,pd),now=later); assert r.error_code=='EF-004'

def test_signature_tamper(env):
 *_,sink,c,pd,ev,a=issued(env); a.issuer.signature='A'+a.issuer.signature[1:]; r=sink.verify_and_release(c,a,allow_req(c,a,pd)); assert r.error_code=='EF-003'

def test_missing_evidence(env):
 st,es,ac,ex,ped,sink,c,pd,ev,a=issued(env); es.remove(a.evidence_id); r=sink.verify_and_release(c,a,allow_req(c,a,pd)); assert r.error_code=='EF-084'

def test_missing_activation(env):
 st,es,ac,ex,ped,sink,c,pd,ev,a=issued(env); ac.remove(a.authority_id); r=sink.verify_and_release(c,a,allow_req(c,a,pd)); assert r.error_code=='EF-085'

def test_authority_copied_to_fresh_sink_state_fails(env):
 st,es,ac,ex,ped,sink,c,pd,ev,a=issued(env); from precision_egress.state import ActivationStore
 fresh=ActivationStore(); sink2=EgressFinalitySink('egress-sink-01',ped.signer.verifier(),st,es,fresh,ex); r=sink2.verify_and_release(c,a,allow_req(c,a,pd)); assert r.error_code=='EF-085'

def test_city_authority_exact_body_denied(env):
 *_,sink,c,pd,ev,a=issued(env); fields={'city':'Balasore','region':'Odisha','country':'IN','latitude':21.49,'longitude':86.93}; req=request_for(c,a,fields,declared=Precision.CITY); r=sink.verify_and_release(c,a,req); assert r.error_code in {'EF-082','EF-023'}

def test_city_authority_exact_header_denied(env):
 *_,sink,c,pd,ev,a=issued(env); fields={'city':'Balasore','region':'Odisha','country':'IN'}; req=request_for(c,a,fields,declared=Precision.CITY,headers={'x-latitude':21.49,'latitude':21.49,'longitude':86.93}); r=sink.verify_and_release(c,a,req); assert r.error_code=='EF-023'

def test_disallowed_extra_field_denied(env):
 *_,sink,c,pd,ev,a=issued(env); fields={'city':'Balasore','region':'Odisha','country':'IN','device_id':'abc'}; r=sink.verify_and_release(c,a,request_for(c,a,fields,Precision.CITY)); assert r.error_code=='EF-082'

def test_false_declared_coarse_does_not_hide_exact(env):
 *_,sink,c,pd,ev,a=issued(env); # emergency gives exact authority, make a city authority instead
 fields={'latitude':21.49,'longitude':86.93}; r=sink.verify_and_release(c,a,request_for(c,a,fields,Precision.CITY)); assert r.error_code in {'EF-082','EF-023'}

def test_uninspectable_payload_fails_closed(env):
 *_,sink,c,pd,ev,a=issued(env); fields={'blob':'opaque-location-token'}; r=sink.verify_and_release(c,a,request_for(c,a,fields,Precision.CITY)); assert r.error_code=='EF-082' or r.error_code=='EF-081'
