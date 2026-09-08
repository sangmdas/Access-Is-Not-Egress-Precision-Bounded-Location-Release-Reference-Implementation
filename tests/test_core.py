from copy import deepcopy
from datetime import datetime, timezone, timedelta
import pytest
from precision_egress.models import *
from precision_egress.factory import base_candidate, request_for
from precision_egress.transform import transform_location
from precision_egress.errors import *
from precision_egress.scenarios import RAW, stack

@pytest.mark.parametrize('purpose,expected',[
 ('local-weather',Precision.CITY),('nearby-pharmacy',Precision.CITY),('analytics',Precision.REGION),('ai-inference',Precision.CITY),('fraud-prevention',Precision.METER_100),('navigation',Precision.EXACT),('emergency-services',Precision.EXACT)])
def test_policy_precision_variations(env,purpose,expected):
 st,es,ac,ex,ped,sink=env; c=base_candidate(purpose=purpose,retention=300)
 pd,ev,a=ped.validate_and_issue(c); assert pd.authorized_precision==expected; assert a is not None

def test_weather_exact_to_city_and_release(env):
 st,es,ac,ex,ped,sink=env; c=base_candidate(); pd,ev,a=ped.validate_and_issue(c)
 assert pd.decision==Decision.ALLOW_WITH_TRANSFORMATION and pd.authorized_precision==Precision.CITY
 fields=transform_location(RAW,Precision.CITY); r=sink.verify_and_release(c,a,request_for(c,a,fields))
 assert r.decision==Decision.ALLOW and r.released_precision==Precision.CITY and r.consumed

def test_ped_does_not_release(env):
 st,es,ac,ex,ped,sink=env; c=base_candidate(); pd,ev,a=ped.validate_and_issue(c); assert a and not ac.is_used(a.authority_id)

@pytest.mark.parametrize('component,expected',[(ComponentType.ADVERTISING,Decision.DENY),(ComponentType.ANALYTICS,Decision.ALLOW_WITH_TRANSFORMATION),(ComponentType.SDK,Decision.ALLOW_WITH_TRANSFORMATION),(ComponentType.AI_AGENT,Decision.ALLOW_WITH_TRANSFORMATION)])
def test_component_caps(env,component,expected):
 *_,ped,sink=env; c=base_candidate(component=component); pd,ev,a=ped.validate_and_issue(c); assert pd.decision==expected

@pytest.mark.parametrize('risk,expected,precision',[(Risk.LOW,Decision.ALLOW_WITH_TRANSFORMATION,Precision.CITY),(Risk.MEDIUM,Decision.ALLOW_WITH_TRANSFORMATION,Precision.CITY),(Risk.HIGH,Decision.ALLOW_WITH_TRANSFORMATION,Precision.REGION),(Risk.CRITICAL,Decision.DENY,Precision.NONE)])
def test_cumulative_policy(env,risk,expected,precision):
 *_,ped,sink=env; c=base_candidate(risk=risk); pd,ev,a=ped.validate_and_issue(c); assert pd.decision==expected and pd.authorized_precision==precision

def test_continuous_fine_trace_escalates(env):
 *_,ped,sink=env; c=base_candidate(purpose='navigation',continuous=True); pd,ev,a=ped.validate_and_issue(c); assert pd.decision==Decision.ESCALATE and a is None

def test_unknown_purpose_escalates(env):
 *_,ped,sink=env; c=base_candidate(purpose='unknown-x'); pd,ev,a=ped.validate_and_issue(c); assert pd.decision==Decision.ESCALATE and not a

def test_jurisdiction_denied(env):
 *_,ped,sink=env; c=base_candidate(jurisdiction='ZZ'); pd,ev,a=ped.validate_and_issue(c); assert pd.decision==Decision.DENY and not a

def test_user_auth_denied(env):
 st,es,ac,ex,ped,sink=env; st.user_authorized=False; c=base_candidate(); pd,ev,a=ped.validate_and_issue(c); assert pd.decision==Decision.DENY

@pytest.mark.parametrize('field,value', [('policy_epoch',41),('authority_epoch',10),('revocation_epoch',6)])
def test_stale_candidate_epochs_fail(env,field,value):
 *_,ped,sink=env; c=base_candidate(); setattr(c.policy_state,field,value)
 with pytest.raises(EgressError): ped.validate_and_issue(c)

def test_expired_candidate_fails(env):
 *_,ped,sink=env; c=base_candidate(); c.expires_at=datetime.now(timezone.utc)-timedelta(seconds=1)
 with pytest.raises(EgressError): ped.validate_and_issue(c)

def test_unauthorized_sink_fails(env):
 *_,ped,sink=env; c=base_candidate(sink_id='evil-sink')
 with pytest.raises(EgressError): ped.validate_and_issue(c)

def test_meter100_release_path(env):
 st,es,ac,ex,ped,sink=env; c=base_candidate(purpose='fraud-prevention',retention=300); pd,ev,a=ped.validate_and_issue(c)
 fields=transform_location(RAW,pd.authorized_precision); r=sink.verify_and_release(c,a,request_for(c,a,fields)); assert r.decision==Decision.ALLOW and r.released_precision==Precision.METER_100
