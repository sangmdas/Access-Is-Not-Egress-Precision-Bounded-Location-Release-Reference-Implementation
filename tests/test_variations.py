from concurrent.futures import ThreadPoolExecutor
import pytest
from precision_egress.models import *
from precision_egress.factory import base_candidate,request_for
from precision_egress.transform import transform_location
from precision_egress.scenarios import RAW,stack

@pytest.mark.parametrize('backend',['ed25519','hmac'])
def test_crypto_backends(backend):
 st,es,ac,ex,ped,sink=stack(backend); c=base_candidate(); pd,ev,a=ped.validate_and_issue(c); r=sink.verify_and_release(c,a,request_for(c,a,transform_location(RAW,pd.authorized_precision))); assert r.decision==Decision.ALLOW

@pytest.mark.parametrize('sink_type,sink_id',[(SinkType.NETWORK_EGRESS,'egress-sink-01'),(SinkType.OS_DATA_BROKER,'os-broker-01'),(SinkType.BROWSER_UPLOAD,'browser-sink-01'),(SinkType.API_GATEWAY,'api-sink-01'),(SinkType.TELEMETRY,'telemetry-sink-01'),(SinkType.FILE_EXPORT,'file-sink-01')])
def test_sink_type_variations(sink_type,sink_id):
 st,es,ac,ex,ped,_=stack(); c=base_candidate(sink_id=sink_id,sink_type=sink_type); pd,ev,a=ped.validate_and_issue(c)
 from precision_egress.sink import EgressFinalitySink
 sink=EgressFinalitySink(sink_id,ped.signer.verifier(),st,es,ac,ex); r=sink.verify_and_release(c,a,request_for(c,a,transform_location(RAW,pd.authorized_precision))); assert r.decision==Decision.ALLOW

@pytest.mark.parametrize('precision',[Precision.EXACT,Precision.METER_10,Precision.METER_100,Precision.GRID,Precision.GEOHASH,Precision.CITY,Precision.REGION,Precision.COUNTRY])
def test_precision_ceiling_math(precision):
 from precision_egress.models import within_ceiling
 assert within_ceiling(precision,precision)


def test_concurrent_single_use_only_one_allows():
 st,es,ac,ex,ped,sink=stack(); c=base_candidate(); pd,ev,a=ped.validate_and_issue(c); req=request_for(c,a,transform_location(RAW,pd.authorized_precision))
 def run(_): return sink.verify_and_release(c,a,req).decision
 with ThreadPoolExecutor(max_workers=8) as pool: results=list(pool.map(run,range(20)))
 assert results.count(Decision.ALLOW)==1

@pytest.mark.parametrize('processor,expected',[ (ProcessorType.AD_NETWORK,Decision.DENY),(ProcessorType.ANALYTICS,Decision.ALLOW_WITH_TRANSFORMATION),(ProcessorType.AI_PROVIDER,Decision.ALLOW_WITH_TRANSFORMATION),(ProcessorType.PUBLIC_AUTHORITY,Decision.ALLOW_WITH_TRANSFORMATION)])
def test_processor_variations(processor,expected):
 *_,ped,sink=stack(); c=base_candidate(processor=processor); pd,ev,a=ped.validate_and_issue(c); assert pd.decision==expected

def test_sqlite_persistence_and_replay_survive_reopen(tmp_path):
 from precision_egress.state import CurrentState,SQLiteEvidenceStore,SQLiteActivationStore,ExposureStore
 from precision_egress.crypto import Ed25519Signer
 from precision_egress.ped import ProtectedEnforcementDomain
 from precision_egress.sink import EgressFinalitySink
 st=CurrentState(); signer=Ed25519Signer(); ep=tmp_path/'evidence.db'; ap=tmp_path/'activation.db'; ex=ExposureStore()
 es=SQLiteEvidenceStore(ep); ac=SQLiteActivationStore(ap); ped=ProtectedEnforcementDomain('ped-device-01',signer,st,es,ac,exposure_store=ex); sink=EgressFinalitySink('egress-sink-01',signer.verifier(),st,es,ac,ex)
 c=base_candidate(); pd,ev,a=ped.validate_and_issue(c); req=request_for(c,a,transform_location(RAW,pd.authorized_precision)); assert sink.verify_and_release(c,a,req).decision==Decision.ALLOW
 # Reopen state from the same DB files: consumed state remains consumed.
 es2=SQLiteEvidenceStore(ep); ac2=SQLiteActivationStore(ap); sink2=EgressFinalitySink('egress-sink-01',signer.verifier(),st,es2,ac2,ex); r=sink2.verify_and_release(c,a,req); assert r.error_code=='EF-005'

def test_sqlite_authority_survives_reopen_before_use(tmp_path):
 from precision_egress.state import CurrentState,SQLiteEvidenceStore,SQLiteActivationStore,ExposureStore
 from precision_egress.crypto import Ed25519Signer
 from precision_egress.ped import ProtectedEnforcementDomain
 from precision_egress.sink import EgressFinalitySink
 st=CurrentState(); signer=Ed25519Signer(); ep=tmp_path/'evidence2.db'; ap=tmp_path/'activation2.db'; ex=ExposureStore(); es=SQLiteEvidenceStore(ep); ac=SQLiteActivationStore(ap); ped=ProtectedEnforcementDomain('ped-device-01',signer,st,es,ac,exposure_store=ex)
 c=base_candidate(); pd,ev,a=ped.validate_and_issue(c); req=request_for(c,a,transform_location(RAW,pd.authorized_precision)); es2=SQLiteEvidenceStore(ep); ac2=SQLiteActivationStore(ap); sink=EgressFinalitySink('egress-sink-01',signer.verifier(),st,es2,ac2,ex); assert sink.verify_and_release(c,a,req).decision==Decision.ALLOW
