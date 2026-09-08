from datetime import datetime, timedelta, timezone
import secrets
from .models import *
from .canonical import digest
from .transform import transform_location

def base_candidate(purpose='local-weather', requested=Precision.EXACT, component=ComponentType.APPLICATION, processor=ProcessorType.PROCESSOR, jurisdiction='IN', sink_id='egress-sink-01', sink_type=SinkType.NETWORK_EGRESS, continuous=False, retention=3600, risk=Risk.LOW, subject='subject-demo'):
    now=datetime.now(timezone.utc)
    return LocationReleaseCandidate(
      candidate_act_id='loc-'+secrets.token_hex(12), created_at=now, expires_at=now+timedelta(seconds=30),
      requester=Requester(application_id='demo-app',component_id='module-1',component_type=component),
      purpose=Purpose(purpose_id=purpose,declared_purpose=purpose.replace('-',' ')),
      source_data=SourceData(data_class=DataClass.LOCATION,available_precision=Precision.EXACT,local_only=True,source_reference='device-location'),
      requested_release=RequestedRelease(requested_precision=requested,fields=['latitude','longitude'],retention_seconds=retention,continuous=continuous),
      destination=Destination(destination_id='service.example',endpoint='https://service.example/api',recipient_id='service-provider',processor_type=processor,jurisdiction=jurisdiction),
      cumulative_disclosure=CumulativeDisclosure(subject_scope=subject,movement_history_risk=risk),
      policy_state=PolicyState(policy_epoch=42,authority_epoch=11,revocation_epoch=7),
      freshness=Freshness(nonce=secrets.token_hex(16),sequence=1,session_id='session-demo'),
      finality_sink=SinkRef(sink_id=sink_id,sink_type=sink_type))

def request_for(c,a,fields,declared=None,destination=None,headers=None):
    from .inspector import inspect_structured_payload
    observed,_=inspect_structured_payload(fields,headers or {})
    p=declared or observed
    payload=OutboundPayload(declared_precision=p,fields=fields,headers=headers or {})
    payload.payload_digest=digest(payload.model_dump(exclude={'payload_digest'}))
    return SinkVerifyRequest(request_id='egress-'+secrets.token_hex(8),candidate_act_id=c.candidate_act_id,authority_id=a.authority_id,sink=c.finality_sink.model_copy(deep=True),outbound_payload=payload,destination=(destination.model_copy(deep=True) if destination is not None else c.destination.model_copy(deep=True)),freshness=c.freshness.model_copy(deep=True))
