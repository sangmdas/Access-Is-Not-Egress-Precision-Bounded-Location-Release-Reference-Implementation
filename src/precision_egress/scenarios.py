from __future__ import annotations
from copy import deepcopy
from datetime import datetime, timezone, timedelta
from .models import *
from .factory import base_candidate, request_for
from .transform import transform_location
from .state import *
from .crypto import Ed25519Signer, HMACSigner
from .ped import ProtectedEnforcementDomain
from .sink import EgressFinalitySink

RAW=RawLocation(latitude=21.494321,longitude=86.932145,accuracy_meters=4.2,city='Balasore',region='Odisha',country='IN')

def stack(backend='ed25519'):
    st=CurrentState(); es=EvidenceStore(); ac=ActivationStore(); ex=ExposureStore(); signer=Ed25519Signer() if backend=='ed25519' else HMACSigner()
    ped=ProtectedEnforcementDomain('ped-device-01',signer,st,es,ac,exposure_store=ex)
    sink=EgressFinalitySink('egress-sink-01',signer.verifier(),st,es,ac,ex)
    return st,es,ac,ex,ped,sink

def run_scenario(name,backend='ed25519'):
    st,es,ac,ex,ped,sink=stack(backend)
    configs={
      'weather':dict(purpose='local-weather'),
      'pharmacy':dict(purpose='nearby-pharmacy'),
      'emergency':dict(purpose='emergency-services',processor=ProcessorType.PUBLIC_AUTHORITY,retention=300),
      'advertising':dict(purpose='advertising',component=ComponentType.ADVERTISING,processor=ProcessorType.AD_NETWORK),
      'analytics':dict(purpose='analytics',component=ComponentType.ANALYTICS,processor=ProcessorType.ANALYTICS),
      'ai-agent':dict(purpose='ai-inference',component=ComponentType.AI_AGENT,processor=ProcessorType.AI_PROVIDER),
      'high-cumulative':dict(purpose='local-weather',risk=Risk.HIGH),
      'critical-cumulative':dict(purpose='local-weather',risk=Risk.CRITICAL),
      'continuous-trace':dict(purpose='navigation',continuous=True),
    }
    if name not in configs: raise KeyError(name)
    c=base_candidate(**configs[name]); pd,ev,a=ped.validate_and_issue(c)
    out={'scenario':name,'policy_decision':pd.model_dump(mode='json')}
    if not a: return out
    fields=transform_location(RAW,pd.authorized_precision)
    req=request_for(c,a,fields,pd.authorized_precision)
    result=sink.verify_and_release(c,a,req)
    out['authority']=a.model_dump(mode='json'); out['payload']=fields; out['sink_result']=result.model_dump(mode='json'); return out
