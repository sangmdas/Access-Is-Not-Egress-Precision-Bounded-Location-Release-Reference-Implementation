import json, pathlib
from precision_egress.models import LocationReleaseCandidate,PrecisionDecision,EgressFinalityAuthority,SinkVerifyRequest,SinkResult
out=pathlib.Path(__file__).resolve().parents[1]/'schemas'; out.mkdir(exist_ok=True)
for cls in [LocationReleaseCandidate,PrecisionDecision,EgressFinalityAuthority,SinkVerifyRequest,SinkResult]:
    (out/f'{cls.__name__}.schema.json').write_text(json.dumps(cls.model_json_schema(),indent=2)+'\n')
print('generated',len(list(out.glob('*.json'))),'schemas')
