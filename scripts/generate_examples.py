import json, pathlib
from precision_egress.scenarios import run_scenario
out=pathlib.Path(__file__).resolve().parents[1]/'examples'
for name in ['weather','pharmacy','emergency','advertising','analytics','ai-agent','high-cumulative','critical-cumulative','continuous-trace']:
    (out/f'{name}.json').write_text(json.dumps(run_scenario(name),indent=2,default=str)+'\n')
print('generated',len(list(out.glob('*.json'))),'scenario vectors')
