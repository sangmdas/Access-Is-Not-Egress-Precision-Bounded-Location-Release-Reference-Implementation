import argparse, json
from .scenarios import run_scenario

def main():
    p=argparse.ArgumentParser(description='Precision-bounded egress reference implementation')
    p.add_argument('scenario',nargs='?',default='weather',choices=['weather','pharmacy','emergency','advertising','analytics','ai-agent','high-cumulative','critical-cumulative','continuous-trace'])
    p.add_argument('--backend',choices=['ed25519','hmac'],default='ed25519')
    args=p.parse_args(); print(json.dumps(run_scenario(args.scenario,args.backend),indent=2,default=str))
if __name__=='__main__': main()
