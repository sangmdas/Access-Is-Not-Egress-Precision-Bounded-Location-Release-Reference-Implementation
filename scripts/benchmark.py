import argparse, statistics, time, platform, sys
from precision_egress.scenarios import stack, RAW
from precision_egress.factory import base_candidate,request_for
from precision_egress.transform import transform_location

def pct(xs,p):
 xs=sorted(xs); return xs[min(len(xs)-1,max(0,int(len(xs)*p)-1))]

def main():
 ap=argparse.ArgumentParser(); ap.add_argument('--iterations',type=int,default=5000); ap.add_argument('--backend',choices=['ed25519','hmac'],default='ed25519'); args=ap.parse_args()
 ped_us=[]; sink_us=[]
 for i in range(args.iterations):
  st,es,ac,ex,ped,sink=stack(args.backend); c=base_candidate(); t=time.perf_counter_ns(); pd,ev,a=ped.validate_and_issue(c); t2=time.perf_counter_ns(); fields=transform_location(RAW,pd.authorized_precision); req=request_for(c,a,fields); t3=time.perf_counter_ns(); r=sink.verify_and_release(c,a,req); t4=time.perf_counter_ns(); ped_us.append((t2-t)/1000); sink_us.append((t4-t3)/1000)
 both=[a+b for a,b in zip(ped_us,sink_us)]
 print('REFERENCE BENCHMARK - local in-process only; NOT network/OS/carrier latency')
 print('python',sys.version.split()[0],'platform',platform.platform(),'backend',args.backend,'iterations',args.iterations)
 for name,xs in [('PED',ped_us),('Sink',sink_us),('Combined',both)]: print(f'{name:8s} mean={statistics.mean(xs):.1f}us p50={pct(xs,.50):.1f}us p95={pct(xs,.95):.1f}us p99={pct(xs,.99):.1f}us')
if __name__=='__main__': main()
