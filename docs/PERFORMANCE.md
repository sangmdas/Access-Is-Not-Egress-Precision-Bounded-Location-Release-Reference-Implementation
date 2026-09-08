# Performance methodology

`scripts/benchmark.py` measures two local in-process intervals:

1. PED validation + evidence commitment + authority construction/signing/activation.
2. Sink signature verification + act/evidence/state checks + structured payload inspection + atomic consumption.

Candidate construction, transformation and request construction occur outside the timed sink/PED intervals where possible.

The benchmark is designed to answer: **is the reference logic executable at measurable software cost?** It does not answer: **what latency does a mobile OS or carrier deployment add?**

Report p50/p95/p99 rather than only mean. Re-run on target hardware. For production work, add end-to-end OS/network measurements and peak-RSS/throughput/concurrency tests.
