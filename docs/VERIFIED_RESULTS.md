# Verified reference results

Verification date: 2026-09-08

## Automated tests

```text
98 tests collected
98 passed
0 failed
```

The suite includes normal release paths, precision transformations, component/processor/sink variations, cumulative-disclosure behavior, Ed25519/HMAC variations, SQLite persistence, replay, concurrent single-use consumption, act/destination/recipient/jurisdiction/sink/nonce substitution, stale epochs, expiry, signature tampering, missing evidence/activation, structured payload inspection and false coarse-label attacks.

## Reference environment

```text
OS:             Linux
Kernel:         6.18.35
Architecture:   x86_64
Hypervisor:     KVM
Visible CPUs:   5
CPU model:      AMD EPYC 9V74 80-Core Processor
Visible RAM:    approximately 5.8 GiB
Swap:           0
Python:         3.13.5
Pydantic:       2.13.4
cryptography:   46.0.4
```

Only five logical CPUs were visible to the environment; the CPU model string does not mean 80 cores were available to the benchmark.

## Ed25519 local in-process benchmark

5,000 iterations:

```text
PED      mean=250.1 us  p50=220.7 us  p95=351.1 us  p99=533.0 us
Sink     mean=250.6 us  p50=224.8 us  p95=345.6 us  p99=510.5 us
Combined mean=500.7 us  p50=457.7 us  p95=662.7 us  p99=882.0 us
```

## HMAC-SHA256 variation

5,000 iterations:

```text
PED      mean=184.8 us  p50=162.7 us  p95=284.6 us  p99=485.4 us
Sink     mean=112.9 us  p50=100.3 us  p95=174.5 us  p99=309.9 us
Combined mean=297.7 us  p50=269.7 us  p95=463.6 us  p99=652.3 us
```

## Benchmark disclaimer

These measurements are **local Python reference-implementation processing times**. They are not end-to-end mobile-device, Internet, 5G, browser, OS, TEE, HSM or cloud-service latency. They exclude IPC, socket/network transport, TLS/QUIC, DNS, server RTT, real reverse geocoding, production storage, remote attestation, remote policy lookup and platform enforcement overhead.

Results should be reproduced on the intended target platform before any performance statement is made.
