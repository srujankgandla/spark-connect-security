# TenantGuard: Security Analysis of Apache Spark Connect

Proof-of-concept attack scripts and benchmark for the paper:

> **TenantGuard: A Security Analysis of Multi-tenancy Isolation Failures in Apache Spark Connect**  
> Srujan Kumar Gandla — srujankgandla@ieee.org

---

## Overview

Apache Spark Connect (default since Spark 4.0) exposes a gRPC endpoint on port 15002
with no authentication and no tenant isolation by default. This repository contains
working proof-of-concept scripts for six attack classes against shared Spark Connect
deployments, plus a benchmark measuring attack success rates across 200 trials each.

All experiments were run against **Spark 4.0.0** in Docker.

---

## Attack Scripts

| Script | Attack | Description |
|--------|--------|-------------|
| `attack_a.py` | A | Unauthenticated plan submission — connect with zero credentials |
| `attack_b.py` | B | Session UUID hijacking — inject into another tenant's session |
| `attack_c.py` | C | Arbitrary plan submission / filter bypass |
| `attack_d.py` | D | Global temporary view poisoning (read + overwrite) |
| `attack_e.py` | E | Block store cache timing side channel (AUC = 0.844) |
| `attack_f.py` | F | Credential extraction from Spark event log and process cmdline |

---

## Requirements

```
Python 3.12+
pyspark==4.0.0
Docker
```

Install dependencies:
```bash
pip install "pyspark[connect]==4.0.0"
```

---

## Setup: Start Spark Connect Server

```bash
docker run -d \
  --name spark-connect-server \
  -p 15002:15002 \
  -p 4040:4040 \
  apache/spark:4.0.0 \
  bash -c "
    mkdir -p /tmp/spark-events &&
    /opt/spark/sbin/start-connect-server.sh \
      --master local[2] \
      --conf spark.connect.grpc.binding.port=15002 \
      --conf spark.eventLog.enabled=true \
      --conf spark.eventLog.dir=/tmp/spark-events \
      --conf spark.hadoop.fs.s3a.access.key=AKIAIOSFODNN7EXAMPLE \
      --conf spark.hadoop.fs.s3a.secret.key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY &&
    tail -f /dev/null
  "
```

Wait ~20 seconds for the server to start, then verify:
```bash
docker logs spark-connect-server 2>&1 | grep "port 15002"
```

---

## Running Individual Attacks

```bash
python attack_a.py   # Unauthenticated access
python attack_b.py   # UUID hijacking
python attack_c.py   # Filter bypass
python attack_d.py   # Global view poisoning
python attack_e.py   # Cache timing oracle
python attack_f.py   # Credential extraction
```

---

## Running the Full Benchmark

200 trials per attack, latency measurements, overhead analysis:

```bash
python full_benchmark.py
```

Results are saved to `benchmark_results.json`.

**Sample output:**
```
[1/5] Attack A — unauthenticated plan submission (n=200)...
  Success: 100%  P50=34.2ms  P95=59.5ms  P99=83.5ms

[2/5] Attack B — session UUID hijacking (n=200)...
  Success: 100%  P50=11.9ms  P95=18.1ms  P99=30.1ms

[3/5] Attack D — global temp view poisoning (n=200)...
  D1 read:  100%  P50=9.0ms  P99=22.7ms
  D2 squat: 100%  P50=3.1ms

[4/5] Attack E — cache timing oracle (n=60)...
  AUC=0.844  Speedup=1.35x  Baseline=23.1ms  Cached=17.1ms

[5/5] Interceptor overhead: P50=0.0025ms  P99=0.003ms
```

---

## Key Results

| Attack | Success Rate | Notes |
|--------|-------------|-------|
| A (unauth access) | 100% | Zero credentials needed |
| B (UUID hijack) | 100% | No cryptographic binding on session IDs |
| C (filter bypass) | 100% | Any client can submit any plan |
| D (view poisoning) | 100% | Global views shared across all sessions |
| E (cache timing) | AUC=0.844 | Shared BlockManager leaks occupancy |
| F (credential leak) | Confirmed | Keys visible in /proc and Spark logs |

TenantGuard interceptor overhead: **<0.01%** of query latency (P99 = 0.003ms per request).

---

## Responsible Disclosure

These vulnerabilities affect Spark Connect deployments that rely on network-level
isolation as their only security boundary. Spark Connect's own documentation
acknowledges that authentication must be provided by an external proxy.

The attack scripts in this repository are intended for security research and
authorized testing only. Do not run them against systems you do not own or
have explicit permission to test.

---

## License

MIT
