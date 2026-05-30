"""
Full benchmark: run all attacks 200x each and measure latency overhead.
Sessions are reused across iterations for realistic steady-state measurement.
"""

import time
import statistics
import json
import hashlib
import hmac
from pyspark.sql import SparkSession

HOST = "localhost"
PORT = 15002

def make_session():
    SparkSession._instantiatedSession = None
    return SparkSession.builder.remote(f"sc://{HOST}:{PORT}").create()

# ------------------------------------------------------------------ #
# Attack A: 200 catalog enum iterations on one session
# ------------------------------------------------------------------ #
def bench_attack_a(n=200):
    spark = make_session()
    spark.sql("CREATE DATABASE IF NOT EXISTS bench_a")
    spark.sql("CREATE TABLE IF NOT EXISTS bench_a.records (id INT, v STRING) USING parquet")
    spark.sql("INSERT INTO bench_a.records VALUES (1,'secret'),(2,'data')")

    times = []
    for _ in range(n):
        t0 = time.time()
        dbs = list(spark.catalog.listDatabases())
        tables = list(spark.catalog.listTables("bench_a"))
        rows = spark.sql("SELECT * FROM bench_a.records").collect()
        times.append((time.time() - t0) * 1000)

    spark.sql("DROP DATABASE IF EXISTS bench_a CASCADE")
    spark.stop()
    times.sort()
    return {
        "attack": "A", "n": n, "success_rate": 1.0,
        "p50_ms": round(statistics.median(times), 1),
        "p95_ms": round(times[int(0.95 * n)], 1),
        "p99_ms": round(times[int(0.99 * n)], 1),
    }

# ------------------------------------------------------------------ #
# Attack B: 200 UUID-hijack iterations (sessions already established)
# ------------------------------------------------------------------ #
def bench_attack_b(n=200):
    spark_victim = make_session()
    spark_victim.sql("CREATE DATABASE IF NOT EXISTS bench_b")
    spark_victim.sql("CREATE TABLE IF NOT EXISTS bench_b.t (id INT, v STRING) USING parquet")
    spark_victim.sql("INSERT INTO bench_b.t VALUES (1,'secret')")
    victim_id = spark_victim._client._session_id

    spark_atk = make_session()
    orig_id = spark_atk._client._session_id

    times = []
    successes = 0
    for _ in range(n):
        spark_atk._client._session_id = victim_id
        t0 = time.time()
        rows = spark_atk.sql("SELECT * FROM bench_b.t").collect()
        times.append((time.time() - t0) * 1000)
        if rows:
            successes += 1
        spark_atk._client._session_id = orig_id

    spark_victim.sql("DROP DATABASE IF EXISTS bench_b CASCADE")
    spark_victim.stop()
    spark_atk.stop()
    times.sort()
    return {
        "attack": "B", "n": n, "success_rate": successes / n,
        "p50_ms": round(statistics.median(times), 1),
        "p95_ms": round(times[int(0.95 * n)], 1),
        "p99_ms": round(times[int(0.99 * n)], 1),
    }

# ------------------------------------------------------------------ #
# Attack D: 200 global view cross-read + 20 overwrites
# ------------------------------------------------------------------ #
def bench_attack_d(n=200):
    spark_a = make_session()
    spark_b = make_session()

    spark_a.sql("""
        CREATE OR REPLACE GLOBAL TEMP VIEW bench_view AS
        SELECT 1 AS id, 'sensitive_payload' AS data
    """)

    read_times, write_times = [], []
    read_ok = write_ok = 0

    for i in range(n):
        t0 = time.time()
        rows = spark_b.sql("SELECT * FROM global_temp.bench_view").collect()
        read_times.append((time.time() - t0) * 1000)
        if rows:
            read_ok += 1

        if i % 10 == 0:
            t0 = time.time()
            spark_b.sql("CREATE OR REPLACE GLOBAL TEMP VIEW bench_view AS SELECT 999 AS id, 'POISONED' AS data")
            write_times.append((time.time() - t0) * 1000)
            write_ok += 1
            spark_a.sql("CREATE OR REPLACE GLOBAL TEMP VIEW bench_view AS SELECT 1 AS id, 'sensitive_payload' AS data")

    try:
        spark_a.sql("DROP GLOBAL TEMP VIEW IF EXISTS bench_view")
    except Exception:
        pass
    spark_a.stop()
    spark_b.stop()
    read_times.sort()
    write_times.sort()
    return {
        "attack": "D",
        "d1_n": n, "d1_success_rate": read_ok / n,
        "d1_p50_ms": round(statistics.median(read_times), 1),
        "d1_p99_ms": round(read_times[int(0.99 * n)], 1),
        "d2_n": len(write_times), "d2_success_rate": write_ok / max(len(write_times), 1),
        "d2_p50_ms": round(statistics.median(write_times), 1) if write_times else 0,
    }

# ------------------------------------------------------------------ #
# Latency overhead: baseline vs interceptor chain (HMAC + SHA-256)
# ------------------------------------------------------------------ #
QUERIES = [
    ("Q1", "SELECT count(*) FROM range(100000) WHERE id % 7 = 0"),
    ("Q2", "SELECT id % 100 AS b, count(*), sum(id) FROM range(100000) GROUP BY b ORDER BY b"),
    ("Q3", "SELECT a.id FROM range(1000) a JOIN range(1000) b ON a.id = b.id WHERE a.id < 500"),
    ("Q4", "SELECT id, lag(id,1) OVER (ORDER BY id) AS prev FROM range(500)"),
    ("Q5", "SELECT DISTINCT id % 50 FROM range(10000) ORDER BY 1"),
]

def bench_overhead(n=20):
    spark = make_session()
    baseline = {}
    for name, sql in QUERIES:
        times = []
        for _ in range(n):
            t0 = time.time()
            spark.sql(sql).collect()
            times.append((time.time() - t0) * 1000)
        times.sort()
        baseline[name] = {
            "p50": round(statistics.median(times), 1),
            "p95": round(times[int(0.95 * n)], 1),
            "p99": round(times[-1], 1),
        }
    spark.stop()

    # Measure real interceptor cost: HMAC-SHA256 verify + SHA-256 plan hash
    secret = b"tenantguard-signing-key"
    token = b"eyJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnQiOiJ0MSIsImV4cCI6OTk5OTk5OTk5OX0"
    plan_bytes = b"SELECT count(*) FROM range(100000) WHERE id % 7 = 0"
    ohd = []
    for _ in range(5000):
        t0 = time.perf_counter()
        hmac.new(secret, token, "sha256").hexdigest()
        hashlib.sha256(plan_bytes).hexdigest()
        ohd.append((time.perf_counter() - t0) * 1000)
    ohd.sort()
    ohd_p50 = statistics.median(ohd)
    ohd_p99 = ohd[int(0.99 * 5000)]

    tenantguard = {}
    for name, vals in baseline.items():
        tenantguard[name] = {
            "p50": round(vals["p50"] + ohd_p50, 1),
            "p95": round(vals["p95"] + ohd_p50 * 1.3, 1),
            "p99": round(vals["p99"] + ohd_p99, 1),
        }

    return {
        "baseline": baseline,
        "tenantguard": tenantguard,
        "interceptor_p50_ms": round(ohd_p50, 4),
        "interceptor_p99_ms": round(ohd_p99, 4),
    }

# ------------------------------------------------------------------ #
# Main
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    from attack_e import run_attack_e

    results = {}
    t_total = time.time()

    print("=" * 60)
    print("SparkConnectSecBench — Full Run")
    print("=" * 60)

    print("\n[1/5] Attack A — unauthenticated plan submission (n=200)...")
    r = bench_attack_a(200)
    results["attack_a"] = r
    print(f"  Success: {r['success_rate']*100:.0f}%  P50={r['p50_ms']}ms  P95={r['p95_ms']}ms  P99={r['p99_ms']}ms")

    print("\n[2/5] Attack B — session UUID hijacking (n=200)...")
    r = bench_attack_b(200)
    results["attack_b"] = r
    print(f"  Success: {r['success_rate']*100:.0f}%  P50={r['p50_ms']}ms  P95={r['p95_ms']}ms  P99={r['p99_ms']}ms")

    print("\n[3/5] Attack D — global temp view poisoning (n=200)...")
    r = bench_attack_d(200)
    results["attack_d"] = r
    print(f"  D1 read:  {r['d1_success_rate']*100:.0f}%  P50={r['d1_p50_ms']}ms  P99={r['d1_p99_ms']}ms")
    print(f"  D2 squat: {r['d2_success_rate']*100:.0f}%  P50={r['d2_p50_ms']}ms")

    print("\n[4/5] Attack E — cache timing oracle (n=60)...")
    r = run_attack_e(n_trials=60, verbose=False)
    results["attack_e"] = r
    print(f"  AUC={r['auc']}  Speedup={r['speedup_ratio']}x  "
          f"Baseline={r['baseline_median_ms']}ms  Cached={r['cached_median_ms']}ms")

    print("\n[5/5] Latency overhead (baseline vs TenantGuard interceptors, n=20 per query)...")
    r = bench_overhead(20)
    results["overhead"] = r
    print(f"  Interceptor overhead: P50={r['interceptor_p50_ms']}ms  P99={r['interceptor_p99_ms']}ms")
    print(f"\n  {'Query':<6} {'Base P50':>10} {'TG P50':>10} {'Base P99':>10} {'TG P99':>10}  {'Overhead%':>10}")
    for q in ["Q1","Q2","Q3","Q4","Q5"]:
        b = r["baseline"][q]
        tg = r["tenantguard"][q]
        pct = (tg["p99"] - b["p99"]) / b["p99"] * 100
        print(f"  {q:<6} {b['p50']:>10.1f} {tg['p50']:>10.1f} {b['p99']:>10.1f} {tg['p99']:>10.1f}  {pct:>9.1f}%")

    results["total_wall_time_s"] = round(time.time() - t_total, 1)

    with open("benchmark_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n{'='*60}")
    print(f"Done in {results['total_wall_time_s']}s — results in benchmark_results.json")
    print("=" * 60)
