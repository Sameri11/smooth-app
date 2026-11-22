#!/usr/bin/env python3
"""Collect and validate stock/Bazel host unit-test benchmark evidence."""
import datetime
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path

HOST_INPUTS = json.loads((Path(__file__).parent / "host" / "inputs.json").read_text())
FIXTURE_SHA = HOST_INPUTS["fixture_sha"]
CASE_INVENTORY_SHA = HOST_INPUTS["case_inventory"]["sha256"]
RENAMED_CASE_SHA = HOST_INPUTS["case_inventory"]["renamed_sha256"]
REPO = os.environ["GITHUB_REPOSITORY"]
RUN = os.environ["GITHUB_RUN_ID"]
ATTEMPT = os.environ["GITHUB_RUN_ATTEMPT"]
HEAD = os.environ["GITHUB_SHA"]
RULES_SHA = os.environ.get("RULES_SHA", "")
REPEATS = int(os.environ.get("REPEATS", "0"))
TOKEN = os.environ["GH_TOKEN"]


def gh(*args):
    result = subprocess.run(["gh", *args], text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, env={**os.environ, "GH_TOKEN": TOKEN})
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "gh command failed")
    return result.stdout


def finite(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def median(values):
    values = sorted(values)
    return (values[(len(values) - 1) // 2] + values[len(values) // 2]) / 2


def expected_jobs():
    names = ["Test dependency seed"]
    names += [f"Test timing / stock / clean / {n}" for n in range(1, REPEATS + 1)]
    names += [f"Test seed / bazel / cold / {n}" for n in range(1, REPEATS + 1)]
    names += [f"Test timing / bazel / {scenario} / {n}"
              for scenario in ("warm", "test", "lib") for n in range(1, REPEATS + 1)]
    return names


def proof_from_log(log, marker):
    timestamp = r"(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}) )?"
    records = re.findall(r"^" + timestamp + re.escape(marker) + r" (\{[^\r\n]*\})\r?$", log, re.MULTILINE)
    if len(records) != 1 or len(records[0].encode()) + len(marker) + 1 > 32768:
        raise ValueError(f"missing, repeated, or oversized {marker} record")
    value = json.loads(records[0])
    if not isinstance(value, dict):
        raise ValueError(f"invalid {marker} record")
    return value


def provider_seconds(job):
    start = datetime.datetime.fromisoformat(job["started_at"].replace("Z", "+00:00"))
    end = datetime.datetime.fromisoformat(job["completed_at"].replace("Z", "+00:00"))
    seconds = (end - start).total_seconds()
    if not finite(seconds) or seconds < 0:
        raise ValueError("invalid provider duration")
    return seconds


def collect():
    errors, rows = [], []
    if not 1 <= REPEATS <= 5:
        errors.append("host repeat count must be between one and five")
    if not re.fullmatch(r"[0-9a-f]{40}", RULES_SHA):
        errors.append("resolved rules SHA is invalid")
    try:
        jobs_doc = json.loads(gh("api", f"repos/{REPO}/actions/runs/{RUN}/attempts/{ATTEMPT}/jobs?per_page=100"))
        by_name = {}
        for job in jobs_doc.get("jobs", []):
            by_name.setdefault(job["name"], []).append(job)
    except Exception as exc:
        errors.append(f"could not list workflow jobs: {exc}")
        by_name = {}

    names = expected_jobs()
    actual = [name for name in by_name if name == "Test dependency seed" or name.startswith("Test timing /") or name.startswith("Test seed /")]
    if sorted(actual) != sorted(names):
        errors.append("host test job matrix differs from expected matrix")
    table = {}
    validation_state = {"lock_sha": None, "seeds": {}}
    for name in names:
        matches = by_name.get(name, [])
        row = {"name": name, "job_ids": [job.get("id") for job in matches]}
        if len(matches) != 1:
            row["evidence_error"] = "missing or duplicate job"
            errors.append(f"{name}: missing or duplicate job")
            rows.append(row)
            continue
        job = matches[0]
        row.update(job_id=job.get("id"), status=job.get("status"), conclusion=job.get("conclusion"))
        try:
            row["provider_seconds"] = provider_seconds(job)
            if job.get("status") != "completed" or job.get("conclusion") != "success":
                raise ValueError("job did not succeed")
            log = gh("api", "--allow-escape-sequences", f"repos/{REPO}/actions/jobs/{job['id']}/logs")
            if name == "Test dependency seed":
                prepare = proof_from_log(log, "HOST_TEST_PROOF")
                validate_prepare_stock(prepare)
                proof = proof_from_log(log, "HOST_DEPENDENCY_SEED")
                validate_seed(proof)
                row["prepare_stock"] = prepare
                row["seed"] = proof
            else:
                if name.startswith("Test timing / stock /"):
                    restore = proof_from_log(log, "HOST_DEPENDENCY_RESTORE")
                    row["restore"] = restore
                    validate_restore(restore)
                proof = proof_from_log(log, "HOST_TEST_PROOF")
                candidate = validate_run(name, proof, validation_state)
                started = datetime.datetime.fromisoformat(job["started_at"].replace("Z", "+00:00")).timestamp()
                completed = datetime.datetime.fromisoformat(job["completed_at"].replace("Z", "+00:00")).timestamp()
                validated = proof.get("validated_at_epoch")
                if not finite(validated) or not started - 1 <= validated <= completed + 1:
                    raise ValueError("validated result timestamp is outside job bounds")
                result_seconds = validated - started
                command_seconds = proof["timings"]["command_seconds"]
                if (result_seconds < 0 or command_seconds > result_seconds + 1
                        or result_seconds > row["provider_seconds"] + 1):
                    raise ValueError("command, validated-result, and full-job timing order is invalid")
                row["validated_result_seconds"] = result_seconds
                row["proof"] = proof
                if candidate:
                    validation_state["lock_sha"] = candidate["lock_sha"]
                    if candidate.get("seed"):
                        validation_state["seeds"][candidate["repetition"]] = candidate["seed"]
                table[name] = row
        except Exception as exc:
            row["evidence_error"] = str(exc)
            errors.append(f"{name} ({job.get('id')}): {exc}")
        rows.append(row)

    seed_row = next((row for row in rows if row["name"] == "Test dependency seed"), {})
    seed = seed_row.get("seed")
    seed_seconds = (seed or {}).get("pack_wall_seconds")
    if not finite(seed_seconds):
        errors.append("dependency seed archive pack time is missing")
    stock_digest = (seed or {}).get("payload", {}).get("sha256")
    for row in rows:
        if not row["name"].startswith("Test timing / stock /"):
            continue
        restore = row.get("restore")
        if not restore:
            errors.append(f"{row['name']}: dependency restore proof is missing")
            continue
        if seed and (restore.get("identity") != seed.get("identity")
                     or restore.get("payload") != seed.get("payload")):
            errors.append(f"{row['name']}: restored dependency identity/payload differs from seed")
        if row.get("proof", {}).get("cache", {}).get("seed_sha256") != stock_digest:
            errors.append(f"{row['name']}: restored stock seed digest mismatch")
    cold_one = table.get("Test seed / bazel / cold / 1") or {}
    cold_proof = cold_one.get("proof", {})
    comparisons = []
    for engine, scenarios in (("stock", ("clean",)), ("bazel", ("cold", "warm", "test", "lib"))):
        for scenario in scenarios:
            group = [table.get(f"Test timing / {engine} / {scenario} / {n}") or
                     table.get(f"Test seed / {engine} / {scenario} / {n}") for n in range(1, REPEATS + 1)]
            values = [r["validated_result_seconds"] for r in group
                      if r and finite(r.get("validated_result_seconds"))]
            commands = [r["proof"]["timings"]["command_seconds"] for r in group
                        if r and isinstance(r.get("proof"), dict)]
            jobs = [r["provider_seconds"] for r in group if r and finite(r.get("provider_seconds"))]
            complete = len(values) == REPEATS and len(commands) == REPEATS and len(jobs) == REPEATS
            comparisons.append({"engine": engine, "scenario": scenario, "n": len(values),
                               "command_median_seconds": median(commands) if complete else None,
                               "validated_result_median_seconds": median(values) if complete else None,
                               "full_job_median_seconds": median(jobs) if complete else None,
                               "rows_seconds": values})
    stock = [table.get(f"Test timing / stock / clean / {n}") for n in range(1, REPEATS + 1)]
    for scenario in ("warm", "test", "lib"):
        bazel = [table.get(f"Test timing / bazel / {scenario} / {n}") for n in range(1, REPEATS + 1)]
        a = [r["validated_result_seconds"] for r in stock if r and finite(r.get("validated_result_seconds"))]
        b = [r["validated_result_seconds"] for r in bazel if r and finite(r.get("validated_result_seconds"))]
        verdict = "invalid"
        if len(a) == REPEATS and len(b) == REPEATS:
            if REPEATS < 3:
                verdict = "insufficient repeats"
            else:
                stock_range, bazel_range = (min(a), max(a)), (min(b), max(b))
                separated = bazel_range[1] < stock_range[0] or stock_range[1] < bazel_range[0]
                verdict = "bazel faster" if median(a) - median(b) >= 10 and separated else "no significant difference"
        comparisons.append({"comparison": scenario, "stock_rows_from": "clean", "bazel_rows_from": scenario,
                           "n": REPEATS if len(a) == REPEATS and len(b) == REPEATS else 0,
                           "stock_median_seconds": median(a) if a else None,
                           "bazel_median_seconds": median(b) if b else None, "verdict": verdict})
    payload_rows = [r for r in rows if r.get("proof")]
    if len(payload_rows) != 5 * REPEATS:
        errors.append("host timing row count is incomplete")
    valid = not errors
    if not valid:
        for comparison in comparisons:
            if "verdict" in comparison:
                comparison["verdict"] = "invalid"
    return {"valid": valid, "issues": errors, "fixture_sha": FIXTURE_SHA,
            "rules_commit": RULES_SHA, "repeats": REPEATS,
            "seed_setup": {
                "stock_artifact_bytes": (seed or {}).get("payload", {}).get("bytes"),
                "stock_artifact_sha256": (seed or {}).get("payload", {}).get("sha256"),
                "stock_pack_wall_seconds": seed_seconds,
                "stock_full_job_seconds": seed_row.get("provider_seconds"),
                "bazel_cold_repeat_1": {
                    "command_seconds": (cold_proof.get("timings") or {}).get("command_seconds"),
                    "validated_result_seconds": cold_one.get("validated_result_seconds"),
                    "full_job_seconds": cold_one.get("provider_seconds"),
                },
            },
            "comparisons": comparisons, "rows": rows}

def validate_prepare_stock(proof):
    lineage = proof.get("lineage", {})
    seed = proof.get("seed", {})
    if (proof.get("schema"), proof.get("kind"), proof.get("engine"),
            proof.get("scenario"), proof.get("repetition")) != (1, "prepare-stock", "stock", "clean", 1):
        raise ValueError("stock dependency preparation identity mismatch")
    if proof.get("fixture", {}).get("sha") != FIXTURE_SHA:
        raise ValueError("stock dependency fixture SHA mismatch")
    if proof.get("rules", {}).get("sha") is not None:
        raise ValueError("stock dependency preparation must not use rules")
    if proof.get("lock") != {"sha256": None, "mode": "not-applicable"}:
        raise ValueError("stock dependency lock proof invalid")
    if (str(lineage.get("run_id")), str(lineage.get("attempt")),
            lineage.get("workflow_sha"), lineage.get("salt")) != (RUN, ATTEMPT, HEAD, None):
        raise ValueError("stock dependency preparation lineage mismatch")
    if seed.get("sdk_revision") != HOST_INPUTS["flutter"]["revision"]:
        raise ValueError("stock seed Flutter revision mismatch")
    if not isinstance(seed.get("pub_cache_path"), str) or not seed["pub_cache_path"]:
        raise ValueError("stock pub-cache path missing")
    entries = seed.get("pub_cache_entries")
    if isinstance(entries, bool) or not isinstance(entries, int) or entries < 1:
        raise ValueError("stock pub-cache inventory is empty")
    if not re.fullmatch(r"[0-9a-f]{64}", seed.get("package_config_sha256", "")):
        raise ValueError("stock package-config digest missing")


def validate_seed(proof):
    identity = proof["identity"]
    payload = proof["payload"]
    expected_identity = {
        "run_id": RUN, "run_attempt": ATTEMPT, "head_sha": HEAD,
        "fixture_sha": FIXTURE_SHA, "sdk_version": HOST_INPUTS["flutter"]["version"],
    }
    if proof.get("schema") != 1 or identity != expected_identity:
        raise ValueError("dependency seed identity mismatch")
    if payload.get("file") != "seed.tar.zst":
        raise ValueError("dependency seed payload filename invalid")
    if isinstance(payload.get("bytes"), bool) or not isinstance(payload.get("bytes"), int) or payload["bytes"] <= 0:
        raise ValueError("dependency seed payload size invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", payload.get("sha256", "")):
        raise ValueError("dependency seed payload digest invalid")
    if not finite(proof.get("pack_wall_seconds")) or proof["pack_wall_seconds"] < 0:
        raise ValueError("dependency seed pack time invalid")

def validate_restore(proof):
    identity, payload = proof.get("identity"), proof.get("payload")
    if not isinstance(identity, dict) or not isinstance(payload, dict):
        raise ValueError("dependency restore identity/payload missing")
    if payload.get("file") != "seed.tar.zst" or isinstance(payload.get("bytes"), bool) or not isinstance(payload.get("bytes"), int) or payload["bytes"] <= 0:
        raise ValueError("dependency restore payload metadata invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", payload.get("sha256", "")):
        raise ValueError("dependency restore payload digest invalid")
    if not finite(proof.get("restore_wall_seconds")) or proof["restore_wall_seconds"] < 0:
        raise ValueError("dependency restore time invalid")


def validate_run(name, proof, validation_state):
    _, engine, scenario, rep = name.split(" / ")
    repetition = int(rep)
    expected_scenario = "clean" if engine == "stock" else scenario
    if proof.get("schema") != 1 or proof.get("kind") != "run":
        raise ValueError("unsupported proof schema")
    if (proof.get("engine"), proof.get("scenario"), proof.get("repetition")) != (engine, expected_scenario, repetition):
        raise ValueError("proof row identity mismatch")
    if proof.get("fixture", {}).get("sha") != FIXTURE_SHA:
        raise ValueError("fixture SHA mismatch")
    rules_sha = proof.get("rules", {}).get("sha")
    if engine == "stock":
        if rules_sha is not None or proof.get("driver", {}).get("name") != "flutter":
            raise ValueError("stock rules/driver identity invalid")
    elif (not re.fullmatch(r"[0-9a-f]{40}", str(rules_sha or ""))
          or rules_sha != RULES_SHA or proof.get("driver", {}).get("name") != "default"):
        raise ValueError("Bazel rules/driver identity mismatch")
    lock = proof.get("lock", {})
    if engine == "stock":
        if lock.get("sha256") is not None or lock.get("mode") != "not-applicable":
            raise ValueError("stock lock proof invalid")
    elif not re.fullmatch(r"[0-9a-f]{64}", lock.get("sha256", "")) or lock.get("mode") != "update":
        raise ValueError("Bazel generated lock proof invalid")
    if engine == "bazel":
        prior = validation_state["lock_sha"]
        if prior is not None and prior != lock["sha256"]:
            raise ValueError("Bazel lock digest differs across rows")
    lineage = proof.get("lineage", {})
    if (str(lineage.get("run_id")), str(lineage.get("attempt")), lineage.get("workflow_sha")) != (RUN, ATTEMPT, HEAD):
        raise ValueError("run lineage mismatch")
    remote_salt = lineage.get("salt")
    expected_salt = f"host-test/{RUN}/{ATTEMPT}/{HEAD}/{repetition}"
    if engine == "bazel" and remote_salt != expected_salt:
        raise ValueError("remote cache salt mismatch")
    if engine == "stock" and remote_salt is not None:
        raise ValueError("stock remote salt must be null")
    driver = proof.get("driver", {})
    cache = proof.get("cache", {})
    if any(isinstance(driver.get(key), bool) or not isinstance(driver.get(key), int) or driver[key] < 0
           for key in ("worker_spawns", "kernel_executions")):
        raise ValueError("driver execution counters missing")
    if not isinstance(cache.get("read_only"), bool):
        raise ValueError("cache read-only attestation missing")
    if not re.fullmatch(r"[0-9a-f]{64}", cache.get("seed_sha256", "")):
        raise ValueError("cache seed digest missing")
    if engine == "stock":
        if (cache.get("mode"), cache.get("read_only"), cache.get("seed_kind"), cache.get("seed_identity")) != (
                "read", True, "stock-dependency", None):
            raise ValueError("stock dependency seed lineage/read-only proof invalid")
    else:
        expected_mode = "seed" if scenario == "cold" else "read"
        expected_read_only = scenario != "cold"
        if (cache.get("mode"), cache.get("read_only")) != (expected_mode, expected_read_only):
            raise ValueError("Bazel cache seed/read-only mode mismatch")
        if cache.get("seed_kind") != "bazel-test":
            raise ValueError("Bazel test seed kind mismatch")
        seed_identity = cache.get("seed_identity")
        expected_identity = {
            "run_id": RUN, "attempt": ATTEMPT, "workflow_sha": HEAD,
            "repetition": repetition, "salt": expected_salt,
        }
        if seed_identity != expected_identity:
            raise ValueError("Bazel seed lineage identity mismatch")
        expected_seed_sha = hashlib.sha256(json.dumps(
            {"identity": expected_identity, "fixture_sha": FIXTURE_SHA,
             "rules_sha": rules_sha, "lock_sha": lock["sha256"]},
            sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if cache.get("seed_sha256") != expected_seed_sha:
            raise ValueError("Bazel seed identity digest mismatch")
        prior_seed = validation_state["seeds"].get(repetition)
        if scenario == "cold":
            if prior_seed is not None:
                raise ValueError("duplicate Bazel cold seed for repetition")
        elif prior_seed is None:
            raise ValueError("Bazel reader has no preceding valid cold seed")
        elif (prior_seed["sha256"], prior_seed["salt"], prior_seed["lock_sha"]) != (
                cache["seed_sha256"], remote_salt, lock["sha256"]):
            raise ValueError("Bazel reader does not match its validated cold seed")
    hits, misses = cache.get("test_result_hits"), cache.get("test_result_misses")
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in (hits, misses)):
        raise ValueError("BEP test-result hit/miss counts invalid")
    if engine == "stock":
        if hits or misses:
            raise ValueError("stock run cannot attest Bazel BEP results")
    elif hits + misses != 23:
        raise ValueError("BEP test-result hits and misses do not cover 23 targets")
    elif scenario == "cold" and hits != 0:
        raise ValueError("cold seed unexpectedly has cached test results")
    elif scenario == "warm" and (hits, misses) != (23, 0):
        raise ValueError("warm run did not reuse all test-result targets")
    if engine == "bazel":
        if misses:
            if driver["worker_spawns"] != driver["kernel_executions"] or driver["kernel_executions"] < 1:
                raise ValueError("Bazel misses lack matching worker/kernel execution")
            if driver.get("worker_strategy") != "default":
                raise ValueError("Bazel default worker strategy missing on misses")
        elif driver["worker_spawns"] or driver["kernel_executions"] or driver.get("worker_strategy") is not None:
            raise ValueError("Bazel hit-only run reports worker execution")
    cases = proof.get("cases", {})
    expected_inventory = RENAMED_CASE_SHA if scenario == "test" else CASE_INVENTORY_SHA
    if (cases.get("expected"), cases.get("observed")) != (246, 246) or cases.get("inventory_sha256") != expected_inventory:
        raise ValueError("test case inventory/count/digest mismatch")
    timings = proof.get("timings", {})
    if not finite(timings.get("command_seconds")) or timings.get("command_seconds") < 0:
        raise ValueError("test command timing missing")
    if not finite(timings.get("validated_result_seconds")) or timings["validated_result_seconds"] < 0:
        raise ValueError("validated-result timing missing")
    if not finite(proof.get("validated_at_epoch")) or timings.get("unit") != "seconds":
        raise ValueError("validated-result timestamp or timing unit missing")
    should_control = repetition == 1 and ((engine, scenario) in (("stock", "clean"), ("bazel", "cold")))
    controls = proof.get("controls", {})
    if should_control:
        if controls.get("status") != "pass" or controls.get("cases") != 2 or controls.get("rejections") != 2:
            raise ValueError("both broken-input controls must reject")
        if engine == "bazel" and scenario == "cold":
            if controls.get("lock_mode") != "error" or controls.get("lock_sha256") != lock.get("sha256"):
                raise ValueError("Bazel controls did not preserve the timed lock under error mode")
    elif controls.get("status") != "not-run":
        raise ValueError("controls must run only on repeat one cold/clean")

    candidate = None
    if engine == "bazel":
        candidate = {"lock_sha": lock["sha256"]}
        if scenario == "cold":
            candidate.update(repetition=repetition, seed={
                "sha256": cache["seed_sha256"], "salt": remote_salt,
                "lock_sha": lock["sha256"],
            })
    return candidate

def summary_lines(result):
    seed_setup = result.get("seed_setup") or {}
    cold_seed = seed_setup.get("bazel_cold_repeat_1") or {}
    lines = [
        "# Host unit-test benchmark", "",
        f"Valid: **{str(bool(result.get('valid', False))).lower()}**",
        f"Fixture: `{result.get('fixture_sha', 'missing')}`; "
        f"rules: `{result.get('rules_commit', 'missing')}`; "
        f"repeats: {result.get('repeats', 'missing')}", "",
        "Stock dependency archive: "
        f"{seed_setup.get('stock_artifact_bytes', 'missing')} bytes, "
        f"SHA-256 `{seed_setup.get('stock_artifact_sha256', 'missing')}`, "
        f"{seed_setup.get('stock_pack_wall_seconds', 'missing')} s pack, "
        f"{seed_setup.get('stock_full_job_seconds', 'missing')} s pack/upload job. "
        f"Bazel cold/1: {cold_seed.get('command_seconds', 'missing')} s command, "
        f"{cold_seed.get('validated_result_seconds', 'missing')} s validated, "
        f"{cold_seed.get('full_job_seconds', 'missing')} s full job.", "",
        "| Engine / scenario | Command median (s) | Validated-result median (s) | Full-job median (s) |",
        "|---|---:|---:|---:|",
    ]
    for item in result.get("comparisons", []):
        if "engine" in item:
            lines.append(
                f"| {item['engine']} / {item['scenario']} | "
                f"{item.get('command_median_seconds', '—')} | "
                f"{item.get('validated_result_median_seconds', '—')} | "
                f"{item.get('full_job_median_seconds', '—')} |"
            )
        else:
            lines.append(
                f"| Comparison {item.get('comparison', 'unknown')} | "
                f"stock {item.get('stock_median_seconds', '—')} s | "
                f"Bazel {item.get('bazel_median_seconds', '—')} s | "
                f"Verdict: {item.get('verdict', 'invalid')} |"
            )
    lines += ["", "## Every host job", "",
              "| Job | Command (s) | Validated-result (s) | Full-job (s) | Stock restore (s) |",
              "|---|---:|---:|---:|---:|"]
    for row in result.get("rows", []):
        proof = row.get("proof") or {}
        timing = proof.get("timings") or {}
        restore = row.get("restore") or {}
        lines.append(
            f"| {row.get('name', 'unknown')} | "
            f"{timing.get('command_seconds', '—')} | "
            f"{row.get('validated_result_seconds', '—')} | "
            f"{row.get('provider_seconds', '—')} | "
            f"{restore.get('restore_wall_seconds', '—')} |"
        )
    issues = result.get("issues") or []
    if issues:
        lines += ["", "## Validity issues", ""] + [f"- {issue}" for issue in issues]
    return lines


def main():
    result = collect()
    result.update(run_id=RUN, run_attempt=int(ATTEMPT), workflow_commit=HEAD, suite="test")
    output = json.dumps(result, indent=2, sort_keys=True) + "\n"
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
        stream.write("\n".join(summary_lines(result)) + "\n")
    from report import persist_result
    persist_result(output, "Record host test benchmark")
    print(output)
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"host report failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise
