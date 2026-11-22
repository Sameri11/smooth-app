#!/usr/bin/env python3
"""Collect, validate, summarize, retire seed caches, and persist one run."""
import base64
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

REPO = os.environ["GITHUB_REPOSITORY"]
RUN = os.environ["GITHUB_RUN_ID"]
ATTEMPT = int(os.environ["GITHUB_RUN_ATTEMPT"])
WORKFLOW_SHA = os.environ["GITHUB_SHA"]
RULES_SHA = os.environ.get("RULES_SHA", "")
APP_REF = os.environ.get("APP_REF", "")
REPEATS = int(os.environ.get("REPEATS", "0"))
TOKEN = os.environ["GH_TOKEN"]
ENGINES = ("stock", "bazel")
SCENARIOS = {"stock": ("cold", "warm"), "bazel": ("cold", "warm", "lib")}
APK_TARGET = "//packages/smooth_app/android/app:smooth_app"


def gh(*args, check=True):
    result = subprocess.run(["gh", *args], text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env={**os.environ, "GH_TOKEN": TOKEN})
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or "gh command failed")
    return result


def expected_names():
    return [f"APK timing / {engine} / {scenario} / {repeat}"
            for engine in ENGINES for scenario in SCENARIOS[engine] for repeat in range(REPEATS)]


def proof_from_log(log):
    metadata = re.findall(r"APK_TIMING_META (\{[^\r\n]+\})", log)
    if len(metadata) != 1:
        raise ValueError("missing or repeated timing proof")
    meta = json.loads(metadata[0])
    if meta.get("encoding") != "gzip+base64" or not 1 <= meta.get("chunks", 0) <= 2048:
        raise ValueError("invalid proof metadata")
    chunks = {}
    for match in re.finditer(r"APK_TIMING_CHUNK (\d+)/(\d+) ([A-Za-z0-9+/=]+)", log):
        index, count = int(match[1]), int(match[2])
        if count != meta["chunks"] or not 1 <= index <= count or index in chunks:
            raise ValueError("invalid proof chunk")
        chunks[index] = match[3]
    if len(chunks) != meta["chunks"]:
        raise ValueError("incomplete proof chunks")
    raw = gzip.decompress(base64.b64decode("".join(chunks[i] for i in range(1, len(chunks) + 1))))
    if hashlib.sha256(raw).hexdigest() != meta.get("sha256"):
        raise ValueError("proof digest mismatch")
    return json.loads(raw)


def median(values):
    values = sorted(values)
    return (values[(len(values) - 1) // 2] + values[len(values) // 2]) / 2


def persist_result(output, subject):
    """Write one benchmark record to the existing results branch."""
    branch = "benchmark-results"
    with tempfile.TemporaryDirectory(prefix="benchmark-results-") as directory:
        path = Path(directory)
        subprocess.run(["git", "init", "-q", "-b", branch], cwd=path, check=True)
        subprocess.run(["git", "config", "user.name", "github-actions[bot]"], cwd=path, check=True)
        subprocess.run(["git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"], cwd=path, check=True)
        remote = gh("api", f"repos/{REPO}/git/ref/heads/{branch}", check=False)
        if remote.returncode == 0:
            subprocess.run(["git", "remote", "add", "origin", f"https://github.com/{REPO}.git"], cwd=path, check=True)
            subprocess.run(["git", "fetch", "--depth=1", "origin", branch], cwd=path, check=True)
            subprocess.run(["git", "checkout", "-B", branch, "FETCH_HEAD"], cwd=path, check=True)
        target = path / "results" / f"{RUN}-{ATTEMPT}.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(output)
        subprocess.run(["git", "add", str(target.relative_to(path))], cwd=path, check=True)
        subprocess.run(["git", "commit", "-m", f"{subject} {RUN}-{ATTEMPT}"], cwd=path, check=True)
        push_env = {**os.environ, "GIT_ASKPASS": "echo", "GIT_TERMINAL_PROMPT": "0"}
        subprocess.run(["git", "-c", f"http.https://github.com/.extraheader=AUTHORIZATION: basic {base64.b64encode(('x-access-token:'+TOKEN).encode()).decode()}",
                        "push", "https://github.com/" + REPO + ".git", branch], cwd=path, env=push_env, check=True)

def finite(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def main():
    suite = os.environ.get("BENCHMARK_SUITE", "apk")
    if suite not in ("apk", "test", "both"):
        raise ValueError("BENCHMARK_SUITE must be apk, test, or both")
    if suite == "test":
        from host_report import main as host_main
        return host_main()
    errors, rows = [], []
    host_result = None
    host_summary_lines = None
    if suite == "both":
        from host_report import collect as collect_host, summary_lines as host_summary_lines
        try:
            host_result = collect_host()
        except Exception as exc:
            host_result = {"valid": False, "issues": [f"host report collection failed: {exc}"]}
            host_summary_lines = None
    try:
        jobs_doc = json.loads(gh(
            "api", f"repos/{REPO}/actions/runs/{RUN}/attempts/{ATTEMPT}/jobs?per_page=100").stdout)
        by_name = {}
        for job in jobs_doc.get("jobs", []):
            by_name.setdefault(job["name"], []).append(job)
    except Exception as exc:
        errors.append(f"could not list workflow jobs: {exc}")
        by_name = {}
    for name in expected_names():
        matches = by_name.get(name, [])
        row = {"name": name, "job_ids": [j["id"] for j in matches]}
        if len(matches) != 1:
            row["evidence_error"] = "missing or duplicate job"
            errors.append(f"{name}: {row['evidence_error']}")
            rows.append(row)
            continue
        job = matches[0]
        row.update(job_id=job["id"], conclusion=job.get("conclusion"), status=job.get("status"))
        try:
            row["provider_seconds"] = (subprocess.run(
                [sys.executable, "-c", "import datetime,sys; a=datetime.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00')); b=datetime.datetime.fromisoformat(sys.argv[2].replace('Z','+00:00')); print((b-a).total_seconds())",
                 job["started_at"], job["completed_at"]], check=True, text=True, stdout=subprocess.PIPE).stdout.strip())
            row["provider_seconds"] = float(row["provider_seconds"])
            if job.get("status") != "completed" or job.get("conclusion") != "success":
                raise ValueError("job did not succeed")
            log = gh("api", "--allow-escape-sequences", f"repos/{REPO}/actions/jobs/{job['id']}/logs").stdout
            proof = proof_from_log(log)
            if (proof.get("head"), str(proof.get("run_id")), str(proof.get("attempt"))) != (
                    WORKFLOW_SHA, RUN, str(ATTEMPT)):
                raise ValueError("proof run/workflow identity mismatch")
            body = proof["body"]
            engine, scenario, repeat = name.split(" / ")[1:]
            repeat = int(repeat)
            ident = body.get("identity", {})
            if (ident.get("head"), str(ident.get("run_id")), str(ident.get("attempt")),
                    ident.get("engine"), ident.get("scenario"), int(body.get("repeat", -1))) != (
                    WORKFLOW_SHA, RUN, str(ATTEMPT), engine, scenario, repeat):
                raise ValueError("proof row identity mismatch")
            if body.get("workflow_job_status") != "success":
                raise ValueError("job log did not attest success")
            timed_name = "stock-flutter-build-apk" if engine == "stock" else "bazel-build-apk"
            commands = body.get("commands", [])
            timed = [command for command in commands if command.get("name") == timed_name]
            if len(timed) != 1 or not isinstance(timed[0].get("argv"), list):
                raise ValueError("timed build command and argv missing from proof")
            argv = timed[0]["argv"]
            if engine == "stock":
                expected = ["build", "apk", "--debug", "--target-platform", "android-x64",
                            "--target", "lib/entrypoints/android/main_google_play.dart", "--no-pub"]
                if (not argv or not argv[0].endswith("/flutter")
                        or len(argv) != len(expected) + 1 or argv[1:] != expected):
                    raise ValueError("stock timed build argv differs from the benchmark command")
            else:
                required = ("build", "--disk_cache=", "--lockfile_mode=error", "--jobs=128",
                            "--remote_download_outputs=toplevel", "--android_platforms=@rules_android//:x86_64",
                            "-c", "fastbuild", "--merge_android_manifest_permissions",
                            "--experimental_record_metrics_for_all_mnemonics",
                            "--@@protobuf+//bazel/toolchains:prefer_prebuilt_protoc", APK_TARGET)
                path_flags = ("--output_base=", "--repository_cache=", "--downloader_config=",
                              "--bazelrc=", "--build_event_json_file=")
                if (not argv or not argv[0].endswith("/bazel")
                        or any(value not in argv for value in required)
                        or not all(any(arg.startswith(prefix) for arg in argv) for prefix in path_flags)
                        or not any(arg.endswith("/ci/benchmark/maven-downloader.cfg") for arg in argv)):
                    raise ValueError("Bazel timed build argv is missing required benchmark flags")
            row.update(engine=engine, scenario=scenario, repeat=repeat,
                       validated_apk_seconds=body.get("required_result_duration_seconds"),
                       repository_cache_before=body.get("repository_cache_before"),
                       remote_cache=body.get("remote_cache"), workflow_clock=body.get("workflow_clock"),
                       cache=body.get("cache_metrics"), artifact=body.get("artifact"),
                       timed_build_argv=argv, lock_diff=body.get("lock_diff"),
                       rules_commit=ident.get("rules_revision"), app_commit=ident.get("app_commit"),
                       runner=body.get("runner"), bazel_profile=body.get("bazel_profile"),
                       bazel_critical_path=body.get("bazel_critical_path"))
            if not finite(row["validated_apk_seconds"]) or not finite(row["provider_seconds"]):
                raise ValueError("missing timed APK/full-job duration")
            key = f"apk-current-{RUN}-{ATTEMPT}-{WORKFLOW_SHA}-{engine}-cold"
            if engine == "bazel":
                lock = row.get("lock_diff") or {}
                if (not isinstance(lock.get("regenerated"), bool)
                        or not isinstance(lock.get("diff_stat"), str)
                        or not re.fullmatch(r"[0-9a-f]{64}", lock.get("lock_sha256", ""))):
                    raise ValueError("Bazel module lock refresh proof missing")
                inventory = row["repository_cache_before"] or {}
                if not inventory or any(v.get("bytes") != 0 or v.get("files") != 0 for v in inventory.values()):
                    raise ValueError("Bazel repository cache is not empty")
                salt = (row["remote_cache"] or {}).get("salt", "")
                expected_salt = f"{RUN}/{ATTEMPT}/{WORKFLOW_SHA}/{repeat if scenario == 'cold' else 0}"
                if salt != expected_salt:
                    raise ValueError("remote cache salt mismatch")
            operations = (row["cache"] or {}).get("operations", [])
            clock = row["workflow_clock"] or {}
            if scenario == "cold" and repeat == 0:
                pack = next((o for o in operations if o.get("command") == "pack"), {})
                cap = (8 if engine == "stock" else 3) * 1024**3
                if pack.get("status") != "ok" or pack.get("key") != key or pack.get("combined_bytes", cap + 1) > cap:
                    raise ValueError("seed pack/key/cap proof failed")
                published = clock.get("published_cache", {})
                if published.get("key") != key or published.get("size_in_bytes", cap + 1) > cap:
                    raise ValueError("published seed proof failed")
            elif scenario == "cold":
                if not any(o.get("command") == "pack" and o.get("status") == "skipped" for o in operations):
                    raise ValueError("nonzero cold repeat unexpectedly packed")
            else:
                restore = next((o for o in operations if o.get("command") == "restore"), {})
                if not (clock.get("cache_hit") is True and clock.get("cache_expected_key") == key and
                        clock.get("cache_matched_key") == key and restore.get("status") == "ok" and
                        restore.get("key") == key):
                    raise ValueError("exact seed restore proof failed")
                if not any(o.get("command") == "pack" and o.get("status") == "skipped" for o in operations):
                    raise ValueError("reader published a seed")
            rows.append(row)
        except Exception as exc:
            row["evidence_error"] = str(exc)
            errors.append(f"{name} ({job['id']}): {exc}")
            rows.append(row)

    # Retire this run's exact seeds before analysis, including invalid runs.
    for engine in ENGINES:
        key = f"apk-current-{RUN}-{ATTEMPT}-{WORKFLOW_SHA}-{engine}-cold"
        try:
            listing = json.loads(gh("api", f"repos/{REPO}/actions/caches?per_page=100").stdout)
            for cache in listing.get("actions_caches", []):
                if cache.get("key") == key:
                    gh("api", "-X", "DELETE", f"repos/{REPO}/actions/caches/{cache['id']}")
        except Exception as exc:
            errors.append(f"could not retire exact seed cache {key}: {exc}")
    table = {(r.get("engine"), r.get("scenario"), r.get("repeat")): r for r in rows}
    for engine in ENGINES:
        artifact = lambda scenario, repeat: (table.get((engine, scenario, repeat), {}).get("artifact") or {})
        cold0 = artifact("cold", 0)
        cold_ids = [artifact("cold", n).get("sha256") for n in range(REPEATS)]
        warm_ids = [artifact("warm", n).get("sha256") for n in range(REPEATS)]
        if engine == "bazel":
            edits = [artifact("lib", n).get("sha256") for n in range(REPEATS)]
            if not all(x and x == cold0.get("sha256") for x in cold_ids + warm_ids):
                errors.append("bazel APK digests differ across cold/warm rows")
            if (len(edits) != REPEATS or not edits[0] or any(x != edits[0] for x in edits)
                    or edits[0] == cold0.get("sha256")):
                errors.append("Bazel Dart-edit APK digest gate failed")
        else:
            if not all(x and x == cold0.get("sha256") for x in warm_ids):
                errors.append("stock warm APK differs from cold/0")
            identity = cold0.get("kernel_sha256"), cold0.get("bytes"), cold0.get("member_count"), cold0.get("native_inventory")
            signer = cold0.get("signing", {}).get("digests")
            for n in range(1, REPEATS):
                a = artifact("cold", n)
                other = (a.get("kernel_sha256"), a.get("bytes"), a.get("member_count"), a.get("native_inventory"))
                if not a.get("sha256") or other != identity or a.get("signing", {}).get("digests") == signer:
                    errors.append(f"stock cold/{n} is not signature-only variation")

    comparisons = []
    for scenario in ("cold", "warm", "edit"):
        stock_scenario = "warm" if scenario == "edit" else scenario
        bazel_scenario = "lib" if scenario == "edit" else scenario
        group = {
            "stock": [table.get(("stock", stock_scenario, i), {}) for i in range(REPEATS)],
            "bazel": [table.get(("bazel", bazel_scenario, i), {}) for i in range(REPEATS)],
        }
        complete = all(all(finite(x.get("validated_apk_seconds")) and finite(x.get("provider_seconds"))
                           for x in group[e]) for e in ENGINES)
        med_apk = {e: median([x["validated_apk_seconds"] for x in group[e]]) for e in ENGINES} if complete else {}
        med_job = {e: median([x["provider_seconds"] for x in group[e]]) for e in ENGINES} if complete else {}
        verdict = "invalid" if not complete else "not enough repeats"
        if complete and REPEATS >= 3:
            stock = [x["validated_apk_seconds"] for x in group["stock"]]
            bazel = [x["validated_apk_seconds"] for x in group["bazel"]]
            verdict = ("stock faster" if med_apk["stock"] + 10 <= med_apk["bazel"] and max(stock) < min(bazel) else
                       "bazel faster" if med_apk["bazel"] + 10 <= med_apk["stock"] and max(bazel) < min(stock) else
                       "no clear difference")
        critical = [x.get("bazel_critical_path") or {} for x in group["bazel"]]
        critical_seconds = [x.get("seconds") for x in critical if finite(x.get("seconds"))]
        component_values = {}
        for row in group["bazel"]:
            for component in ((row.get("bazel_critical_path") or {}).get("components", [])):
                name, seconds = component.get("name"), component.get("duration_seconds")
                if isinstance(name, str) and finite(seconds):
                    component_values.setdefault(name, []).append(seconds)
        comparisons.append({"scenario": scenario, "stock_rows_from": stock_scenario,
                            "bazel_rows_from": bazel_scenario, "n": REPEATS if complete else 0,
                            "validated_apk_median_seconds": med_apk, "full_job_median_seconds": med_job,
                            "rows_seconds": {e: [x.get("validated_apk_seconds") for x in group[e]] for e in ENGINES},
                            "bazel_critical_path_median_seconds": median(critical_seconds) if critical_seconds else None,
                            "bazel_critical_path_components_median_seconds": {
                                name: median(values) for name, values in component_values.items()},
                            "verdict": verdict})
    valid = not errors and len(rows) == 5 * REPEATS
    costs = {}
    for engine in ENGINES:
        durations = [r["provider_seconds"] for r in rows if r.get("engine") == engine and finite(r.get("provider_seconds"))]
        minutes = sum(math.ceil(x / 60) for x in durations)
        costs[engine] = {"jobs": len(durations), "rounded_job_minutes": minutes,
                         "public_compute_usd": 0, "2_core_proxy_usd": round(minutes * .006, 3),
                         "4_core_proxy_usd": round(minutes * .012, 3)}

    app_commits = sorted({r.get("app_commit") for r in rows if r.get("app_commit")})
    rules_commits = sorted({r.get("rules_commit") for r in rows if r.get("rules_commit")})
    if len(app_commits) != 1:
        errors.append("app commit provenance is missing or inconsistent")
    if rules_commits and rules_commits != [RULES_SHA]:
        errors.append("resolved rules commit differs across rows")
    lock_rows = [r.get("lock_diff") for r in rows if r.get("lock_diff")]
    if lock_rows and any((x.get("lock_sha256"), x.get("diff_stat")) !=
                         (lock_rows[0].get("lock_sha256"), lock_rows[0].get("diff_stat"))
                         for x in lock_rows):
        errors.append("lock refresh proof differs across rows")
    valid = not errors and len(rows) == 5 * REPEATS
    if not valid:
        for comparison in comparisons:
            comparison["verdict"] = "invalid"
    seed_proofs = []
    for engine in ENGINES:
        seed_row = table.get((engine, "cold", 0), {})
        operations = (seed_row.get("cache") or {}).get("operations", [])
        pack = next((o for o in operations if o.get("command") == "pack" and o.get("status") == "ok"), {})
        roots = [root for component in pack.get("components", [])
                 for root in component.get("roots", [])]
        gradle = next((root for root in roots if root.get("name") == "gradle-dependency-cache"), {})
        seed_proofs.append({"engine": engine, "combined_bytes": pack.get("combined_bytes"),
                            "gradle_top_level_directories": gradle.get("top_level_directories", [])})
    apk_valid = valid
    if suite == "both":
        if host_result is None:
            host_result = {"valid": False, "issues": ["host report unavailable"]}
        valid = apk_valid and host_result["valid"]
    result = {"run_id": RUN, "run_attempt": ATTEMPT, "workflow_commit": WORKFLOW_SHA,
              "rules_commit": RULES_SHA, "app_ref": APP_REF,
              "app_commit": app_commits[0] if len(app_commits) == 1 else None,
              "repeats": REPEATS, "valid": valid, "issues": errors,
              "runner_class": "ubuntu-24.04 standard public runner",
              "runner_observations": [{"job": r["name"], "vcpus": (r.get("runner") or {}).get("cpu_count"),
                                       "memory_bytes": (r.get("runner") or {}).get("memory_bytes")}
                                      for r in rows],
              "seed_cache_proofs": seed_proofs, "comparisons": comparisons, "cost": costs, "rows": rows}
    if suite == "both":
        result["suite"] = suite
        result["apk_valid"] = apk_valid
        result["host_tests"] = host_result
    output = json.dumps(result, indent=2, sort_keys=True) + "\n"
    outpath = Path(tempfile.gettempdir()) / "benchmark.json"
    outpath.write_text(output)
    summary = ["# Stock vs Bazel debug APK benchmark", "", f"Valid: **{str(valid).lower()}**",
               f"Workflow commit: `{WORKFLOW_SHA}`  ", f"Rules commit: `{RULES_SHA}`  ",
               f"App commit: `{result['app_commit'] or APP_REF}`", "", "## Seed sizes", ""]
    if suite == "both":
        summary += [f"APK valid: **{str(apk_valid).lower()}**"]
    for seed in seed_proofs:
        summary.append(f"- {seed['engine']}: {seed['combined_bytes'] if seed['combined_bytes'] is not None else 'missing'} bytes")
        if seed["engine"] == "stock":
            summary.append("- Seeded `~/.gradle` top-level directories: " +
                           (", ".join(seed["gradle_top_level_directories"]) or "none recorded"))
    summary += ["", "| Scenario | Stock median (s) | Bazel median (s) | Stock full-job median (s) | Bazel full-job median (s) | Verdict |",
                "|---|---:|---:|---:|---:|---|"]
    for c in comparisons:
        a, b = c["validated_apk_median_seconds"], c["full_job_median_seconds"]
        summary.append(f"| {c['scenario']} (stock rows: {c['stock_rows_from']}) | {a.get('stock', '—')} | {a.get('bazel', '—')} | {b.get('stock', '—')} | {b.get('bazel', '—')} | {c['verdict']} |")
    summary += ["", "## Bazel critical-path components (medians)", "",
                "| Scenario | Total critical path (s) | Profile phase components (s) |",
                "|---|---:|---|"]
    for comparison in comparisons:
        if comparison["scenario"] not in ("warm", "edit"):
            continue
        components = comparison["bazel_critical_path_components_median_seconds"]
        detail = ", ".join(f"{name}: {value}" for name, value in sorted(components.items())) or "unavailable"
        total = comparison["bazel_critical_path_median_seconds"]
        summary.append(f"| Bazel {comparison['scenario']} | {total if total is not None else '—'} | {detail} |")
    summary += ["", "## Every row", "",
                "| Job | APK seconds | Full-job seconds | vCPU | RAM (GiB) | APK SHA-256 |",
                "|---|---:|---:|---:|---:|---|"]
    for row in rows:
        artifact = row.get("artifact") or {}
        runner = row.get("runner") or {}
        ram = runner.get("memory_bytes")
        summary.append(f"| {row['name']} | {row.get('validated_apk_seconds', '—')} | {row.get('provider_seconds', '—')} | {runner.get('cpu_count', '—')} | {round(ram / 2**30, 1) if isinstance(ram, (int, float)) else '—'} | `{artifact.get('sha256', '—')}` |")
    lock_rows = [r.get("lock_diff") for r in rows if r.get("lock_diff")]
    if lock_rows:
        summary += ["", "## Module lock refresh", "",
                    f"- Diff stat: `{lock_rows[0].get('diff_stat') or 'no change'}`",
                    f"- SHA-256: `{lock_rows[0].get('lock_sha256') or 'missing'}`"]
    summary += ["", "## Cost proxy", "", "| Engine | Rounded job minutes | 2-core proxy ($0.006/min) | 4-core proxy ($0.012/min) |", "|---|---:|---:|---:|"]
    for engine, cost in costs.items():
        summary.append(f"| {engine} | {cost['rounded_job_minutes']} | ${cost['2_core_proxy_usd']:.3f} | ${cost['4_core_proxy_usd']:.3f} |")
    if errors:
        summary += ["", "## Validity issues", ""] + [f"- {error}" for error in errors]
    summary += ["", "## APK hashes", ""]
    for row in rows:
        summary.append(f"- {row['name']}: `{(row.get('artifact') or {}).get('sha256', 'missing')}`")
    if suite == "both":
        if host_summary_lines is None:
            summary += ["", "# Host unit-test benchmark", "", "Valid: **false**",
                        "", "## Validity issues", "",
                        *[f"- {issue}" for issue in host_result.get("issues", ["host summary unavailable"])]]
        else:
            summary += [""] + host_summary_lines(host_result)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
        stream.write("\n".join(summary) + "\n")
    persist_result(output, "Record APK benchmark")
    return 0 if valid else 1
if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"report failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise
