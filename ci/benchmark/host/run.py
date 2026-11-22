"""Run the frozen smooth-app host-test workload on stock Flutter or Bazel."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
INPUTS = json.loads((HERE / "inputs.json").read_text())
PACKAGES = INPUTS["packages"]
FIXTURE_SHA = INPUTS["fixture_sha"]
INVENTORY = INPUTS["case_inventory"]
SMOOTH = "packages/smooth_app"
TEST_FILE = SMOOTH + "/test/utils/string_extensions_test.dart"
LIB_FILE = SMOOTH + "/lib/helpers/string_extension.dart"
TEST_OLD = "Multiple occurrence (without case)"
TEST_NEW = "Multiple occurrences (lowercase query, ignoring case)"


class Stop(RuntimeError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(path: Path) -> str | None:
    return sha(path.read_bytes()) if path.is_file() else None


def command(argv, *, cwd, env, capture=False):
    start = time.monotonic()
    result = subprocess.run(argv, cwd=cwd, env=env, text=True,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.STDOUT if capture else None)
    return result, time.monotonic() - start


def need_env(name):
    value = os.environ.get(name, "")
    if not value or "\n" in value or "\r" in value:
        raise Stop("missing or invalid " + name)
    return value


def app_root():
    root = Path(need_env("GITHUB_WORKSPACE")) / "host-app"
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip() != FIXTURE_SHA:
        raise Stop("host-app checkout is not the frozen fixture")
    return root


def runner_temp():
    return Path(need_env("RUNNER_TEMP"))


def environment(root, engine):
    rt = runner_temp()
    env = os.environ.copy()
    env.update({"FLUTTER_ROOT": str(rt / "flutter"),
                "PUB_CACHE": str(rt / "cache-state" / "pub"),
                "BAZELISK_HOME": str(rt / "cache-state" / "bazelisk")})
    flutter = rt / "flutter" / "bin" / "flutter"
    if not flutter.is_file():
        raise Stop("Flutter missing at " + str(flutter))
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=rt / "flutter", text=True).strip()
    if revision != INPUTS["flutter"]["revision"]:
        raise Stop("Flutter checkout revision differs from inputs.json")
    bazel = None
    if engine == "bazel":
        bazel = rt / "bazel"
        if not bazel.is_file():
            raise Stop("Bazelisk missing at " + str(bazel))
        if digest(bazel) != INPUTS["bazelisk"]["archive_sha256"]:
            raise Stop("Bazelisk checksum differs from inputs.json")
    return env, flutter, bazel



def clean_outputs(root):
    dirty = []
    for package in PACKAGES:
        p = root / package
        for name in (".dart_tool", "build", "bazel-out", "bazel-bin", "bazel-testlogs"):
            if (p / name).exists():
                dirty.append(package + "/" + name)
    if (root / "bazel-testlogs").exists() or (root / "bazel-bin").exists():
        dirty.extend([str(root / name) for name in ("bazel-testlogs", "bazel-bin") if (root / name).exists()])
    if dirty:
        raise Stop("timed stock resolution must start without outputs: " + ", ".join(dirty))


def stock_lock_snapshot(root):
    locks = {package: digest(root / package / "pubspec.lock") for package in PACKAGES}
    if any(value is None for value in locks.values()):
        raise Stop("a frozen package pubspec.lock is missing")
    return locks


def stock_pub(root, env, flutter):
    before = stock_lock_snapshot(root)
    elapsed = 0.0
    for package in PACKAGES:
        result, duration = command([str(flutter), "pub", "get", "--enforce-lockfile"], cwd=root / package, env=env)
        elapsed += duration
        if result.returncode:
            raise Stop(package + " pub get --enforce-lockfile failed")
    if stock_lock_snapshot(root) != before:
        raise Stop("stock pub get changed a frozen pubspec.lock")
    return elapsed


def parse_machine(text, package):
    suites, tests, records = {}, {}, []
    done = None
    errors = 0
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise Stop(f"{package}: machine output line {number} is invalid JSON: {error}")
        if isinstance(event, list):
            continue
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            raise Stop(f"{package}: invalid machine event on line {number}")
        kind = event["type"]
        try:
            if kind == "suite":
                path = event["suite"]["path"]
                marker = package + "/"
                if marker not in path:
                    raise Stop(f"{package}: suite path outside package: {path}")
                rel = path.split(marker, 1)[1]
                if not rel.startswith("test/"):
                    raise Stop(f"{package}: suite outside test/: {rel}")
                suites[event["suite"]["id"]] = rel
            elif kind == "testStart":
                test = event["test"]
                tests[test["id"]] = (suites[test["suiteID"]], test["name"])
            elif kind == "testDone":
                file, name = tests[event["testID"]]
                result = "skip" if event.get("skipped") or event.get("result") == "skipped" else event.get("result")
                outcome = {"success": "pass", "failure": "fail", "error": "error"}.get(result)
                if outcome is None:
                    raise Stop(f"{package}: unknown Flutter machine test result {result!r}")
                if not (event.get("hidden") and outcome in ("pass", "skip")):
                    records.append((package, file, name, outcome))
            elif kind == "error":
                errors += 1
            elif kind == "done":
                done = event["success"]
        except (KeyError, TypeError) as error:
            raise Stop(f"{package}: incomplete machine event: {error}")
    if not isinstance(done, bool):
        raise Stop(package + " machine output has no done event")
    return sorted(suites.values()), records, done, errors


def expected_hash(records):
    normalized = [list(record) for record in sorted(records)]
    return sha(json.dumps(normalized, separators=(",", ":"), ensure_ascii=False).encode())

def package_relative(classname, package):
    marker = package + "/"
    if classname.startswith(marker):
        return classname[len(marker):]
    index = classname.find("/" + marker)
    if index < 0:
        raise Stop(f"{classname!r} does not name {package}")
    return classname[index + 1 + len(marker):]


def stock_tests(root, env, flutter):
    all_records, elapsed = [], 0.0
    for package in PACKAGES:
        proc, duration = command([str(flutter), "test", "--no-pub", "--machine"], cwd=root / package, env=env, capture=True)
        elapsed += duration
        suites, cases, done, errors = parse_machine(proc.stdout or "", package)
        all_records.extend(cases)
        if proc.returncode or not done or errors or any(c[3] != "pass" for c in cases):
            raise Stop(package + " stock tests failed")
        discovered = sorted(p.relative_to(root / package).as_posix()
                            for p in (root / package / "test").rglob("*_test.dart"))
        if suites != discovered:
            raise Stop(package + " stock suite discovery differs from source inventory")
    return all_records, elapsed


def host_salt(run_id, attempt, head, repetition):
    return f"host-test/{run_id}/{attempt}/{head}/{repetition}"


def remote_policy(rt, scenario, repetition, *, controls=False):
    mode = "read" if controls or scenario != "cold" else "seed"
    run_id, attempt, head = (need_env("GITHUB_RUN_ID"), need_env("GITHUB_RUN_ATTEMPT"), need_env("GITHUB_SHA"))
    if not run_id.isdigit() or not attempt.isdigit() or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise Stop("remote cache lineage needs numeric run/attempt and 40-hex GITHUB_SHA")
    salt = host_salt(run_id, attempt, head, repetition)
    rc = rt / "remote-cache.bazelrc"
    host, project, token = (need_env(k) for k in ("BAZEL_CACHE_HOST", "BAZEL_CACHE_PROJECT_ID", "BAZEL_CACHE_TOKEN_RW"))
    if "://" in host or "/" in host:
        raise Stop("BAZEL_CACHE_HOST must be a host without scheme or path")
    rc.write_text("\n".join("build " + shlex.quote(flag) for flag in (
        "--remote_cache=grpcs://" + host, "--remote_instance_name=" + project,
        "--remote_cache_header=Authorization=Bearer " + token)) + "\n")
    rc.chmod(0o600)
    scrub = rt / "remote-scrubbing.textproto"
    scrub.write_text('rules { matcher { kind: ".*" label: ".*" mnemonic: ".*" match_tools: true } transform { salt: "' + salt + '" } }\n')
    return mode, salt, rc, scrub


def bazel_argv(root, env, bazel, command_name, scenario, repetition, *opts, controls=False):
    rt = runner_temp()
    mode, salt, rc, scrub = remote_policy(rt, scenario, repetition, controls=controls)
    output_base = rt / "bazel-output"
    cache = rt / "cache-state"
    startup = [str(bazel), "--output_base=" + str(output_base), "--nosystem_rc", "--nohome_rc",
               "--bazelrc=" + str(rc)]
    build = ["--disk_cache=", "--remote_accept_cached=" + ("false" if mode == "seed" else "true"),
             "--remote_upload_local_results=" + ("true" if mode == "seed" else "false"),
             "--remote_cache_async=false", "--remote_download_outputs=all", "--announce_rc=false",
             "--experimental_remote_scrubbing_config=" + str(scrub),
             "--repository_cache=" + str(cache / "repository"), "--repo_env=FLUTTER_ROOT=" + env["FLUTTER_ROOT"]]
    return [*startup, command_name, *build, *opts], mode, salt


def parse_bep(path):
    text = path.read_text()
    dec = json.JSONDecoder()
    events, pos = [], 0
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
            continue
        item, pos = dec.raw_decode(text, pos)
        events.append(item)
    results, summaries = {}, {}
    for event in events:
        result = event.get("testResult")
        if result is not None:
            label = event.get("id", {}).get("testResult", {}).get("label")
            if not isinstance(label, str):
                raise Stop("Bazel test result has no label")
            results.setdefault(label, []).append(result)
        summary = event.get("testSummary")
        if summary is not None:
            label = event.get("id", {}).get("testSummary", {}).get("label")
            if not isinstance(label, str):
                raise Stop("Bazel test summary has no label")
            summaries.setdefault(label, []).append(summary)
    hits = sum(bool(r.get("executionInfo", {}).get("cachedRemotely"))
               for values in results.values() for r in values)
    return events, results, summaries, hits


def parse_execution_log(path):
    if not path.is_file():
        raise Stop("Bazel wrote no execution log")
    dec = json.JSONDecoder()
    text, pos, records = path.read_text(), 0, []
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
            continue
        item, pos = dec.raw_decode(text, pos)
        if item.get("mnemonic") in ("DartTestKernel", "TestKernelDriver"):
            records.append(item)
    return records

def prepare_bazel_inputs(root, env):
    rt = runner_temp()
    tool = rt / "flutter" / "packages" / "flutter_tools"
    dart = rt / "flutter" / "bin" / "cache" / "dart-sdk" / "bin" / "dart"
    locked = digest(tool / "pubspec.lock")
    if not locked:
        raise Stop("flutter_tools lockfile missing")
    result, _ = command([str(dart), "pub", "get", "--enforce-lockfile", "--suppress-analytics"], cwd=tool, env=env)
    if result.returncode or digest(tool / "pubspec.lock") != locked:
        raise Stop("flutter_tools dependency setup failed or changed lock")
    smooth = root / SMOOTH
    lock = digest(smooth / "pubspec.lock")
    aggregate = digest(smooth / "lib/l10n/app_localizations.dart")
    result, _ = command([str(rt / "flutter/bin/flutter"), "pub", "get", "--enforce-lockfile"], cwd=smooth, env=env)
    if result.returncode or digest(smooth / "pubspec.lock") != lock or digest(smooth / "lib/l10n/app_localizations.dart") != aggregate:
        raise Stop("smooth_app dependency setup failed or changed frozen input")
    if not (smooth / ".dart_tool/package_config.json").is_file():
        raise Stop("smooth_app pub get wrote no package config")

def run_controls(root, env, flutter, bazel, engine, scenario, repetition, lock_sha):
    if repetition != 1 or not ((engine == "stock" and scenario == "clean") or
                               (engine == "bazel" and scenario == "cold")):
        return {"status": "not-run", "cases": 0, "rejections": 0,
                "lock_mode": None, "lock_sha256": None, "results": []}
    controls = [
        ("corrupted-assertion", "      () => expect(demoText.removeCharacterAt(0), equals('entence')),\n",
         "      () => expect(demoText.removeCharacterAt(0), equals('corrupted')),\n",
         "removeCharacterAt tests Position 0"),
        ("identity-remove-spaces", "  String removeSpaces() => replaceAll(RegExp(r' |\\n|\\r|\\s|\\t'), '');\n",
         "  String removeSpaces() => this;\n",
         "removeEmptySpaces tests String with spaces at the beginning")]
    results = []
    for name, old, new, required in controls:
        path = root / (TEST_FILE if name == "corrupted-assertion" else LIB_FILE)
        original = path.read_bytes()
        before = sha(original)
        expected = ("102b926575c8980acdeea1393b737e8be84a115cb6cdcde9c2cbd328db171b62"
                    if name == "corrupted-assertion" else "35edd245bf824b5805d0453d0583d60c69b12a49a1468387217f5a902eb5bfd9")
        if before != expected or original.decode().count(old) != 1:
            raise Stop("control source anchor/hash mismatch: " + name)
        try:
            path.write_text(original.decode().replace(old, new, 1))
            if engine == "stock":
                proc, _ = command([str(flutter), "test", "--no-pub", "--machine", "test/utils/string_extensions_test.dart"],
                                  cwd=root / SMOOTH, env=env, capture=True)
                _, cases, _, _ = parse_machine(proc.stdout or "", SMOOTH)
                failures = [c[2] for c in cases if c[3] in ("fail", "error")]
            else:
                if not lock_sha or digest(root / "MODULE.bazel.lock") != lock_sha:
                    raise Stop("Bazel controls require the timed lock unchanged")
                raw, log = runner_temp() / "control-bep.json", runner_temp() / "control-execution.json"
                args, _, _ = bazel_argv(root, env, bazel, "test", "cold", repetition,
                    "--lockfile_mode=error", "--test_output=errors",
                    "--build_event_json_file=" + str(raw), "--execution_log_json_file=" + str(log),
                    "--noexecution_log_sort", "//packages/smooth_app:test/utils/string_extensions_test", controls=True)
                proc = subprocess.run(args, cwd=root, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                xml = root / "bazel-testlogs/packages/smooth_app/test/utils/string_extensions_test/test.xml"
                failures = []
                if xml.is_file():
                    tree = ET.parse(xml).getroot()
                    failures = [c.get("name") for c in tree.iter("testcase") if c.find("failure") is not None or c.find("error") is not None]
                raw.unlink(missing_ok=True)
                log.unlink(missing_ok=True)
            accepted = proc.returncode != 0 and any(required in item for item in failures)
            results.append({"name": name, "rejected": accepted, "case": required if accepted else None})
            if not accepted:
                raise Stop("negative control did not reject expected case: " + name)
        finally:
            path.write_bytes(original)
            if digest(path) != before:
                raise Stop("control source restoration failed: " + name)
    return {"status": "pass", "cases": 2, "rejections": 2,
            "lock_mode": "error" if engine == "bazel" else None,
            "lock_sha256": lock_sha if engine == "bazel" else None, "results": results}

def cleanup_private_logs():
    rt = runner_temp()
    for name in ("bep.json", "execution.json", "control-bep.json", "control-execution.json",
                 "remote-cache.bazelrc", "remote-scrubbing.textproto"):
        (rt / name).unlink(missing_ok=True)

def bazel_records(root, env, bazel, scenario, repetition):
    rt = runner_temp()
    raw, execution = rt / "bep.json", rt / "execution.json"
    for p in (raw, execution):
        p.unlink(missing_ok=True)
    profile = env.get("HOST_BAZEL_PROFILE")
    profile_flags = [
        "--profile=" + profile,
        "--record_full_profiler_data",
        "--experimental_profile_include_target_label",
        "--experimental_profile_include_primary_output",
    ] if profile else []
    args, mode, salt = bazel_argv(root, env, bazel, "test", scenario, repetition,
        "--lockfile_mode=update", "--keep_going", "--test_output=errors",
        "--build_event_json_file=" + str(raw), "--execution_log_json_file=" + str(execution),
        "--noexecution_log_sort", *profile_flags, *["//" + p + ":tests" for p in PACKAGES])
    start = time.monotonic()
    result = subprocess.run(args, cwd=root, env=env)
    elapsed = time.monotonic() - start
    lock_sha = digest(root / "MODULE.bazel.lock")
    if not lock_sha or not raw.is_file():
        raise Stop("Bazel wrote no lockfile or build event stream")
    events, results, summaries, hits = parse_bep(raw)
    expected_labels = {
        "//" + package + ":" + path.relative_to(root / package).with_suffix("").as_posix()
        for package in PACKAGES
        for path in (root / package / "test").rglob("*_test.dart")
    }
    if set(results) != expected_labels or set(summaries) != expected_labels:
        raise Stop("BEP test result/summary labels differ from the source test target inventory")
    for label in expected_labels:
        if len(results[label]) != 1 or results[label][0].get("status") != "PASSED":
            raise Stop(label + " must have exactly one PASSED TestResult")
        if len(summaries[label]) != 1 or summaries[label][0].get("overallStatus") != "PASSED":
            raise Stop(label + " must have exactly one PASSED TestSummary")
    if any(r.get("cachedLocally") for values in results.values() for r in values):
        raise Stop("test results must not come from a local output-base cache")
    spawns = parse_execution_log(execution)
    kernels = [x for x in spawns if x.get("mnemonic") == "DartTestKernel" and not x.get("cacheHit", False)]
    workers = [x for x in kernels if "worker" in str(x.get("runner", "")).lower()]
    misses = len(expected_labels) - hits
    if scenario == "warm" and (hits != len(expected_labels) or misses != 0 or kernels):
        raise Stop(f"warm cache gate failed: {hits} remote test hits, {misses} misses, {len(kernels)} kernel executions")
    if mode == "seed":
        if (hits or misses != len(expected_labels) or len(kernels) != misses or
                len(workers) != len(kernels) or any(r.get("cachedLocally") for rs in results.values() for r in rs)):
            raise Stop("cold seed must execute every test through the default worker without cache hits")
    edited_label = "//" + SMOOTH + ":test/utils/string_extensions_test"
    if scenario in ("test", "lib"):
        edited_results = results.get(edited_label, [])
        edited_kernels = [x for x in kernels if x.get("targetLabel") == edited_label + "_kernel"]
        if (len(edited_results) != 1 or edited_results[0].get("cachedLocally") or
                edited_results[0].get("executionInfo", {}).get("cachedRemotely") or
                not edited_kernels or any("worker" not in str(x.get("runner", "")).lower()
                                          for x in edited_kernels)):
            raise Stop("edited test target must be uncached and execute its test kernel with the default worker")
    records = []
    records, xml_labels = [], set()
    for package in PACKAGES:
        directory = root / "bazel-testlogs" / package
        xmls = sorted(directory.rglob("test.xml")) if directory.exists() else []
        for xml in xmls:
            rel_xml = xml.relative_to(directory).as_posix()
            if not rel_xml.startswith("test/") or not rel_xml.endswith("/test.xml"):
                raise Stop(f"unexpected JUnit path {rel_xml}")
            target = "//" + package + ":" + rel_xml[:-len("/test.xml")]
            xml_labels.add(target)
            expected_file = target.split(":", 1)[1] + ".dart"
            try:
                tree = ET.parse(xml).getroot()
            except ET.ParseError as error:
                raise Stop(f"invalid JUnit file {xml}: {error}")
            for case in tree.iter("testcase"):
                name = case.get("name")
                if name is None or package_relative(case.get("classname", ""), package) != expected_file:
                    raise Stop(f"malformed or mismatched JUnit testcase in {xml}")
                outcome = "fail" if case.find("failure") is not None else "error" if case.find("error") is not None else "skip" if case.find("skipped") is not None else "pass"
                records.append((package, expected_file, name, outcome))
    if xml_labels != expected_labels:
        raise Stop("JUnit file labels differ from the complete test target inventory")
    if result.returncode:
        raise Stop("Bazel test command failed")
    return records, elapsed, lock_sha, hits, misses, len(kernels), len(workers), result.returncode


def mutation(root, scenario):
    path = root / (TEST_FILE if scenario == "test" else LIB_FILE)
    original = path.read_bytes()
    before = sha(original)
    if scenario == "test":
        expected = "102b926575c8980acdeea1393b737e8be84a115cb6cdcde9c2cbd328db171b62"
        if before != expected:
            raise Stop("test edit source hash differs from fixture")
        text = original.decode()
        old = "    test(\n      'Multiple occurrence (without case)',"
        new = "    test(\n      '" + TEST_NEW + "',"
        if text.count(old) != 1:
            raise Stop("test edit anchor did not match exactly once")
        path.write_text(text.replace(old, new, 1))
    else:
        expected = "35edd245bf824b5805d0453d0583d60c69b12a49a1468387217f5a902eb5bfd9"
        if before != expected:
            raise Stop("library edit source hash differs from fixture")
        text = original.decode()
        old = "  String removeSpaces() => replaceAll(RegExp(r' |\\n|\\r|\\s|\\t'), '');\n"
        new = "  String removeSpaces() => replaceAll(_removeSpacesPattern, '');\n"
        decl = "extension StringExtension on String {"
        if text.count(old) != 1 or text.count(decl) != 1:
            raise Stop("library edit anchors did not match exactly once")
        text = text.replace(old, new, 1).replace(decl, "final RegExp _removeSpacesPattern = RegExp(r' |\\n|\\r|\\s|\\t');\n\n" + decl, 1)
        path.write_text(text)
    return path, original


def proof(record):
    line = "HOST_TEST_PROOF " + json.dumps(record, sort_keys=True, separators=(",", ":"))
    if len(line.encode()) > 32 * 1024:
        raise Stop("proof line exceeds 32 KiB")
    print(line, flush=True)


def main(argv):
    if argv not in (["prepare-stock"], ["run"]):
        raise Stop("usage: python3 ci/benchmark/host/run.py prepare-stock|run")
    root = app_root()
    engine = "stock" if argv == ["prepare-stock"] else need_env("ENGINE")
    env, flutter, bazel = environment(root, engine)
    rt = runner_temp()
    if argv == ["prepare-stock"]:
        seed_locks = stock_lock_snapshot(root)
        for package in PACKAGES:
            proc, _ = command([str(flutter), "pub", "get", "--enforce-lockfile"], cwd=root / package, env=env)
            if proc.returncode:
                raise Stop(package + " seed pub get failed")
        if stock_lock_snapshot(root) != seed_locks:
            raise Stop("stock seed pub get changed a frozen pubspec.lock")
        config = root / SMOOTH / ".dart_tool" / "package_config.json"
        seed = {"sdk_revision": INPUTS["flutter"]["revision"], "pub_cache_path": env["PUB_CACHE"],
                "pub_cache_entries": sum(1 for p in Path(env["PUB_CACHE"]).rglob("*")),
                "package_config_sha256": digest(config)}
        # Leave the cache contents as the seed but remove every app-generated output.
        for package in PACKAGES:
            import shutil
            shutil.rmtree(root / package / ".dart_tool", ignore_errors=True)
            shutil.rmtree(root / package / "build", ignore_errors=True)
        proof({"schema": 1, "kind": "prepare-stock", "engine": "stock", "scenario": "clean",
               "repetition": int(os.environ.get("REPETITION", "1")),
               "fixture": {"sha": FIXTURE_SHA}, "rules": {"sha": None},
               "lock": {"sha256": None, "mode": "not-applicable"},
               "lineage": {"run_id": os.environ.get("GITHUB_RUN_ID", "local"),
                           "attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
                           "workflow_sha": os.environ.get("GITHUB_SHA", "local"), "salt": None},
               "seed": seed})
        return 0

    engine, scenario = need_env("ENGINE"), need_env("SCENARIO")
    repetition = int(need_env("REPETITION"))
    if engine not in ("stock", "bazel") or scenario not in ("clean", "cold", "warm", "test", "lib") or not 1 <= repetition <= 5:
        raise Stop("invalid engine, scenario or repetition")
    rules_sha = None
    if engine == "stock":
        if scenario != "clean":
            raise Stop("stock engine supports only clean scenario")
        clean_outputs(root)
        start = time.monotonic()
        pub_seconds = stock_pub(root, env, flutter)
        records, command_seconds = stock_tests(root, env, flutter)
        lock_sha, hits, misses, kernels, workers = None, 0, 0, 0, 0
    else:
        rules_dir = root / ".ci-rules"
        rules_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=rules_dir, text=True).strip()
        wanted_rules = need_env("RULES_SHA")
        if rules_sha != wanted_rules:
            raise Stop(".ci-rules checkout does not match RULES_SHA")
        setup_start = time.monotonic()
        prepare_bazel_inputs(root, env)
        pub_seconds = time.monotonic() - setup_start
        restore = None
        if scenario in ("test", "lib"):
            path, restore = mutation(root, scenario)
        try:
            records, command_seconds, lock_sha, hits, misses, kernels, workers, _ = bazel_records(root, env, bazel, scenario, repetition)
        finally:
            if restore is not None:
                path.write_bytes(restore)
        if restore is not None and digest(path) != sha(restore):
            raise Stop("scenario source edit was not restored byte-for-byte")
    observed_hash = expected_hash(records)
    observed = len(records)
    allowed = INVENTORY["renamed_sha256"] if scenario == "test" else INVENTORY["sha256"]
    if observed != INVENTORY["count"] or observed_hash != allowed:
        raise Stop(f"case inventory mismatch: {observed} cases, digest {observed_hash}")
    validated_at = time.time()
    control_result = run_controls(root, env, flutter, bazel, engine, scenario, repetition, lock_sha)
    cleanup_private_logs()
    run_id, attempt, head = (os.environ.get("GITHUB_RUN_ID", "local"),
                             os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
                             os.environ.get("GITHUB_SHA", "local"))
    salt = host_salt(run_id, attempt, head, repetition) if engine == "bazel" else None
    seed_identity = {"run_id": run_id, "attempt": attempt, "workflow_sha": head,
                     "repetition": repetition, "salt": salt} if engine == "bazel" else None
    seed_sha = os.environ.get("HOST_DEPENDENCY_SEED_SHA256") if engine == "stock" else sha(
        json.dumps({"identity": seed_identity, "fixture_sha": FIXTURE_SHA,
                    "rules_sha": rules_sha, "lock_sha": lock_sha},
                   sort_keys=True, separators=(",", ":")).encode())
    proof({"schema": 1, "kind": "run", "engine": engine, "scenario": scenario, "repetition": repetition,
           "fixture": {"sha": FIXTURE_SHA}, "rules": {"sha": rules_sha},
           "lock": {"sha256": lock_sha, "mode": "update" if engine == "bazel" else "not-applicable"},
           "lineage": {"run_id": run_id, "attempt": attempt, "workflow_sha": head, "salt": salt},
           "cache": {"mode": ("seed" if scenario == "cold" else "read") if engine == "bazel" else "read",
                     "read_only": engine == "stock" or scenario != "cold",
                     "seed_sha256": seed_sha, "seed_kind": "stock-dependency" if engine == "stock" else "bazel-test",
                     "seed_identity": seed_identity, "test_result_hits": hits, "test_result_misses": misses},
           "driver": {"name": "flutter" if engine == "stock" else "default",
                      "worker_strategy": "default" if engine == "bazel" and misses else None,
                      "worker_spawns": workers, "kernel_executions": kernels},
           "cases": {"expected": INVENTORY["count"], "observed": observed,
                     "inventory_sha256": observed_hash},
           "timings": {"command_seconds": round(command_seconds, 3),
                       "validated_result_seconds": round(command_seconds, 3),
                       "stock_pub_seconds": round(pub_seconds, 3), "unit": "seconds"},
           "validated_at_epoch": validated_at,
           "controls": control_result})
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (Stop, OSError, subprocess.SubprocessError, ValueError) as error:
        print("HOST_TEST_ERROR " + str(error), file=sys.stderr, flush=True)
        if os.environ.get("RUNNER_TEMP"):
            cleanup_private_logs()
        sys.exit(1)
