#!/usr/bin/env python3
"""Timed host-test runs over the frozen eight-package workload, with frozen-case oracles.

  timing.py run --engine flutter|bazel --scenario cold|warm|test|lib --rep 1|2|3
      Times one matched run, gates every required result against expected-cases.json
      and writes result.json under the evidence directory, even on failure.
  timing.py controls --engine flutter|bazel --rep 1
      Runs after the cold repetition 1 snapshot is saved. Corrupts an existing assertion
      in the string test, then makes removeSpaces return its input, one source at a time.
      Each actual test invocation must exit nonzero and report a parsed case failure.

Parsers and input guards come from probe.py, which is unchanged.
"""

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe  # noqa: E402

ENGINES = ("flutter", "bazel")
SCENARIOS = ("cold", "warm", "test", "lib")
REPS = (1, 2, 3)
ROOT = probe.ROOT
OUT = probe.OUT
LOGS = OUT / "logs"
EXPECTED = ROOT / "ci/economics/expected-cases.json"
PACKAGES = probe.PACKAGES
SMOOTH = "packages/smooth_app"
TEST_REL = "test/utils/string_extensions_test.dart"
TEST_STEM = TEST_REL[: -len(".dart")]
TEST_FILE = SMOOTH + "/" + TEST_REL
LIB_FILE = SMOOTH + "/lib/helpers/string_extension.dart"
TARGET = "//packages/smooth_app:" + TEST_STEM
TEST_OLD_NAME = "indexesOf tests Multiple occurrence (without case)"
TEST_NEW_NAME = "indexesOf tests Multiple occurrences (lowercase query, ignoring case)"
CORRUPT_NAME = "removeCharacterAt tests Position 0"
REMOVE_NAME = "removeEmptySpaces tests String with spaces at the beginning"
LISTED = 50
SOURCE_FILES = (TEST_FILE, LIB_FILE, "MODULE.bazel", "MODULE.bazel.lock", ".bazelversion",
                "ci/economics/inputs.json", "ci/economics/expected-cases.json",
                "ci/economics/timing.py", "ci/economics/probe.py")

# Source edits are predeclared: each anchor must match exactly once and the result must
# hash to the recorded new digest. The mutated file is restored byte-for-byte afterwards.
TEST_RENAME_OLD = """    test(
      'Multiple occurrence (without case)',
      () => expect(
        demoText.indexesOf('e', ignoreCase: true),
        equals(<int>[1, 4, 7]),
      ),
    );
"""
TEST_RENAME_NEW = """    test('Multiple occurrences (lowercase query, ignoring case)', () {
      expect(
        demoText.indexesOf('e', ignoreCase: true),
        equals(<int>[1, 4, 7]),
      );
      expect(
        'sEnTeNcE'.indexesOf('E', ignoreCase: true),
        equals(<int>[1, 4, 7]),
      );
    });
"""
LIB_DECL_OLD = "extension StringExtension on String {"
LIB_DECL_NEW = ("final RegExp _removeSpacesPattern = RegExp(r' |\\n|\\r|\\s|\\t');\n"
                "\n"
                "extension StringExtension on String {")
LIB_REMOVE_OLD = "  String removeSpaces() => replaceAll(RegExp(r' |\\n|\\r|\\s|\\t'), '');\n"
LIB_REMOVE_NEW = "  String removeSpaces() => replaceAll(_removeSpacesPattern, '');\n"
LIB_INPUT_NEW = "  String removeSpaces() => this;\n"
CORRUPT_OLD = "      () => expect(demoText.removeCharacterAt(0), equals('entence')),\n"
CORRUPT_NEW = "      () => expect(demoText.removeCharacterAt(0), equals('corrupted')),\n"
TEST_SHA = "102b926575c8980acdeea1393b737e8be84a115cb6cdcde9c2cbd328db171b62"
LIB_SHA = "35edd245bf824b5805d0453d0583d60c69b12a49a1468387217f5a902eb5bfd9"

MUTATIONS = {
    "test-edit": {"path": TEST_FILE, "old_sha": TEST_SHA,
                  "new_sha": "725b965fe9927eac11e454c96374ba543d44abdb63d93ce927f7cec811b82f3d",
                  "edits": [(TEST_RENAME_OLD, TEST_RENAME_NEW)]},
    "library-edit": {"path": LIB_FILE, "old_sha": LIB_SHA,
                     "new_sha": "5e0160f09b1bed2fab4dfa38d5e481f350e3f3024b49836e49ecbb6402825b61",
                     "edits": [(LIB_REMOVE_OLD, LIB_REMOVE_NEW), (LIB_DECL_OLD, LIB_DECL_NEW)]},
}
MUTATION_FOR_SCENARIO = {"test": "test-edit", "lib": "library-edit"}
CONTROLS = {
    "corrupted-assertion": {"path": TEST_FILE, "old_sha": TEST_SHA,
                            "new_sha": "ef554ac705059876bf4262248f7dd08921c17e8ec95a10b9b6a871c9b680e872",
                            "edits": [(CORRUPT_OLD, CORRUPT_NEW)]},
    "identity-remove-spaces": {"path": LIB_FILE, "old_sha": LIB_SHA,
                               "new_sha": "bd82df069e15eeeff5fafe17b8b2799e6a1477af9e46aa4d0b0862f186d24a8b",
                               "edits": [(LIB_REMOVE_OLD, LIB_INPUT_NEW)]},
}


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def apply_edits(text, edits, where):
    for old, new in edits:
        count = text.count(old)
        if count != 1:
            raise probe.Stop("%s: edit anchor found %d times" % (where, count))
        text = text.replace(old, new)
    return text


@contextlib.contextmanager
def mutated(spec, label):
    """Applies a predeclared source edit, yields its record, and restores the original bytes."""
    path = ROOT / spec["path"]
    original = path.read_bytes()
    if sha_bytes(original) != spec["old_sha"]:
        raise probe.Stop("%s: %s differs from its predeclared source hash" % (label, spec["path"]))
    changed = apply_edits(original.decode("utf-8"), spec["edits"], label).encode("utf-8")
    if sha_bytes(changed) != spec["new_sha"]:
        raise probe.Stop("%s: edited %s differs from its predeclared hash" % (label, spec["path"]))
    applied = {"name": label, "path": spec["path"], "old_sha256": spec["old_sha"],
               "new_sha256": spec["new_sha"]}
    path.write_bytes(changed)
    try:
        yield applied
    finally:
        path.write_bytes(original)
        applied["restored_sha256"] = probe.digest(path)
        if applied["restored_sha256"] != spec["old_sha"]:
            raise probe.Stop("%s: restoring %s did not reproduce its original hash" % (label, spec["path"]))


class Recorder:
    """Phase spans and commands with epoch and monotonic offsets from this process start."""

    def __init__(self):
        self.origin = time.monotonic()
        self.phases = []

    def _open(self, name, kind, **extra):
        record = {"name": name, "kind": kind, "start_epoch": time.time(),
                  "start_offset_seconds": round(time.monotonic() - self.origin, 3), **extra}
        self.phases.append(record)
        return record

    def _close(self, record, **extra):
        record["end_epoch"] = time.time()
        record["end_offset_seconds"] = round(time.monotonic() - self.origin, 3)
        record["seconds"] = round(record["end_offset_seconds"] - record["start_offset_seconds"], 3)
        record.update(extra)

    @contextlib.contextmanager
    def span(self, name):
        record = self._open(name, "span")
        try:
            yield record
        finally:
            self._close(record)

    def command(self, name, argv, cwd, env, stdout_path=None):
        stdout_path = stdout_path or LOGS / (name + ".stdout")
        stderr_path = LOGS / (name + ".stderr")
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        record = self._open(name, "command", argv=[str(part) for part in argv],
                            cwd=cwd.relative_to(ROOT).as_posix() if cwd.is_relative_to(ROOT) else str(cwd))
        with stdout_path.open("w") as out, stderr_path.open("w") as err:
            code = subprocess.run(argv, cwd=cwd, env=env, stdout=out, stderr=err).returncode
        self._close(record, exit_code=code, stdout=stdout_path.relative_to(OUT).as_posix())
        print("PHASE_RESULT " + json.dumps({"phase": name, "exit_code": code}), flush=True)
        if code:
            print("\n".join(stderr_path.read_text().splitlines()[-40:]), flush=True)
        return record


def runner_paths():
    temp = os.environ.get("RUNNER_TEMP")
    if not temp:
        raise probe.Stop("RUNNER_TEMP is not set")
    return Path(temp)


def job_env(engine, rt):
    required = {"FLUTTER_ROOT": rt / "flutter", "PUB_CACHE": rt / "cache-state" / "pub"}
    if engine == "bazel":
        required["BAZELISK_HOME"] = rt / "cache-state" / "bazelisk"
    for key, path in required.items():
        if os.environ.get(key) != str(path):
            raise probe.Stop("%s must be %s" % (key, path))
    env = dict(os.environ)
    env["FLUTTER_SUPPRESS_ANALYTICS"] = "true"
    return env


def bazel_argv(rt, command, *options):
    cache = rt / "cache-state"
    return [str(rt / "bazel"), "--output_base=" + str(rt / "bazel-output"),
            "--nosystem_rc", "--nohome_rc", command,
            "--disk_cache=" + str(cache / "disk"), "--repository_cache=" + str(cache / "repository"),
            "--remote_cache=", "--repo_env=FLUTTER_ROOT=" + str(rt / "flutter"), *options]


def ensure_tool_package_config(rt, env, recorder, name="flutter-tools-pub-get"):
    """Resolve the SDK tool's locked packages; include this setup in measured job cost."""
    tool = rt / "flutter" / "packages" / "flutter_tools"
    dart = rt / "flutter" / "bin" / "cache" / "dart-sdk" / "bin" / "dart"
    if not dart.is_file():
        raise probe.Stop("SDK dart is missing at %s" % dart)
    locked = probe.digest(tool / "pubspec.lock")
    if locked is None:
        raise probe.Stop("SDK flutter_tools pubspec.lock is missing")
    with recorder.span("tool_dependency_resolution"):
        phase = recorder.command(name, [str(dart), "pub", "get", "--enforce-lockfile",
                                        "--suppress-analytics"], tool, env)
    if phase["exit_code"]:
        raise probe.Stop("flutter_tools pub get exited %d" % phase["exit_code"])
    if probe.digest(tool / "pubspec.lock") != locked:
        raise probe.Stop("flutter_tools pub get changed its SDK lock")
    if not (tool / ".dart_tool" / "package_config.json").is_file():
        raise probe.Stop("flutter_tools pub get wrote no package_config.json")


def capture(argv, env, what):
    result = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True)
    if result.returncode:
        raise probe.Stop("%s exited %d" % (what, result.returncode))
    return result.stdout


def identities(engine, manifest, env, rt):
    if engine == "flutter":
        version = json.loads(capture([str(rt / "flutter" / "bin" / "flutter"), "--version", "--machine"],
                                     env, "flutter --version"))
        if (version.get("frameworkRevision") != manifest["flutter"]["revision"]
                or version.get("frameworkVersion") != manifest["flutter"]["version"]):
            raise probe.Stop("installed Flutter differs from the manifest")
        return {"flutter": {"version": version["frameworkVersion"],
                            "revision": version["frameworkRevision"],
                            "dart": version.get("dartSdkVersion")}}
    rules = capture(["git", "-C", ".ci-rules", "rev-parse", "HEAD"], env, "rules revision").strip()
    if rules != manifest["rules"]["revision"]:
        raise probe.Stop("checked-out rules %s differ from the manifest" % rules)
    bazel_text = capture([str(rt / "bazel"), "--version"], env, "bazel --version")
    if "bazel " + manifest["bazel"]["version"] not in bazel_text:
        raise probe.Stop("installed Bazel differs from the manifest")
    return {"rules": rules, "bazel": manifest["bazel"]["version"],
            "bazel_version_output": bazel_text.strip()}


def source_hashes(manifest):
    names = sorted(set(SOURCE_FILES) | set(manifest["inputs"]))
    return {name: probe.digest(ROOT / name) for name in names}


def load_expected():
    data = json.loads(EXPECTED.read_text())
    if data.get("schema") != 1:
        raise probe.Stop("expected-cases.json schema is not 1")
    if list(data["packages"]) != PACKAGES:
        raise probe.Stop("expected-cases.json packages differ from the probe's fixed order")
    total = sum(len(entry["cases"]) for entry in data["packages"].values())
    if total != data.get("total_cases") or total != 246:
        raise probe.Stop("expected cases total %d, not 246" % total)
    return data


def scenario_cases(data, scenario):
    """Frozen per-package cases for a scenario. The test edit renames exactly one identity."""
    cases = {pkg: [dict(c) for c in entry["cases"]] for pkg, entry in data["packages"].items()}
    if scenario == "test":
        hits = [c for c in cases[SMOOTH] if c["file"] == TEST_REL and c["name"] == TEST_OLD_NAME]
        if len(hits) != 1 or any(c["name"] == TEST_NEW_NAME for c in cases[SMOOTH]):
            raise probe.Stop("expected cases do not hold exactly one renamable identity")
        hits[0]["name"] = TEST_NEW_NAME
    return cases


def flutter_job(rt, env, recorder, manifest, data, expected):
    flutter = str(rt / "flutter" / "bin" / "flutter")
    exits, parsed = {}, {}
    with recorder.span("dependency_resolution"):
        for index, pkg in enumerate(PACKAGES):
            probe.check_inputs(manifest, "before %s pub get" % pkg)
            pub = recorder.command("stock-pub-%02d" % index,
                                   [flutter, "pub", "get", "--enforce-lockfile"], ROOT / pkg, env)
            if pub["exit_code"]:
                raise probe.Stop("%s: stock pub get exited %d" % (pkg, pub["exit_code"]))
            probe.check_inputs(manifest, "after %s pub get" % pkg)
    with recorder.span("tests"):
        for index, pkg in enumerate(PACKAGES):
            probe.check_inputs(manifest, "before %s tests" % pkg)
            machine = OUT / "stock" / pkg / "machine.jsonl"
            test = recorder.command("stock-test-%02d" % index,
                                    [flutter, "test", "--no-pub", "--machine"], ROOT / pkg, env, machine)
            probe.check_inputs(manifest, "after %s tests" % pkg)
            exits[pkg] = test["exit_code"]
            parsed[pkg] = probe.parse_machine(machine.read_text(), pkg)
    packages = {}
    for pkg in PACKAGES:
        default, _plural = probe.inventory(pkg)
        run = parsed[pkg]
        cases = probe.case_entry(expected[pkg], run["cases"])
        ok = (sorted(default) == sorted(data["packages"][pkg]["suites"]) == run["suites"]
              and exits[pkg] == 0 and run["done_success"] is True and run["errors"] == 0
              and not probe.failing(run["cases"]) and cases["verdict"] == "pass")
        packages[pkg] = {"inventory": len(default), "suites": len(run["suites"]),
                         "exit_code": exits[pkg], "done_success": run["done_success"],
                         "errors": run["errors"], "cases": cases,
                         "verdict": "pass" if ok else "fail"}
    return {"packages": packages, "verdict": probe.aggregate([p["verdict"] for p in packages.values()])}


def parse_events(text):
    decoder, index, events = json.JSONDecoder(), 0, []
    while True:
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            return events
        try:
            value, index = decoder.raw_decode(text, index)
        except json.JSONDecodeError as error:
            raise probe.Stop("build event stream is not JSON at %d: %s" % (index, error))
        events.append(value)


def bep_gate(scenario, events, labels):
    """Correctness gate over per-label TestResult/TestSummary (Bazel 9.2.0 build_event_stream.proto).

    Cache hits are measurements. Bazel reports any spawn cache hit (disk or remote tier) as
    executionInfo.cachedRemotely=true (analysis/test/StandaloneTestStrategy: isCacheHit -> cachedRemotely;
    remote/CombinedCache: disk tier returns a cache hit). Top-level cachedLocally is set only when Bazel
    reuses its own output-base test result. Only the string target must execute in test/lib runs.
    """
    results, summaries = {}, {}
    for event in events:
        if "testResult" in event:
            results.setdefault(event["id"]["testResult"]["label"], []).append(event["testResult"])
        elif "testSummary" in event:
            summaries.setdefault(event["id"]["testSummary"]["label"], []).append(event["testSummary"])
    problems = []
    unknown = sorted(set(results) - labels)
    if unknown:
        problems.append("results for labels outside the workload: %s" % unknown[:LISTED])
    per_label = {}
    for label in sorted(labels):
        found = results.get(label, [])
        if len(found) != 1:
            problems.append("%s: %d test results, expected 1" % (label, len(found)))
            continue
        result = found[0]
        summary = summaries.get(label, [])
        if result.get("status") != "PASSED":
            problems.append("%s: status %s" % (label, result.get("status")))
        if len(summary) != 1 or summary[0].get("overallStatus") != "PASSED":
            problems.append("%s: test summary missing or not PASSED" % label)
        per_label[label] = {"status": result.get("status"),
                            "cachedLocally": result.get("cachedLocally") is True,
                            "cachedRemotely": (result.get("executionInfo") or {}).get("cachedRemotely") is True,
                            "totalNumCached": summary[0].get("totalNumCached", 0) if len(summary) == 1 else None}
    target = per_label.get(TARGET)
    if scenario in ("test", "lib") and (target is None or target["cachedLocally"] or target["cachedRemotely"]):
        problems.append("string target must execute, not be served from a cache")
    hits = sorted(label for label, entry in per_label.items() if entry["cachedLocally"] or entry["cachedRemotely"])
    return {"labels": len(labels), "cache_hits": len(hits), "cache_hit_labels": hits[:LISTED],
            "string_target": {"label": TARGET, **(target or {})},
            "per_label": per_label, "problems": problems, "verdict": "fail" if problems else "pass"}


def bazel_job(rt, env, recorder, manifest, data, scenario, expected, defaults):
    if not (rt / "bazel").is_file():
        raise probe.Stop("Bazelisk is not installed at %s" % (rt / "bazel"))
    frozen = data["bazel_module_lock_sha256"]
    lock = ROOT / "MODULE.bazel.lock"
    if scenario != "cold" and probe.digest(lock) != frozen:
        raise probe.Stop("module lock is absent or differs from the frozen digest before a %s run" % scenario)
    labels = {"//%s:%s" % (pkg, rel[: -len(".dart")]) for pkg in PACKAGES for rel in defaults[pkg]}
    raw = rt / "bep-raw.json"
    if raw.exists():
        raw.unlink()
    mode = "update" if scenario == "cold" else "error"
    ensure_tool_package_config(rt, env, recorder)
    probe.check_inputs(manifest, "before bazel test")
    with recorder.span("tests"):
        test = recorder.command("bazel-test", bazel_argv(
            rt, "test", "--lockfile_mode=" + mode, "--keep_going", "--test_output=errors",
            "--build_event_json_file=" + str(raw), *["//%s:tests" % pkg for pkg in PACKAGES]), ROOT, env)
    probe.check_inputs(manifest, "after bazel test")
    if lock.is_file():
        probe.copy_artifact(lock, OUT / "bazel" / "MODULE.bazel.lock")
    lock_ok = probe.digest(lock) == frozen
    if not raw.is_file():
        raise probe.Stop("bazel test wrote no build event stream")
    events = parse_events(raw.read_text())
    filtered = [e for e in events if "testResult" in e or "testSummary" in e]
    (OUT / "bazel").mkdir(parents=True, exist_ok=True)
    (OUT / "bazel" / "bep-filtered.jsonl").write_text(
        "".join(json.dumps(e, sort_keys=True) + "\n" for e in filtered))
    bep = bep_gate(scenario, events, labels)
    packages = {}
    for pkg in PACKAGES:
        found = probe.collect_bazel(pkg, defaults[pkg])
        testlogs = ROOT / "bazel-testlogs" / pkg
        present = ({p.relative_to(testlogs).as_posix() for p in testlogs.rglob("test.xml")}
                   if testlogs.is_dir() else set())
        wanted = {rel[: -len(".dart")] + "/test.xml" for rel in defaults[pkg]}
        cases = probe.case_entry(expected[pkg], found["cases"])
        ok = (cases["verdict"] == "pass" and not found["missing"] and not found["unparsed"]
              and present == wanted and sorted(data["packages"][pkg]["suites"]) == sorted(defaults[pkg]))
        packages[pkg] = {"inventory": len(defaults[pkg]), "xml_files": len(present),
                         "missing_test_xml": found["missing"], "unparsed": found["unparsed"],
                         "cases": cases, "verdict": "pass" if ok else "fail"}
    verdict = probe.aggregate(
        [p["verdict"] for p in packages.values()] + [bep["verdict"], "pass" if test["exit_code"] == 0 else "fail",
                                                     "pass" if lock_ok else "fail"])
    return {"exit_code": test["exit_code"], "module_lock": {"frozen_sha256": frozen,
            "before_sha256": None if scenario == "cold" else frozen,
            "after_sha256": probe.digest(lock), "copied": "bazel/MODULE.bazel.lock",
            "verdict": "pass" if lock_ok else "fail"},
            "bep": bep, "packages": packages, "verdict": verdict}


def run_timed(engine, scenario, rep):
    rt = runner_paths()
    OUT.mkdir(parents=True, exist_ok=True)
    recorder = Recorder()
    report = {"mode": "timed", "classification": "host_timing_no_coverage", "engine": engine,
              "scenario": scenario, "rep": rep, "workflow_revision": os.environ.get("GITHUB_SHA"),
              "runner_image": os.environ.get("ImageVersion"), "mutation": None,
              "required_result": None, "verdict": "fail", "exit_code": 1, "stopped": None}
    try:
        env = job_env(engine, rt)
        manifest = probe.load_manifest()
        data = load_expected()
        defaults = {pkg: probe.inventory(pkg)[0] for pkg in PACKAGES}
        for pkg in PACKAGES:
            if not defaults[pkg] or sorted(defaults[pkg]) != sorted(data["packages"][pkg]["suites"]):
                raise probe.Stop("%s: source test inventory differs from expected-cases.json" % pkg)
        report["identities"] = identities(engine, manifest, env, rt)
        report["sources_sha256_before"] = source_hashes(manifest)
        expected = scenario_cases(data, scenario)
        name = MUTATION_FOR_SCENARIO.get(scenario)
        report["mutation_scope"] = "predeclared source edit applied before the timed command"
        with contextlib.ExitStack() as stack:
            if name:
                report["mutation"] = stack.enter_context(mutated(MUTATIONS[name], name))
            if engine == "flutter":
                gate = flutter_job(rt, env, recorder, manifest, data, expected)
            else:
                gate = bazel_job(rt, env, recorder, manifest, data, scenario, expected, defaults)
        after = source_hashes(manifest)
        sources_restored = all(after[p] == report["sources_sha256_before"][p] for p in (TEST_FILE, LIB_FILE))
        report["sources_restored"] = sources_restored
        report["sources_sha256_after"] = after
        report["gate"] = gate
        passed = (gate["verdict"] == "pass" and sources_restored
                  and (name is None or report["mutation"]["restored_sha256"] == MUTATIONS[name]["old_sha"]))
        report["verdict"] = "pass" if passed else "fail"
        report["exit_code"] = 0 if passed else 1
        report["required_result"] = {"epoch": time.time(),
                                     "offset_seconds": round(time.monotonic() - recorder.origin, 3),
                                     "verdict": report["verdict"]}
    except probe.Stop as stop:
        report["stopped"] = str(stop)
        print("STOP " + str(stop), flush=True)
    finally:
        report["phases"] = recorder.phases
        probe.write_json(OUT / "result.json", report)
    print("TIMING_RESULT " + json.dumps({"verdict": report["verdict"], "engine": engine,
                                         "scenario": scenario, "rep": rep}), flush=True)
    return report["exit_code"]


def control_verdict(exit_code, cases, names, required):
    failing = sorted({c["name"] for c in cases if c["outcome"] in ("fail", "error")})
    ok = exit_code != 0 and required in failing and all(n in names for n in failing)
    return {"exit_code": exit_code, "failing": failing, "required": required,
            "verdict": "pass" if ok else "fail"}


def run_controls(engine, rep):
    if rep != 1:
        raise probe.Stop("controls run only for cold repetition 1")
    rt = runner_paths()
    env = job_env(engine, rt)
    data = load_expected()
    try:
        result = json.loads((OUT / "result.json").read_text())
    except OSError as error:
        raise probe.Stop("no timed result to control against: %s" % error)
    if (result.get("engine"), result.get("scenario"), result.get("rep"), result.get("verdict")) != (
            engine, "cold", 1, "pass"):
        raise probe.Stop("controls require a passing cold repetition 1 run of the same engine")
    manifest = probe.load_manifest()
    cases = scenario_cases(data, "cold")
    names = {c["name"] for c in cases[SMOOTH] if c["file"] == TEST_REL}
    recorder = Recorder()
    report = {"mode": "controls", "engine": engine, "rep": 1, "controls": [], "verdict": "fail",
              "exit_code": 1, "stopped": None}
    try:
        for control, spec in CONTROLS.items():
            required = CORRUPT_NAME if control == "corrupted-assertion" else REMOVE_NAME
            with mutated(spec, control) as applied:
                if engine == "flutter":
                    flutter = str(rt / "flutter" / "bin" / "flutter")
                    out = OUT / "controls" / (control + ".machine.jsonl")
                    phase = recorder.command("control-" + control,
                                             [flutter, "test", "--no-pub", "--machine", TEST_REL],
                                             ROOT / SMOOTH, env, out)
                    parsed = probe.parse_machine(out.read_text(), SMOOTH)
                    outcome = control_verdict(phase["exit_code"], parsed["cases"], names, required)
                else:
                    if probe.digest(ROOT / "MODULE.bazel.lock") != data["bazel_module_lock_sha256"]:
                        raise probe.Stop("controls require the frozen module lock")
                    ensure_tool_package_config(rt, env, recorder, "control-tools-pub-get-" + control)
                    phase = recorder.command("control-" + control, bazel_argv(
                        rt, "test", "--lockfile_mode=error",
                        "--test_output=errors", TARGET), ROOT, env)
                    xml = ROOT / "bazel-testlogs" / SMOOTH / TEST_STEM / "test.xml"
                    if xml.is_file():
                        probe.copy_artifact(xml, OUT / "controls" / (control + ".test.xml"))
                        outcome = control_verdict(phase["exit_code"],
                                                  probe.parse_junit(xml, SMOOTH, TEST_REL), names, required)
                    else:
                        outcome = {"exit_code": phase["exit_code"], "failing": [], "required": required,
                                   "verdict": "fail", "reason": "no test.xml from the actual invocation"}
            outcome["control"] = control
            outcome["applied"] = applied
            report["controls"].append(outcome)
        verdict = probe.aggregate([c["verdict"] for c in report["controls"]])
        report["verdict"] = verdict
        report["exit_code"] = 0 if verdict == "pass" else 1
    except probe.Stop as stop:
        report["stopped"] = str(stop)
        print("STOP " + str(stop), flush=True)
    finally:
        report["phases"] = recorder.phases
        probe.write_json(OUT / "controls.json", report)
    print("CONTROLS_RESULT " + json.dumps({"verdict": report["verdict"], "engine": engine}), flush=True)
    return report["exit_code"]


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--engine", choices=ENGINES, required=True)
    run.add_argument("--scenario", choices=SCENARIOS, required=True)
    run.add_argument("--rep", type=int, choices=REPS, required=True)
    control = commands.add_parser("controls")
    control.add_argument("--engine", choices=ENGINES, required=True)
    control.add_argument("--rep", type=int, choices=REPS, required=True)
    args = parser.parse_args(argv[1:])
    if args.command == "run":
        return run_timed(args.engine, args.scenario, args.rep)
    return run_controls(args.engine, args.rep)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
