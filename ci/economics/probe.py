#!/usr/bin/env python3
"""Compare stock Flutter and Bazel host-test results over the frozen eight-package workload.

`probe.py equivalence`, in order:
  1. the rules checkout and both toolchains match the manifest;
  2. per package, stock `flutter pub get --enforce-lockfile` and
     `flutter test --no-pub --machine`;
  3. Bazel bootstrap analysis (lock updates allowed), then `--lockfile_mode=error`
     analysis, then a discovery query per package, then `bazel test` on the suite labels.

Per-case records (file, name, outcome) are compared exactly, and discovery is compared
against the source inventory. Coverage is not requested on either arm: the host driver
writes JUnit reports only, so there is no LCOV to compare. The overall exit is 0 only
when every verdict passes and every phase exited 0.
"""

import collections
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "smooth-ci-evidence"
SAME_RUNNER_SAMPLES = ("01-all-1", "02-toplevel-1", "03-toplevel-2", "04-all-2")
if "SAME_RUNNER_SAMPLE" in os.environ:
    sample = os.environ["SAME_RUNNER_SAMPLE"]
    if sample not in SAME_RUNNER_SAMPLES:
        raise RuntimeError("invalid same-runner sample identity")
    OUT = OUT / "invocations" / sample
LOGS = OUT / "logs"
STOCK = OUT / "stock"
BAZEL = OUT / "bazel"
COMPARISON = OUT / "comparison"
MANIFEST = ROOT / "ci/economics/inputs.json"
PACKAGES = [
    "packages/app_store/apple_app_store",
    "packages/app_store/google_play",
    "packages/app_store/shared",
    "packages/app_store/uri_store",
    "packages/scanner/ml_kit",
    "packages/scanner/shared",
    "packages/scanner/zxing",
    "packages/smooth_app",
]
STARTUP = ["--nosystem_rc", "--nohome_rc"]
# Cache flags are build-command options; query and analysis-only commands do not accept them.
CACHE = ["--disk_cache=", "--remote_cache="]
LISTED = 50
OUTCOMES = {"success": "pass", "failure": "fail", "error": "error"}
COVERAGE = {
    "status": "not_requested",
    "stock": "flutter test without --coverage",
    "bazel": "bazel coverage not run",
    "reason": "the host driver writes JUnit reports only; no LCOV output or instrumented files",
}
PHASES = []


class Stop(Exception):
    """Drift, a missing identity or a failed execution: no comparison can be made."""


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def copy_artifact(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def run(name, command, cwd=ROOT, stdout_path=None):
    started = time.monotonic()
    LOGS.mkdir(parents=True, exist_ok=True)
    stdout_path = stdout_path or LOGS / (name + ".stdout")
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path = LOGS / (name + ".stderr")
    print(json.dumps({"phase": name, "command": command,
                      "cwd": cwd.relative_to(ROOT).as_posix() or "."}), flush=True)
    with stdout_path.open("w") as out, stderr_path.open("w") as err:
        code = subprocess.run(command, cwd=cwd, stdout=out, stderr=err).returncode
    phase = {"phase": name, "exit_code": code,
             "wall_seconds": round(time.monotonic() - started, 1), "command": command}
    PHASES.append(phase)
    print("PHASE_RESULT " + json.dumps(phase), flush=True)
    if code:
        print("\n".join(stderr_path.read_text().splitlines()[-40:]), flush=True)
    return phase


def read_stdout(name):
    return (LOGS / (name + ".stdout")).read_text()


def capture(name, command, cwd=ROOT):
    """Runs a command whose stdout is needed; a nonzero exit stops the probe."""
    phase = run(name, command, cwd)
    if phase["exit_code"]:
        raise Stop("%s exited %d" % (name, phase["exit_code"]))
    return read_stdout(name)


def bazel_command(command, *options, cache=True):
    if "FLUTTER_ROOT" not in os.environ:
        raise Stop("FLUTTER_ROOT is not set")
    cache_flags = CACHE if cache else []
    return ["bazel", *STARTUP, command, *cache_flags,
            "--repo_env=FLUTTER_ROOT=" + os.environ["FLUTTER_ROOT"], *options]


def suite_label(pkg):
    return "//%s:tests" % pkg


def load_manifest():
    manifest = json.loads(MANIFEST.read_text())
    if manifest.get("schema") != 1:
        raise Stop("manifest schema is not 1")
    if manifest["packages"] != PACKAGES:
        raise Stop("manifest package order differs from the probe's fixed order")
    expected = {"%s/%s" % (pkg, name) for pkg in PACKAGES
                for name in ("pubspec.yaml", "pubspec.lock")}
    if set(manifest["inputs"]) != expected:
        raise Stop("manifest inputs must list exactly the eight pubspec and lock paths")
    check_inputs(manifest, "manifest load")
    if (ROOT / ".bazelversion").read_text().strip() != manifest["bazel"]["version"]:
        raise Stop(".bazelversion differs from the manifest Bazel version")
    return manifest


def check_inputs(manifest, where):
    drift = [name for name, sha in manifest["inputs"].items() if digest(ROOT / name) != sha]
    if drift:
        raise Stop("%s: input drift or missing input: %s" % (where, drift))


def require_lock(locked, where):
    if digest(ROOT / "MODULE.bazel.lock") != locked:
        raise Stop("%s changed MODULE.bazel.lock" % where)


def inventory(pkg):
    """Stock discovery is test/**/*_test.dart; *_tests.dart is inventoried only."""
    tests = ROOT / pkg / "test"

    def find(pattern):
        return sorted(path.relative_to(ROOT / pkg).as_posix()
                      for path in tests.rglob(pattern) if path.is_file())

    return find("*_test.dart"), find("*_tests.dart")


def package_relative(text, pkg):
    """The path below the package, from a path that names the package.

    Retained runner logs hold absolute checkout paths, so the package is found
    by its marker rather than by the current checkout root.
    """
    marker = pkg + "/"
    if text.startswith(marker):
        return text[len(marker):]
    index = text.find("/" + marker)
    if index < 0:
        raise Stop("%r does not name %s" % (text, pkg))
    return text[index + 1 + len(marker):]


def suite_path(path, pkg):
    rel = path if path.startswith("test/") else package_relative(path, pkg)
    if not rel.startswith("test/"):
        raise Stop("%s: suite %s is outside test/" % (pkg, path))
    return rel


def machine_outcome(event, pkg):
    if event.get("skipped") or event.get("result") == "skipped":
        return "skip"
    outcome = OUTCOMES.get(event.get("result"))
    if outcome is None:
        raise Stop("%s: unknown machine result %r" % (pkg, event.get("result")))
    return outcome


def parse_machine(text, pkg):
    """Suites, per-case records and the final done flag from `flutter test --machine`.

    Hidden events are cases only when they fail, as the Bazel driver reports only
    hook and loading failures. Hidden passes and skips are not cases on either arm.
    Flutter daemon notification arrays are counted by event name and are never cases.
    """
    suites, tests, discovered, cases = {}, {}, set(), []
    errors, done_success = 0, None
    notifications, event_counts = collections.Counter(), collections.Counter()
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            raise Stop("%s: machine output line %d is not JSON" % (pkg, number))
        if isinstance(value, list):
            notifications.update(daemon_notifications(value, pkg, number))
            continue
        if not isinstance(value, dict) or not isinstance(value.get("type"), str):
            raise Stop("%s: machine line %d is neither a typed event nor a notification array" % (pkg, number))
        event = value
        kind = event["type"]
        event_counts[kind] += 1
        try:
            if kind == "suite":
                suite = suite_path(event["suite"]["path"], pkg)
                suites[event["suite"]["id"]] = suite
                discovered.add(suite)
            elif kind == "testStart":
                test = event["test"]
                tests[test["id"]] = (suites[test["suiteID"]], test["name"])
            elif kind == "testDone":
                file, name = tests[event["testID"]]
                outcome = machine_outcome(event, pkg)
                if event.get("hidden") and outcome in ("pass", "skip"):
                    continue
                cases.append({"file": file, "name": name, "outcome": outcome})
            elif kind == "error":
                errors += 1
            elif kind == "done":
                done_success = event["success"]
        except (KeyError, TypeError) as error:
            raise Stop("%s: machine line %d lacks %s" % (pkg, number, error))
    if not isinstance(done_success, bool):
        raise Stop("%s: machine output has no done event with a boolean success" % pkg)
    return {"suites": sorted(discovered), "cases": cases, "errors": errors,
            "done_success": done_success, "notifications": dict(notifications),
            "event_counts": dict(event_counts)}


def daemon_notifications(items, pkg, number):
    """Event names of a Flutter daemon notification array, e.g. [{"event": ..., "params": {...}}]."""
    names = []
    for item in items:
        if not isinstance(item, dict) or set(item) != {"event", "params"}:
            raise Stop("%s: machine line %d is a malformed notification" % (pkg, number))
        if not isinstance(item["event"], str) or not isinstance(item["params"], dict):
            raise Stop("%s: machine line %d has a notification with bad field types" % (pkg, number))
        names.append(item["event"])
    if not names:
        raise Stop("%s: machine line %d is an empty notification array" % (pkg, number))
    return names


def parse_junit(path, pkg, rel):
    """Per-case records from one host test's JUnit report, which names its own file."""
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as error:
        raise Stop("%s: %s" % (path, error))
    cases = []
    for case in root.iter("testcase"):
        file = package_relative(case.get("classname", ""), pkg)
        if file != rel:
            raise Stop("%s reports %s, not %s" % (path, file, rel))
        name = case.get("name")
        if name is None:
            raise Stop("%s: testcase without a name" % path)
        if case.find("failure") is not None:
            outcome = "fail"
        elif case.find("error") is not None:
            outcome = "error"
        elif case.find("skipped") is not None:
            outcome = "skip"
        else:
            outcome = "pass"
        cases.append({"file": rel, "name": name, "outcome": outcome})
    return cases


def case_counter(cases):
    return collections.Counter((c["file"], c["name"], c["outcome"]) for c in cases)


def case_entry(stock_cases, bazel_cases):
    left, right = case_counter(stock_cases), case_counter(bazel_cases)
    only_stock, only_bazel = left - right, right - left
    return {
        "verdict": "pass" if stock_cases and not only_stock and not only_bazel else "fail",
        "stock_count": len(stock_cases),
        "bazel_count": len(bazel_cases),
        "stock_only": sorted(only_stock.elements())[:LISTED],
        "bazel_only": sorted(only_bazel.elements())[:LISTED],
        "stock_only_count": sum(only_stock.values()),
        "bazel_only_count": sum(only_bazel.values()),
    }


def failing(cases):
    return sum(1 for c in cases if c["outcome"] in ("fail", "error"))


def discovery_entry(default, stock_suites, bazel_rels):
    expected = set(default)
    stock_set, bazel_set = set(stock_suites), set(bazel_rels)
    entry = {
        "stock_missing": sorted(expected - stock_set),
        "stock_extra": sorted(stock_set - expected),
        "bazel_missing": sorted(expected - bazel_set),
        "bazel_extra": sorted(bazel_set - expected),
    }
    entry["verdict"] = "pass" if expected and not any(entry.values()) else "fail"
    entry["inventory"] = len(default)
    return entry


def stock_summary(stock):
    return {"pub_exit": stock["pub_exit"], "test_exit": stock["test_exit"],
            "done_success": stock["done_success"], "errors": stock["errors"],
            "suites": len(stock["suites"]), "cases": len(stock["cases"]),
            "failing": failing(stock["cases"])}


def run_stock(manifest, index, pkg):
    directory = ROOT / pkg
    check_inputs(manifest, "before " + pkg)
    run("stock-pub-%02d" % index, ["flutter", "pub", "get", "--enforce-lockfile"], directory)
    pub = PHASES[-1]
    if pub["exit_code"]:
        raise Stop("%s: stock pub get exited %d" % (pkg, pub["exit_code"]))
    check_inputs(manifest, "after %s pub get" % pkg)
    test = run("stock-test-%02d" % index, ["flutter", "test", "--no-pub", "--machine"],
               directory, stdout_path=STOCK / pkg / "machine.jsonl")
    check_inputs(manifest, "after %s tests" % pkg)
    parsed = parse_machine((STOCK / pkg / "machine.jsonl").read_text(), pkg)
    return {"pub_exit": pub["exit_code"], "test_exit": test["exit_code"], **parsed}


def collect_bazel(pkg, rels):
    cases, missing, unparsed = [], [], []
    for rel in rels:
        stem = rel[:-len(".dart")]
        xml = ROOT / "bazel-testlogs" / pkg / stem / "test.xml"
        if not xml.is_file():
            missing.append(rel)
            continue
        copy_artifact(xml, BAZEL / pkg / (stem + ".test.xml"))
        try:
            cases += parse_junit(xml, pkg, rel)
        except Stop as error:
            unparsed.append({"file": rel, "error": str(error)})
    return {"cases": cases, "missing": missing, "unparsed": unparsed}


def run_bazel(manifest, report):
    """Returns ({package: sorted test files}, bazel test exit code)."""
    lock = ROOT / "MODULE.bazel.lock"
    suites = [suite_label(pkg) for pkg in PACKAGES]
    run("bazel-bootstrap", bazel_command(
        "build", "--nobuild", "--keep_going", "--lockfile_mode=update", *suites))
    if PHASES[-1]["exit_code"]:
        raise Stop("bazel bootstrap analysis exited %d" % PHASES[-1]["exit_code"])
    if not lock.is_file():
        raise Stop("bootstrap analysis wrote no MODULE.bazel.lock")
    copy_artifact(lock, BAZEL / "MODULE.bazel.lock")
    report["module_lock_sha256"] = digest(lock)
    locked = digest(lock)
    check_inputs(manifest, "after bootstrap")
    run("bazel-error-analysis", bazel_command(
        "build", "--nobuild", "--keep_going", "--lockfile_mode=error", *suites))
    if PHASES[-1]["exit_code"]:
        raise Stop("bazel --lockfile_mode=error analysis exited %d" % PHASES[-1]["exit_code"])
    require_lock(locked, "--lockfile_mode=error analysis")
    check_inputs(manifest, "after error analysis")
    rels = {}
    for index, pkg in enumerate(PACKAGES):
        found = capture("bazel-query-%02d" % index, bazel_command(
            "query", "--nofetch", "--output=label", "tests(%s)" % suite_label(pkg), cache=False))
        prefix = "//%s:" % pkg
        labels = found.split()
        if not labels:
            raise Stop("%s: discovery query returned no labels" % pkg)
        if any(not item.startswith(prefix) for item in labels):
            raise Stop("%s: discovery query returned output that is not labels of this package" % pkg)
        rels[pkg] = sorted(item[len(prefix):] + ".dart" for item in labels)
    require_lock(locked, "discovery queries")
    test = run("bazel-test", bazel_command(
        "test", "--lockfile_mode=error", "--nocache_test_results", "--keep_going",
        "--test_output=errors", *suites))
    require_lock(locked, "bazel test")
    check_inputs(manifest, "after bazel test")
    return rels, test["exit_code"]


def build_entries(inventories, stock, rels, bazel):
    entries, verdicts = [], collections.defaultdict(list)
    for pkg in PACKAGES:
        default, plural = inventories[pkg]
        discovery = discovery_entry(default, stock[pkg]["suites"], rels[pkg])
        found = bazel[pkg]
        cases = case_entry(stock[pkg]["cases"], found["cases"])
        if found["missing"] or found["unparsed"]:
            cases["verdict"] = "fail"
        cases["missing_test_xml"] = found["missing"][:LISTED]
        cases["unparsed"] = found["unparsed"][:LISTED]
        stock_ok = (stock[pkg]["test_exit"] == 0 and stock[pkg]["done_success"] is True
                    and stock[pkg]["errors"] == 0)
        outcomes = ("pass" if stock_ok and not failing(stock[pkg]["cases"])
                    and not failing(found["cases"]) else "fail")
        write_json(COMPARISON / (pkg.replace("/", "__") + ".json"),
                   {"stock": stock[pkg]["cases"], "bazel": found["cases"]})
        verdicts["discovery"].append(discovery["verdict"])
        verdicts["cases"].append(cases["verdict"])
        verdicts["outcomes"].append(outcomes)
        entries.append({
            "package": pkg,
            "inventory": {"default": len(default), "plural_suffix": plural},
            "discovery": discovery,
            "stock": stock_summary(stock[pkg]),
            "bazel": {"cases": len(found["cases"]), "failing": failing(found["cases"])},
            "cases": cases,
            "outcomes": outcomes,
        })
    return entries, verdicts


def aggregate(values):
    return "pass" if values and all(v == "pass" for v in values) else "fail"


def write_summary(report):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    lines = ["## Matched host-test correctness", "",
             "Correctness comparison only; no speed claim. Coverage not requested on either arm.", ""]
    lines += ["- %s: %s" % (name, verdict) for name, verdict in report.get("verdicts", {}).items()]
    lines += ["", "| package | discovery | cases | outcomes |", "|---|---|---|---|"]
    for entry in report.get("packages", []):
        lines.append("| `%s` | %s | %s | %s |" % (
            entry["package"], entry["discovery"]["verdict"], entry["cases"]["verdict"],
            entry["outcomes"]))
    if report.get("stopped"):
        lines += ["", "Stopped: " + report["stopped"]]
    with open(path, "a") as stream:
        stream.write("\n".join(lines) + "\n")


def execute(report):
    manifest = load_manifest()
    rules = capture("rules-revision", ["git", "-C", ".ci-rules", "rev-parse", "HEAD"]).strip()
    if rules != manifest["rules"]["revision"]:
        raise Stop("checked-out rules %s differ from the manifest" % rules)
    version = json.loads(capture("flutter-version", ["flutter", "--version", "--machine"]))
    if (version.get("frameworkRevision") != manifest["flutter"]["revision"]
            or version.get("frameworkVersion") != manifest["flutter"]["version"]):
        raise Stop("installed Flutter differs from the manifest")
    bazel_version = capture("bazel-version", ["bazel", "--version"])
    if "bazel " + manifest["bazel"]["version"] not in bazel_version:
        raise Stop("installed Bazel differs from the manifest")
    report["identities"] = {
        "rules": manifest["rules"], "app": manifest["app"],
        "flutter": {"version": version["frameworkVersion"],
                    "revision": version["frameworkRevision"],
                    "dart": version.get("dartSdkVersion")},
        "bazel": manifest["bazel"]["version"],
    }
    inventories, stock = {}, {}
    report["stock"] = {}
    for index, pkg in enumerate(PACKAGES):
        default, plural = inventory(pkg)
        if not default:
            raise Stop("%s has no test/**/*_test.dart files" % pkg)
        inventories[pkg] = (default, plural)
        stock[pkg] = run_stock(manifest, index, pkg)
        report["stock"][pkg] = stock_summary(stock[pkg])
    rels, bazel_test_exit = run_bazel(manifest, report)
    report["bazel_test_exit"] = bazel_test_exit
    bazel = {pkg: collect_bazel(pkg, rels[pkg]) for pkg in PACKAGES}
    entries, verdicts = build_entries(inventories, stock, rels, bazel)
    report["coverage"] = COVERAGE
    report["packages"] = entries
    report["verdicts"] = {
        "discovery": aggregate(verdicts["discovery"]),
        "cases": aggregate(verdicts["cases"]),
        "outcomes": aggregate(verdicts["outcomes"]),
        "bazel_test": "pass" if bazel_test_exit == 0 else "fail",
        "phases": "pass" if all(p["exit_code"] == 0 for p in PHASES) else "fail",
    }
    return 0 if all(v == "pass" for v in report["verdicts"].values()) else 1


def main(argv):
    if argv[1:] != ["equivalence"]:
        raise SystemExit("usage: probe.py equivalence")
    shutil.rmtree(OUT, ignore_errors=True)
    OUT.mkdir(parents=True)
    report = {"mode": "equivalence", "classification": "correctness_not_benchmark",
              "workflow_revision": os.environ.get("GITHUB_SHA"),
              "runner_image": os.environ.get("ImageVersion")}
    try:
        report["exit_code"] = execute(report)
    except Stop as stop:
        report["stopped"] = str(stop)
        report["exit_code"] = 1
        print("STOP " + str(stop), flush=True)
    finally:
        report["phases"] = PHASES
        write_json(OUT / "result.json", report)
        write_summary(report)
    print("EQUIVALENCE_RESULT " + json.dumps(report.get("verdicts", {})), flush=True)
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main(sys.argv))
