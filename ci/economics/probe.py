#!/usr/bin/env python3
"""Record dependency feasibility and the unchanged upstream host-test workload."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "smooth-ci-evidence"
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


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(name, command, cwd):
    started = time.monotonic()
    print(json.dumps({"phase": name, "command": command, "cwd": str(cwd.relative_to(ROOT))}), flush=True)
    with (OUT / (name + ".log")).open("w") as log:
        process = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            log.write(line)
            print(line, end="", flush=True)
        code = process.wait()
    result = {"phase": name, "exit_code": code,
              "wall_seconds": time.monotonic() - started, "command": command}
    print("PHASE_RESULT " + json.dumps(result), flush=True)
    return result


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("flutter", "bazel"):
        raise SystemExit("usage: probe.py flutter|bazel")
    engine = sys.argv[1]
    OUT.mkdir(parents=True, exist_ok=True)
    inputs = {}
    inventory = {}
    for package in PACKAGES:
        directory = ROOT / package
        for name in ("pubspec.yaml", "pubspec.lock"):
            path = directory / name
            inputs[str(path.relative_to(ROOT))] = (
                digest(path) if name == "pubspec.yaml" or path.exists() else None)
        test_root = directory / "test"
        inventory[package] = {
            "upstream_default": sorted(str(p.relative_to(directory))
                                       for p in test_root.rglob("*_test.dart")),
            "additional_plural_suffix": sorted(str(p.relative_to(directory))
                                               for p in test_root.rglob("*_tests.dart")),
        }
    report = {"engine": engine, "classification": "feasibility_not_benchmark",
              "app_revision": "a286f0a932e28f4b15a3b03e6dc9eff9c14f35b1",
              "rules_revision": "bf7cfa24443db40d342cc48d565bdc34925f9466",
              "workflow_revision": os.environ.get("GITHUB_SHA"),
              "runner_image": os.environ.get("ImageVersion"),
              "inputs_before": inputs, "test_inventory": inventory, "phases": []}
    failure = False
    if engine == "flutter":
        for index, package in enumerate(PACKAGES):
            directory = ROOT / package
            command = ["flutter", "pub", "get"]
            if inputs[package + "/pubspec.lock"] is not None:
                command.append("--enforce-lockfile")
            phase = run("pub-%02d" % index, command, directory)
            report["phases"].append({"package": package, **phase})
            if phase["exit_code"]:
                failure = True
                continue
            phase = run("test-%02d" % index,
                        ["flutter", "test", "--coverage", "--machine"], directory)
            report["phases"].append({"package": package, **phase})
            failure = failure or phase["exit_code"] != 0
    else:
        phase = run("public-pub-lock", [
            "bazel", "--nosystem_rc", "--nohome_rc", "--bazelrc=/dev/null",
            "build", "--nobuild", "--lockfile_mode=update",
            "--repo_env=FLUTTER_ROOT=" + os.environ["FLUTTER_ROOT"],
            "--disk_cache=", "--remote_cache=", "@pub//:package_config.json",
        ], ROOT)
        report["phases"].append(phase)
        failure = phase["exit_code"] != 0
    report["inputs_after"] = {
        name: digest(ROOT / name) if (ROOT / name).exists() else None for name in inputs}
    report["generated_locks"] = [
        name for name in inputs
        if inputs[name] is None and report["inputs_after"][name] is not None]
    report["input_drift"] = [
        name for name in inputs
        if inputs[name] is not None and inputs[name] != report["inputs_after"][name]]
    for name in inputs:
        if name.endswith("/pubspec.lock") and (ROOT / name).exists():
            destination = OUT / "resolved-locks" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((ROOT / name).read_bytes())
    failure = failure or bool(report["input_drift"])
    report["exit_code"] = int(failure)
    (OUT / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print("FEASIBILITY_RESULT " + json.dumps(report), flush=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as stream:
            stream.write("## %s feasibility\n\n" % engine)
            stream.write("Dependency and host-test diagnostics only; no speedup claim.\n\n")
            for phase in report["phases"]:
                stream.write("- `%s` %s: exit %d, %.1fs\n" % (
                    phase.get("package", "app lock"), phase["phase"],
                    phase["exit_code"], phase["wall_seconds"]))
            stream.write("\nInput drift: %s\n" % report["input_drift"])
    return int(failure)


if __name__ == "__main__":
    sys.exit(main())
