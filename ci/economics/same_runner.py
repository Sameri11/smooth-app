"""Runs the same-runner output-reader sequence: four warm Bazel replays in one job.

Each sample runs timing.py in its own process against a fresh output base. The base and the
workspace bazel-* links are removed after every sample. The first failed sample stops the chain.
"""

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

import cache
import probe
import timing

SCHEMA = "smooth-same-runner-summary/1"
# Fixed for every sample: the reader job is warm, replay-mode and repetition 1.
FIXED_ENV = {"ENGINE": "bazel", "SCENARIO": "warm", "REMOTE_CACHE_MODE": "replay", "REPETITION": "1",
             "SAME_RUNNER_OUTPUTS": "1"}
# Set per child from the sample name. An inherited value would select a different reader.
CHILD_ONLY = ("SAME_RUNNER_SAMPLE", "REMOTE_DOWNLOAD_OUTPUTS", "OUTPUT_READER")
FORBIDDEN_IN_PARENT = CHILD_ONLY + ("BAZEL_PROFILE",)
SPAN_KEYS = ("name", "kind", "start_offset_seconds", "end_offset_seconds", "seconds", "exit_code",
             "argv", "stdout")
TIMING_PREFIX = "TIMING_RESULT "


def evidence_root():
    return cache.runner_temp() / "smooth-ci-evidence"


def invocation_dir(sample):
    return evidence_root() / "invocations" / sample


def output_base():
    return cache.runner_temp() / "bazel-output"


def sample_identity(sample):
    reader = sample.split("-", 1)[1]
    mode = reader.rsplit("-", 1)[0]
    if reader not in timing.READER_IDENTITIES or mode not in timing.DOWNLOAD_OUTPUTS:
        raise probe.Stop("sample %r has no reader identity" % sample)
    return mode, reader


def validate_parent():
    if os.environ.get("SAME_RUNNER_OUTPUTS") != "1":
        raise probe.Stop("SAME_RUNNER_OUTPUTS must be 1 for the same-runner harness")
    for key in FORBIDDEN_IN_PARENT:
        if key in os.environ:
            raise probe.Stop("%s must be unset in the harness parent" % key)
    for key, value in FIXED_ENV.items():
        if os.environ.get(key, value) != value:
            raise probe.Stop("%s must be %s" % (key, value))
    runner_temp = Path(os.environ.get("RUNNER_TEMP", ""))
    if not runner_temp.is_absolute() or not runner_temp.is_dir():
        raise probe.Stop("RUNNER_TEMP must be an existing absolute directory")


def bazel_links():
    return sorted(entry.name for entry in os.scandir(probe.ROOT) if entry.name.startswith("bazel-"))


def precheck(sample):
    """Refuses to start a sample over anything that already exists, so teardown only removes our own."""
    if os.path.lexists(output_base()):
        raise probe.Stop("output base already exists; refusing to delete it")
    if os.path.lexists(invocation_dir(sample)):
        raise probe.Stop("%s evidence directory already exists" % sample)
    links = bazel_links()
    if links:
        raise probe.Stop("workspace bazel links already exist: %s" % ", ".join(links))


def child_env(sample, mode, reader):
    env = dict(os.environ)
    env.update(FIXED_ENV)
    env.update(SAME_RUNNER_SAMPLE=sample, REMOTE_DOWNLOAD_OUTPUTS=mode, OUTPUT_READER=reader)
    return env


def run_child(sample, mode, reader):
    started = time.monotonic()
    proc = subprocess.run(
        [sys.executable, str(probe.ROOT / "ci/economics/timing.py"), "run",
         "--engine", "bazel", "--scenario", "warm", "--rep", "1"],
        cwd=probe.ROOT, env=child_env(sample, mode, reader), stdout=subprocess.PIPE, text=True)
    # Keep child diagnostics in the job log, not in the compact artifact.
    print(proc.stdout, end="", flush=True)
    timing_result = None
    for line in proc.stdout.splitlines():
        if line.startswith(TIMING_PREFIX):
            timing_result = json.loads(line[len(TIMING_PREFIX):])
    return {"exit_code": proc.returncode, "seconds": round(time.monotonic() - started, 3),
            "timing_result": timing_result}


def read_report(sample):
    path = invocation_dir(sample) / "result.json"
    if not path.is_file():
        raise probe.Stop("child wrote no result.json")
    return json.loads(path.read_text())


def span_of(phase):
    return {key: phase[key] for key in SPAN_KEYS if key in phase}


def extract(report):
    gate = report.get("gate") or {}
    return {"verdict": report.get("verdict"), "exit_code": report.get("exit_code"),
            "stopped": report.get("stopped"), "gate_verdict": gate.get("verdict"),
            "bep_verdict": (gate.get("bep") or {}).get("verdict"),
            "package_verdicts": {pkg: data.get("verdict") for pkg, data in (gate.get("packages") or {}).items()},
            "remote_cache": report.get("remote_cache"), "module_lock": gate.get("module_lock"),
            "sources_restored": report.get("sources_restored"),
            "sources_sha256_before": report.get("sources_sha256_before"),
            "sources_sha256_after": report.get("sources_sha256_after"),
            "identities": report.get("identities"),
            "spans": [span_of(phase) for phase in report.get("phases", [])]}


def judge(mode, reader, child, report):
    problems = []
    if child["exit_code"] != 0:
        problems.append("child exited %s" % child["exit_code"])
    if (child["timing_result"] or {}).get("verdict") != "pass":
        problems.append("TIMING_RESULT missing or not pass")
    if report.get("mode") != "timed" or (report.get("engine"), report.get("scenario"), report.get("rep")) != (
            "bazel", "warm", 1):
        problems.append("report is not the warm bazel repetition 1 timed run")
    if report.get("stopped"):
        problems.append("child stopped: " + report["stopped"])
    if report.get("verdict") != "pass" or report.get("exit_code") != 0:
        problems.append("report verdict %s" % report.get("verdict"))
    remote = report.get("remote_cache") or {}
    if (remote.get("mode"), remote.get("download_outputs"), remote.get("reader_identity")) != (
            "replay", mode, reader):
        problems.append("reader identity differs from the sample")
    if (report.get("gate") or {}).get("verdict") != "pass":
        problems.append("gate verdict %s" % (report.get("gate") or {}).get("verdict"))
    if report.get("sources_restored") is not True:
        problems.append("sources not restored")
    return problems


def remove_tree(path):
    def make_writable(function, target, _info):
        for entry in (os.path.dirname(target), target):
            if os.path.isdir(entry) and not os.path.islink(entry):
                os.chmod(entry, stat.S_IRWXU)
        function(target)

    shutil.rmtree(path, onerror=make_writable)


def shut_down_base(base):
    if not os.path.lexists(base):
        return {"status": "absent"}
    try:
        return {"status": "ok", "result": cache.shutdown_bazel()}
    except cache.CacheError as error:
        # The message carries bazel stderr, which is not recorded.
        match = re.match(r"bazel shutdown exited (\d+)", str(error))
        return {"status": "failed", "exit_code": int(match.group(1)) if match else None}
    except Exception as error:
        return {"status": "error", "error": type(error).__name__}


def teardown():
    """Shuts down the sample's base, then removes only the base and links that resolve inside it."""
    started = time.monotonic()
    base = output_base()
    before = {"base_present": os.path.lexists(base), "links": bazel_links()}
    shutdown = shut_down_base(base)
    problems = []
    if shutdown["status"] not in ("absent", "ok"):
        problems.append("bazel shutdown %s" % shutdown["status"])
        return {"before": before, "shutdown": shutdown, "removed_links": [],
                "base_removed": False,
                "after": {"base_present": os.path.lexists(base), "links": bazel_links()},
                "problems": problems, "seconds": round(time.monotonic() - started, 3)}
    base_real = Path(os.path.realpath(base))
    removed_links = []
    for name in before["links"]:
        link = probe.ROOT / name
        if os.path.islink(link) and Path(os.path.realpath(link)).is_relative_to(base_real):
            os.unlink(link)
            removed_links.append(name)
    base_removed = False
    if os.path.lexists(base):
        try:
            remove_tree(base)
            base_removed = True
        except OSError as error:
            problems.append("remove base: " + type(error).__name__)
    after = {"base_present": os.path.lexists(base), "links": bazel_links()}
    if after["base_present"]:
        problems.append("output base remains")
    if after["links"]:
        problems.append("bazel links remain: " + ", ".join(after["links"]))
    return {"before": before, "shutdown": shutdown, "removed_links": removed_links,
            "base_removed": base_removed, "after": after, "problems": problems,
            "seconds": round(time.monotonic() - started, 3)}


def run_sample(sample, summary):
    mode, reader = sample_identity(sample)
    record = {"sample": sample, "download_outputs": mode, "reader_identity": reader, "problems": []}
    summary["samples"].append(record)
    try:
        precheck(sample)
    except probe.Stop as stop:
        record["problems"].append("precheck: " + str(stop))
        return False
    started = time.monotonic()
    try:
        child = run_child(sample, mode, reader)
        record["child"] = child
        report = read_report(sample)
        record["result"] = extract(report)
        record["problems"] += judge(mode, reader, child, report)
    except probe.Stop as stop:
        record["problems"].append("stopped: " + str(stop))
    except Exception as error:
        record["problems"].append("unexpected " + type(error).__name__)
    finally:
        record["seconds"] = round(time.monotonic() - started, 3)
        record["teardown"] = teardown()
    record["problems"] += record["teardown"]["problems"]
    print("SAME_RUNNER_SAMPLE_RESULT " + json.dumps({"sample": sample, "problems": record["problems"]}),
          flush=True)
    return not record["problems"]


def main(argv):
    if argv[1:]:
        raise SystemExit("usage: same_runner.py")
    try:
        validate_parent()
    except probe.Stop as stop:
        print("STOP " + str(stop), flush=True)
        return 1
    started = time.monotonic()
    summary = {"schema": SCHEMA, "script_sha256": probe.digest(Path(__file__)),
               "head": os.environ.get("GITHUB_SHA"), "run_id": os.environ.get("GITHUB_RUN_ID"),
               "attempt": os.environ.get("GITHUB_RUN_ATTEMPT"), "sequence": list(probe.SAME_RUNNER_SAMPLES),
               "samples": [], "stopped": None, "status": "fail"}
    try:
        for sample in probe.SAME_RUNNER_SAMPLES:
            if not run_sample(sample, summary):
                summary["stopped"] = "%s did not pass" % sample
                break
        else:
            summary["status"] = "pass"
    except probe.Stop as stop:
        summary["stopped"] = str(stop)
    finally:
        summary["orchestration_seconds"] = round(time.monotonic() - started, 3)
        summary["clock"] = "time.monotonic"
        probe.write_json(evidence_root() / "same-runner-summary.json", summary)
    print("SAME_RUNNER_RESULT " + json.dumps({"status": summary["status"], "stopped": summary["stopped"]}),
          flush=True)
    return 0 if summary["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
