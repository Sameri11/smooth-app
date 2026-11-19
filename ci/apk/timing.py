#!/usr/bin/env python3
"""Run one isolated, timed stock-Flutter or Bazel debug APK build."""
from __future__ import annotations

import argparse
import base64
import contextlib
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import platform
import shlex
import shutil
import struct
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import economics as econ

WS = Path(__file__).resolve().parents[2]
ROOT = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / "apk-timing"
SDK = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / "flutter"
PUB = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / "cache-state" / "pub"
BAZELISK = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / "cache-state" / "bazelisk"
WORKLOAD_HEAD = "6e7408fda8e46bc97a0d8f2b33a801cf27c8dabe"
PREVIOUS_HARNESS_HEAD = "b10ff4f1157fba52b2cd566e5c34965397de3c1d"
HARNESS_FILES = {
    ".github/workflows/ci-apk-timing.yml", "ci/apk/timing.py", "ci/apk/timing_cache.py",
}
PROFILE_PHASES = {
    "Launch Blaze", "Initialize command", "Evaluate target patterns",
    "Load and analyze dependencies", "Load, analyze dependencies and build artifacts",
    "Analyze licenses", "Prepare for build", "Build artifacts", "Complete build",
}
REMOTE_PROFILE_CATEGORIES = {
    "remote action cache check", "remote network", "remote output download", "Fetching repository",
}
RESOURCE_SAMPLE_SECONDS = 1.0
OLD_SHA = "35edd245bf824b5805d0453d0583d60c69b12a49a1468387217f5a902eb5bfd9"
NEW_SHA = "5e0160f09b1bed2fab4dfa38d5e481f350e3f3024b49836e49ecbb6402825b61"
LIB_REL = "packages/smooth_app/lib/helpers/string_extension.dart"
MARKER = b"_removeSpacesPattern"
ENTRYPOINT = "lib/entrypoints/android/main_google_play.dart"
APK_REL = "packages/smooth_app/build/app/outputs/flutter-apk/app-debug.apk"
APK_TARGET = "//packages/smooth_app/android/app:smooth_app"
SCENARIOS = ("cold", "warm", "lib")
ENGINES = ("stock", "bazel")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_hash(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def json_write(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    tmp.replace(path)


def state_load():
    path = ROOT / "state.json"
    if not path.is_file():
        raise RuntimeError("state.json is absent; run prepare first")
    return json.loads(path.read_text())


def save(state):
    json_write(ROOT / "state.json", state)


def phase(state, name):
    @contextlib.contextmanager
    def measured():
        row = {"name": name, "start_epoch": time.time(), "start_monotonic": time.monotonic(), "status": "running"}
        state.setdefault("phases", []).append(row)
        save(state)
        try:
            yield row
        except BaseException as exc:
            row["status"] = "failed"
            row["error"] = (type(exc).__name__ + ": " + str(exc))[:1200]
            raise
        else:
            row["status"] = "complete"
        finally:
            row["end_epoch"] = time.time()
            row["duration_seconds"] = round(time.monotonic() - row["start_monotonic"], 6)
            save(state)
    return measured()


def _system_memory_usage():
    try:
        values = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, value = line.split(":", 1)
            if key in ("MemAvailable", "SwapTotal", "SwapFree"):
                values[key] = int(value.split()[0]) * 1024
        if not all(key in values for key in ("MemAvailable", "SwapTotal", "SwapFree")):
            return None
        return {
            "mem_available_bytes": values["MemAvailable"],
            "swap_used_bytes": max(0, values["SwapTotal"] - values["SwapFree"]),
        }
    except (OSError, ValueError, IndexError):
        return None


def command(state, name, argv, cwd, env, timeout=3600, *, output_limit=5000,
            sample_resources=False):
    start_epoch, start_mono = time.time(), time.monotonic()
    safe_argv = [str(x) for x in argv]
    stored_argv = [re.sub(r"^--profile=.*$", "--profile=[temporary]", arg) for arg in safe_argv]
    deadline = float(os.environ.get("APK_TIMING_DEADLINE_EPOCH", "0") or 0)
    if deadline:
        timeout = min(timeout, deadline - time.time())
        if timeout <= 0:
            raise RuntimeError("global APK timing deadline exhausted")
    if name in ("stock-flutter-build-apk", "bazel-build-apk"):
        print(f"APK_TIMING_HEARTBEAT build_started engine={state['identity']['engine']} scenario={state['identity']['scenario']}", flush=True)
    proc = subprocess.Popen(safe_argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, errors="replace",
                            start_new_session=True)
    min_mem_available = None
    peak_swap_used = None
    next_sample = start_mono
    try:
        if sample_resources:
            while True:
                if time.monotonic() >= next_sample:
                    observed = _system_memory_usage()
                    if observed is not None:
                        available, swap_used = observed["mem_available_bytes"], observed["swap_used_bytes"]
                        min_mem_available = available if min_mem_available is None else min(min_mem_available, available)
                        peak_swap_used = swap_used if peak_swap_used is None else max(peak_swap_used, swap_used)
                    next_sample = time.monotonic() + RESOURCE_SAMPLE_SECONDS
                remaining = timeout - (time.monotonic() - start_mono)
                try:
                    text, _ = proc.communicate(timeout=min(1.0, max(0.01, remaining)))
                    break
                except subprocess.TimeoutExpired:
                    if remaining <= 0:
                        raise
        else:
            text, _ = proc.communicate(timeout=timeout)
        rc = proc.returncode
        if rc:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGTERM)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGTERM)
        try:
            text, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            text, _ = proc.communicate()
        rc = 124
    for arg in safe_argv:
        if arg.startswith("--profile="):
            text = text.replace(arg.split("=", 1)[1], "[temporary]")
    text = text or ""
    for key in ("BAZEL_CACHE_TOKEN_RW", "BAZEL_CACHE_HOST", "BAZEL_CACHE_PROJECT_ID"):
        secret = os.environ.get(key)
        if secret:
            text = text.replace(secret, "[REDACTED]")
    end_epoch = time.time()
    row = {"name": name, "argv": stored_argv, "cwd": str(cwd), "start_epoch": start_epoch,
           "end_epoch": end_epoch, "duration_seconds": round(time.monotonic() - start_mono, 6),
           "exit_code": rc, "output_tail": text[-output_limit:]}
    if sample_resources:
        memory = {
            "status": "sampled" if min_mem_available is not None else "unavailable",
            "sampling_interval_seconds": RESOURCE_SAMPLE_SECONDS,
            "semantics": "host-wide sampled minimum MemAvailable and peak SwapTotal-SwapFree; unrelated processes included",
        }
        if min_mem_available is not None:
            memory["minimum_mem_available_bytes"] = min_mem_available
            memory["peak_swap_used_bytes"] = peak_swap_used
        row["system_memory"] = memory
    state.setdefault("commands", []).append(row)
    save(state)
    if rc:
        raise RuntimeError(f"{name} exited {rc}; output tail: {row['output_tail']}")
    return text


def frozen_inputs():
    return json.loads((WS / "ci/economics/inputs.json").read_text())


def verify_frozen(root: Path | None = None):
    manifest = frozen_inputs()
    if manifest.get("schema") != 1 or manifest["rules"]["revision"] != econ.RULES_REVISION:
        raise RuntimeError("frozen rules/input manifest identity mismatch")
    if manifest["flutter"]["version"] != "3.41.8" or manifest["flutter"]["revision"] != "02085feb3f5d8a8156e5e28512b9d99351d510c0":
        raise RuntimeError("frozen Flutter identity mismatch")
    if manifest["bazel"]["version"] != "9.2.0":
        raise RuntimeError("frozen Bazel identity mismatch")
    for rel, expected in manifest["inputs"].items():
        path = (root or WS) / rel
        if file_hash(path) != expected:
            raise RuntimeError(f"frozen pub input mismatch: {rel}")
    return manifest
def verify_tool_identity(engine, tree, state, env):
    version = json.loads(command(state, "flutter-version", [SDK / "bin/flutter", "--version", "--machine"], tree, env))
    if version.get("frameworkVersion") != "3.41.8" or version.get("frameworkRevision") != "02085feb3f5d8a8156e5e28512b9d99351d510c0":
        raise RuntimeError("installed Flutter identity differs from frozen 3.41.8 revision")
    state["identity"]["flutter_runtime"] = {
        "version": version.get("frameworkVersion"), "revision": version.get("frameworkRevision"),
        "dart": version.get("dartSdkVersion")}
    if engine == "bazel":
        rules = subprocess.run(["git", "-C", str(WS / ".ci-rules"), "rev-parse", "HEAD"],
                               text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if rules.returncode or rules.stdout.strip() != econ.RULES_REVISION:
            raise RuntimeError("checked-out rules revision differs from frozen manifest")
        bazel_text = command(state, "bazel-version", [Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / "bazel", "--version"], tree, env)
        if "bazel 9.2.0" not in bazel_text:
            raise RuntimeError("installed Bazel differs from frozen 9.2.0")
        state["identity"]["rules_revision"] = rules.stdout.strip()
        state["identity"]["bazel_runtime"] = bazel_text.strip()
    save(state)

def tracked_source_fingerprint(root: Path):
    listing = subprocess.run(
        ["git", "-C", str(WS), "ls-files", "-z", "--", "packages/smooth_app", "packages/app_store",
         "packages/scanner", "MODULE.bazel", "MODULE.bazel.lock", "plugin_deps.MODULE.bazel",
         ".bazelversion", "ci/economics/inputs.json"],
        check=True, stdout=subprocess.PIPE).stdout.split(b"\0")
    rows = []
    for raw in listing:
        if not raw:
            continue
        rel = raw.decode("utf-8", "surrogateescape")
        path = root / rel
        sha = file_hash(path)
        if sha is None:
            raise RuntimeError(f"tracked source missing: {rel}")
        rows.append((rel, sha))
    data = b"".join(rel.encode("utf-8", "surrogateescape") + b"\0" + sha.encode() + b"\n" for rel, sha in rows)
    return {"count": len(rows), "sha256": digest(data)}



def identity(root):
    result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError("git rev-parse HEAD failed")
    return result.stdout.strip()


def dispatch_head():
    head = identity(WS)
    if head != os.environ.get("GITHUB_SHA"):
        raise RuntimeError("checkout HEAD does not match GITHUB_SHA")
    parent = subprocess.check_output(["git", "rev-parse", head + "^"], cwd=WS, text=True).strip()
    if parent != PREVIOUS_HARNESS_HEAD:
        raise RuntimeError("dispatch commit is not an exact child of the previous harness")
    changed = set(subprocess.check_output(
        ["git", "diff", "--name-only", WORKLOAD_HEAD, head], cwd=WS, text=True
    ).splitlines())
    if changed != HARNESS_FILES:
        raise RuntimeError("cumulative changed paths differ from the exact harness path table")
    return head


def tracked_tree(engine):
    tree = ROOT / "trees" / engine
    if tree.exists():
        shutil.rmtree(tree)
    tree.mkdir(parents=True)
    proc = subprocess.Popen(["git", "-C", str(WS), "archive", "--format=tar", WORKLOAD_HEAD], stdout=subprocess.PIPE)
    assert proc.stdout
    with tarfile.open(fileobj=proc.stdout, mode="r|") as archive:
        archive.extractall(tree, filter="data")
    proc.stdout.close()
    if proc.wait() != 0:
        raise RuntimeError("git archive of frozen tracked tree failed")
    if engine == "bazel":
        rules = WS / ".ci-rules"
        if not rules.is_dir():
            raise RuntimeError("frozen .ci-rules checkout is absent")
        shutil.copytree(rules, tree / ".ci-rules", symlinks=True, ignore=shutil.ignore_patterns(".git"))
    return tree
def runner_metadata():
    memory = None
    cpu_model = None
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                memory = int(line.split()[1]) * 1024
                break
    except OSError:
        pass
    try:
        for line in Path("/proc/cpuinfo").read_text(errors="replace").splitlines():
            if line.startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    usage = shutil.disk_usage(ROOT)
    return {"os": platform.platform(), "system": platform.system(), "machine": platform.machine(),
            "cpu_count": os.cpu_count(), "cpu_model": cpu_model, "memory_bytes": memory,
            "run_image_os": os.environ.get("ImageOS"), "run_image_version": os.environ.get("ImageVersion"),
            "disk_total_bytes": usage.total, "disk_free_bytes_at_prepare": usage.free}




def requested_download_outputs(engine, scenario):
    if engine != "bazel":
        return None
    return "all" if scenario == "cold" else "toplevel"


def requested_bazel_jobs(engine, scenario):
    if engine != "bazel":
        return None
    jobs = os.environ.get("APK_BAZEL_JOBS")
    if scenario == "cold":
        if jobs != "default":
            raise RuntimeError("cold seed requires APK_BAZEL_JOBS=default")
    elif jobs not in ("4", "128"):
        raise RuntimeError("APK_BAZEL_JOBS must be 4 or 128 for readers")
    return jobs


def proof_identity(identity):
    run, attempt, head = (identity[key] for key in ("run_id", "attempt", "head"))
    if not (re.fullmatch(r"[0-9]+", run) and re.fullmatch(r"[0-9]+", attempt)
            and re.fullmatch(r"[0-9a-f]{40}", head)):
        raise RuntimeError("APK proof requires exact run, attempt and commit identity")
    return f"{run}/{attempt}/{head}"


def policy_references(identity, env):
    prefix = proof_identity(identity)
    scenario = identity["scenario"]
    references = {}
    for key, name, predecessor, required in (
        ("seed_sha256", "APK_SEED_PROOF", "cold", scenario != "cold"),
        ("edit_sha256", "APK_EDIT_PROOF", "lib",
         scenario == "lib" and identity["bazel_jobs"] == "4"),
    ):
        proof = env.get(name, "")
        if not required:
            if proof:
                raise RuntimeError(f"unexpected {name} for this APK policy row")
            continue
        match = re.fullmatch(prefix + f"/{predecessor}/([0-9a-f]{{64}})", proof)
        if not match:
            raise RuntimeError(f"{name} is absent, malformed or from the wrong run or scenario")
        references[key] = match[1]
    return references


def require_policy_apk(scenario, references, apk_sha256):
    if scenario == "warm" and apk_sha256 != references["seed_sha256"]:
        raise RuntimeError("unchanged APK digest does not match the cold seed")
    expected = ("749a34170ea803bb8d84e3fce0f47f6288dd576f74c0e39e8cc13df6a8cdda8b"
                if scenario in ("cold", "warm") else
                "e24aefe28e6a84478fc259a9b8a79dfead0341a70476a1a219e207c2051e1bac")
    if apk_sha256 != expected:
        raise RuntimeError(f"{scenario} APK digest differs from frozen expected digest")
    if scenario == "lib" and apk_sha256 == references["seed_sha256"]:
        raise RuntimeError("edited APK digest matches the unedited APK")
    if "edit_sha256" in references and apk_sha256 != references["edit_sha256"]:
        raise RuntimeError("edited APK digests do not match across jobs")


def cmd_prepare(args):
    download_outputs = requested_download_outputs(args.engine, args.scenario)
    bazel_jobs = requested_bazel_jobs(args.engine, args.scenario)
    ROOT.mkdir(parents=True, exist_ok=True)
    head = dispatch_head()
    manifest = verify_frozen()
    tree = tracked_tree(args.engine)
    verify_frozen(tree)
    state = {"schema": 1, "kind": "smooth-current-debug-apk-timing", "status": "prepared",
             "identity": {"head": head, "run_id": os.environ.get("GITHUB_RUN_ID", ""),
                          "workload_head": WORKLOAD_HEAD,
                          "attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
                          "engine": args.engine, "scenario": args.scenario,
                          "download_outputs": download_outputs, "bazel_jobs": bazel_jobs,
                          "workflow_start_epoch": None,
                          "inputs_sha256": digest(json.dumps(manifest["inputs"], sort_keys=True).encode()),
                          "rules_revision": manifest["rules"]["revision"],
                          "library_source_sha256": file_hash(tree / LIB_REL),
                          "flutter": manifest["flutter"], "bazel": manifest["bazel"]},
             "runner": runner_metadata(),
             "build_config": {"target": APK_TARGET, "stock_target": ENTRYPOINT, "abi": "x86_64",
                              "mode": "debug", "bazel_configuration": "fastbuild",
                              "bazel_jobs": bazel_jobs,
                              "compile_sdk": 36, "build_tools": "36.0.0", "ndk": "28.2.13676358",
                              "java": 17, "lockfile_mode": "error"},
             "phases": [], "commands": [], "errors": [],
             "prior_host_runtime_proof": {"run_id": "44291552151", "scope": "seven-state offline runtime; frozen consumer configuration only"},
             "tree": str(tree), "tracked_source": tracked_source_fingerprint(tree),
             "artifact": None, "cache_metrics": None}
    if download_outputs:
        state["output_policy"] = policy_references(state["identity"], os.environ)
    save(state)
    clock = ROOT / "workflow-clock.json"
    if clock.is_file():
        state["workflow_clock"] = json.loads(clock.read_text())
        state["identity"]["workflow_start_epoch"] = state["workflow_clock"].get("job_start_epoch")
    save(state)
    print(json.dumps({"status": "prepared", "tree": str(tree), "head": head,
                      "download_outputs": download_outputs, "bazel_jobs": bazel_jobs}))


def job_env(engine, state):
    env = dict(os.environ)
    for key in ("BAZEL_CACHE_TOKEN_RW", "BAZEL_CACHE_HOST", "BAZEL_CACHE_PROJECT_ID"):
        env.pop(key, None)
    home = ROOT / "home"
    home.mkdir(parents=True, exist_ok=True)
    (ROOT / "logs").mkdir(parents=True, exist_ok=True)
    env.update({"HOME": str(home), "ANDROID_USER_HOME": str(home / ".android"),
                "GRADLE_USER_HOME": str(home / ".gradle"), "TMPDIR": str(ROOT / "tmp"),
                "FLUTTER_ROOT": str(SDK), "PUB_CACHE": str(PUB),
                "FLUTTER_SUPPRESS_ANALYTICS": "true", "CI": "true"})
    Path(env["TMPDIR"]).mkdir(parents=True, exist_ok=True)
    if engine == "bazel":
        env["BAZELISK_HOME"] = str(BAZELISK)
    return env




def run_remote_config(state):
    required = ("BAZEL_CACHE_HOST", "BAZEL_CACHE_PROJECT_ID", "BAZEL_CACHE_TOKEN_RW")
    values = [os.environ.get(k, "") for k in required]
    if any(not x or "\n" in x or "\r" in x for x in values):
        raise RuntimeError("remote backend requires three nonempty single-line credentials")
    host, project, token = values
    if "://" in host or "/" in host:
        raise RuntimeError("remote cache host must contain no scheme/path")
    identity_values = [state["identity"][k] for k in ("run_id", "attempt", "head")]
    if not (re.fullmatch(r"[0-9]+", identity_values[0]) and re.fullmatch(r"[0-9]+", identity_values[1])
            and re.fullmatch(r"[0-9a-f]{40}", identity_values[2])):
        raise RuntimeError("remote salt requires numeric run/attempt and exact 40-hex head")
    salt = "/".join(identity_values)
    rc = ROOT / "remote-cache.bazelrc"
    rc_text = "".join("build " + shlex.quote(x) + "\n" for x in (
        "--remote_cache=grpcs://" + host, "--remote_instance_name=" + project,
        "--remote_cache_header=Authorization=Bearer " + token))
    fd = os.open(rc, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(rc_text)
    scrub = ROOT / "remote-scrubbing.textproto"
    scrub.write_text('rules {\n  matcher { kind: ".*" label: ".*" mnemonic: ".*" match_tools: true }\n'
                     '  transform { salt: "' + salt + '" }\n}\n')
    identity = state["identity"]
    cold = identity["scenario"] == "cold"
    state["remote_cache"] = {"salt": salt, "rc_mode": oct(rc.stat().st_mode & 0o777),
                             "scrubbing_sha256": file_hash(scrub), "disk_cache": False,
                             "accept_cached": not cold, "upload_local_results": cold, "upload_async": False,
                             "download_outputs": identity.get("download_outputs") or "all",
                             "remote_execution": False}
    return rc, scrub


def bazel_argv(root, command_name, env, *, bep=None, remote=True, extra=()):
    args = [str(Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / "bazel"),
            "--nosystem_rc", "--nohome_rc", "--noworkspace_rc",
            "--output_base=" + str(ROOT / "bazel-output-base")]
    rc, scrub = run_remote_config(_ACTIVE_STATE) if remote else (None, None)
    if remote:
        args.append("--bazelrc=" + str(rc))
    args.append(command_name)
    args.append("--disk_cache=")
    if not remote:
        args.append("--remote_cache=")
    args += ["--repository_cache=" + str(ROOT / "repository-cache"),
             "--repo_env=FLUTTER_ROOT=" + str(SDK), "--repo_env=ANDROID_HOME=" + env["ANDROID_HOME"],
             "--repo_env=ANDROID_NDK_HOME=" + env["ANDROID_NDK_HOME"],
             "--android_platforms=@rules_android//:x86_64", "--@rules_flutter_core//flutter:mode=debug",
             "-c", "fastbuild", "--merge_android_manifest_permissions", "--tool_java_language_version=17",
             "--tool_java_runtime_version=remotejdk_17", "--java_language_version=17",
             "--java_runtime_version=remotejdk_17", "--desugar_java8_libs", "--color=no", "--curses=no",
             *(["--jobs=" + _ACTIVE_STATE["identity"]["bazel_jobs"]]
               if _ACTIVE_STATE["identity"]["bazel_jobs"] in ("4", "128") else []),
             *extra]
    if remote:
        policy = _ACTIVE_STATE["remote_cache"]
        args += ["--experimental_remote_scrubbing_config=" + str(scrub), "--remote_executor=",
                 "--remote_accept_cached=" + str(policy["accept_cached"]).lower(),
                 "--remote_upload_local_results=" + str(policy["upload_local_results"]).lower(),
                 "--remote_cache_async=false", "--remote_download_outputs=" + policy["download_outputs"],
                 "--announce_rc=false", "--nobuild_event_json_file_path_conversion"]
    if bep:
        args.append("--build_event_json_file=" + str(bep))
    args.append("--lockfile_mode=error")
    args.append(APK_TARGET)
    return args


_ACTIVE_STATE = {}


def phase_start(state, name):
    return phase(state, name)


def apply_library_edit(path):
    old = path.read_bytes()
    oldsha = digest(old)
    marker = MARKER in old
    if oldsha != OLD_SHA or marker:
        raise RuntimeError(f"invalid measurement baseline: source sha256={oldsha}, marker_present={marker}; no forced re-execution/cache bypass")
    text = old.decode("utf-8")
    needle = "extension StringExtension on String {"
    usage = "  String removeSpaces() => replaceAll(RegExp(r' |\\n|\\r|\\s|\\t'), '');"
    if text.count(needle) != 1 or text.count(usage) != 1:
        raise RuntimeError("library source mutation anchors are not unique")
    updated = (text.replace(needle, "final RegExp _removeSpacesPattern = RegExp(r' |\\n|\\r|\\s|\\t');\n\n" + needle)
               .replace(usage, "  String removeSpaces() => replaceAll(_removeSpacesPattern, '');")).encode()
    if digest(updated) != NEW_SHA:
        raise RuntimeError(f"library edit hash mismatch: {digest(updated)}")
    path.write_bytes(updated)
    return {"path": LIB_REL, "old_sha256": oldsha, "new_sha256": digest(updated), "marker": MARKER.decode()}


def native_inventory(apk):
    records = []
    names_seen = set()
    with zipfile.ZipFile(apk) as zf:
        for info in zf.infolist():
            name = info.filename
            if econ.unsafe_reason(name):
                raise RuntimeError(f"unsafe APK member {name!r}")
            if name in names_seen:
                raise RuntimeError("duplicate APK member name")
            names_seen.add(name)
            if name.startswith("lib/") and name.endswith(".so"):
                data = zf.read(info)
                if len(data) < 20 or data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01":
                    raise RuntimeError(f"invalid ELF64 little-endian native: {name}")
                machine = struct.unpack_from("<H", data, 18)[0]
                if machine != econ.X86_64_MACHINE or not name.startswith("lib/x86_64/"):
                    raise RuntimeError(f"native ABI/machine mismatch: {name} machine={machine}")
                record = {"name": name, "bytes": len(data), "sha256": digest(data), "elf_machine": machine}
                accepted = econ.PINNED_APK_NATIVES.get(name, {})
                record["matches_reference"] = accepted.get(record["sha256"]) == len(data)
                records.append(record)
        required = {"assets/flutter_assets/kernel_blob.bin", "classes.dex", "lib/x86_64/libflutter.so"}
        missing = required - names_seen
        if missing:
            raise RuntimeError("required APK members absent: " + ", ".join(sorted(missing)))
        if any(name.endswith("libapp.so") for name in names_seen):
            raise RuntimeError("libapp.so present; expected debug kernel APK")
    return records, names_seen


def validate_apk(engine, tree, scenario, state):
    apk = Path(state["bazel_apk"]) if engine == "bazel" else tree / APK_REL
    if not apk.is_file() or apk.stat().st_size == 0:
        raise RuntimeError("built APK missing or empty")
    tools = Path(os.environ.get("APK_TREE_BUILD_TOOLS", os.environ["ANDROID_HOME"] + "/build-tools/36.0.0"))
    badging = command(state, "apk-badging", [tools / "aapt2", "dump", "badging", apk], tree, _ENV)
    signing = command(state, "apk-signature", [tools / "apksigner", "verify", "--print-certs", "-v", apk], tree, _ENV)
    facts = econ.parse_badging(badging)
    sig = econ.parse_signing(signing)
    expected = {"package": "org.openfoodfacts.scanner", "minSdk": "24", "targetSdk": "36", "compileSdk": "36"}
    for key, val in expected.items():
        if facts.get(key) != val:
            raise RuntimeError(f"APK badging {key}={facts.get(key)!r}, expected {val!r}")
    if facts["native_code"] != ["x86_64"] or not facts["debuggable"]:
        raise RuntimeError("APK is not the expected x86_64 debug package")
    if not sig["verifies"] or not (sig["schemes"].get("v2") or sig["schemes"].get("v3")) or sig["signers"] != 1:
        raise RuntimeError("APK signature verification failed")
    natives, members = native_inventory(apk)
    kernel = zipfile.ZipFile(apk).read("assets/flutter_assets/kernel_blob.bin")
    marker = MARKER in kernel
    if scenario == "lib" and not marker:
        raise RuntimeError("edited build kernel lacks unique _removeSpacesPattern marker (stale baseline output)")
    if scenario != "lib" and marker:
        raise RuntimeError("baseline kernel unexpectedly contains _removeSpacesPattern marker")
    state["artifact"] = {"path": str(apk), "bytes": apk.stat().st_size, "sha256": file_hash(apk),
                          "kernel_sha256": digest(kernel), "kernel_marker_present": marker,
                          "badging": facts, "signing": sig, "native_inventory": natives,
                          "member_count": len(members), "byte_identity_gate": False}
    save(state)


def pub_get(tree, state, env, label):
    verify_frozen(tree)
    command(state, label, [SDK / "bin/flutter", "pub", "get", "--enforce-lockfile"],
            tree / "packages/smooth_app", env, timeout=900)
    verify_frozen(tree)


def ensure_sdk_tools(state, env):
    flutter_tools = SDK / "packages/flutter_tools"
    dart = SDK / "bin/cache/dart-sdk/bin/dart"
    lock = file_hash(flutter_tools / "pubspec.lock")
    if not lock:
        raise RuntimeError("verified Flutter SDK flutter_tools lock missing")
    command(state, "flutter-tools-locked-pub-get", [dart, "pub", "get", "--enforce-lockfile", "--suppress-analytics"],
            flutter_tools, env, timeout=900)
    if file_hash(flutter_tools / "pubspec.lock") != lock or not (flutter_tools / ".dart_tool/package_config.json").is_file():
        raise RuntimeError("flutter_tools locked preparation did not preserve lock/write package config")


def collect_profile(path):
    try:
        if not path.is_file():
            return {"status": "missing"}
        try:
            raw = path.read_bytes()
            if raw.startswith(b"\x1f\x8b"):
                raw = gzip.decompress(raw)
            document = json.loads(raw.decode("utf-8"))
        except (OSError, gzip.BadGzipFile, json.JSONDecodeError, UnicodeDecodeError):
            return {"status": "invalid"}
        events = document.get("traceEvents") if isinstance(document, dict) else None
        if not isinstance(events, list):
            return {"status": "invalid"}
        phase_markers, action_spans, mnemonics = [], [], {}
        remote_categories = {key: {"event_count": 0, "max_event_span_seconds": 0.0}
                             for key in sorted(REMOTE_PROFILE_CATEGORIES)}
        fetch_spans, download_spans = [], []
        action_duration = 0.0
        action_count = 0
        profile_end = max((event["ts"] + event.get("dur", 0)
                           for event in events if isinstance(event, dict)
                           and isinstance(event.get("ts"), (int, float))
                           and isinstance(event.get("dur", 0), (int, float))
                           and not isinstance(event.get("dur", 0), bool)), default=0)
        for event in events:
            if not isinstance(event, dict):
                continue
            category, name, ph = event.get("cat"), event.get("name"), event.get("ph")
            ts, duration = event.get("ts"), event.get("dur", 0)
            if not isinstance(ts, (int, float)) or isinstance(ts, bool):
                continue
            if category == "build phase marker" and name in PROFILE_PHASES and ph in ("i", "I", "X"):
                phase_markers.append((float(ts), str(name)))
            if (ph != "X" or not isinstance(duration, (int, float)) or isinstance(duration, bool)
                    or duration < 0):
                continue
            span = float(duration) / 1_000_000
            if category in remote_categories:
                remote_categories[category]["event_count"] += 1
                remote_categories[category]["max_event_span_seconds"] = max(
                    remote_categories[category]["max_event_span_seconds"], span)
            if category == "Fetching repository":
                fetch_spans.append((float(ts), float(ts + duration)))
            elif category == "remote output download":
                download_spans.append((float(ts), float(ts + duration)))
            if category == "action processing":
                args = event.get("args") if isinstance(event.get("args"), dict) else {}
                action_count += 1
                action_duration += float(duration)
                action_spans.extend(((float(ts), 1), (float(ts + duration), -1)))
                mnemonic = args.get("mnemonic")
                if isinstance(mnemonic, str) and re.fullmatch(r"[A-Za-z0-9_]{1,80}", mnemonic):
                    mnemonics[mnemonic] = mnemonics.get(mnemonic, 0) + 1
        phase_markers.sort()
        phase_rows = [{"name": name, "timestamp_seconds": round(ts / 1_000_000, 6),
                       "duration_to_next_seconds": round(((phase_markers[i + 1][0] if i + 1 < len(phase_markers) else profile_end) - ts) / 1_000_000, 6)}
                      for i, (ts, name) in enumerate(phase_markers)]
        concurrent = peak_concurrent = 0
        for _, change in sorted(action_spans, key=lambda item: (item[0], item[1])):
            concurrent += change
            peak_concurrent = max(peak_concurrent, concurrent)
        fetch_end = fetch_union = 0.0
        for start, end in sorted(fetch_spans):
            fetch_union += max(0.0, end - max(start, fetch_end))
            fetch_end = max(fetch_end, end)
        remote_categories["Fetching repository"]["union_seconds"] = round(fetch_union / 1_000_000, 6)
        download_end = download_union = 0.0
        for start, end in sorted(download_spans):
            download_union += max(0.0, end - max(start, download_end))
            download_end = max(download_end, end)
        remote_categories["remote output download"]["union_seconds"] = round(download_union / 1_000_000, 6)
        return {
            "status": "available",
            "schema": "Bazel 9.2 traceEvents: build phase marker instant events; action and remote spans ph=X",
            "build_phase_markers": phase_rows,
            "build_phase_marker_event_count": len(phase_rows),
            "repository_fetch": {"event_count": remote_categories["Fetching repository"]["event_count"],
                                "union_seconds": round(fetch_union / 1_000_000, 6),
                                "category": "Fetching repository"},
            "action_event_count": action_count,
            "action_concurrency_peak": peak_concurrent,
            "action_duration_sum_seconds": round(action_duration / 1_000_000, 6),
            "action_duration_semantics": "sum of action processing spans; overlaps and is not wall time",
            "action_mnemonic_counts": dict(sorted(mnemonics.items())),
            "remote_category_events": remote_categories,
            "remote_category_semantics": "counts and max spans of complete events, seconds; download union merges overlaps",
        }
    finally:
        with contextlib.suppress(OSError):
            path.unlink(missing_ok=True)

def final_critical_path(build_log):
    matches = re.findall(
        r"(?m)^INFO: Elapsed time: [0-9]+(?:\.[0-9]+)?s, Critical Path: ([0-9]+(?:\.[0-9]+)?)s(?:,.*)?$",
        build_log,
    )
    if not matches:
        return {"status": "unavailable"}
    return {"status": "available", "seconds": float(matches[-1]), "source": "final Bazel INFO summary"}

def collect_bep(path, build_log):
    counts = {"events": 0, "actions_completed": 0, "actions_failed": 0, "mnemonics": {}}
    summary = re.findall(r"(?m)^INFO: (\d+) process(?:es)?: ([^\r\n]+)", build_log)
    if summary:
        total, breakdown = summary[-1]
        hits = re.search(r"\b(\d+) remote cache hits?\b", breakdown)
        counts["process_summary"] = {"total": int(total)}
        if hits:
            counts["process_summary"]["remote_cache_hits"] = int(hits[1])
    try:
        with path.open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise RuntimeError("malformed Bazel build-event JSON line") from exc
                for event in row if isinstance(row, list) else [row]:
                    if not isinstance(event, dict):
                        continue
                    counts["events"] += 1
                    completed = event.get("actionCompleted")
                    if completed:
                        counts["actions_completed"] += 1
                        counts["actions_failed"] += completed.get("success") is False
                        mnemonic = completed.get("mnemonic") or "unknown"
                        counts["mnemonics"][mnemonic] = counts["mnemonics"].get(mnemonic, 0) + 1
                    metrics = event.get("buildMetrics")
                    if metrics:
                        counts["build_metrics"] = {
                            "action_summary": metrics.get("actionSummary"),
                            "target_count": metrics.get("targetCount"),
                        }
    finally:
        path.unlink(missing_ok=True)
    if not counts["events"]:
        raise RuntimeError("Bazel build-event stream contained no events")
    counts["mnemonics"] = dict(sorted(counts["mnemonics"].items()))
    return counts


def cmd_run(args):
    global _ACTIVE_STATE, _ENV
    state = state_load()
    if state.get("status") not in ("prepared", "running"):
        raise RuntimeError("state is not prepared")
    ident = state["identity"]
    if ident["engine"] != args.engine or ident["scenario"] != args.scenario:
        raise RuntimeError("CLI engine/scenario differs from prepared identity")
    head = dispatch_head()
    if ident["head"] != head:
        raise RuntimeError("checkout HEAD/GITHUB_SHA identity changed")
    mode = requested_download_outputs(args.engine, args.scenario)
    jobs = requested_bazel_jobs(args.engine, args.scenario)
    if ident.get("download_outputs") != mode or ident.get("bazel_jobs") != jobs:
        raise RuntimeError("download mode or Bazel jobs differs from prepared identity")
    references = policy_references(ident, os.environ) if mode else {}
    if mode and references != state.get("output_policy"):
        raise RuntimeError("APK digest references differ from prepared identity")
    if mode and (ident["run_id"], ident["attempt"]) != (os.environ.get("GITHUB_RUN_ID"),
                                                         os.environ.get("GITHUB_RUN_ATTEMPT")):
        raise RuntimeError("run or attempt differs from prepared identity")
    tree = Path(state["tree"])
    verify_frozen(tree)
    _ACTIVE_STATE = state
    env = _ENV = job_env(args.engine, state)
    profile_path = None
    build_log = None
    if args.scenario == "lib":
        source_baseline = (tree / LIB_REL).read_bytes()
        mutation = apply_library_edit(tree / LIB_REL)
        state["mutation"] = mutation
        save(state)
    state["status"] = "running"
    clock_path = ROOT / "workflow-clock.json"
    clock = json.loads(clock_path.read_text()) if clock_path.is_file() else {}
    required_start = float(clock.get("job_start_epoch", time.time()))
    try:
        with phase(state, "verify-tool-identities"):
            verify_tool_identity(args.engine, tree, state, env)
        if args.engine == "bazel":
            with phase(state, "flutter-tools-locked-preparation"):
                ensure_sdk_tools(state, env)
        with phase(state, "consumer-pub-get"):
            pub_get(tree, state, env, "consumer-locked-pub-get")
        if args.engine == "stock":
            with phase(state, "stock-debug-apk-build"):
                command(state, "stock-flutter-build-apk", [SDK / "bin/flutter", "build", "apk", "--debug",
                        "--target-platform", "android-x64", "--target", ENTRYPOINT, "--no-pub"],
                        tree / "packages/smooth_app", env, timeout=3300, sample_resources=True)
        else:
            bep = ROOT / "logs" / "bep.json"
            profile_path = ROOT / "logs" / "bazel-profile.json"
            bep.unlink(missing_ok=True)
            profile_path.unlink(missing_ok=True)
            with phase(state, "bazel-debug-apk-build"):
                build_log = command(
                    state, "bazel-build-apk",
                    bazel_argv(tree, "build", env, bep=bep,
                               extra=("--profile=" + str(profile_path), "--worker_quit_after_build")),
                    tree, env, timeout=3300, sample_resources=True,
                )
            if not bep.is_file():
                raise RuntimeError("Bazel did not produce required build event stream")
            query = command(state, "bazel-apk-output", bazel_argv(tree, "cquery", env, extra=("--output=files",)), tree, env, timeout=300)
            apk_name = APK_TARGET.rsplit(":", 1)[1] + ".apk"
            apks = [line.strip() for line in query.splitlines() if Path(line.strip()).name == apk_name]
            if len(apks) != 1:
                raise RuntimeError(f"expected one public APK output, found {len(apks)}")
            state["bazel_apk"] = apks[0] if Path(apks[0]).is_absolute() else str(tree / apks[0])
        with phase(state, "artifact-validation"):
            validate_apk(args.engine, tree, args.scenario, state)
            if mode:
                require_policy_apk(args.scenario, references, state["artifact"]["sha256"])
                state["output_policy"]["passed"] = True
        state["required_result_epoch"] = time.time()
        state["required_result_duration_seconds"] = round(state["required_result_epoch"] - required_start, 6)
        if args.engine == "bazel":
            state["bazel_profile"] = collect_profile(profile_path)
            state["bazel_profile"]["raw_trace_cleanup"] = "removed" if not profile_path.exists() else "failed"
            state["bazel_critical_path"] = final_critical_path(build_log)
            save(state)
            if state["bazel_profile"]["raw_trace_cleanup"] != "removed":
                raise RuntimeError("temporary Bazel profile cleanup failed")
            with phase(state, "bep-metrics-post-result"):
                state["bep_metrics"] = collect_bep(bep, build_log)
        state["status"] = "passed"
    except BaseException as exc:
        if args.engine == "bazel" and profile_path is not None:
            state["bazel_profile"] = collect_profile(profile_path)
            state["bazel_profile"]["raw_trace_cleanup"] = "removed" if not profile_path.exists() else "failed"
            state["bazel_critical_path"] = final_critical_path(build_log) if build_log is not None else {"status": "unavailable"}
        state["status"] = "failed"
        state["failure"] = {"type": type(exc).__name__, "message": str(exc)[:1500]}
        state.setdefault("errors", []).append(state["failure"])
    finally:
        if args.scenario == "lib" and state.get("mutation"):
            path = tree / LIB_REL
            path.write_bytes(source_baseline)
            state["mutation"]["restored_sha256"] = file_hash(path)
            state["mutation"]["restored_exact"] = state["mutation"]["restored_sha256"] == OLD_SHA
            if not state["mutation"]["restored_exact"]:
                state["status"] = "failed"
                state["failure"] = {"type": "RuntimeError", "message": "edited source restoration hash mismatch"}
        actual_sources = tracked_source_fingerprint(tree)
        state["source_check"] = {"expected": state["tracked_source"], "actual": actual_sources,
                                 "changed": actual_sources != state["tracked_source"]}
        if state["source_check"]["changed"]:
            state["status"] = "failed"
            state["failure"] = {"type": "RuntimeError", "message": "tracked consumer source changed during build"}
        verify_frozen(tree)
        clock = ROOT / "workflow-clock.json"
        if clock.is_file():
            state["workflow_clock"] = json.loads(clock.read_text())
            start = state["workflow_clock"].get("job_start_epoch")
            if start is not None and state.get("required_result_epoch") is not None:
                state["required_result_duration_seconds"] = round(state["required_result_epoch"] - float(start), 6)
        save(state)
    if mode and state["status"] == "passed":
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write(f"apk_proof={proof_identity(ident)}/{args.scenario}/{state['artifact']['sha256']}\n")
    print(json.dumps({"status": state["status"], "failure": state.get("failure"),
                      "artifact": state.get("artifact"), "required_result_duration_seconds": state.get("required_result_duration_seconds")}))
    return 0 if state["status"] == "passed" else 1


def cmd_emit(args):
    try:
        state = state_load()
    except Exception as exc:
        state = {"schema": 1, "kind": "smooth-current-debug-apk-timing", "status": "failed",
                 "failure": {"type": type(exc).__name__, "message": str(exc)[:1000]},
                 "identity": {"head": os.environ.get("GITHUB_SHA", ""),
                              "run_id": os.environ.get("GITHUB_RUN_ID", ""),
                              "attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
                              "engine": args.engine, "scenario": args.scenario,
                              "download_outputs": None if args.engine != "bazel" else ("all" if args.scenario == "cold" else "toplevel"),
                              "bazel_jobs": os.environ.get("APK_BAZEL_JOBS")},
                 "phases": [], "commands": [], "errors": []}
    for sidecar in (ROOT / "cache.json", ROOT / "workflow-clock.json"):
        if sidecar.is_file():
            try:
                state["cache_metrics" if sidecar.name == "cache.json" else "workflow_clock"] = json.loads(sidecar.read_text())
            except Exception as exc:
                state.setdefault("errors", []).append({"sidecar": sidecar.name, "error": str(exc)[:300]})
    state["workflow_job_status"] = os.environ.get("APK_TIMING_JOB_STATUS", "")
    envelope = {"schema": 1, "kind": "current-debug-apk-timing",
                "head": state.get("identity", {}).get("head", os.environ.get("GITHUB_SHA", "")),
                "run_id": state.get("identity", {}).get("run_id", os.environ.get("GITHUB_RUN_ID", "")),
                "attempt": state.get("identity", {}).get("attempt", os.environ.get("GITHUB_RUN_ATTEMPT", "")),
                "engine": state.get("identity", {}).get("engine", args.engine),
                "scenario": state.get("identity", {}).get("scenario", args.scenario), "body": state}
    raw = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > 2 * 1024 * 1024:
        raise RuntimeError("bounded timing evidence exceeds 2 MiB")
    packed = base64.b64encode(gzip.compress(raw, mtime=0)).decode()
    chunks = [packed[i:i + 1800] for i in range(0, len(packed), 1800)]
    print("APK_TIMING_META " + json.dumps({"encoding": "gzip+base64", "chunks": len(chunks), "sha256": digest(raw)}, separators=(",", ":")))
    for i, chunk in enumerate(chunks, 1):
        print(f"APK_TIMING_CHUNK {i}/{len(chunks)} {chunk}")
    return 0


def cmd_verify(_args):
    state = state_load()
    issues = []
    head = dispatch_head()
    if state.get("status") != "passed":
        issues.append("run did not pass")
    if os.environ.get("APK_TIMING_JOB_STATUS") != "success":
        issues.append("workflow job did not succeed")
    ident = state.get("identity", {})
    if ident.get("head") != head or ident.get("engine") != _args.engine or ident.get("scenario") != _args.scenario:
        issues.append("identity provenance invalid")
    artifact = state.get("artifact") or {}
    if artifact.get("bytes", 0) <= 0 or not artifact.get("sha256"):
        issues.append("artifact absent or invalid")
    if artifact.get("byte_identity_gate") is not False:
        issues.append("unexpected APK identity/parity gate")
    if state.get("source_check", {}).get("changed") is not False:
        issues.append("tracked source identity not preserved")
    if ident.get("scenario") == "lib":
        mutation = state.get("mutation") or {}
        if mutation.get("old_sha256") != OLD_SHA or mutation.get("new_sha256") != NEW_SHA or not mutation.get("restored_exact"):
            issues.append("library mutation proof/restoration invalid")
    if ident.get("engine") == "bazel" and not state.get("bep_metrics"):
        issues.append("BEP metrics missing")
    clock_path = ROOT / "workflow-clock.json"
    clock = json.loads(clock_path.read_text()) if clock_path.is_file() else {}
    cache_path = ROOT / "cache.json"
    cache = json.loads(cache_path.read_text()) if cache_path.is_file() else {}
    operations = cache.get("operations", [])
    if not operations:
        issues.append("cache operation evidence missing")
    if any(op.get("status") == "error" or op.get("error") for op in operations):
        issues.append("cache operation failed")
    if any(op.get("head") != ident.get("head") or str(op.get("run_id")) != str(ident.get("run_id"))
           or str(op.get("run_attempt")) != str(ident.get("attempt")) or op.get("engine") != ident.get("engine")
           or op.get("scenario") != ident.get("scenario") for op in operations):
        issues.append("cache operation provenance mismatch")
    cold_key = f"apk-current-{ident.get('run_id')}-{ident.get('attempt')}-{ident.get('head')}-{ident.get('engine')}-cold"
    if ident.get("scenario") != "cold":
        if clock.get("cache_hit") is not True or clock.get("cache_matched_key") != cold_key or clock.get("cache_expected_key") != cold_key:
            issues.append("exact cache restore hit/provenance missing")
        restored = [op for op in operations if op.get("command") == "restore"]
        if not restored or restored[-1].get("status") != "ok" or restored[-1].get("key") != cold_key:
            issues.append("exact cold cache snapshot was not restored")
    expected_pack_status = "ok" if ident.get("scenario") == "cold" or (ident.get("engine") == "stock" and ident.get("scenario") == "lib") else "skipped"
    packed = [op for op in operations if op.get("command") == "pack"]
    if not packed or packed[-1].get("status") != expected_pack_status:
        issues.append("cache pack status does not match expected publication")
    if expected_pack_status == "ok" and packed:
        suffix = "cold" if ident.get("scenario") == "cold" else "lib"
        expected_key = f"apk-current-{ident.get('run_id')}-{ident.get('attempt')}-{ident.get('head')}-{ident.get('engine')}-{suffix}"
        if packed[-1].get("key") != expected_key:
            issues.append("cache publication key mismatch")
        published = clock.get("published_cache")
        if not published or published.get("key") != expected_key:
            issues.append("published cache record missing or incorrect")
    if issues:
        print(json.dumps({"status": "failed", "issues": issues}))
        return 1
    print(json.dumps({"status": "passed", "engine": ident["engine"], "scenario": ident["scenario"],
                      "artifact_sha256": artifact["sha256"]}))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "run", "emit", "verify"):
        item = sub.add_parser(name)
        if name in ("prepare", "run", "emit", "verify"):
            item.add_argument("--engine", choices=ENGINES, required=True)
            item.add_argument("--scenario", choices=SCENARIOS, required=True)
    args = parser.parse_args()
    try:
        return {"prepare": cmd_prepare, "run": cmd_run, "emit": cmd_emit, "verify": cmd_verify}[args.command](args)
    except Exception as exc:
        try:
            state = state_load()
            state["status"] = "failed"
            state["failure"] = {"type": type(exc).__name__, "message": str(exc)[:1500]}
            state.setdefault("errors", []).append(state["failure"])
            save(state)
        except Exception:
            pass
        print(json.dumps({"status": "failed", "error": type(exc).__name__ + ": " + str(exc)[:1500]}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())


