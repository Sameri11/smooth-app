#!/usr/bin/env python3
"""Run one isolated, timed stock-Flutter or Bazel debug APK build."""
from __future__ import annotations

import argparse
import base64
import contextlib
import difflib
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
import tempfile
import time
import zipfile

APP_ROOT = Path(os.environ.get("APK_APP_ROOT", Path(__file__).resolve().parents[2] / "app"))
WS = APP_ROOT
SCRIPTS = Path(__file__).resolve().parents[2]
ROOT = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / "apk-timing"
SDK = Path(os.environ.get("FLUTTER_ROOT",
         Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / "flutter"))
PUB = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / "cache-state" / "pub"
BAZELISK = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / "cache-state" / "bazelisk"
TOOL_VERSIONS = {"bazel": {"version": "9.2.0"}}

def flutter_pin():
    version = json.loads((APP_ROOT / ".fvmrc").read_text()).get("flutter")
    if not isinstance(version, str) or not version:
        raise RuntimeError("app .fvmrc has no Flutter version")
    return {"version": version}
RESOURCE_SAMPLE_SECONDS = 1.0
LIB_REL = "packages/smooth_app/lib/helpers/string_extension.dart"
MARKER = b"_removeSpacesPattern"
ENTRYPOINT = "lib/entrypoints/android/main_google_play.dart"
APK_REL = "packages/smooth_app/build/app/outputs/flutter-apk/app-debug.apk"
APK_TARGET = "//packages/smooth_app/android/app:smooth_app"
APK_BADGING_EXPECTED = {"package": "org.openfoodfacts.scanner", "minSdk": "24",
                        "targetSdk": "36", "compileSdk": "36"}
SCENARIOS = ("cold", "warm", "lib")
ENGINES = ("stock", "bazel")
X86_64_MACHINE = 62
OLD_SHA = "35edd245bf824b5805d0453d0583d60c69b12a49a1468387217f5a902eb5bfd9"
NEW_SHA = "5e0160f09b1bed2fab4dfa38d5e481f350e3f3024b49836e49ecbb6402825b61"
 
def unsafe_reason(name):
    if not name:
        return "empty member name"
    if name.startswith("/") or "\\" in name or re.match(r"^[A-Za-z]:", name):
        return "absolute or backslash path"
    parts = name.split("/")
    if any(part in ("", "..") for part in parts[:-1]) or parts[-1] == "..":
        return "empty or traversal component"
    return None
def parse_badging(text):
    def first(pattern):
        match = re.search(pattern, text, re.M)
        return match.group(1) if match else None

    native_line = first(r"^native-code: (.*)$") or ""
    return {
        "package": first(r"^package: name='([^']*)'"),
        "version_name": first(r"versionName='([^']*)'"),
        "minSdk": first(r"^minSdkVersion:'(\d+)'") or first(r"^sdkVersion:'(\d+)'"),
        "targetSdk": first(r"^targetSdkVersion:'(\d+)'"),
        "compileSdk": first(r"compileSdkVersion='(\d+)'") or first(r"compileSdkVersion:'(\d+)'"),
        "native_code": re.findall(r"'([^']+)'", native_line),
        "debuggable": bool(re.search(r"^application-debuggable$", text, re.M)),
    }
def parse_signing(text):
    schemes = {}
    for match in re.finditer(r"^Verified using v(\d) scheme.*: (true|false)\s*$", text, re.M):
        schemes["v" + match.group(1)] = match.group(2) == "true"
    return {
        "verifies": bool(re.search(r"^Verifies\s*$", text, re.M)),
        "schemes": schemes,
        "signers": len(re.findall(r"^Signer #\d+ certificate DN:", text, re.M)),
        "dns": re.findall(r"^Signer #\d+ certificate DN: (.+)$", text, re.M),
        "digests": re.findall(r"^Signer #\d+ certificate SHA-256 digest: ([0-9a-f]+)\s*$", text, re.M),
    }

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
        row = {"name": name, "start_epoch": time.time(), "start_monotonic": time.monotonic(),
               "excluded_logging_seconds": 0.0, "status": "running"}
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
            row["duration_seconds"] = round(
                time.monotonic() - row["start_monotonic"] - row["excluded_logging_seconds"], 6)
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


def network_429_urls(output):
    failed = set(re.findall(
        r"Download from (https://\S+) failed:[^\r\n]*(?:GET returned 429|HTTP response code: 429)",
        output,
    ))
    failed.update(re.findall(
        r"HTTP response code: 429 for URL: (https://[^\s)]+)",
        output,
    ))
    return sorted(failed)


def write_bazel_log(name, output):
    path = ROOT / "logs" / f"bazel-{name}.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(output or "", encoding="utf-8")
    return path

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
    duration_seconds = round(time.monotonic() - start_mono, 6)
    log_path = None
    if Path(safe_argv[0]).name == "bazel":
        log_index = len(state.get("commands", []))
        log_start = time.monotonic()
        log_path = write_bazel_log(
            f"{log_index:02d}-{re.sub(r'[^A-Za-z0-9_.-]', '-', name)}", text)
        for phase_row in reversed(state.get("phases", [])):
            if phase_row["status"] == "running":
                phase_row["excluded_logging_seconds"] += time.monotonic() - log_start
                break
    end_epoch = time.time()
    row = {"name": name, "argv": stored_argv, "cwd": str(cwd), "start_epoch": start_epoch,
           "end_epoch": end_epoch, "duration_seconds": duration_seconds,
           "exit_code": rc, "output_tail": text[-output_limit:]}
    if log_path:
        row["output_log"] = str(log_path)
    if name == "bazel-build-apk":
        failed_urls = network_429_urls(text)
        row["network_429_urls"] = failed_urls
        row["network_429_count"] = len(failed_urls)
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


def tracked_tree(engine):
    tree = ROOT / "trees" / engine
    if tree.exists():
        shutil.rmtree(tree)
    def exclude(_directory, names):
        return {name for name in names if name == ".git" or (engine == "stock" and name == ".ci-rules")}
    shutil.copytree(WS, tree, symlinks=True, ignore=exclude)
    if engine == "bazel":
        module_path = tree / "MODULE.bazel"
        module = module_path.read_text()
        start_marker = "# The proxy and the import stay in this Consumer Module"
        end_marker = "# This root module owns the Android SDK and NDK repositories and toolchains."
        start = module.find(start_marker)
        end = module.find(end_marker, start)
        if start < 0 or end < 0 or module.find(start_marker, start + 1) >= 0:
            raise RuntimeError("frozen app module does not match the benchmark overlay anchors")
        overlay = (SCRIPTS / "ci/benchmark/bazel-module-overlay.txt").read_text().rstrip()
        module_path.write_text(module[:start] + overlay + "\n\n" + module[end:])
        shutil.copy2(SCRIPTS / "ci/benchmark/bazel-overlay.MODULE.bazel.lock",
                     tree / "MODULE.bazel.lock")
    return tree

def verify_tool_identity(engine, tree, state, env):
    pin = flutter_pin()
    version = json.loads(command(state, "flutter-version", [SDK / "bin/flutter", "--version", "--machine"], tree, env))
    if (version.get("frameworkVersion") != pin["version"]
            or not isinstance(version.get("frameworkRevision"), str)
            or not version["frameworkRevision"]):
        raise RuntimeError("installed Flutter identity differs from the app's .fvmrc pin")
    state["identity"]["flutter_runtime"] = {"version": version.get("frameworkVersion"),
        "revision": version.get("frameworkRevision"), "dart": version.get("dartSdkVersion")}
    if engine == "bazel":
        rules = subprocess.run(["git", "-C", str(WS / ".ci-rules"), "rev-parse", "HEAD"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        rules_sha = os.environ.get("RULES_SHA", "")
        if rules.returncode or rules.stdout.strip() != rules_sha:
            raise RuntimeError("rules checkout differs from resolved commit")
        bazel_version = (tree / ".bazelversion").read_text().strip()
        if bazel_version != TOOL_VERSIONS["bazel"]["version"]:
            raise RuntimeError("app Bazel version pin differs from benchmark Bazel version")
        state["identity"]["rules_revision"] = rules.stdout.strip()
        state["identity"]["bazel_version"] = bazel_version
    save(state)
def dispatch_head():
    head = os.environ.get("GITHUB_SHA", "")
    if identity(SCRIPTS) != head:
        raise RuntimeError("benchmark scripts are not from the workflow commit")
    return head


def tracked_source_inventory(root: Path):
    listing = subprocess.run(
        ["git", "-C", str(WS), "ls-files", "-z", "--", "packages/smooth_app", "packages/app_store",
         "packages/scanner", "MODULE.bazel", "MODULE.bazel.lock", "plugin_deps.MODULE.bazel",
         ".bazelversion"],
        check=True, stdout=subprocess.PIPE).stdout.split(b"\0")
    return {
        raw.decode("utf-8", "surrogateescape"): file_hash(root / raw.decode("utf-8", "surrogateescape"))
        for raw in listing if raw
    }


def fingerprint_source_inventory(files):
    data = b"".join(
        rel.encode("utf-8", "surrogateescape") + b"\0" + (sha or "missing").encode() + b"\n"
        for rel, sha in sorted(files.items()))
    return {"count": len(files), "sha256": digest(data)}


def tracked_source_fingerprint(root: Path):
    return fingerprint_source_inventory(tracked_source_inventory(root))


def tracked_source_diagnostics(before, after, root: Path):
    changed = sorted(path for path in before.keys() | after.keys()
                     if before.get(path) != after.get(path))
    diffs = []
    for rel in changed[:12]:
        original, current = WS / rel, root / rel
        if not original.is_file() or not current.is_file():
            diffs.append(f"--- {rel}: original={original.is_file()} current={current.is_file()}")
            continue
        try:
            original_lines = original.read_text(errors="replace").splitlines(keepends=True)
            current_lines = current.read_text(errors="replace").splitlines(keepends=True)
            diff = list(difflib.unified_diff(original_lines, current_lines,
                fromfile=f"a/{rel}", tofile=f"b/{rel}", n=2))
        except OSError as error:
            diffs.append(f"--- {rel}: could not read diff: {error}")
            continue
        diffs.extend(line.rstrip("\n") for line in diff[:24])
        if len(diff) > 24:
            diffs.append("... diff truncated ...")
    return changed, diffs



def identity(root):
    result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError("git rev-parse HEAD failed")
    return result.stdout.strip()


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
    return "toplevel"


def requested_bazel_jobs(engine, scenario):
    if engine != "bazel":
        return None
    jobs = os.environ.get("APK_BAZEL_JOBS")
    if jobs != "128":
        raise RuntimeError("Bazel rows require APK_BAZEL_JOBS=128")
    return jobs


def proof_identity(identity):
    run, attempt, head = (identity[key] for key in ("run_id", "attempt", "head"))
    if not (re.fullmatch(r"[0-9]+", run) and re.fullmatch(r"[0-9]+", attempt)
            and re.fullmatch(r"[0-9a-f]{40}", head)):
        raise RuntimeError("APK proof requires exact run, attempt and commit identity")
    return f"{run}/{attempt}/{head}"


def policy_references(identity, env):
    prefix = proof_identity(identity)
    if identity["scenario"] == "cold":
        if env.get("APK_SEED_PROOF"): raise RuntimeError("unexpected seed proof for cold row")
        return {}
    match = re.fullmatch(prefix + r"/cold/([0-9a-f]{64})", env.get("APK_SEED_PROOF", ""))
    if not match: raise RuntimeError("cold seed proof missing or malformed")
    return {"seed_sha256": match[1]}

def require_policy_apk(scenario, references, apk_sha256):
    if scenario == "warm" and apk_sha256 != references["seed_sha256"]:
        raise RuntimeError("warm APK digest differs from cold/0 seed")
    if scenario == "lib" and apk_sha256 == references["seed_sha256"]:
        raise RuntimeError("edited APK digest equals the unchanged cold seed")


def cmd_prepare(args):
    download_outputs = requested_download_outputs(args.engine, args.scenario)
    bazel_jobs = requested_bazel_jobs(args.engine, args.scenario)
    ROOT.mkdir(parents=True, exist_ok=True)
    head = dispatch_head()
    tree = tracked_tree(args.engine)
    lock_metadata = None
    if args.engine == "bazel":
        try:
            lock_bytes = gzip.decompress(base64.b64decode(
                os.environ["APK_MODULE_LOCK_B64"], validate=True))
            lock_metadata = json.loads(os.environ["APK_LOCK_METADATA"])
        except (KeyError, ValueError, gzip.BadGzipFile, json.JSONDecodeError) as exc:
            raise RuntimeError("prepared module lock output is missing or malformed") from exc
        if (not isinstance(lock_metadata, dict)
                or lock_metadata.get("lock_sha256") != digest(lock_bytes)
                or not isinstance(lock_metadata.get("regenerated"), bool)
                or not isinstance(lock_metadata.get("diff_stat"), str)):
            raise RuntimeError("prepared module lock metadata does not match its payload")
        (tree / "MODULE.bazel.lock").write_bytes(lock_bytes)
    source_inventory = tracked_source_inventory(tree)
    missing_source = [path for path, sha in source_inventory.items() if sha is None]
    if missing_source:
        raise RuntimeError("tracked source missing before build: " + ", ".join(missing_source[:12]))
    json_write(ROOT / "tracked-source-before.json", source_inventory)
    repeat = int(os.environ.get("APK_REPEAT", "0"))
    app_commit = identity(WS)
    identity_row = {"head": head, "workflow_commit": head, "app_commit": app_commit,
                    "run_id": os.environ.get("GITHUB_RUN_ID", ""),
                    "attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
                    "engine": args.engine, "scenario": args.scenario, "repeat": repeat,
                    "download_outputs": download_outputs, "bazel_jobs": bazel_jobs,
                    "rules_revision": os.environ.get("RULES_SHA", ""), "library_source_sha256": file_hash(tree / LIB_REL),
                    "flutter": flutter_pin(), "bazel": TOOL_VERSIONS["bazel"]}
    state = {"schema": 1, "kind": "smooth-current-debug-apk-timing", "status": "prepared",
             "identity": identity_row, "runner": runner_metadata(),
             "build_config": {"target": APK_TARGET, "stock_target": ENTRYPOINT, "abi": "x86_64",
                              "mode": "debug", "bazel_configuration": "fastbuild",
                              "bazel_jobs": bazel_jobs,
                              "compile_sdk": 36, "build_tools": "36.0.0", "ndk": "28.2.13676358",
                              "java": 17, "lockfile_mode": "error"},
             "phases": [], "commands": [], "errors": [],
             "tree": str(tree), "tracked_source": fingerprint_source_inventory(source_inventory),
             "lock_diff": lock_metadata, "artifact": None, "cache_metrics": None}
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
    repeat = state["identity"].get("repeat") if state["identity"]["scenario"] == "cold" else 0
    if repeat not in (0, 1, 2, 3, 4):
        raise RuntimeError("remote salt requires repeat 0 through 4")
    identity_values = [str(state["identity"][key]) for key in ("run_id", "attempt", "head")]
    salt = "/".join(identity_values + [str(repeat)])
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


def bazel_argv(root, command_name, env, *, bep=None, remote=True, extra=(),
               output_base=None, repository_cache=None, lockfile_mode="error"):
    output_base = output_base or (ROOT / "bazel-output-base")
    repository_cache = repository_cache or repository_cache_path()
    args = [str(Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / "bazel"),
            "--nosystem_rc", "--nohome_rc", "--noworkspace_rc",
            "--output_base=" + str(output_base)]
    rc, scrub = run_remote_config(_ACTIVE_STATE) if remote else (None, None)
    if remote:
        args.append("--bazelrc=" + str(rc))
    args.append(command_name)
    args.append("--disk_cache=")
    args.append("--downloader_config=" + str(SCRIPTS / "ci/benchmark/maven-downloader.cfg"))
    if not remote:
        args.append("--remote_cache=")
    args += ["--repository_cache=" + str(repository_cache),
             "--repo_env=FLUTTER_ROOT=" + str(SDK), "--repo_env=ANDROID_HOME=" + env["ANDROID_HOME"],
             "--repo_env=ANDROID_NDK_HOME=" + env["ANDROID_NDK_HOME"],
             "--android_platforms=@rules_android//:x86_64", "--@rules_flutter_core//flutter:mode=debug",
             "-c", "fastbuild", "--merge_android_manifest_permissions", "--tool_java_language_version=17",
             "--tool_java_runtime_version=remotejdk_17", "--java_language_version=17",
             "--java_runtime_version=remotejdk_17", "--desugar_java8_libs", "--color=no", "--curses=no",
             "--jobs=128", "--experimental_record_metrics_for_all_mnemonics",
             "--@@protobuf+//bazel/toolchains:prefer_prebuilt_protoc",
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
    args.append("--lockfile_mode=" + lockfile_mode)
    args.append("deps(" + APK_TARGET + ")" if command_name == "aquery" else APK_TARGET)
    return args


_ACTIVE_STATE = {}




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
    records, names_seen, native_abis = [], set(), set()
    abi_elf = {"armeabi-v7a": (1, 40), "arm64-v8a": (2, 183), "x86_64": (2, X86_64_MACHINE)}
    with zipfile.ZipFile(apk) as zf:
        for info in zf.infolist():
            name = info.filename
            if unsafe_reason(name): raise RuntimeError(f"unsafe APK member {name!r}")
            if name in names_seen: raise RuntimeError("duplicate APK member name")
            names_seen.add(name)
            if name.startswith("lib/") and name.endswith(".so"):
                data = zf.read(info)
                parts = name.split("/")
                abi = parts[1] if len(parts) >= 3 else ""
                expected = abi_elf.get(abi)
                if (len(data) < 20 or data[:4] != b"\x7fELF" or data[5] != 1
                        or expected is None or (data[4], struct.unpack_from("<H", data, 18)[0]) != expected):
                    raise RuntimeError(f"native ABI/machine mismatch: {name}")
                native_abis.add(abi)
                records.append({"name": name, "bytes": len(data), "sha256": digest(data),
                                "elf_class": data[4], "elf_machine": expected[1]})
        required = {"assets/flutter_assets/kernel_blob.bin", "classes.dex", "lib/x86_64/libflutter.so"}
        if required - names_seen: raise RuntimeError("required APK members absent")
        if any(name.endswith("libapp.so") for name in names_seen): raise RuntimeError("libapp.so present; expected debug kernel APK")
    return records, names_seen, native_abis


def validate_apk(engine, tree, scenario, state):
    apk = Path(state["bazel_apk"]) if engine == "bazel" else tree / APK_REL
    if not apk.is_file() or apk.stat().st_size == 0:
        raise RuntimeError("built APK missing or empty")
    tools = Path(os.environ.get("APK_TREE_BUILD_TOOLS", os.environ["ANDROID_HOME"] + "/build-tools/36.0.0"))
    badging = command(state, "apk-badging", [tools / "aapt2", "dump", "badging", apk], tree, _ENV)
    signing = command(state, "apk-signature", [tools / "apksigner", "verify", "--print-certs", "-v", apk], tree, _ENV)
    facts = parse_badging(badging)
    sig = parse_signing(signing)
    for key, val in APK_BADGING_EXPECTED.items():
        if facts.get(key) != val:
            raise RuntimeError(f"APK badging {key}={facts.get(key)!r}, expected {val!r}")
    if not facts["debuggable"]:
        raise RuntimeError("APK is not debuggable")
    if not sig["verifies"] or not (sig["schemes"].get("v2") or sig["schemes"].get("v3")) or sig["signers"] != 1:
        raise RuntimeError("APK signature verification failed")
    natives, members, native_abis = native_inventory(apk)
    if "x86_64" not in native_abis or set(facts["native_code"]) != native_abis:
        raise RuntimeError(f"APK native ABIs {facts['native_code']!r} do not match ELF members {sorted(native_abis)!r}")
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
    command(state, label, [SDK / "bin/flutter", "pub", "get", "--enforce-lockfile"],
            tree / "packages/smooth_app", env, timeout=900)


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


def repository_cache_inventory(path):
    result = {}
    for name in ("content_addressable", "contents"):
        root = path / name
        files = 0
        byte_count = 0
        if root.is_dir():
            for item in root.rglob("*"):
                try:
                    if item.is_file():
                        files += 1
                        byte_count += item.stat().st_size
                except OSError:
                    raise RuntimeError(f"repository cache changed during inventory: {item}")
        result[name] = {"files": files, "bytes": byte_count}
    return result


def repository_cache_path():
    return ROOT / "repository-cache"


PROFILE_PHASES = {
    "Launch Blaze", "Initialize command", "Evaluate target patterns",
    "Load and analyze dependencies", "Load, analyze dependencies and build artifacts",
    "Analyze licenses", "Prepare for build", "Build artifacts", "Complete build",
}
PROFILE_MNEMONICS = (
    "DartJitKernel", "FlutterAssetBundle", "FlutterAssetCopy",
    "PackageAndroidResources", "ApkBuilder", "AndroidZipAlign",
    "ApkSignerTool", "DexBuilder", "Desugar", "Javac", "KotlinCompile",
)


def collect_profile(path):
    result = {"status": "missing", "cache_hit_distinction": "unavailable"}
    try:
        if not path.is_file():
            return result
        raw = path.read_bytes()
        if raw.startswith(b"\x1f\x8b"):
            raw = gzip.decompress(raw)
        document = json.loads(raw.decode("utf-8"))
        events = document.get("traceEvents") if isinstance(document, dict) else None
        if not isinstance(events, list):
            return {"status": "invalid", "cache_hit_distinction": "unavailable"}
        markers, actions = [], {name: {"count": 0, "duration_seconds": 0.0,
                                       "local_count": 0, "local_duration_seconds": 0.0,
                                       "remote_count": 0, "remote_duration_seconds": 0.0,
                                       "unknown_location_count": 0,
                                       "unknown_location_duration_seconds": 0.0}
                                for name in PROFILE_MNEMONICS}
        profile_end = 0.0
        for event in events:
            if not isinstance(event, dict):
                continue
            ts, duration = event.get("ts"), event.get("dur", 0)
            if not isinstance(ts, (int, float)) or isinstance(ts, bool):
                continue
            if isinstance(duration, (int, float)) and not isinstance(duration, bool) and duration >= 0:
                profile_end = max(profile_end, ts + duration)
            if event.get("cat") == "build phase marker" and event.get("name") in PROFILE_PHASES:
                if event.get("ph") in ("i", "I", "X"):
                    markers.append((float(ts), str(event["name"])))
            if (event.get("cat") != "action processing" or event.get("ph") != "X"
                    or not isinstance(duration, (int, float)) or isinstance(duration, bool) or duration < 0):
                continue
            args = event.get("args") if isinstance(event.get("args"), dict) else {}
            mnemonic = args.get("mnemonic")
            if mnemonic not in actions:
                continue
            seconds = float(duration) / 1_000_000
            row = actions[mnemonic]
            row["count"] += 1
            row["duration_seconds"] += seconds
            strategy = " ".join(str(args.get(k, "")) for k in ("strategy", "executor")).lower()
            location = "remote" if "remote" in strategy else "local" if any(
                value in strategy for value in ("local", "worker")) else "unknown_location"
            row[location + "_count"] += 1
            row[location + "_duration_seconds"] += seconds
        markers.sort()
        components = [{"name": name, "duration_seconds": round(
            max(0.0, ((markers[i + 1][0] if i + 1 < len(markers) else profile_end) - ts) / 1_000_000), 3)}
            for i, (ts, name) in enumerate(markers)]
        return {"status": "available", "cache_hit_distinction": "unavailable",
                "action_processing_semantics": "action-processing spans only; remote cache checks are excluded; cached-versus-executed status is not explicit",
                "build_phase_components": components,
                "mnemonics": {name: {key: round(value, 3) if key.endswith("seconds") else value
                                     for key, value in row.items()}
                              for name, row in actions.items()}}
    except (OSError, gzip.BadGzipFile, json.JSONDecodeError, UnicodeDecodeError):
        return {"status": "invalid", "cache_hit_distinction": "unavailable"}
    finally:
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
    counts = {"events": 0, "actions_completed": 0, "actions_failed": 0,
              "action_completed_mnemonics": {}, "mnemonics": {}}
    summary = re.findall(r"(?m)^INFO: (\d+) process(?:es)?: ([^\r\n]+)", build_log)
    if summary:
        total, breakdown = summary[-1]
        hits = re.search(r"\b(\d+) remote cache hits?\b", breakdown)
        internal = re.search(r"\b(\d+) internal\b", breakdown)
        counts["process_summary"] = {
            "total": int(total),
            "remote_cache_hits": int(hits[1]) if hits else 0,
            "internal": int(internal[1]) if internal else 0,
        }
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
                    started = event.get("started")
                    if started:
                        counts["build_tool_version"] = started.get("buildToolVersion")
                    completed = event.get("actionCompleted")
                    if completed:
                        counts["actions_completed"] += 1
                        counts["actions_failed"] += completed.get("success") is False
                        mnemonic = completed.get("mnemonic") or "unknown"
                        counts["action_completed_mnemonics"][mnemonic] = (
                            counts["action_completed_mnemonics"].get(mnemonic, 0) + 1)
                    metrics = event.get("buildMetrics")
                    if metrics:
                        action_summary = metrics.get("actionSummary") or {}
                        data = action_summary.get("actionData") or []
                        counts["mnemonics"] = {
                            item["mnemonic"]: int(item.get("actionsExecuted", 0))
                            for item in data
                            if item.get("mnemonic")
                            and str(item.get("actionsExecuted", "0")).isdigit()
                        }
                        counts["target_count"] = metrics.get("targetCount")
    finally:
        path.unlink(missing_ok=True)
    if not counts["events"]:
        raise RuntimeError("Bazel build-event stream is empty")
    # The .bazelversion pin does not prove what Bazelisk ran; the build's own event does.
    if counts.get("build_tool_version") != TOOL_VERSIONS["bazel"]["version"]:
        raise RuntimeError(f"Bazel ran {counts.get('build_tool_version')!r}, "
                           f"expected {TOOL_VERSIONS['bazel']['version']!r}")
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
    if ident["head"] != dispatch_head():
        raise RuntimeError("workflow checkout identity changed")
    if ident.get("app_commit") != identity(WS):
        raise RuntimeError("selected app checkout identity changed")
    mode = requested_download_outputs(args.engine, args.scenario)
    jobs = requested_bazel_jobs(args.engine, args.scenario)
    if ident.get("download_outputs") != mode or ident.get("bazel_jobs") != jobs:
        raise RuntimeError("download mode or jobs differs from prepared identity")
    references = policy_references(ident, os.environ) if mode else {}
    if mode and references != state.get("output_policy"):
        raise RuntimeError("APK digest references differ from prepared identity")
    if mode and (ident["run_id"], ident["attempt"]) != (os.environ.get("GITHUB_RUN_ID"),
                                                         os.environ.get("GITHUB_RUN_ATTEMPT")):
        raise RuntimeError("run or attempt differs from prepared identity")
    tree = Path(state["tree"])
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
    state["repeat"] = int(os.environ.get("APK_REPEAT", "0"))
    try:
        if args.engine == "stock":
            mirror_source = SCRIPTS / "ci/benchmark/stock-maven-mirror.init.gradle"
            mirror_installed = Path(env["GRADLE_USER_HOME"]) / "init.d" / mirror_source.name
            expected_mirror_hash = file_hash(mirror_source)
            if not expected_mirror_hash or file_hash(mirror_installed) != expected_mirror_hash:
                raise RuntimeError("stock Maven mirror init script is missing or differs from its tracked source")
            state["stock_gradle_mirror"] = {
                "script_sha256": expected_mirror_hash,
                "installed_path": "home/.gradle/init.d/" + mirror_source.name,
                "mirror_url": "https://maven-central.storage-download.googleapis.com/maven2",
            }
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
            repo_cache = repository_cache_path()
            state["repository_cache_before"] = repository_cache_inventory(repo_cache)
            with phase(state, "bazel-debug-apk-build"):
                build_log = command(
                    state, "bazel-build-apk",
                    bazel_argv(tree, "build", env, bep=bep,
                               extra=("--profile=" + str(profile_path), "--worker_quit_after_build")),
                    tree, env, timeout=3300, sample_resources=True,
                )
            state["repository_cache_after"] = repository_cache_inventory(repo_cache)
            if not bep.is_file():
                raise RuntimeError("Bazel did not produce required build event stream")
            query = command(state, "bazel-apk-output",
                            bazel_argv(tree, "cquery", env, extra=("--output=files",)),
                            tree, env, timeout=300)
            apk_name = APK_TARGET.rsplit(":", 1)[1] + ".apk"
            apks = [line.strip() for line in query.splitlines()
                    if Path(line.strip()).name == apk_name]
            if len(apks) != 1:
                raise RuntimeError(f"expected one public APK output, found {len(apks)}")
            state["bazel_apk"] = (
                apks[0] if Path(apks[0]).is_absolute() else str(tree / apks[0]))
        with phase(state, "artifact-validation"):
            validate_apk(args.engine, tree, args.scenario, state)
            if mode:
                require_policy_apk(args.scenario, references, state["artifact"]["sha256"])
                state["output_policy"]["passed"] = True
        state["required_result_epoch"] = time.time()
        state["required_result_duration_seconds"] = round(
            state["required_result_epoch"] - required_start, 6)
        if args.engine == "bazel":
            state["bazel_profile"] = collect_profile(profile_path)
            state["bazel_critical_path"] = final_critical_path(build_log)
            state["bazel_critical_path"]["components"] = state["bazel_profile"].get(
                "build_phase_components", [])
            state["bep_metrics"] = collect_bep(bep, build_log)
            summary = state["bep_metrics"].get("process_summary", {})
            if not isinstance(summary.get("total"), int) or isinstance(summary.get("total"), bool):
                raise RuntimeError("Bazel process summary is missing an integer process count")
            state["process_summary"] = {
                "processes": summary.get("total"),
                "remote_cache_hits": summary.get("remote_cache_hits", 0),
                "internal": summary.get("internal", 0),
            }
            build_row = next((row for row in reversed(state.get("commands", []))
                              if row.get("name") == "bazel-build-apk"), {})
            state["network_429_urls"] = build_row.get("network_429_urls", [])
            state["network_429_count"] = build_row.get("network_429_count", 0)
            with phase(state, "protoc-action-graph-post-result"):
                compile_graph = command(
                    state, "bazel-compile-action-graph",
                    bazel_argv(tree, "aquery", env,
                               extra=("--output=text", "--include_commandline",
                                      "--toolchain_resolution_debug=.*proto.*")),
                    tree, env, timeout=300,
                )
            actions = re.findall(r"(?ms)^action .*?:.*?(?=^action .*?:|\Z)", compile_graph)
            compile_actions = [a for a in actions if "Mnemonic: CppCompile" in a]
            link_actions = [a for a in actions if "Mnemonic: CppLink" in a]
            proto_actions = [a for a in actions if "Mnemonic: ProtoCompile" in a]
            protobuf_compiles = [a for a in compile_actions if "protoc" in a.lower()]
            protobuf_links = [a for a in link_actions if "protoc" in a.lower()]
            selected_proto_toolchains = []
            for line in compile_graph.splitlines():
                match = re.search(
                    r"type @@protobuf\+//bazel/private:proto_toolchain_type -> toolchain (\S+)",
                    line,
                )
                if match:
                    selected_proto_toolchains.append(match.group(1))
            state["protoc_selection"] = {
                "prefer_prebuilt_protoc_flag": True,
                "selected_proto_toolchain": selected_proto_toolchains[-1] if selected_proto_toolchains else None,
                "prebuilt_protoc_selected": any("prebuilt_protoc." in label for label in selected_proto_toolchains),
                "action_count": len(actions),
                "proto_compile_action_count": len(proto_actions),
                "prebuilt_protoc_proto_compile_action_count": sum(
                    "prebuilt_protoc" in action.lower() for action in proto_actions),
                "cpp_compile_action_count": len(compile_actions),
                "cpp_link_action_count": len(link_actions),
                "protobuf_cpp_compile_action_count": len(protobuf_compiles),
                "protobuf_cpp_link_action_count": len(protobuf_links),
            }
        state["status"] = "passed"
    except BaseException as exc:
        if args.engine == "bazel":
            build_row = next((row for row in reversed(state.get("commands", []))
                              if row.get("name") == "bazel-build-apk"), {})
            state["network_429_urls"] = build_row.get("network_429_urls", [])
            state["network_429_count"] = build_row.get("network_429_count", 0)
        if args.engine == "bazel" and profile_path is not None and "bazel_profile" not in state:
            state["bazel_profile"] = collect_profile(profile_path)
            state["bazel_critical_path"] = final_critical_path(build_log or "")
            state["bazel_critical_path"]["components"] = state["bazel_profile"].get(
                "build_phase_components", [])
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
        actual_inventory = tracked_source_inventory(tree)
        actual_sources = fingerprint_source_inventory(actual_inventory)
        before_inventory = json.loads((ROOT / "tracked-source-before.json").read_text())
        changed_paths, source_diffs = tracked_source_diagnostics(
            before_inventory, actual_inventory, tree)
        state["source_check"] = {"expected": state["tracked_source"], "actual": actual_sources,
                                 "changed": actual_sources != state["tracked_source"],
                                 "changed_paths": changed_paths, "short_diffs": source_diffs}
        if state["source_check"]["changed"]:
            details = "\n".join([*changed_paths, *source_diffs])
            print("tracked consumer source changed during build:\n" + details, file=sys.stderr)
            state["status"] = "failed"
            state["failure"] = {"type": "RuntimeError",
                                "message": "tracked consumer source changed during build: " + details[:1200]}
        clock = ROOT / "workflow-clock.json"
        if clock.is_file():
            state["workflow_clock"] = json.loads(clock.read_text())
            start = state["workflow_clock"].get("job_start_epoch")
            if start is not None and state.get("required_result_epoch") is not None:
                state["required_result_duration_seconds"] = round(
                    state["required_result_epoch"] - required_start, 6)
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
                              "download_outputs": None if args.engine != "bazel" else "toplevel",
                              "bazel_jobs": os.environ.get("APK_BAZEL_JOBS")},
                 "phases": [], "commands": [], "errors": []}
    for sidecar in (ROOT / "cache.json", ROOT / "workflow-clock.json"):
        if sidecar.is_file():
            try:
                key = "cache_metrics" if sidecar.name == "cache.json" else "workflow_clock"
                state[key] = json.loads(sidecar.read_text())
            except Exception as exc:
                state.setdefault("errors", []).append({"sidecar": sidecar.name, "error": str(exc)[:300]})
    timed_names = {"stock-flutter-build-apk", "bazel-build-apk"}
    compact_commands = []
    for row in state.get("commands", []):
        compact = {key: row.get(key) for key in ("name", "duration_seconds", "exit_code")}
        if row.get("name") in timed_names:
            compact["argv"] = row.get("argv")
        compact_commands.append(compact)
    state["commands"] = compact_commands
    state["workflow_job_status"] = os.environ.get("APK_TIMING_JOB_STATUS", "")
    envelope = {"schema": 1, "kind": "current-debug-apk-timing",
                "head": state.get("identity", {}).get("head", os.environ.get("GITHUB_SHA", "")),
                "run_id": state.get("identity", {}).get("run_id", os.environ.get("GITHUB_RUN_ID", "")),
                "attempt": state.get("identity", {}).get("attempt", os.environ.get("GITHUB_RUN_ATTEMPT", "")),
                "engine": state.get("identity", {}).get("engine", args.engine),
                "scenario": state.get("identity", {}).get("scenario", args.scenario), "body": state}
    raw = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > 256 * 1024:
        raise RuntimeError("compact timing proof exceeds 256 KiB")
    packed = base64.b64encode(gzip.compress(raw, mtime=0)).decode()
    chunks = [packed[i:i + 1800] for i in range(0, len(packed), 1800)]
    print("APK_TIMING_META " + json.dumps({"encoding": "gzip+base64", "chunks": len(chunks), "sha256": digest(raw)}, separators=(",", ":")))
    for i, chunk in enumerate(chunks, 1):
        print(f"APK_TIMING_CHUNK {i}/{len(chunks)} {chunk}")
def cmd_prepare_lock(_args):
    ROOT.mkdir(parents=True, exist_ok=True)
    if dispatch_head() != identity(SCRIPTS):
        raise RuntimeError("benchmark scripts are not from the workflow commit")
    tree = tracked_tree("bazel")
    rules = subprocess.run(["git", "-C", str(WS / ".ci-rules"), "rev-parse", "HEAD"],
                           text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    expected_rules = os.environ.get("RULES_SHA", "")
    if rules.returncode or rules.stdout.strip() != expected_rules:
        raise RuntimeError("rules checkout differs from resolved commit")
    scratch = ROOT / "module-lock-probe"
    if scratch.exists():
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True)
    probe_state = {"identity": {"run_id": os.environ.get("GITHUB_RUN_ID", ""),
                                "attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
                                "head": os.environ.get("GITHUB_SHA", ""),
                                "engine": "bazel", "scenario": "cold", "repeat": 0}}
    env = job_env("bazel", probe_state)
    bazel = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())) / "bazel"
    output_base = scratch / "output-base"
    repository_cache = scratch / "repository-cache"
    baseline = SCRIPTS / "ci/benchmark/bazel-overlay.MODULE.bazel.lock"
    try:
        result = subprocess.run(
            bazel_argv(tree, "build", env, remote=False, extra=("--nobuild",),
                       output_base=output_base, repository_cache=repository_cache,
                       lockfile_mode="error"),
            cwd=tree, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        write_bazel_log("prepare-lock-error", result.stdout)
        regenerated = False
        if result.returncode:
            result = subprocess.run(
                bazel_argv(tree, "build", env, remote=False, extra=("--nobuild",),
                           output_base=output_base, repository_cache=repository_cache,
                           lockfile_mode="update"),
                cwd=tree, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            write_bazel_log("prepare-lock-update", result.stdout)
            regenerated = result.returncode == 0
        if result.returncode:
            raise RuntimeError("Bazel module lock probe/update failed: " + result.stdout[-4000:])
    finally:
        shutdown = subprocess.run(
            [str(bazel), "--nosystem_rc", "--nohome_rc", "--noworkspace_rc",
             "--output_base=" + str(output_base), "shutdown"],
            cwd=tree, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        write_bazel_log("prepare-lock-shutdown", shutdown.stdout)
        shutil.rmtree(scratch, ignore_errors=True)
        if shutdown.returncode:
            raise RuntimeError("Bazel module-lock server shutdown failed: " + shutdown.stdout[-2000:])
    lock_bytes = (tree / "MODULE.bazel.lock").read_bytes()
    baseline_lines = baseline.read_text().splitlines()
    current_lines = lock_bytes.decode().splitlines()
    matcher = difflib.SequenceMatcher(a=baseline_lines, b=current_lines)
    added = removed = 0
    for tag, first, last, new_first, new_last in matcher.get_opcodes():
        if tag in ("insert", "replace"):
            added += new_last - new_first
        if tag in ("delete", "replace"):
            removed += last - first
    diff_stat = ("no change" if added == removed == 0 else
                 f"MODULE.bazel.lock | {added + removed} lines changed (+{added} -{removed})")
    metadata = {"regenerated": regenerated, "diff_stat": diff_stat,
                "lock_sha256": digest(lock_bytes)}
    encoded_lock = base64.b64encode(gzip.compress(lock_bytes, mtime=0)).decode("ascii")
    encoded_metadata = json.dumps(metadata, sort_keys=True, separators=(",", ":"))
    # Rows receive the lock as one environment string; Linux caps each at 128 KiB.
    if len(encoded_lock) + len(encoded_metadata) > 120_000:
        raise RuntimeError("prepared lock outputs exceed the per-variable environment limit")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write("module_lock=" + encoded_lock + "\n")
        output.write("lock_metadata=" + encoded_metadata + "\n")
    print(json.dumps({**metadata, "lock_output_bytes": len(encoded_lock)}))
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
    expected_pack_status = "ok" if ident.get("scenario") == "cold" and int(ident.get("repeat", 0)) == 0 else "skipped"
    packed = [op for op in operations if op.get("command") == "pack"]
    if not packed or packed[-1].get("status") != expected_pack_status:
        issues.append("cache pack status does not match expected publication")
    if expected_pack_status == "ok" and packed:
        expected_key = cold_key
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
    sub.add_parser("prepare-lock")
    for name in ("prepare", "run", "emit", "verify"):
        item = sub.add_parser(name)
        item.add_argument("--engine", choices=ENGINES, required=True)
        item.add_argument("--scenario", choices=SCENARIOS, required=True)
    args = parser.parse_args()
    try:
        if args.command == "prepare-lock":
            return cmd_prepare_lock(args)
        return {"prepare": cmd_prepare, "run": cmd_run, "emit": cmd_emit,
                "verify": cmd_verify}[args.command](args)
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
