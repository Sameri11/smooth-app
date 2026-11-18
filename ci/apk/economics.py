#!/usr/bin/env python3
"""Smooth debug APK feasibility driver: stock Flutter arm vs Bazel arm.

Subcommands, in workflow order:
  build    stock and Bazel x86_64 debug APKs from isolated source trees, plus inventories.
           Exits 0 only when at least one arm is contract-valid; otherwise exits 1.
  runtime  every contract-valid arm on the emulator (apk_runtime.py), deadline-bound.
  emit     always: logs-only gzip+base64 evidence envelope. Never raises.
  verdict  always, after emit: machine gates. Manual visual review stays pending.

Scope: bounded equivalence evidence for this experiment. File hashes, DEX class and member
inventories, structural manifest and compiled-resource records and exported dynamic symbols
show equality of what was inventoried. They do not prove semantic equivalence: method bodies,
constants and native behaviour are not compared.

State: $RUNNER_TEMP/apk-economics (task-owned, never uploaded). Stdlib only.
APK_DEADLINE_EPOCH and APK_STEP_DEADLINE_EPOCH: the earlier of the two caps build and runtime only; emit and verdict ignore both.
"""

from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apk_runtime  # noqa: E402

WS = Path(__file__).resolve().parents[2]
TASK = Path(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()) / "apk-economics"
STATE_FILE = TASK / "state.json"

KIND = "smooth-debug-apk-feasibility"
PACKAGE = "org.openfoodfacts.scanner"
ENTRYPOINT = "lib/entrypoints/android/main_google_play.dart"
APP_DIR = "packages/smooth_app"
APP_BAZEL = "//packages/smooth_app/android/app"
APK_TARGET = f"{APP_BAZEL}:smooth_app"
CHECK_TARGETS = [f"{APP_BAZEL}:smooth_app_check_test", f"{APP_BAZEL}:plugin_deps_guards_test"]
APP_TEST_PACKAGE = "//packages/smooth_app:app_test_package"
UPDATE_TARGETS = [f"{APP_BAZEL}:plugin_deps_update", "//packages/smooth_app:dart_registrant_update"]
SEEDED = ["plugin_deps.MODULE.bazel", f"{APP_DIR}/lib/dart_plugin_registrant.dart"]
BAZEL_ALLOWED = frozenset({"MODULE.bazel.lock", *SEEDED})
STOCK_APK_REL = "build/app/outputs/flutter-apk/app-debug.apk"
L10N_DIR = f"{APP_DIR}/lib/l10n"
L10N_AGGREGATE = f"{L10N_DIR}/app_localizations.dart"
LOCALE_IMPORT_RE = re.compile(r"^import '(app_localizations_[A-Za-z0-9_]+\.dart)';$", re.MULTILINE)
ARMS = ("stock", "bazel")
RULES_REVISION = "6ab5ab906916abfdbd80d8a843bee87df500766d"
EXPECT = {
    "flutter": "3.41.8",
    "bazel": "9.2.0",
    "abis": ["x86_64"],
    "minSdk": "24",
    "targetSdk": "36",
    "compileSdk": "36",
    "ndk": "28.2.13676358",
    "build_tools": "36.0.0",
}

# sqlite3 is pinned to the version frozen in packages/smooth_app/pubspec.lock (3.3.3).
# SQLITE_X64_SHA is libsqlite3.x64.android.so as published by that package's own hook
# (lib/src/hook/asset_hashes.dart in sqlite3-3.3.3); checked against the pub cache.
SQLITE_PACKAGE = "sqlite3"
SQLITE_PACKAGE_VERSION = "3.3.3"
SQLITE_X64_SHA = "52c7183d99b1d85df5d09d9cf11613213f92121756df2562e7319fbe6b2a00b3"
RIVE_LIB = "lib/x86_64/librive_native.so"
# Packaged bytes of pinned natives must be the verified original or the verified
# llvm-strip --strip-unneeded output, per name. Nothing else is accepted.
PINNED_APK_NATIVES = {
    "lib/x86_64/libsqlite3.so": {
        SQLITE_X64_SHA: 1802504,
        "51738906518a591f118b18601135bcbcbfa28fbfdfa6a8aeacbff4d875163da0": 1703640,
    },
    RIVE_LIB: {
        "b4f78fcde381c44537e1351b949db91ce4cf42f1c5b98e613e2ed5a14f84b779": 9354568,
        "8ad222ac8ea20f9f46a216d66bac37d68b1607cde805439aa87b712a7e6b59e1": 7833048,
    },
}
# Exported dynamic symbols (count, sha256) of each pinned native, observed on the stock APK.
PINNED_EXPORTS = {
    "lib/x86_64/libsqlite3.so": (330, "f4a20c277319cd780f4af42a2b467c3cdd6afb955512c39ad7f6c9fe0977cc9c"),
    RIVE_LIB: (11014, "6628c32ed7113ccd38d7584af0dd3ae3d99c2c0aeafe062211827cba53655b8f"),
}
# Differing natives reviewed by Main, keyed by (name, stock sha256, bazel sha256) -> reason.
# Empty until Main classifies each from source and runtime; a name alone never matches.
NATIVE_CLASSIFIED: dict = {}
AGP_METADATA = "META-INF/com/android/build/gradle/app-metadata.properties"
# Kinds that keep parity pending rather than failing the runtime gate.
PENDING_KINDS = frozenset({"kernel", "native_pending"})
X86_64_MACHINE = 62
DEBUG_ALIAS = "androiddebugkey"
DEBUG_STOREPASS = "android"

CHUNK_CHARS = 1900
MAX_CHUNKS = 12000
MAX_RAW = 24 * 1024 * 1024
DIAG_TAIL = 4000
RUNTIME_MAX = 840
STATE_RESERVE = 60
_DEADLINE_VARS = ("APK_DEADLINE_EPOCH", "APK_STEP_DEADLINE_EPOCH")


def deadline_epoch():
    """Earlier of the step and global deadlines. Only build and runtime call this."""
    values = [int(float(os.environ[name])) for name in _DEADLINE_VARS if os.environ.get(name)]
    return min(values) if values else int(time.time() + 3300)


DEADLINE = 0
END_AT = 0.0
MEM: dict = {}
STATE: dict = {}

DEX_RE = re.compile(r"classes\d*\.dex")
SIGNING_RE = re.compile(r"META-INF/(MANIFEST\.MF|[^/]+\.(SF|RSA|DSA|EC))")
UNRES_RE = re.compile(r"unresolved:0x[0-9a-f]+")
KEYSTORE_ATTRS = ("debug_key", "debug_keystore", "keystore", "signing_key")
RES_HEADER = re.compile(r"^\s*resource (0x[0-9a-fA-F]+) (\S+)")
RES_NOISE = re.compile(r"^\s*(type|Package|spec)\b")
REF_RE = re.compile(r"@0x([0-9a-fA-F]{8})\b")
ELEM_LINE = re.compile(r"^(\s*)E: ([^\s(]+)")
ATTR_LINE = re.compile(r"^(\s*)A: ([^\s(=]+)(?:\(0x[0-9a-fA-F]+\))?=(.*)$")

LOSS_ORDER = ["command_tails", "allowed_items", "failure_png", "mandatory_png"]
REQUIRED_LOSS = frozenset({"mandatory_png"})
SKIP_CATS = frozenset({"dex", "manifest", "arsc", "res_xml", "native"})
SCOPE = (
    "bounded equivalence evidence: file hashes; DEX class and member inventories; structural "
    "manifest and compiled-resource records; exported dynamic symbols of native libraries. "
    "Not semantic equivalence: method bodies, constants and native behaviour are not compared."
)
LIMITATIONS = [
    SCOPE,
    "Kernel blob bytes clear only when both arms' VM script source hashes and widget-creation flag match; otherwise they stay pending.",
    "Differing native libraries stay native_pending until Main classifies each from source and runtime; exports, NEEDED and .comment are recorded.",
    "Native equality after llvm-strip normalisation is content equality after non-runtime symbol removal, not semantic equivalence.",
    "Same member inventory does not excuse a different library when pinned provenance differs.",
    "Runtime proves one scripted offline onboarding path on one emulator (API 34 google_apis x86_64).",
    "visual_review is pending: research parity is not accepted until Main records a real view of the PNGs.",
]


class StageError(RuntimeError):
    pass


class DeadlineError(StageError):
    pass


class DexError(ValueError):
    pass


def log(message):
    print(f"[apk-economics] {message}", flush=True)


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def slug(text):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_")[:120] or "x"


def tail(text, limit=DIAG_TAIL):
    return (text or "")[-limit:]


def as_text(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


def env_required(name):
    value = os.environ.get(name)
    if not value:
        raise StageError(f"{name} is unset")
    return value


def flutter_bin():
    return Path(env_required("FLUTTER_ROOT")) / "bin" / "flutter"


def build_tools():
    return Path(env_required("ANDROID_HOME")) / "build-tools" / EXPECT["build_tools"]


def ndk_nm():
    return Path(env_required("ANDROID_NDK_HOME")) / "toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-nm"


def blank_state():
    return {
        "schema": 1,
        "kind": KIND,
        "status": "started",
        "failure": None,
        "identity": {
            "head": None,
            "run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            "started_epoch": time.time(),
            "flutter": None,
            "bazel": None,
            "sqlite3_locked": None,
        },
        "stages": [],
        "commands": [],
        "disk": [],
        "arms": {},
        "arm_failures": [],
        "valid_arms": [],
        "comparison": None,
        "runtime": None,
        "runtime_status": "not_run",
    }


def save_state():
    TASK.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(STATE, indent=1, sort_keys=True), encoding="utf-8")
    tmp.replace(STATE_FILE)


def load_state():
    global STATE
    STATE = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return STATE


def load_or_default():
    global STATE
    try:
        return load_state()
    except (OSError, ValueError) as exc:
        STATE = blank_state()
        STATE["status"] = "missing_state"
        STATE["failure"] = f"state unreadable: {type(exc).__name__}: {exc}"[:500]
        return STATE


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def clamp(timeout):
    left = END_AT - time.time()
    if left < 10:
        raise DeadlineError(f"under {max(left, 0):.0f} s of budget left")
    return min(float(timeout), left)


def tool_env():
    env = dict(os.environ)
    env["HOME"] = str(TASK / "home")
    env["ANDROID_USER_HOME"] = str(TASK / "home" / ".android")
    env["TMPDIR"] = str(TASK / "tmp")
    env.setdefault("LC_ALL", "C.UTF-8")
    return env


def public_argv(argv):
    out, hide = [], False
    for item in argv:
        text = str(item)
        if hide:
            out.append("***")
            hide = False
            continue
        out.append(text)
        if text in ("-storepass", "-keypass"):
            hide = True
    return out


def run(label, argv, cwd, timeout, record=True):
    limit = clamp(timeout)
    started = time.time()
    rc, out, err = 127, "", ""
    log(f"command_start label={label} timeout_seconds={limit:.1f}")
    try:
        proc = subprocess.run(
            [str(item) for item in argv],
            cwd=str(cwd),
            env=tool_env(),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=limit,
            check=False,
        )
        rc, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        rc, out, err = 124, as_text(exc.stdout), as_text(exc.stderr)
    except OSError as exc:
        rc, out, err = 127, "", f"{type(exc).__name__}: {exc}"
    entry = {
        "label": label,
        "argv": public_argv(argv),
        "rc": rc,
        "seconds": round(time.time() - started, 1),
    }
    if record:
        entry["stdout_tail"] = tail(out)
        entry["stderr_tail"] = tail(err)
        if rc != 0:
            entry["stdout_head"] = out[:16000]
            entry["stderr_head"] = err[:16000]
    STATE["commands"].append(entry)
    save_state()
    log(f"command_end label={label} rc={rc} seconds={entry['seconds']}")
    if rc != 0:
        raise StageError(f"{label} exited {rc}: {tail(err or out, 600)}")
    return out


@contextmanager
def stage(name):
    started = time.time()
    entry = {"name": name, "status": "running"}
    STATE["stages"].append(entry)
    try:
        yield
        entry["status"] = "ok"
    except BaseException as exc:
        entry["status"] = "fail"
        entry["error"] = f"{type(exc).__name__}: {exc}"[:800]
        raise
    finally:
        entry["seconds"] = round(time.time() - started, 1)
        save_state()


def require_free(label):
    free_gib = shutil.disk_usage(TASK).free / 2**30
    minimum = float(os.environ.get("APK_MIN_FREE_GIB", "20"))
    STATE["disk"].append({"label": label, "free_gib": round(free_gib, 2)})
    if free_gib < minimum:
        raise StageError(f"{label}: {free_gib:.1f} GiB free, minimum {minimum} GiB")


def git_show(rel):
    return subprocess.run(
        ["git", "-C", str(WS), "show", f"{STATE['identity']['head']}:{rel}"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def git_head():
    return subprocess.run(
        ["git", "-C", str(WS), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def load_inputs():
    return json.loads((WS / "ci/economics/inputs.json").read_text(encoding="utf-8"))


def check_identity(inputs):
    if inputs.get("schema") != 1:
        raise StageError("inputs.json schema is not 1")
    if inputs["rules"]["revision"] != RULES_REVISION:
        raise StageError(f"rules revision {inputs['rules']['revision']} != {RULES_REVISION}")
    if inputs["flutter"]["version"] != EXPECT["flutter"]:
        raise StageError("inputs.json Flutter version is not 3.41.8")
    if inputs["bazel"]["version"] != EXPECT["bazel"]:
        raise StageError("inputs.json Bazel version is not 9.2.0")
    for rel, want in sorted(inputs["inputs"].items()):
        if sha256_file(WS / rel) != want:
            raise StageError(f"frozen input differs in worktree: {rel}")
    text = "\n" + git_show(f"{APP_DIR}/pubspec.lock")
    match = re.search(r'\n  sqlite3:\n(?:    [^\n]*\n)*?    version: "([^"]+)"', text)
    locked = match.group(1) if match else None
    if locked != SQLITE_PACKAGE_VERSION:
        raise StageError(f"locked {SQLITE_PACKAGE} is {locked}, pinned {SQLITE_PACKAGE_VERSION}")
    STATE["identity"]["sqlite3_locked"] = locked


def sdk_identity():
    text = run("flutter-version", [flutter_bin(), "--version"], WS, 300, record=False)
    if not re.search(rf"Flutter {re.escape(EXPECT['flutter'])}\b", text):
        raise StageError("flutter is not 3.41.8")
    bazel_text = run("bazel-version", ["bazel", "--version"], WS, 120, record=False)
    if f"bazel {EXPECT['bazel']}" not in bazel_text:
        raise StageError("bazel is not 9.2.0")
    if not build_tools().is_dir():
        raise StageError(f"build-tools {EXPECT['build_tools']} absent")
    if Path(env_required("ANDROID_NDK_HOME")).name != EXPECT["ndk"]:
        raise StageError(f"ANDROID_NDK_HOME is not NDK {EXPECT['ndk']}")
    if not (Path(env_required("ANDROID_HOME")) / "platforms" / "android-36").is_dir():
        raise StageError("platform android-36 absent")
    STATE["identity"]["flutter"] = EXPECT["flutter"]
    STATE["identity"]["bazel"] = EXPECT["bazel"]


def gradle_pins():
    path = Path(env_required("FLUTTER_ROOT")) / "packages/flutter_tools/gradle/src/main/kotlin/FlutterExtension.kt"
    text = path.read_text(encoding="utf-8")

    def first(pattern):
        match = re.search(pattern, text)
        return match.group(1) if match else None

    values = {
        "compileSdk": first(r"val compileSdkVersion: Int = (\d+)"),
        "minSdk": first(r"val minSdkVersion: Int = (\d+)"),
        "targetSdk": first(r"val targetSdkVersion: Int = (\d+)"),
        "ndk": first(r"val ndkVersion: String = \"([^\"]+)\""),
    }
    want = {
        "compileSdk": EXPECT["compileSdk"],
        "minSdk": EXPECT["minSdk"],
        "targetSdk": EXPECT["targetSdk"],
        "ndk": EXPECT["ndk"],
    }
    if values != want:
        raise StageError(f"FlutterExtension.kt pins {values} != {want}")
    return {"file": str(path), "sha256": sha256_file(path), "values": values}


def make_tree(arm):
    head = STATE["identity"]["head"]
    root = TASK / "trees" / arm
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    git = subprocess.Popen(
        ["git", "-C", str(WS), "archive", "--format=tar", head],
        stdout=subprocess.PIPE,
        env=tool_env(),
    )
    try:
        with tarfile.open(fileobj=git.stdout, mode="r|") as archive:
            archive.extractall(root, filter="data")
    finally:
        git.stdout.close()
    if git.wait() != 0:
        raise StageError(f"git archive {head} failed")
    if arm == "bazel":
        shutil.copytree(WS / ".ci-rules", root / ".ci-rules", symlinks=True, ignore=shutil.ignore_patterns(".git"))
    return root


SNAP_SKIP_ANYWHERE = {".dart_tool", ".gradle", ".git"}
SNAP_SKIP_TOP = {"build", ".ci-rules"}


def snapshot_tree(root):
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        at_top = here == root
        keep = []
        for name in dirnames:
            if name in SNAP_SKIP_ANYWHERE:
                continue
            if at_top and (name in SNAP_SKIP_TOP or name.startswith("bazel-")):
                continue
            keep.append(name)
        dirnames[:] = keep
        for name in filenames:
            path = here / name
            if path.is_symlink():
                continue
            out[path.relative_to(root).as_posix()] = sha256_file(path)
    return out


def source_check(rec, root, before, allowed):
    after = snapshot_tree(root)
    changed = sorted(p for p, digest in before.items() if after.get(p) != digest)
    unexpected = [p for p in changed if p not in allowed]
    rec["source_check"] = {"changed": changed, "allowed": sorted(allowed), "unexpected": unexpected}
    if unexpected:
        raise StageError(f"tracked source changed outside the allowed set: {unexpected}")


def verify_locks(root, inputs):
    for rel, want in sorted(inputs["inputs"].items()):
        path = root / rel
        if not path.is_file():
            raise StageError(f"frozen input missing in tree: {rel}")
        if sha256_file(path) != want:
            raise StageError(f"frozen input differs in tree: {rel}")


def require_seeded(root):
    for rel in SEEDED:
        path = root / rel
        if not path.is_file() or path.stat().st_size == 0:
            raise StageError(f"seeded input absent or empty: {rel}")


def bazel_startup():
    return ["bazel", "--nosystem_rc", "--nohome_rc", "--noworkspace_rc", f"--output_base={TASK / 'bazel-output-base'}"]

def bazel_repository_options():
    return [
        f"--repository_cache={TASK / 'repository-cache'}",
        f"--repo_env=FLUTTER_ROOT={env_required('FLUTTER_ROOT')}",
        f"--repo_env=ANDROID_HOME={env_required('ANDROID_HOME')}",
        f"--repo_env=ANDROID_NDK_HOME={env_required('ANDROID_NDK_HOME')}",
    ]



def bazel_common():
    return [
        *bazel_repository_options(),
        "--jobs=2",
        "--android_platforms=@rules_android//:x86_64",
        "--@rules_flutter_core//flutter:mode=debug",
        "-c", "fastbuild",
        "--merge_android_manifest_permissions",
        "--tool_java_language_version=17",
        "--tool_java_runtime_version=remotejdk_17",
        "--java_language_version=17",
        "--java_runtime_version=remotejdk_17",
    ]


def bazel_argv(command, lockmode, targets=(), extra=()):
    return [*bazel_startup(), command, *bazel_common(), *extra, f"--lockfile_mode={lockmode}", *targets]


def bazel_files(root, target):
    out = run(f"bazel-files-{slug(target)}", bazel_argv("cquery", "error", [target], extra=["--output=files"]), root, 300, record=False)
    info = [*bazel_startup(), "info", *bazel_repository_options()]
    execroot = Path(run("bazel-execroot", [*info, "execution_root"], root, 300, record=False).strip())
    output_base = Path(run("bazel-output-base", [*info, "output_base"], root, 300, record=False).strip())
    paths = []
    for line in out.splitlines():
        if line.strip():
            path = Path(line.strip())
            base = output_base if path.parts[0] == "external" else execroot
            paths.append(path if path.is_absolute() else base / path)
    return paths


def keystore_cert(path, label):
    out = TASK / "keystores" / f"{label}.der"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.unlink(missing_ok=True)
    run(
        f"keytool-{label}",
        ["keytool", "-exportcert", "-noprompt", "-alias", DEBUG_ALIAS, "-storepass", DEBUG_STOREPASS, "-keystore", path, "-file", out],
        TASK,
        120,
    )
    if not out.is_file() or out.stat().st_size == 0:
        raise StageError(f"{label}: keytool exported no certificate")
    return sha256_file(out)


def stock_keystore():
    path = TASK / "home" / ".android" / "debug.keystore"
    if not path.is_file():
        raise StageError("AGP debug keystore absent under task HOME")
    if path.stat().st_mtime < STATE["identity"]["started_epoch"]:
        raise StageError("AGP debug keystore predates this job")
    return {
        "path": str(path),
        "cert_sha256": keystore_cert(path, "stock-debug"),
        "provenance": "created by AGP under the task HOME during this job",
    }


def bazel_keystore(root):
    try:
        argv = [
            *bazel_startup(), "query", *bazel_repository_options(), "--nofetch",
            "--lockfile_mode=error", "--output=xml", "--xml:default_values", APK_TARGET,
        ]
        text = run("bazel-query-xml", argv, root, 300, record=False)
        attrs = {}
        for el in ET.fromstring(text).iter("label"):
            if el.get("name") in KEYSTORE_ATTRS and el.get("value"):
                attrs.setdefault(el.get("name"), el.get("value"))
        if not attrs:
            return None, f"APK target exposes no keystore attribute among {KEYSTORE_ATTRS} (xml:default_values)"
        attr, label = next(iter(attrs.items()))
        paths = bazel_files(root, label)
        if len(paths) != 1:
            return None, f"keystore label {label} resolves to {len(paths)} files"
        return {
            "label": label,
            "attribute": attr,
            "path": str(paths[0]),
            "cert_sha256": keystore_cert(paths[0], "bazel-debug"),
            "provenance": f"default {attr} of the APK target, from bazel query --xml:default_values",
        }, "declared"
    except (StageError, ET.ParseError) as exc:
        if isinstance(exc, DeadlineError):
            raise
        return None, f"keystore resolution failed: {exc}"[:500]


def unsafe_reason(name):
    if not name:
        return "empty member name"
    if name.startswith("/") or "\\" in name or re.match(r"^[A-Za-z]:", name):
        return "absolute or backslash path"
    parts = name.split("/")
    if any(part in ("", "..") for part in parts[:-1]) or parts[-1] == "..":
        return "empty or traversal component"
    return None


def native_toolchain(name, path, nm):
    readelf = Path(nm).with_name("llvm-readelf")
    try:
        dynamic = run(f"readelf-dynamic-{slug(name)}", [readelf, "-d", path], TASK, 120, record=False)
        comment = run(f"readelf-comment-{slug(name)}", [readelf, "-p", ".comment", path], TASK, 120, record=False)
    except DeadlineError:
        raise
    except StageError as exc:
        return [], [], str(exc)[:300]
    needed = sorted(re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", dynamic))
    notes = sorted({m.group(1).strip() for m in re.finditer(r"\]\s+(.+)$", comment, re.M)})
    return needed, notes, None


def normalize_native(name, path, nm_tool):
    """Normalise a distinct copy with the pinned NDK strip; the packaged bytes stay untouched."""
    strip = Path(nm_tool).with_name("llvm-strip")
    copy = path.with_name(path.stem + ".normalized.so")
    try:
        shutil.copyfile(path, copy)
        first = run(f"strip-version-{slug(name)}", [strip, "--version"], TASK, 60, record=False).strip().splitlines()
        if not first:
            raise StageError("llvm-strip printed no version")
        run(f"strip-{slug(name)}", [strip, "--strip-unneeded", copy], TASK, 120, record=False)
        data = copy.read_bytes()
    except DeadlineError:
        raise
    except (StageError, OSError) as exc:
        return {"normalized_sha256": None, "normalized_bytes": None, "normalize_command": None, "normalize_tool": None, "normalize_error": f"{type(exc).__name__}: {str(exc)[:300]}"}
    return {"normalized_sha256": sha256_bytes(data), "normalized_bytes": len(data), "normalize_command": "llvm-strip --strip-unneeded", "normalize_tool": "\n".join(first), "normalize_error": None}


def native_record(name, data, path, nm):
    rec = {
        "name": name,
        "sha256": sha256_bytes(data),
        "bytes": len(data),
        "elf_machine": None,
        "dynsym_count": None,
        "dynsym_sha256": None,
        "errors": [],
    }
    if data[:4] != b"\x7fELF" or len(data) < 20:
        rec["errors"].append("not an ELF file")
        return rec
    rec["elf_machine"] = struct.unpack_from("<H", data, 18)[0]
    if data[4] != 2 or data[5] != 1:
        rec["errors"].append("not ELF64 little-endian")
    try:
        out = run(f"nm-{slug(name)}", [nm, "-D", "--defined-only", path], TASK, 120, record=False)
    except DeadlineError:
        raise
    except StageError as exc:
        rec["errors"].append(f"llvm-nm failed: {str(exc)[:300]}")
        return rec
    symbols = sorted(line.split()[-1] for line in out.splitlines() if line.strip())
    rec["dynsym_count"] = len(symbols)
    rec["dynsym_sha256"] = sha256_bytes("\n".join(symbols).encode("utf-8"))
    if not symbols:
        rec["errors"].append("no exported dynamic symbols parsed")
    rec["needed"], rec["comment"], rec["readelf_error"] = native_toolchain(name, path, nm)
    rec.update(normalize_native(name, path, nm))
    return rec


def read_apk(apk, extract, nm, facts):
    blobs = []
    with zipfile.ZipFile(apk) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(set(names)) != len(names):
            facts["parse_errors"].append("duplicate zip member names")
        for info in infos:
            name = info.filename
            reason = unsafe_reason(name)
            if reason:
                facts["unsafe_names"].append(f"{name!r}: {reason}")
                continue
            data = archive.read(info)
            digest = sha256_bytes(data)
            facts["entries"].append({
                "name": name,
                "bytes": len(data),
                "sha256": digest,
                "compressed_bytes": info.compress_size,
                "compression": info.compress_type,
            })
            if name == "assets/flutter_assets/NativeAssetsManifest.json":
                try:
                    facts["native_assets_manifest"] = json.loads(data)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    facts["parse_errors"].append(f"{name}: {exc}")
            if DEX_RE.fullmatch(name):
                blobs.append((name, data))
            if name.startswith("lib/") and name.endswith(".so"):
                path = extract / "natives" / f"{digest}.so"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                facts["natives"].append(native_record(name, data, path, nm))
    return blobs


def _u32(data, off):
    if off < 0 or off + 4 > len(data):
        raise DexError(f"u32 read out of range at {off}")
    return struct.unpack_from("<I", data, off)[0]


def _u16(data, off):
    if off < 0 or off + 2 > len(data):
        raise DexError(f"u16 read out of range at {off}")
    return struct.unpack_from("<H", data, off)[0]


def _uleb(data, pos):
    result, shift = 0, 0
    while True:
        if pos >= len(data):
            raise DexError("truncated uleb128")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 35:
            raise DexError("uleb128 too long")


def _mutf8(raw):
    try:
        return raw.replace(b"\xc0\x80", b"\x00").decode("utf-8", "surrogatepass")
    except UnicodeDecodeError as exc:
        raise DexError(f"bad MUTF-8 string: {exc}") from exc


def parse_dex(data):
    """Return {class descriptor: member inventory} for one DEX file; raise DexError on any malformation."""
    if len(data) < 0x70 or data[:4] != b"dex\n" or data[7:8] != b"\0":
        raise DexError("bad DEX magic")
    if _u32(data, 0x20) != len(data):
        raise DexError("header file_size differs from entry size")
    if _u32(data, 0x24) != 0x70:
        raise DexError("unexpected header_size")
    if _u32(data, 0x28) != 0x12345678:
        raise DexError("unsupported endian tag")

    def table(count_at, off_at, width):
        count, start = _u32(data, count_at), _u32(data, off_at)
        if start + count * width > len(data):
            raise DexError(f"table at {start} exceeds file")
        return count, start

    n_str, o_str = table(0x38, 0x3C, 4)
    strings = []
    for index in range(n_str):
        pos = _u32(data, o_str + 4 * index)
        _, text_at = _uleb(data, pos)
        end = data.find(b"\0", text_at)
        if end < 0:
            raise DexError("unterminated string")
        strings.append(_mutf8(data[text_at:end]))

    def string_at(index):
        if index >= len(strings):
            raise DexError(f"string index {index} out of range")
        return strings[index]

    n_ty, o_ty = table(0x40, 0x44, 4)
    types = [string_at(_u32(data, o_ty + 4 * i)) for i in range(n_ty)]

    def type_at(index):
        if index >= len(types):
            raise DexError(f"type index {index} out of range")
        return types[index]

    n_pr, o_pr = table(0x48, 0x4C, 12)
    protos = []
    for index in range(n_pr):
        base = o_pr + 12 * index
        ret = type_at(_u32(data, base + 4))
        params_off = _u32(data, base + 8)
        params = []
        if params_off:
            count = _u32(data, params_off)
            params = [type_at(_u16(data, params_off + 4 + 2 * j)) for j in range(count)]
        protos.append("(" + "".join(params) + ")" + ret)

    n_fi, o_fi = table(0x50, 0x54, 8)
    field_ids = []
    for index in range(n_fi):
        base = o_fi + 8 * index
        field_ids.append(f"{type_at(_u16(data, base))}.{string_at(_u32(data, base + 4))}:{type_at(_u16(data, base + 2))}")

    n_me, o_me = table(0x58, 0x5C, 8)
    method_ids = []
    for index in range(n_me):
        base = o_me + 8 * index
        proto = _u16(data, base + 2)
        if proto >= len(protos):
            raise DexError(f"proto index {proto} out of range")
        method_ids.append(f"{type_at(_u16(data, base))}.{string_at(_u32(data, base + 4))}{protos[proto]}")

    n_cl, o_cl = table(0x60, 0x64, 32)
    classes = {}
    for index in range(n_cl):
        base = o_cl + 32 * index
        desc = type_at(_u32(data, base))
        access = _u32(data, base + 4)
        super_index = _u32(data, base + 8)
        superclass = None if super_index == 0xFFFFFFFF else type_at(super_index)
        data_off = _u32(data, base + 24)
        fields, methods = [], []
        if data_off:
            pos = data_off
            sizes = []
            for _ in range(4):
                value, pos = _uleb(data, pos)
                sizes.append(value)
            static_count, instance_count, direct_count, virtual_count = sizes
            for count in (static_count, instance_count):
                current = 0
                for _ in range(count):
                    diff, pos = _uleb(data, pos)
                    flags, pos = _uleb(data, pos)
                    current += diff
                    if current >= len(field_ids):
                        raise DexError(f"field index {current} out of range")
                    fields.append(f"{field_ids[current]} {flags}")
            for count in (direct_count, virtual_count):
                current = 0
                for _ in range(count):
                    diff, pos = _uleb(data, pos)
                    flags, pos = _uleb(data, pos)
                    _, pos = _uleb(data, pos)
                    current += diff
                    if current >= len(method_ids):
                        raise DexError(f"method index {current} out of range")
                    methods.append(f"{method_ids[current]} {flags}")
        if desc in classes:
            raise DexError(f"class {desc} defined twice in one file")
        classes[desc] = {"access": access, "super": superclass, "fields": sorted(fields), "methods": sorted(methods)}
    return classes


def dex_union(blobs, facts, mem):
    classes, split = {}, {}
    if not blobs:
        facts["parse_errors"].append("no classes*.dex entries")
    for name, data in blobs:
        try:
            parsed = parse_dex(data)
        except DexError as exc:
            facts["parse_errors"].append(f"{name}: {exc}")
            continue
        for desc, cls in parsed.items():
            if desc in classes:
                facts["parse_errors"].append(f"class {desc} defined in {split[desc]} and {name}")
                continue
            classes[desc] = cls
            split[desc] = name
    facts["dex"] = {
        "files": [name for name, _ in blobs],
        "class_count": len(classes),
        "method_count": sum(len(cls["methods"]) for cls in classes.values()),
        "field_count": sum(len(cls["fields"]) for cls in classes.values()),
    }
    mem["dex_classes"] = classes
    mem["dex_split"] = split


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


def map_ids(text, ids):
    def sub(match):
        rid = int(match.group(1), 16)
        if rid in ids:
            return "@" + ids[rid]
        if rid >> 24 == 0x01:
            return f"framework:0x{match.group(1).lower()}"
        return f"unresolved:0x{match.group(1).lower()}"

    return REF_RE.sub(sub, text)


def parse_resources(text):
    """Return (ids, arsc, header_count): ids maps resource id -> name; arsc maps name -> mapped value lines."""
    ids, rows = {}, []
    current = None
    count = 0
    for line in text.splitlines():
        header = RES_HEADER.match(line)
        if header:
            rid = int(header.group(1), 16)
            ids[rid] = header.group(2)
            current = header.group(2)
            count += 1
            continue
        if RES_NOISE.match(line):
            current = None
            continue
        if current is not None and line.strip():
            rows.append((current, line.strip()))
    arsc = {}
    for name, value in rows:
        arsc.setdefault(name, []).append(map_ids(value, ids))
    return ids, arsc, count


def parse_xmltree(text, ids):
    records, stack, current = [], [], None
    for line in text.splitlines():
        namespace = re.match(r"^(\s*)N: ", line)
        if namespace:
            indent = len(namespace.group(1))
            while stack and stack[-1][0] >= indent:
                stack.pop()
            current = None
            continue
        element = ELEM_LINE.match(line)
        if element:
            indent = len(element.group(1))
            while stack and stack[-1][0] >= indent:
                stack.pop()
            stack.append((indent, element.group(2)))
            current = {"path": "/".join(name for _, name in stack), "attrs": []}
            records.append(current)
            continue
        attr = ATTR_LINE.match(line)
        if attr and current is not None:
            value = re.sub(r"\s+\(Raw: .*\)\s*$", "", attr.group(3))
            current["attrs"].append([attr.group(2), map_ids(value, ids)])
    for record in records:
        record["attrs"].sort()
    return records


def category(name):
    if DEX_RE.fullmatch(name):
        return "dex"
    if name == "AndroidManifest.xml":
        return "manifest"
    if name == "resources.arsc":
        return "arsc"
    if name.startswith("res/raw/"):
        return "res_file"
    if name.startswith("res/") and name.endswith(".xml"):
        return "res_xml"
    if name.startswith("res/"):
        return "res_file"
    if name.startswith("lib/") and name.endswith(".so"):
        return "native"
    if name == "assets/flutter_assets/kernel_blob.bin":
        return "kernel"
    if name.startswith("META-INF/"):
        return "meta_inf"
    if name.startswith("assets/"):
        return "asset"
    return "other"


def all_strings(mem):
    for values in mem["arsc"].values():
        yield from values
    for records in [mem["manifest"], *mem["res_xml"].values()]:
        for record in records:
            for _, value in record["attrs"]:
                yield value


def facts_for(arm, apk):
    tools = build_tools()
    aapt2 = tools / "aapt2"
    apksigner = tools / "apksigner"
    extract = TASK / "extract" / arm
    shutil.rmtree(extract, ignore_errors=True)
    extract.mkdir(parents=True)
    facts = {
        "apk_sha256": sha256_file(apk),
        "apk_bytes": apk.stat().st_size,
        "entries": [],
        "natives": [],
        "unsafe_names": [],
        "parse_errors": [],
        "unresolved_refs": [],
        "abis": [],
        "dex": None,
        "badging": None,
        "signing": None,
    }
    mem = {}
    MEM[arm] = mem
    blobs = read_apk(apk, extract, ndk_nm(), facts)
    facts["abis"] = sorted({e["name"].split("/")[1] for e in facts["entries"] if e["name"].startswith("lib/") and e["name"].count("/") == 2})
    dex_union(blobs, facts, mem)
    facts["badging"] = parse_badging(run(f"aapt2-badging-{arm}", [aapt2, "dump", "badging", apk], TASK, 600))
    if not facts["badging"]["package"]:
        facts["parse_errors"].append("badging: package line not parsed")
    ids, arsc, resource_count = parse_resources(run(f"aapt2-resources-{arm}", [aapt2, "dump", "resources", apk], TASK, 1200, record=False))
    if resource_count == 0:
        facts["parse_errors"].append("aapt2 dump resources: no resource entries parsed")
    mem["arsc"] = arsc
    manifest_text = run(f"aapt2-manifest-{arm}", [aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", apk], TASK, 600, record=False)
    mem["manifest"] = parse_xmltree(manifest_text, ids)
    if not mem["manifest"]:
        facts["parse_errors"].append("AndroidManifest.xml: no element parsed")
    mem["res_xml"] = {}
    for entry in facts["entries"]:
        name = entry["name"]
        if category(name) != "res_xml":
            continue
        try:
            text = run(f"xmltree-{arm}-{slug(name)}", [aapt2, "dump", "xmltree", "--file", name, apk], TASK, 300, record=False)
        except DeadlineError:
            raise
        except StageError as exc:
            facts["parse_errors"].append(f"{name}: xmltree failed: {str(exc)[:300]}")
            continue
        records = parse_xmltree(text, ids)
        if records:
            mem["res_xml"][name] = records
        else:
            facts["parse_errors"].append(f"{name}: no element parsed")
    facts["unresolved_refs"] = sorted({tok for value in all_strings(mem) for tok in UNRES_RE.findall(value)})
    facts["signing"] = parse_signing(run(f"apksigner-verify-{arm}", [apksigner, "verify", "--print-certs", "-v", apk], TASK, 600))
    return facts


def contract_failures(rec):
    facts = rec.get("facts")
    if facts is None:
        return ["facts not produced"]
    failures = list(facts["parse_errors"])
    failures += [f"unsafe zip member {item}" for item in facts["unsafe_names"]]
    badging = facts["badging"]
    if badging["package"] != PACKAGE:
        failures.append(f"applicationId {badging['package']!r} != {PACKAGE}")
    for key in ("minSdk", "targetSdk", "compileSdk"):
        if badging[key] != EXPECT[key]:
            failures.append(f"{key} {badging[key]!r} != {EXPECT[key]!r}")
    if facts["abis"] != EXPECT["abis"]:
        failures.append(f"ABIs {facts['abis']} != {EXPECT['abis']}")
    if badging["native_code"] != EXPECT["abis"]:
        failures.append(f"native-code {badging['native_code']} != {EXPECT['abis']}")
    if not badging["debuggable"]:
        failures.append("application-debuggable absent: not a debug build")
    names = {entry["name"] for entry in facts["entries"]}
    if "assets/flutter_assets/kernel_blob.bin" not in names:
        failures.append("kernel_blob.bin absent (debug build expects it)")
    if any(name.endswith("libapp.so") for name in names):
        failures.append("libapp.so present: AOT build, not debug")
    for native in facts["natives"]:
        if not native["name"].startswith("lib/x86_64/") or native["name"].count("/") != 2:
            failures.append(f"native outside lib/x86_64: {native['name']}")
        failures += [f"{native['name']}: {error}" for error in native["errors"]]
        if not native["errors"] and native["elf_machine"] != X86_64_MACHINE:
            failures.append(f"{native['name']}: ELF machine {native['elf_machine']} != x86_64")
    natives = {native["name"]: native for native in facts["natives"]}
    for name, accepted in PINNED_APK_NATIVES.items():
        native = natives.get(name)
        if native is None:
            failures.append(f"pinned native {name} absent")
        elif accepted.get(native["sha256"]) != native["bytes"]:
            failures.append(f"pinned native {name} is neither its verified original nor verified stripped form (sha256 {native['sha256']}, {native['bytes']} bytes)")
        elif (native["dynsym_count"], native["dynsym_sha256"]) != PINNED_EXPORTS[name]:
            failures.append(f"pinned native {name} exports differ from the verified pin")
    if not facts["dex"] or facts["dex"]["class_count"] == 0:
        failures.append("no DEX classes parsed")
    signing = facts["signing"]
    if not signing["verifies"]:
        failures.append("apksigner did not verify the APK")
    if not (signing["schemes"].get("v2") or signing["schemes"].get("v3")):
        failures.append("neither v2 nor v3 signature verified")
    if signing["signers"] != 1:
        failures.append(f"expected one signer, found {signing['signers']}")
    if not signing["digests"] or len(signing["digests"]) != signing["signers"]:
        failures.append("signer certificate SHA-256 not parsed")
    if not signing["dns"] or not all(dn.strip() for dn in signing["dns"]):
        failures.append("signer certificate DN not parsed")
    keystore = rec.get("keystore")
    if not keystore:
        failures.append(f"debug keystore provenance unresolved: {rec.get('keystore_note', 'no keystore record')}")
    elif not keystore.get("cert_sha256"):
        failures.append("debug keystore certificate unreadable")
    elif signing["digests"] != [keystore["cert_sha256"]]:
        failures.append("APK signer certificate differs from its declared debug keystore certificate")
    return failures


def arm_valid(rec):
    return isinstance(rec, dict) and "facts" in rec and "apk" in rec and not rec.get("failure") and not rec.get("contract_failures")



def generated_inventory(root):
    """Name -> SHA-256 of the locale sources the aggregator imports; fails if any are missing."""
    directory = root / L10N_DIR
    aggregate = root / L10N_AGGREGATE
    if not aggregate.is_file():
        raise StageError(f"localization aggregator absent at {L10N_AGGREGATE}")
    imports = LOCALE_IMPORT_RE.findall(aggregate.read_text(encoding="utf-8"))
    if not imports:
        raise StageError("localization aggregator declares no locale imports")
    missing = [name for name in imports if not (directory / name).is_file()]
    if missing:
        raise StageError(f"generated locale sources missing: {missing}")
    names = sorted({*imports, aggregate.name})
    return {name: sha256_file(directory / name) for name in names}


def build_stock(rec, inputs):
    root = make_tree("stock")
    rec["tree"] = str(root)
    before = snapshot_tree(root)
    with stage("stock-prepare"):
        verify_locks(root, inputs)
        rec["gradle_pins"] = gradle_pins()
        require_free("stock-prepare")
        run("stock-pub-get", [flutter_bin(), "pub", "get", "--enforce-lockfile"], root / APP_DIR, 900)
        rec["generated_inputs"] = generated_inventory(root)
    with stage("stock-build"):
        require_free("stock-build")
        try:
            run(
                "stock-build-apk",
                [flutter_bin(), "build", "apk", "--debug", "--target-platform", "android-x64", "--target", ENTRYPOINT, "--no-pub"],
                root / APP_DIR,
                2400,
            )
            android = root / APP_DIR / "android"
            try:
                rec["gradle_runtime_dependencies"] = run(
                    "stock-runtime-dependencies",
                    [android / "gradlew", ":app:dependencies", "--configuration", "debugRuntimeClasspath", "--console=plain"],
                    android,
                    600,
                )
            except StageError as exc:
                rec["gradle_runtime_dependencies_error"] = f"{type(exc).__name__}: {exc}"[:500]
        finally:
            gradlew = root / APP_DIR / "android" / "gradlew"
            if gradlew.is_file():
                try:
                    run("stock-stop-gradle", [gradlew, "--stop"], gradlew.parent, 120)
                except StageError as exc:
                    rec["gradle_stop_error"] = f"{type(exc).__name__}: {exc}"[:500]
            else:
                rec["gradle_stop_error"] = "gradlew absent: build ended before Flutter injected the wrapper"
    with stage("stock-source-check"):
        source_check(rec, root, before, frozenset())
        if generated_inventory(root) != rec["generated_inputs"]:
            raise StageError("stock generated locale inputs changed during the build")
    apk = root / APP_DIR / STOCK_APK_REL
    if not apk.is_file():
        raise StageError(f"stock APK absent at {STOCK_APK_REL}")
    rec["apk"] = {"path": str(apk), "sha256": sha256_file(apk), "bytes": apk.stat().st_size}
    with stage("stock-keystore"):
        rec["keystore"] = stock_keystore()
    with stage("stock-inventory"):
        rec["facts"] = facts_for("stock", apk)
    rec["contract_failures"] = contract_failures(rec)


def resolved_maven_debug():
    path = TASK / "bazel-output-base/external/rules_jvm_external++maven+flutter_maven_debug/coursier-deps.json"
    raw = path.read_bytes()
    resolved = json.loads(raw)
    dependencies = resolved.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        raise StageError("resolved debug Maven dependency list is missing or empty")
    return {
        "metadata_file": str(path.relative_to(TASK)),
        "metadata_sha256": sha256_bytes(raw),
        "conflict_resolution": resolved.get("conflict_resolution"),
        "artifacts": [
            {key: dep.get(key) for key in ("coord", "file", "sha256", "directDependencies")}
            for dep in dependencies
        ],
    }


def build_bazel(rec, inputs):
    root = make_tree("bazel")
    rec["tree"] = str(root)
    before = snapshot_tree(root)
    with stage("bazel-prepare"):
        verify_locks(root, inputs)
        require_seeded(root)
        version = (root / ".bazelversion").read_text(encoding="utf-8").strip()
        if version != EXPECT["bazel"]:
            raise StageError(f".bazelversion is {version}, pinned {EXPECT['bazel']}")
    with stage("bazel-consumer-pub-get"):
        verify_locks(root, inputs)
        aggregate_before = sha256_file(root / L10N_AGGREGATE)
        run("bazel-consumer-pub-get", [flutter_bin(), "pub", "get", "--enforce-lockfile"], root / APP_DIR, 900)
        verify_locks(root, inputs)
        if sha256_file(root / L10N_AGGREGATE) != aggregate_before:
            raise StageError("pub get changed the frozen localization aggregator")
        rec["generated_inputs"] = generated_inventory(root)
    with stage("bazel-update"):
        require_free("bazel-update")
        for target in UPDATE_TARGETS:
            run(f"bazel-run-{slug(target)}", bazel_argv("run", "update", [target]), root, 1500)
    with stage("bazel-build"):
        require_free("bazel-build")
        run("bazel-build-apk", bazel_argv("build", "update", [APK_TARGET]), root, 2400)
    with stage("bazel-source-check"):
        source_check(rec, root, before, BAZEL_ALLOWED)
    with stage("bazel-final-gate"):
        run("bazel-final-nobuild", bazel_argv("build", "error", [APK_TARGET, *CHECK_TARGETS, APP_TEST_PACKAGE], extra=["--nobuild"]), root, 1200)
    with stage("bazel-checks"):
        run("bazel-test-checks", bazel_argv("test", "error", CHECK_TARGETS), root, 1500)
        run("bazel-build-app-test-package", bazel_argv("build", "error", [APP_TEST_PACKAGE]), root, 1500)
    with stage("bazel-artifacts"):
        signed = APK_TARGET.rsplit(":", 1)[1] + ".apk"
        apks = [path for path in bazel_files(root, APK_TARGET) if path.name == signed]
        if len(apks) != 1:
            raise StageError(f"expected one {signed} output, found {len(apks)}")
        apk = apks[0]
        rec["apk"] = {"path": str(apk), "sha256": sha256_file(apk), "bytes": apk.stat().st_size}
        rec["keystore"], rec["keystore_note"] = bazel_keystore(root)
    with stage("bazel-inventory"):
        rec["facts"] = facts_for("bazel", apk)
    with stage("bazel-resolution-evidence"):
        try:
            rec["maven_debug_resolution"] = resolved_maven_debug()
        except Exception as exc:
            rec["maven_debug_resolution_error"] = f"{type(exc).__name__}: {exc}"[:500]
    rec["contract_failures"] = contract_failures(rec)


def build_arm(arm, builder, inputs):
    rec = STATE["arms"].setdefault(arm, {})
    try:
        builder(rec, inputs)
    except Exception as exc:
        rec["failure"] = f"{type(exc).__name__}: {exc}"[:2000]
        rec["traceback_tail"] = traceback.format_exc()[-2000:]
        STATE["arm_failures"].append(arm)
        log(f"{arm} arm failed: {rec['failure'][:300]}")
    save_state()


def class_diff(x, y):
    parts = []
    for key in ("access", "super"):
        if x[key] != y[key]:
            parts.append(f"{key}: {x[key]} vs {y[key]}")
    for key in ("fields", "methods"):
        only_x = sorted((Counter(x[key]) - Counter(y[key])).elements())
        only_y = sorted((Counter(y[key]) - Counter(x[key])).elements())
        if only_x:
            parts.append(f"{key} only in stock: {only_x}")
        if only_y:
            parts.append(f"{key} only in bazel: {only_y}")
    return parts


def records_diff(xs, ys):
    cx = Counter(json.dumps(r, sort_keys=True) for r in xs)
    cy = Counter(json.dumps(r, sort_keys=True) for r in ys)
    return sorted((cx - cy).elements()), sorted((cy - cx).elements())


def compare(sa, sb):
    fa, fb = sa["facts"], sb["facts"]
    ma, mb = MEM["stock"], MEM["bazel"]
    findings, allowed = [], []

    def find(area, name, detail, kind="difference"):
        findings.append({"area": area, "name": name, "kind": kind, "detail": detail})

    def allow(area, name, reason):
        allowed.append({"area": area, "name": name, "reason": reason})

    for side, facts in (("stock", fa), ("bazel", fb)):
        for error in facts["parse_errors"]:
            find("unparsed", side, error, kind="unparsed")
        for ref in facts["unresolved_refs"]:
            find("unresolved", side, ref, kind="unresolved")

    ea = {e["name"]: e for e in fa["entries"]}
    eb = {e["name"]: e for e in fb["entries"]}
    for name in sorted(set(ea) | set(eb)):
        cat = category(name)
        if cat in SKIP_CATS:
            continue
        if SIGNING_RE.fullmatch(name):
            if ea.get(name) != eb.get(name):
                allow("signing", name, "signing files differ under the disposable debug-key policy")
            continue
        if name not in ea:
            find(cat, name, "present only in bazel")
            continue
        if name not in eb:
            if name == AGP_METADATA:
                allow("build_metadata", name, "AGP build metadata, not read at runtime")
            else:
                find(cat, name, "present only in stock")
            continue
        if ea[name]["sha256"] == eb[name]["sha256"]:
            continue
        if cat == "kernel":
            find("kernel", name, "kernel blob bytes differ", kind="kernel")
        else:
            find(cat, name, "bytes differ")

    na = {n["name"]: n for n in fa["natives"]}
    nb = {n["name"]: n for n in fb["natives"]}
    for name in sorted(set(na) | set(nb)):
        if name not in na or name not in nb:
            find("native", name, "native library present in one arm only")
            continue
        x, y = na[name], nb[name]
        if x["errors"] or y["errors"]:
            find("native", name, f"exports not comparable: {x['errors'] + y['errors']}", kind="unparsed")
        elif x["elf_machine"] != y["elf_machine"]:
            find("native", name, f"ELF machine {x['elf_machine']} vs {y['elf_machine']}")
        elif x["dynsym_sha256"] != y["dynsym_sha256"]:
            find("native", name, f"exported dynamic symbol sets differ ({x['dynsym_count']} vs {y['dynsym_count']})")
        elif x["sha256"] == y["sha256"]:
            continue
        elif x.get("normalized_sha256") and x["normalized_sha256"] == y.get("normalized_sha256"):
            allow("native", name, f"raw bytes differ; identical after {x['normalize_command']} ({x['normalize_tool']}); ELF machine and exported symbols also equal")
        elif not x.get("normalized_sha256") or not y.get("normalized_sha256"):
            find("native", name, {"stock": x.get("normalize_error"), "bazel": y.get("normalize_error")}, kind="unparsed")
        elif (name, x["sha256"], y["sha256"]) in NATIVE_CLASSIFIED:
            allow("native", name, NATIVE_CLASSIFIED[(name, x["sha256"], y["sha256"])])
        else:
            find("native", name, {
                "exports": x["dynsym_count"],
                "exports_sha256": x["dynsym_sha256"],
                "needed": {"stock": x.get("needed"), "bazel": y.get("needed")},
                "comment": {"stock": x.get("comment"), "bazel": y.get("comment")},
                "normalized_sha256": {"stock": x.get("normalized_sha256"), "bazel": y.get("normalized_sha256")},
            }, kind="native_pending")

    ga, gb = sa.get("generated_inputs"), sb.get("generated_inputs")
    if ga != gb:
        find("generated_inputs", L10N_AGGREGATE, {"stock": ga, "bazel": gb})

    ca, cb = ma.get("dex_classes", {}), mb.get("dex_classes", {})
    sa_split, sb_split = ma.get("dex_split", {}), mb.get("dex_split", {})
    for desc in sorted(set(ca) | set(cb)):
        if desc not in ca:
            find("dex", desc, "class present only in bazel")
        elif desc not in cb:
            find("dex", desc, "class present only in stock")
        elif ca[desc] != cb[desc]:
            find("dex", desc, class_diff(ca[desc], cb[desc]))
        elif sa_split.get(desc) != sb_split.get(desc):
            allow("dex", desc, f"identical member inventory; file split differs ({sa_split.get(desc)} vs {sb_split.get(desc)})")

    only_a, only_b = records_diff(ma.get("manifest", []), mb.get("manifest", []))
    if only_a or only_b:
        find("manifest", "AndroidManifest.xml", {"only_stock": only_a, "only_bazel": only_b})

    aa, ab = ma.get("arsc", {}), mb.get("arsc", {})
    for name in sorted(set(aa) | set(ab)):
        if name not in aa or name not in ab:
            find("arsc", name, "resource present in one arm only")
        elif aa[name] != ab[name]:
            find("arsc", name, {"stock": aa[name], "bazel": ab[name]})

    xa, xb = ma.get("res_xml", {}), mb.get("res_xml", {})
    for name in sorted(set(xa) | set(xb)):
        if name not in xa or name not in xb:
            find("res_xml", name, "compiled XML present in one arm only")
            continue
        only_a, only_b = records_diff(xa[name], xb[name])
        if only_a or only_b:
            find("res_xml", name, {"only_stock": only_a, "only_bazel": only_b})

    for key in ("package", "minSdk", "targetSdk", "compileSdk", "native_code", "debuggable"):
        if fa["badging"][key] != fb["badging"][key]:
            find("badging", key, {"stock": fa["badging"][key], "bazel": fb["badging"][key]})

    da, db = fa["signing"]["digests"], fb["signing"]["digests"]
    if da != db:
        if sa.get("keystore") and sb.get("keystore"):
            allow("signing_cert", "APK signer", "each arm signed by its own debug keystore (stock AGP-created; Bazel declared target keystore)")
        else:
            find("signing_cert", "APK signer", {"stock": da, "bazel": db})

    blocking = [f for f in findings if f["kind"] not in PENDING_KINDS]
    status = "fail" if blocking else ("pending" if findings else "pass")
    return {
        "status": status,
        "scope": SCOPE,
        "findings": findings,
        "allowed": allowed,
        "counts": {
            "findings": len(findings),
            "allowed": len(allowed),
            "entries": {"stock": len(ea), "bazel": len(eb)},
            "dex_classes": {"stock": len(ca), "bazel": len(cb)},
            "natives": {"stock": len(na), "bazel": len(nb)},
        },
        "limitations": LIMITATIONS,
    }


def cmd_build():
    global DEADLINE, END_AT, STATE
    shutil.rmtree(TASK, ignore_errors=True)
    (TASK / "home").mkdir(parents=True)
    (TASK / "tmp").mkdir(parents=True)
    DEADLINE = deadline_epoch()
    END_AT = float(DEADLINE - STATE_RESERVE)
    STATE = blank_state()
    STATE["identity"]["deadline_epoch"] = DEADLINE
    try:
        STATE["identity"]["head"] = os.environ.get("GITHUB_SHA") or git_head()
        save_state()
        with stage("identity"):
            inputs = load_inputs()
            check_identity(inputs)
        with stage("sdk-identity"):
            sdk_identity()
    except Exception as exc:
        STATE["status"] = "fail"
        STATE["failure"] = f"{type(exc).__name__}: {exc}"[:2000]
        save_state()
        log(f"build aborted before arms: {STATE['failure'][:300]}")
        return 1

    build_arm("stock", build_stock, inputs)
    build_arm("bazel", build_bazel, inputs)

    if all("facts" in STATE["arms"].get(arm, {}) for arm in ARMS):
        try:
            with stage("compare"):
                STATE["comparison"] = compare(STATE["arms"]["stock"], STATE["arms"]["bazel"])
        except Exception as exc:
            STATE["comparison"] = {"status": "fail", "failure": f"{type(exc).__name__}: {exc}"[:800]}
    else:
        STATE["comparison"] = {"status": "not_compared", "reason": "an arm produced no inventory"}

    valid = [arm for arm in ARMS if arm_valid(STATE["arms"].get(arm, {}))]
    STATE["valid_arms"] = valid
    STATE["status"] = "built" if len(valid) == len(ARMS) else ("partial" if valid else "fail")
    save_state()
    for arm in ARMS:
        rec = STATE["arms"].get(arm, {})
        log(f"{arm}: valid={arm_valid(rec)} contract_failures={len(rec.get('contract_failures', []))}")
    log(f"comparison: {(STATE.get('comparison') or {}).get('status')}; status: {STATE['status']}")
    return 0 if valid else 1


def cmd_runtime():
    global DEADLINE, END_AT
    try:
        load_state()
    except (OSError, ValueError) as exc:
        log(f"runtime cannot read build state: {exc}")
        return 1
    eligible = []
    for arm in ARMS:
        rec = STATE["arms"].get(arm, {})
        if arm_valid(rec):
            eligible.append((arm, rec["apk"]["path"], rec["apk"]["sha256"]))
    results = {}
    adb_log = []
    runtime = {"arms": results, "eligible": [arm for arm, _, _ in eligible], "network_restored": False, "adb_commands": adb_log}
    STATE["runtime"] = runtime
    if not eligible:
        STATE["runtime_status"] = "skipped_no_valid_arm"
        save_state()
        log("runtime skipped: no contract-valid arm")
        return 1
    DEADLINE = deadline_epoch()
    STATE["identity"]["deadline_epoch"] = DEADLINE
    END_AT = float(min(DEADLINE - STATE_RESERVE, time.time() + RUNTIME_MAX))
    try:
        with stage("runtime"):
            summary = apk_runtime.run_all(eligible, TASK / "runtime", results, END_AT, adb_log, save_state)
        runtime.update(summary)
    except Exception as exc:
        runtime["failure"] = f"{type(exc).__name__}: {exc}"[:1000]
    eligible_names = {arm for arm, _, _ in eligible}
    for arm in ARMS:
        if arm not in results:
            reason = "runtime stage aborted before this arm" if arm in eligible_names else "arm did not build validly"
            results[arm] = {"status": "not_run", "failure": reason}
    ok = len(eligible) == len(ARMS) and all(results[arm].get("status") == "pass" for arm in ARMS) and runtime.get("network_restored") is True
    STATE["runtime_status"] = "pass" if ok else "fail"
    save_state()
    for arm in ARMS:
        log(f"runtime {arm}: {results[arm].get('status')}")
    return 0 if ok else 1


def minimal_summary(state):
    arms = state.get("arms") or {}
    summary = {
        "status": state.get("status"),
        "failure": state.get("failure"),
        "runtime_status": state.get("runtime_status"),
        "valid_arms": state.get("valid_arms"),
        "arms": {arm: {"valid": arm_valid(arms.get(arm, {})), "failure": (arms.get(arm) or {}).get("failure")} for arm in ARMS},
    }
    return summary, ["facts", "findings", "mandatory_png", "command_tails", "allowed_items", "failure_png"]


def apply_losses(state, level):
    body = copy.deepcopy(state)
    dropped = LOSS_ORDER[:level]
    if "command_tails" in dropped:
        for command in body.get("commands") or []:
            command.pop("stdout_tail", None)
            command.pop("stderr_tail", None)
            command.pop("stdout_head", None)
            command.pop("stderr_head", None)
    comparison = body.get("comparison")
    if "allowed_items" in dropped and isinstance(comparison, dict):
        comparison["allowed"] = {"omitted": True, "count": len(comparison.get("allowed") or [])}
    runtime = body.get("runtime") or {}
    for result in (runtime.get("arms") or {}).values():
        if not isinstance(result, dict):
            continue
        if "failure_png" in dropped:
            shot = ((result.get("diagnostics") or {}).get("failure_screenshot") or {})
            if isinstance(shot, dict):
                shot.pop("png_base64", None)
        if "mandatory_png" in dropped:
            for shot in (result.get("screenshots") or {}).values():
                if isinstance(shot, dict):
                    shot.pop("png_base64", None)
    return body, dropped


def envelope(body, mode, lost, complete):
    return {
        "schema": 1,
        "kind": KIND,
        "head": os.environ.get("GITHUB_SHA", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        "job_status": os.environ.get("APK_JOB_STATUS", "unknown"),
        "emitted_at": now_iso(),
        "mode": mode,
        "complete": complete,
        "lost": lost,
        "body": body,
    }


def dump_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def encode(raw):
    return base64.b64encode(gzip.compress(raw, mtime=0)).decode("ascii")


def chunk(encoded):
    return [encoded[i:i + CHUNK_CHARS] for i in range(0, len(encoded), CHUNK_CHARS)]


def choose_envelope(state):
    for level in range(len(LOSS_ORDER) + 1):
        body, lost = apply_losses(state, level)
        complete = not (set(lost) & REQUIRED_LOSS)
        raw = dump_json(envelope(body, "full" if level == 0 else "trimmed", lost, complete))
        chunks = chunk(encode(raw))
        if len(raw) <= MAX_RAW and len(chunks) <= MAX_CHUNKS:
            return raw, chunks, complete, lost
    body, lost = minimal_summary(state)
    raw = dump_json(envelope(body, "minimal", lost, False))
    chunks = chunk(encode(raw))
    if len(raw) > MAX_RAW or len(chunks) > MAX_CHUNKS:
        raise StageError("minimal evidence envelope exceeds the limits")
    return raw, chunks, False, lost


def cmd_emit():
    try:
        state = load_or_default()
        raw, chunks, complete, lost = choose_envelope(state)
    except Exception as exc:
        failure = {"status": "emit_failed", "failure": f"{type(exc).__name__}: {exc}"[:500]}
        lost = ["facts", "findings", "mandatory_png"]
        complete = False
        raw = dump_json(envelope(failure, "emit-failed", lost, complete))
        chunks = chunk(encode(raw))
    digest = sha256_bytes(raw)
    meta = {"encoding": "gzip+base64", "chunks": len(chunks), "sha256": digest}
    status = {
        "schema": 1,
        "emitted_at": now_iso(),
        "complete": complete,
        "lost": lost,
        "chunks": len(chunks),
        "raw_bytes": len(raw),
        "sha256": digest,
    }
    try:
        TASK.mkdir(parents=True, exist_ok=True)
        (TASK / "evidence.json").write_bytes(raw)
        (TASK / "emit_status.json").write_text(json.dumps(status, sort_keys=True), encoding="utf-8")
    except OSError as exc:
        status["write_error"] = str(exc)[:300]
    lines = ["APK_EVIDENCE_META " + json.dumps(meta, separators=(",", ":"), sort_keys=True)]
    lines += [f"APK_EVIDENCE_CHUNK {index}/{len(chunks)} {text}" for index, text in enumerate(chunks, 1)]
    sys.stdout.write("\n".join(lines) + "\n")
    sys.stdout.flush()
    return 0


def kernel_cleared(state):
    comparison = state.get("comparison") or {}
    findings = comparison.get("findings") or []
    if not findings or any(f.get("kind") != "kernel" for f in findings):
        return False
    arms = ((state.get("runtime") or {}).get("arms") or {})
    proofs = {}
    for arm in ARMS:
        vm = (arms.get(arm) or {}).get("vm") or {}
        if vm.get("status") != "ok" or not vm.get("libraries_complete") or not vm.get("sources_complete"):
            return False
        if not vm.get("widget_creation"):
            return False
        proofs[arm] = (vm.get("sources"), vm.get("widget_creation"))
    return proofs["stock"] == proofs["bazel"]


def cmd_verdict():
    state = load_or_default()
    emit = read_json(TASK / "emit_status.json") or {}
    comparison = state.get("comparison") or {}
    parity_status = comparison.get("status", "missing")
    parity_ok = parity_status == "pass" or (parity_status == "pending" and kernel_cleared(state))
    arms = state.get("arms") or {}
    gates = {
        "build_complete": state.get("status") == "built",
        "arm_contracts": {arm: arm_valid(arms.get(arm, {})) for arm in ARMS},
        "parity_status": parity_status,
        "parity": parity_ok,
        "runtime": state.get("runtime_status") == "pass",
        "network_restored": ((state.get("runtime") or {}).get("network_restored")) is True,
        "evidence_complete": emit.get("complete") is True,
    }
    failed = [name for name in ("build_complete", "parity", "runtime", "network_restored", "evidence_complete") if not gates[name]]
    failed += [f"arm_contract:{arm}" for arm, ok in gates["arm_contracts"].items() if not ok]
    machine = not failed
    verdict = {
        "schema": 1,
        "kind": KIND,
        "machine_verdict": "pass" if machine else "fail",
        "visual_review": "pending",
        "research_parity": "not_accepted_until_main_records_visual_review",
        "gates": gates,
        "failed_gates": failed,
        "limitations": LIMITATIONS,
        "generated_at": now_iso(),
    }
    TASK.mkdir(parents=True, exist_ok=True)
    (TASK / "verdict.json").write_text(json.dumps(verdict, indent=1, sort_keys=True), encoding="utf-8")
    log(f"machine_verdict={verdict['machine_verdict']} visual_review=pending failed={failed}")
    return 0 if machine else 1


def main(argv):
    commands = {"build": cmd_build, "runtime": cmd_runtime, "emit": cmd_emit, "verdict": cmd_verdict}
    if len(argv) != 2 or argv[1] not in commands:
        print("usage: economics.py build|runtime|emit|verdict", file=sys.stderr)
        return 2
    return commands[argv[1]]()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
