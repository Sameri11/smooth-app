"""Runtime half of the Smooth APK feasibility driver (called by economics.py `runtime`).

Per contract-valid arm: install, offline setup, scripted English onboarding with
accessibility-tree waits on named states, camera-screen PNG and process maps, database check,
fatal-log gate, VM loaded-library capture. Network is always restored. Stdlib only.

Every adb call is bounded by a Budget. Failures are recorded per arm with their
evidence (PNG, database bytes and hash, logcat tail); one arm's failure never hides the other.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zipfile
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

PACKAGE = "org.openfoodfacts.scanner"
DB_NAME = "smoothie.db"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
PNG_MAX_BYTES = int(2.5 * 1024 * 1024)
DIAG_TAIL = 4000
STEP_TIMEOUT = 150
# Monkey accepts the activity start before Android's asynchronous process fork completes.
APP_START_TIMEOUT = 20
FINAL_TIMEOUT = 150
POLL_SECONDS = 2
RESTORE_BUDGET = 60
FATAL_RE = re.compile(
    r"FATAL EXCEPTION|FatalError|appinitialisationfailed|UnsatisfiedLinkError|"
    r"ClassNotFoundException|Fatal signal|RiveFailure",
    re.IGNORECASE,
)
VM_RE = re.compile(r"Dart VM service is listening on http://127\.0\.0\.1:(\d+)/([^/\s]*)/?")
BOUNDS_RE = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")

# Accessibility-tree helper: reads the active window without an idle wait. It is built at
# run time from the frozen SDK build-tools and platform, so nothing is downloaded; its snapshot is read via run-as.
TREE_PACKAGE = "org.rulesflutter.apkcheck.treedump"
TREE_CLASS = f"{TREE_PACKAGE}.TreeDumpInstrumentation"
TREE_SNAPSHOT_PREFIX = "files/window_dump-"
TREE_KEY_PASS = "treedump-test-key"
TREE_SOURCE = Path(__file__).with_name("TreeDumpInstrumentation.java")
TREE_MANIFEST = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{TREE_PACKAGE}">
    <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34" />
    <application android:debuggable="true" android:label="Tree dump" />
    <instrumentation android:name="{TREE_CLASS}" android:targetPackage="{TREE_PACKAGE}" />
</manifest>
"""

SNAPSHOT_ABSENT = "SNAPSHOT=absent"
SNAPSHOT_EMPTY = "SNAPSHOT=empty"
SNAPSHOT_NONEMPTY = "SNAPSHOT=nonempty"
SNAPSHOT_PRESENT = "SNAPSHOT=present"
INSTRUMENTATION_OK = re.compile(r"^INSTRUMENTATION_CODE: -1\s*$", re.MULTILINE)

# Named onboarding states: (name, labels that must be present, labels that must be absent, tap label).
ONBOARD = [
    ("welcome", ["Welcome !"], [], "Continue"),
    ("country", ["Next"], ["Welcome !"], "Next"),
    ("foods", ["Choose foods that are good for you"], ["Welcome !"], "Next"),
    ("planet", ["good for the planet"], ["Choose foods that are good for you"], "Next"),
    ("preferences", ["Next"], ["good for the planet"], "Next"),
    ("camera", ["Camera access", "Later"], [], "Later"),
]
FINAL_STATE = ("final", ["Search for a product", "Welcome to Open Food Facts"], ["Camera access"])


class FlowError(RuntimeError):
    pass


class AdbError(RuntimeError):
    pass


class DumpError(FlowError):
    pass


class StepDeadline(DumpError):
    pass


class BudgetError(RuntimeError):
    pass


class DbError(RuntimeError):
    def __init__(self, message, record):
        super().__init__(message)
        self.record = record


def _tail(text, limit=DIAG_TAIL):
    return (text or "")[-limit:]


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _text(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


class Budget:
    def __init__(self, end):
        self.end = end

    def left(self):
        return self.end - time.time()

    def clamp(self, timeout):
        left = self.left()
        if left < 10:
            raise BudgetError(f"under {max(left, 0):.0f} s of budget left")
        return min(float(timeout), left)


class Adb:
    def __init__(self, budget, log):
        self.budget = budget
        self.log = log
        self.base = [os.environ.get("ADB", "adb")]

    def run(self, args, timeout=60, check=True, record=True):
        limit = self.budget.clamp(timeout)
        started = time.time()
        rc, out, err = 127, b"", b""
        try:
            proc = subprocess.run(self.base + args, capture_output=True, timeout=limit, check=False)
            rc, out, err = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            rc, out, err = 124, exc.stdout or b"", exc.stderr or b""
        except OSError as exc:
            err = str(exc).encode()
        entry = {"argv": args, "rc": rc, "seconds": round(time.time() - started, 1)}
        if record:
            entry["stdout_tail"] = _tail(_text(out))
            entry["stderr_tail"] = _tail(_text(err))
        self.log.append(entry)
        if check and rc != 0:
            raise AdbError(f"adb {' '.join(args[:2])} exited {rc}: {_tail(_text(err) or _text(out), 400)}")
        return rc, out

    def shell(self, command, timeout=60, check=True, record=True):
        _, out = self.run(["shell", command], timeout=timeout, check=check, record=record)
        return _text(out)


def ensure_device(adb):
    adb.run(["wait-for-device"], timeout=600)
    while True:
        if adb.shell("getprop sys.boot_completed", timeout=30, check=False).strip() == "1":
            break
        time.sleep(POLL_SECONDS)
    locale = adb.shell("getprop persist.sys.locale", timeout=30, check=False).strip()
    source = "persist.sys.locale"
    if not locale:
        locale = adb.shell("getprop ro.product.locale", timeout=30, check=False).strip()
        source = "ro.product.locale"
    if not locale.lower().startswith("en"):
        raise FlowError(f"device locale {locale!r} from {source} is not English")
    return {"locale": locale, "locale_source": source}


def set_network(adb, enabled):
    verb = "enable" if enabled else "disable"
    for kind in ("wifi", "data"):
        adb.shell(f"svc {kind} {verb}", timeout=60, check=True)


def assert_offline(adb):
    routes = adb.shell("cat /proc/net/route", timeout=30, check=True)
    for line in routes.splitlines()[1:]:
        fields = line.split()
        if len(fields) > 1 and fields[1] == "00000000":
            raise FlowError("default route present while offline")
    out = adb.shell("ping -c 1 -W 3 8.8.8.8; echo rc=$?", timeout=60, check=False)
    match = re.search(r"rc=(\d+)", out)
    if not match:
        raise FlowError("offline proof unavailable: ping printed no exit status")
    code = match.group(1)
    if code == "0":
        raise FlowError("8.8.8.8 reachable while offline")
    if code not in ("1", "2"):
        raise FlowError(f"offline proof unavailable: ping exited {code} (not a no-reply result)")
    return {"default_route": False, "ping_rc": int(code)}


def restore_network(log):
    adb = Adb(Budget(time.time() + RESTORE_BUDGET), log)
    set_network(adb, True)
    return True


def snapshot_path(token):
    return f"{TREE_SNAPSHOT_PREFIX}{token}.xml"


def snapshot_state(adb, limit, path):
    script = (
        f"if [ -s {path} ]; then echo {SNAPSHOT_NONEMPTY}; "
        f"elif [ -e {path} ]; then echo {SNAPSHOT_EMPTY}; "
        f"else echo {SNAPSHOT_ABSENT}; fi"
    )
    out = adb.shell(f"run-as {TREE_PACKAGE} sh -c '{script}'", timeout=limit(30), check=True)
    # Exact match only: a run-as failure prints an error and never reaches the sentinel.
    state = out.strip()
    if state not in (SNAPSHOT_ABSENT, SNAPSHOT_EMPTY, SNAPSHOT_NONEMPTY):
        raise FlowError(f"run-as did not report the tree snapshot state: {_tail(out, 300)!r}")
    return state


def clear_snapshots(adb, limit):
    # Removes every snapshot a previous request left, including one a cancelled instrumentation
    # wrote late. Names carry a request token, so none of them can be accepted by a later request.
    script = (
        f"rm -f {TREE_SNAPSHOT_PREFIX}*; "
        f"for f in {TREE_SNAPSHOT_PREFIX}*; do "
        f'if [ -e "$f" ]; then echo {SNAPSHOT_PRESENT}; exit 0; fi; done; '
        f"echo {SNAPSHOT_ABSENT}"
    )
    out = adb.shell(f"run-as {TREE_PACKAGE} sh -c '{script}'", timeout=limit(30), check=True)
    state = out.strip()
    if state != SNAPSHOT_ABSENT:
        raise FlowError(f"stale tree snapshots were not removed: {state!r} {_tail(out, 300)!r}")


def dump_ui(adb, deadline=None):
    def limit(seconds):
        if deadline is None:
            return seconds
        remaining = deadline - time.time()
        if remaining <= 0:
            raise StepDeadline("UI step deadline reached")
        return min(seconds, remaining)

    # The request token names the only file this call may accept.
    token = uuid.uuid4().hex
    path = snapshot_path(token)
    clear_snapshots(adb, limit)
    out = adb.shell(f"am instrument -w -e token {token} {TREE_PACKAGE}/{TREE_CLASS}", timeout=limit(90), check=True)
    if not INSTRUMENTATION_OK.search(out):
        raise DumpError(f"tree helper reported no success line: {_tail(out, 300)}")
    state = snapshot_state(adb, limit, path)
    if state != SNAPSHOT_NONEMPTY:
        raise DumpError(f"tree helper left snapshot state {state}: {_tail(out, 300)}")
    _, data = adb.run(["exec-out", "run-as", TREE_PACKAGE, "cat", f"/data/data/{TREE_PACKAGE}/{path}"], timeout=limit(60))
    xml = _text(data)
    return xml, parse_nodes(xml)


def parse_nodes(xml):
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise FlowError(f"tree XML unparseable: {exc}") from exc
    if root.tag != "hierarchy":
        raise FlowError(f"tree XML root is {root.tag!r}, not hierarchy")
    nodes = [
        {
            "text": node.get("text", ""),
            "content_desc": node.get("content-desc", ""),
            "class": node.get("class", ""),
            "bounds": node.get("bounds", ""),
            "clickable": node.get("clickable") == "true",
        }
        for node in root.iter("node")
    ]
    if not nodes:
        raise FlowError("tree XML contains no nodes")
    return nodes


def _label(text):
    return " ".join(text.split()).lower()


def _labels(nodes):
    return [_label(f"{node['text']} {node['content_desc']}") for node in nodes]


def wait_for(adb, step, present, absent, timeout):
    limit = adb.budget.clamp(timeout)
    deadline = time.time() + limit
    seen, failure = [], "UI step deadline reached before the first dump"
    while time.time() < deadline:
        try:
            xml, nodes = dump_ui(adb, deadline)
        except StepDeadline:
            break
        except AdbError:
            if time.time() < deadline:
                raise
            break
        except DumpError as exc:
            # A window without a root can become usable before the step deadline.
            seen, failure = [], str(exc)
        else:
            labels = _labels(nodes)
            if all(any(_label(p) in lab for lab in labels) for p in present) and not any(
                _label(a) in lab for lab in labels for a in absent
            ):
                return xml, nodes
            seen, failure = sorted({lab.strip() for lab in labels if lab.strip()})[:40], None
        time.sleep(min(POLL_SECONDS, max(0, deadline - time.time())))
    if failure is not None:
        raise FlowError(f"step {step}: no usable UI dump: {failure}")
    raise FlowError(f"step {step}: wanted {present} absent {absent}; labels seen {seen}")


def tap_label(adb, nodes, label):
    want = _label(label)
    hits = [n for n in nodes if want in (_label(n["text"]), _label(n["content_desc"]))]
    if not hits:
        hits = [n for n in nodes if want in _label(n["text"]) or want in _label(n["content_desc"])]
    if not hits:
        raise FlowError(f"no node labelled {label!r} to tap")
    hits.sort(key=lambda n: not n["clickable"])
    match = BOUNDS_RE.fullmatch(hits[0]["bounds"])
    if not match:
        raise FlowError(f"bad bounds {hits[0]['bounds']!r}")
    x1, y1, x2, y2 = (int(v) for v in match.groups())
    adb.shell(f"input tap {(x1 + x2) // 2} {(y1 + y2) // 2}", timeout=30, check=True)


def screenshot(adb, name, out):
    _, data = adb.run(["exec-out", "screencap", "-p"], timeout=60)
    rec = {"name": name, "bytes": len(data), "sha256": _sha(data), "png": False, "png_base64": None, "error": None}
    if not data.startswith(PNG_MAGIC):
        rec["error"] = "screencap output is not a PNG"
        return rec
    if len(data) > PNG_MAX_BYTES:
        rec["error"] = f"PNG exceeds the {PNG_MAX_BYTES}-byte evidence cap"
        return rec
    (out / f"{name}.png").write_bytes(data)
    rec["png"] = True
    rec["png_base64"] = base64.b64encode(data).decode("ascii")
    return rec


PT_LOAD = 1
PF_X = 1
NATIVE_MAP_LINES = 24


def _page_down(value, page):
    return value - value % page


def _page_up(value, page):
    return -(-value // page) * page


def _le(data, offset, size):
    return int.from_bytes(data[offset : offset + size], "little")


def _file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _device_sha256(adb, path):
    # Empty when the file is missing or unreadable; callers treat that as a mismatch.
    if "'" in path:
        raise FlowError(f"device path with a quote is not supported: {path}")
    out = adb.shell(f"sha256sum '{path}'", timeout=120, check=False).split()
    return out[0] if out else ""


def maps_rows(text):
    rows = []
    for line in text.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        start, end = (int(value, 16) for value in parts[0].split("-"))
        rows.append(
            {
                "start": start,
                "end": end,
                "perms": parts[1],
                "offset": int(parts[2], 16),
                "path": parts[5].strip() if len(parts) == 6 else "",
                "line": line,
            }
        )
    return rows


def elf_load_segments(data):
    # (p_flags, p_offset, p_filesz) of each file-backed PT_LOAD of a little-endian ELF32/ELF64 image.
    if data[:4] != b"\x7fELF" or data[4] not in (1, 2) or data[5] != 1:
        raise FlowError("not a little-endian ELF32/ELF64 image")
    wide = data[4] == 2
    phoff = _le(data, 0x20 if wide else 0x1C, 8 if wide else 4)
    entsize = _le(data, 0x36 if wide else 0x2A, 2)
    count = _le(data, 0x38 if wide else 0x2C, 2)
    if entsize < (56 if wide else 32) or phoff + entsize * count > len(data):
        raise FlowError("program header table is outside the ELF image")
    segments = []
    for index in range(count):
        at = phoff + index * entsize
        if _le(data, at, 4) != PT_LOAD:
            continue
        if wide:
            flags, offset, filesz = _le(data, at + 4, 4), _le(data, at + 8, 8), _le(data, at + 32, 8)
        else:
            offset, filesz, flags = _le(data, at + 4, 4), _le(data, at + 16, 4), _le(data, at + 24, 4)
        if filesz:
            segments.append((flags, offset, filesz))
    if not segments:
        raise FlowError("ELF image has no file-backed PT_LOAD segment")
    return segments


def _attributed(rows, path, base, size):
    # Rows of `path` whose file offsets overlap [base, base + size).
    return [
        row
        for row in rows
        if row["path"] == path and row["offset"] < base + size and row["offset"] + row["end"] - row["start"] > base
    ]


def _covered(rows, lo, hi, perm):
    spans = sorted((row["offset"], row["offset"] + row["end"] - row["start"]) for row in rows if perm in row["perms"])
    reached = lo
    for start, end in spans:
        if start > reached:
            break
        reached = max(reached, end)
    return reached >= hi


def elf_mapping_proof(rows, path, data, base, page):
    # Every file-backed PT_LOAD page range must be mapped readable from `path`, executable ones executable.
    attributed = _attributed(rows, path, base, len(data))
    if not attributed:
        return False, "not mapped: no mapping of the file overlaps the library"
    segments = elf_load_segments(data)
    for flags, offset, filesz in segments:
        if offset + filesz > len(data):
            return False, f"PT_LOAD at {offset:#x} extends past the ELF image"
        lo = _page_down(base + offset, page)
        hi = _page_up(base + offset + filesz, page)
        if not _covered(attributed, lo, hi, "r"):
            return False, f"PT_LOAD at {offset:#x} is not mapped readable from the file"
        if flags & PF_X and not _covered(attributed, lo, hi, "x"):
            return False, f"executable PT_LOAD at {offset:#x} is not mapped executable"
    return True, f"{len(segments)} PT_LOAD segments mapped from file offset {base:#x}"


def _local_data_offset(fh, info):
    # Data offset from the local header: its extra field can differ from the central directory's.
    fh.seek(info.header_offset)
    head = fh.read(30)
    if len(head) != 30 or head[:4] != b"PK\x03\x04":
        raise FlowError(f"{info.filename}: bad local file header")
    name_len = int.from_bytes(head[26:28], "little")
    extra_len = int.from_bytes(head[28:30], "little")
    if fh.read(name_len) != info.orig_filename.encode("utf-8"):
        raise FlowError(f"{info.filename}: local header name differs from the central directory")
    return info.header_offset + 30 + name_len + extra_len


def _native_proofs(rows, installed, apk, abi, page, device_sha256):
    # Per device-ABI native library of `apk`: the proof of how the process maps it, or why none holds.
    prefix = installed.rsplit("/", 1)[0] + "/lib/"
    proofs = {}
    with zipfile.ZipFile(apk) as zf, open(apk, "rb") as fh:
        for info in zf.infolist():
            parts = info.filename.split("/")
            if len(parts) != 3 or parts[:2] != ["lib", abi] or not parts[2].endswith(".so"):
                continue
            name = parts[2]
            data = zf.read(info)
            tries = []  # (mode, ok, detail, attributed rows)
            try:
                if info.compress_type != zipfile.ZIP_STORED:
                    tries.append(("apk", False, "not mapped from the APK: entry is compressed", []))
                else:
                    offset = _local_data_offset(fh, info)
                    fh.seek(offset)
                    if fh.read(len(data)) != data:
                        raise FlowError(f"{name}: stored bytes at the data offset differ from the entry")
                    if offset % page:
                        tries.append(("apk", False, f"entry data at {offset:#x} is not page-aligned", []))
                    else:
                        ok, detail = elf_mapping_proof(rows, installed, data, offset, page)
                        tries.append(("apk", ok, detail, _attributed(rows, installed, offset, len(data))))
                extracted = {row["path"] for row in rows if row["path"].startswith(prefix) and row["path"].rsplit("/", 1)[-1] == name}
                for path in sorted(extracted):
                    if device_sha256(path) != _sha(data):
                        tries.append(("extracted", False, f"{path}: sha256 differs from the APK entry", []))
                        continue
                    ok, detail = elf_mapping_proof(rows, path, data, 0, page)
                    tries.append(("extracted", ok, detail, _attributed(rows, path, 0, len(data))))
            except FlowError as exc:
                tries.append(("elf", False, str(exc), []))
            won = next((t for t in tries if t[1]), None)
            if won:
                proofs[name] = {"mode": won[0], "detail": won[2], "lines": [r["line"] for r in won[3][:NATIVE_MAP_LINES]]}
            else:
                shown = [r["line"] for t in tries for r in t[3]]
                proofs[name] = {
                    "mode": None,
                    "detail": "; ".join(t[2] for t in tries) or "no mapping in the process",
                    "lines": shown[:NATIVE_MAP_LINES],
                }
    return proofs


def mapped_libraries(adb, package, apk, apk_sha, expected_pid):
    # Native libraries of the supplied APK that the process has mapped from the bytes. The installed
    # base APK must be that APK (sha256), and a library counts only when every PT_LOAD is mapped from it.
    pid = app_pid(adb, package)
    if pid != expected_pid:
        raise FlowError(f"app process restarted: launched {expected_pid}, now {pid}")
    listed = adb.shell(f"pm path {package}", timeout=60, check=True).splitlines()
    installed_paths = [line.split(":", 1)[1].strip() for line in listed if line.startswith("package:")]
    if len(installed_paths) != 1:
        raise FlowError(f"{package} has {len(installed_paths)} installed APK paths; the proof covers one base APK")
    installed = installed_paths[0]
    installed_sha = _device_sha256(adb, installed)
    if installed_sha != apk_sha:
        raise FlowError(f"installed {installed} sha256 {installed_sha or 'unreadable'} != supplied {apk_sha}")
    supplied = _file_sha256(apk)
    if supplied != apk_sha:
        raise FlowError(f"supplied APK sha256 {supplied} != contract record {apk_sha}")
    abi = adb.shell("getprop ro.product.cpu.abi", timeout=30, check=True).strip()
    page = int(adb.shell("getconf PAGE_SIZE", timeout=30, check=True).strip())
    rows = maps_rows(adb.shell(f"run-as {package} cat /proc/{pid}/maps", timeout=60, check=True))
    proofs = _native_proofs(rows, installed, apk, abi, page, lambda path: _device_sha256(adb, path))
    loaded = sorted(name for name, proof in proofs.items() if proof["mode"])
    observed = sorted({row["path"].rsplit("/", 1)[-1] for row in rows if row["path"].endswith(".so")})
    return {
        "pid": pid,
        "abi": abi,
        "page_size": page,
        "installed_apk": installed,
        "installed_sha256": installed_sha,
        "maps_rows": len(rows),
        "libraries": loaded,
        "modes": {name: proofs[name]["mode"] for name in loaded},
        "unproven": {name: proof["detail"] for name, proof in proofs.items() if not proof["mode"]},
        "map_lines": {name: proof["lines"] for name, proof in proofs.items() if proof["lines"]},
        "rive_native": "librive_native.so" in loaded,
        "flutter": "libflutter.so" in loaded,
        # Observed .so basenames from any mapping (system libraries included); not an APK proof.
        "sqlite": [lib for lib in observed if "sqlite" in lib.lower()],
    }


def drive_onboarding(adb, result, out, package, apk, apk_sha):
    steps = result["flow"]["steps"]
    for name, present, absent, tap in ONBOARD:
        xml, nodes = wait_for(adb, name, present, absent, STEP_TIMEOUT)
        steps.append({"step": name, "xml_sha256": _sha(xml.encode("utf-8")), "nodes": len(nodes)})
        if name == "camera":
            result["screenshots"]["camera"] = screenshot(adb, "camera", out)
            result["maps_camera"] = mapped_libraries(adb, package, apk, apk_sha, result["launch_pid"])
        tap_label(adb, nodes, tap)
    name, present, absent = FINAL_STATE
    xml, nodes = wait_for(adb, name, present, absent, FINAL_TIMEOUT)
    steps.append({"step": name, "xml_sha256": _sha(xml.encode("utf-8")), "nodes": len(nodes)})
    result["screenshots"]["final"] = screenshot(adb, "final", out)
    result["maps_final"] = mapped_libraries(adb, package, apk, apk_sha, result["launch_pid"])


def install(adb, apk, package):
    adb.shell(f"pm uninstall {package}", timeout=120, check=False)
    _, out = adb.run(["install", "-r", str(apk)], timeout=900)
    text = _text(out)
    if "Success" not in text:
        raise AdbError(f"adb install did not report Success: {_tail(text, 400)}")
    return {"output_tail": _tail(text, 400)}


def _sdk_dir(name):
    value = os.environ.get(name)
    if not value:
        raise FlowError(f"{name} must name the SDK directory for the tree helper")
    path = Path(value)
    if not path.is_dir():
        raise FlowError(f"{name} is not an existing directory: {value}")
    return path


def _tool(args, budget):
    try:
        proc = subprocess.run(args, capture_output=True, timeout=budget.clamp(120), check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FlowError(f"{Path(args[0]).name} did not run: {exc}") from exc
    if proc.returncode != 0:
        detail = _tail(_text(proc.stderr) or _text(proc.stdout), 400)
        raise FlowError(f"{Path(args[0]).name} exited {proc.returncode}: {detail}")


def build_tree_helper(work, budget):
    """Compile, dex, link and sign the tree helper with the frozen SDK build-tools and platform."""
    tools = _sdk_dir("APK_TREE_BUILD_TOOLS")
    platform = _sdk_dir("APK_TREE_PLATFORM")
    for name in ("d8", "aapt2", "apksigner"):
        if not (tools / name).is_file():
            raise FlowError(f"{name} missing from APK_TREE_BUILD_TOOLS={tools}")
    jar = platform / "android.jar"
    if not jar.is_file():
        raise FlowError(f"android.jar missing from APK_TREE_PLATFORM={platform}")
    classes, dex = work / "classes", work / "dex"
    classes.mkdir()
    dex.mkdir()
    manifest = work / "AndroidManifest.xml"
    manifest.write_text(TREE_MANIFEST, encoding="utf-8")
    _tool(["javac", "--release", "8", "-classpath", str(jar), "-d", str(classes), str(TREE_SOURCE)], budget)
    sources = sorted(str(p) for p in classes.rglob("*.class"))
    _tool([str(tools / "d8"), "--min-api", "24", "--lib", str(jar), "--output", str(dex), *sources], budget)
    base = work / "base.apk"
    _tool(
        [str(tools / "aapt2"), "link", "--manifest", str(manifest), "-I", str(jar),
         "--min-sdk-version", "24", "--target-sdk-version", "34", "-o", str(base)],
        budget,
    )
    with zipfile.ZipFile(base, "a") as archive:
        archive.write(dex / "classes.dex", "classes.dex", compress_type=zipfile.ZIP_STORED)
    keystore = work / "helper.jks"
    _tool(
        ["keytool", "-genkeypair", "-keystore", str(keystore), "-storepass", TREE_KEY_PASS,
         "-keypass", TREE_KEY_PASS, "-alias", "treedump", "-keyalg", "RSA", "-keysize", "2048",
         "-validity", "3650", "-dname", "CN=treedump"],
        budget,
    )
    signed = work / "tree-helper.apk"
    _tool(
        [str(tools / "apksigner"), "sign", "--ks", str(keystore), "--ks-key-alias", "treedump",
         "--ks-pass", f"pass:{TREE_KEY_PASS}", "--key-pass", f"pass:{TREE_KEY_PASS}",
         "--out", str(signed), str(base)],
        budget,
    )
    data = signed.read_bytes()
    return signed, {"sha256": _sha(data), "bytes": len(data), "build_tools": str(tools), "platform": str(platform)}


def install_tree_helper(adb, budget):
    with tempfile.TemporaryDirectory(prefix="tree-helper-") as work:
        apk, record = build_tree_helper(Path(work), budget)
        record["install"] = install(adb, apk, TREE_PACKAGE)
    return record



def launch(adb, package):
    adb.shell("logcat -c", timeout=30, check=False)
    out = adb.shell(f"monkey -p {package} -c android.intent.category.LAUNCHER 1", timeout=120, check=True)
    if "Events injected: 1" not in out:
        raise FlowError(f"launch not confirmed: {_tail(out, 300)}")


# Threadtime rows: date time [uid] pid tid level tag: message.
LOG_ROW_RE = re.compile(r"^\S+\s+\S+\s+(?:\S+\s+)?(\d+)\s+\d+\s+[VDIWEFAS]\s")


def app_pid(adb, package, timeout=0):
    deadline = time.time() + adb.budget.clamp(timeout) if timeout else None
    while True:
        now = time.time()
        if deadline is not None and now >= deadline:
            raise FlowError("app process not found by pidof before startup deadline")
        limit = min(30, deadline - now) if deadline is not None else 30
        rc, raw = adb.run(["shell", f"pidof {package}"], timeout=limit, check=False)
        pids = _text(raw).split()
        if rc not in (0, 1) or (rc != 0 and pids):
            raise AdbError(f"pidof {package} exited {rc}: {_text(raw).strip()[:100]!r}")
        if len(pids) > 1:
            raise FlowError(f"pidof found several {package} processes: {' '.join(pids)[:100]}")
        if rc == 0 and len(pids) == 1 and re.fullmatch(r"\d+", pids[0]):
            return pids[0]
        if pids:
            raise AdbError(f"pidof {package} exited {rc}: {_text(raw).strip()[:100]!r}")
        if deadline is None or time.time() >= deadline:
            raise FlowError(f"app process not found by pidof (exit {rc})")
        time.sleep(min(POLL_SECONDS, max(0, deadline - time.time())))


def names_app_pid(line, pid):
    row = LOG_ROW_RE.match(line)
    if row and row.group(1) == pid:
        return True
    # A native crash is logged by the crash handler under its own pid and names the crashed pid in the message.
    return re.search(rf"\bpid:?\s+{pid}\b", line, re.IGNORECASE) is not None


def logcat_gate(adb, expected_pid, package=PACKAGE):
    # Only the app process's fatal lines count. Other processes (Settings, system_server) log FATAL-like
    # warnings in a normal run, so a whole-logcat match fails on them.
    pid = app_pid(adb, package)
    if pid != expected_pid:
        raise FlowError(f"app process restarted: launched {expected_pid}, now {pid}")
    text = adb.shell("logcat -d", timeout=120, check=True, record=False)
    matched = [line for line in text.splitlines() if FATAL_RE.search(line) and names_app_pid(line, pid)]
    return {"app_pid": pid, "fatal_count": len(matched), "fatal_lines": matched, "tail": _tail(text)}


def db_check(adb, package, out):
    remote = f"/data/data/{package}/databases/{DB_NAME}"
    rec = {
        "labelled": "sqflite_android",
        "remote_path": remote,
        "bytes": None,
        "sha256": None,
        "user_version": None,
        "quick_check": None,
        "tables": None,
        "host_sqlite_version": sqlite3.sqlite_version,
        "error": None,
    }
    try:
        _, data = adb.run(["exec-out", "run-as", package, "cat", remote], timeout=120)
    except Exception as exc:
        rec["error"] = f"pull failed: {type(exc).__name__}: {str(exc)[:300]}"
        raise DbError(rec["error"], rec) from exc
    local = out / DB_NAME
    local.write_bytes(data)
    rec.update(bytes=len(data), sha256=_sha(data))
    try:
        _, wal = adb.run(["exec-out", "run-as", package, "cat", remote + "-wal"], timeout=60, check=False)
        if wal:
            (out / (DB_NAME + "-wal")).write_bytes(wal)
            rec["wal_bytes"] = len(wal)
    except Exception:
        rec["wal_bytes"] = None
    try:
        con = sqlite3.connect(str(local))
        try:
            rec["quick_check"] = [row[0] for row in con.execute("PRAGMA quick_check").fetchall()]
            rec["user_version"] = con.execute("PRAGMA user_version").fetchone()[0]
            rec["tables"] = sorted(row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'"))
        finally:
            con.close()
    except sqlite3.Error as exc:
        rec["error"] = f"sqlite: {exc}"[:300]
        raise DbError(rec["error"], rec) from exc
    if rec["quick_check"] != ["ok"]:
        rec["error"] = f"PRAGMA quick_check returned {rec['quick_check']}"
        raise DbError(rec["error"], rec)
    if rec["user_version"] != 9:
        rec["error"] = f"user_version {rec['user_version']} != 9"
        raise DbError(rec["error"], rec)
    return rec


RPC_TIMEOUT = 20


def rpc(base, method, budget, **params):
    query = urllib.parse.urlencode(params)
    url = f"{base}/{method}" + (f"?{query}" if query else "")
    # The socket timeout never outlasts what the arm has left.
    with urllib.request.urlopen(url, timeout=budget.clamp(RPC_TIMEOUT)) as response:
        body = json.loads(response.read().decode("utf-8"))
    if "error" in body:
        raise FlowError(f"VM {method} error: {str(body['error'])[:300]}")
    return body.get("result") or {}


# Observed 5815 scripts for one Smooth isolate; the bound stops a runaway VM without cutting that.
MAX_SCRIPTS = 8000
MIN_SOURCE_BUDGET = 30
# Parallel getObject calls per capture; the serial capture ran out of budget at 4773 of 5815 scripts.
SOURCE_WORKERS = 4
# Registrant source text is kept for classification; every other script keeps only its hash.
SOURCE_EXAMPLE_RE = re.compile(r"(^|/)dart_plugin_registrant\.dart$")
SOURCE_EXAMPLE_BYTES = 64 * 1024


def sha_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def record_source(rec, uri, digest):
    # The VM can list several script objects under one URI (SDK part files shared by libraries).
    # Each URI keeps the sorted list of all its hashes, so arms compare equal only when every
    # URI has the same multiset of sources.
    hashes = rec["sources"].setdefault(uri, [])
    hashes.append(digest)
    hashes.sort()


def fetch_script(base, isolate_id, budget, script):
    obj = rpc(base, "getObject", budget, isolateId=isolate_id, objectId=script["id"])
    text = obj.get("source")
    if not isinstance(text, str) or not script.get("uri"):
        raise FlowError(f"script {script.get('uri')!r} has no source text")
    return script["uri"], text


def finish_examples(rec, found):
    # Sorted, so the same registrants are kept on every run. A registrant that does not fit keeps its
    # URI and hash with text None and is counted in source_examples_overflow; nothing is truncated.
    used, overflow, examples = 0, 0, []
    for uri, digest, text in sorted(found, key=lambda item: item[:2]):
        size = len(text.encode("utf-8"))
        fits = used + size <= SOURCE_EXAMPLE_BYTES
        if fits:
            used += size
        else:
            overflow += 1
        examples.append({"uri": uri, "sha256": digest, "bytes": size, "text_omitted": not fits, "text": text if fits else None})
    rec.update(source_examples=examples, source_examples_bytes=used, source_examples_overflow=overflow)


def vm_sources(base, isolate_id, budget, rec):
    # Fills rec in place, so a failure keeps the scripts hashed so far. At most SOURCE_WORKERS calls are
    # in flight, so nothing queues behind them. After a failure, or once the reserve is reached, no new
    # call starts; calls already in flight finish, so every completed script still counts.
    scripts = rpc(base, "getScripts", budget, isolateId=isolate_id).get("scripts") or []
    rec["script_count"] = len(scripts)
    if len(scripts) > MAX_SCRIPTS:
        raise FlowError(f"{len(scripts)} scripts exceed the {MAX_SCRIPTS} bound")
    todo = iter(scripts)
    running, found, failure = set(), [], None
    try:
        with ThreadPoolExecutor(max_workers=SOURCE_WORKERS) as pool:
            while True:
                while failure is None and len(running) < SOURCE_WORKERS:
                    script = next(todo, None)
                    if script is None:
                        break
                    if budget.left() < MIN_SOURCE_BUDGET:
                        failure = FlowError(f"out of budget after {rec['scripts_hashed']} of {len(scripts)} VM script sources")
                        break
                    running.add(pool.submit(fetch_script, base, isolate_id, budget, script))
                if not running:
                    break
                done, running = wait(running, return_when=FIRST_COMPLETED)
                for future in done:
                    try:
                        uri, text = future.result()
                    except Exception as exc:
                        if failure is None:
                            failure = exc
                        continue
                    digest = sha_text(text)
                    record_source(rec, uri, digest)
                    rec["scripts_hashed"] += 1
                    if SOURCE_EXAMPLE_RE.search(uri):
                        found.append((uri, digest, text))
    finally:
        rec["sources"] = dict(sorted(rec["sources"].items()))
        finish_examples(rec, found)
    if failure is not None:
        raise failure


def vm_probe(adb, logtext):
    rec = {
        "status": "unavailable",
        "isolate_id": None,
        "libraries": [],
        "libraries_complete": False,
        "script_count": None,
        "scripts_hashed": 0,
        "sources": {},
        "source_examples": [],
        "source_examples_bytes": 0,
        "source_examples_overflow": 0,
        "sources_complete": False,
        "widget_creation": None,
        "error": None,
    }
    matches = list(VM_RE.finditer(logtext or ""))
    if not matches:
        rec["error"] = "no Dart VM service URL in logcat"
        return rec
    device_port = int(matches[-1].group(1))
    token = matches[-1].group(2)
    host_port = device_port
    try:
        adb.run(["forward", f"tcp:{host_port}", f"tcp:{device_port}"], timeout=30)
        base = f"http://127.0.0.1:{host_port}/{token}"
        vm = rpc(base, "getVM", adb.budget)
        isolates = vm.get("isolates") or []
        if not isolates:
            raise FlowError("VM reported no isolates")
        isolate_id = isolates[0]["id"]
        rec["isolate_id"] = isolate_id
        isolate = rpc(base, "getIsolate", adb.budget, isolateId=isolate_id)
        libraries = isolate.get("libraries") or []
        uris = sorted({lib["uri"] for lib in libraries if "uri" in lib})
        rec.update(libraries=uris, libraries_complete=bool(uris) and isolate.get("type") == "Isolate")
        vm_sources(base, isolate_id, adb.budget, rec)
        rec["sources_complete"] = bool(uris) and set(uris) <= set(rec["sources"])
        tracked = rpc(base, "ext.flutter.inspector.isWidgetCreationTracked", adb.budget, isolateId=isolate_id)
        rec.update(status="ok", widget_creation=json.dumps(tracked.get("result", tracked), sort_keys=True))
    except Exception as exc:
        rec["error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
    finally:
        try:
            adb.run(["forward", "--remove", f"tcp:{host_port}"], timeout=30, check=False, record=False)
        except Exception:
            pass
    return rec


def gates(result):
    shots = result["screenshots"]
    for key, label in (("camera", "camera screen"), ("final", "home screen")):
        shot = shots.get(key) or {}
        if not shot.get("png") or not shot.get("png_base64"):
            raise FlowError(f"{label} PNG missing: {shot.get('error')}")
    camera_maps = result["maps_camera"] or {}
    if not (camera_maps.get("rive_native") and camera_maps.get("flutter")):
        raise FlowError("librive_native.so or libflutter.so not mapped while the camera screen was shown")
    if not (result["maps_final"] or {}).get("rive_native"):
        raise FlowError("librive_native.so not mapped at the home screen")
    fatal = result["logcat"]["fatal_count"]
    if fatal:
        raise FlowError(f"{fatal} fatal log line(s) during the run")


def diagnostics(adb, out, failing):
    diag = {"failure_screenshot": None, "logcat_tail": None, "ui_error": None}
    if failing:
        try:
            diag["failure_screenshot"] = screenshot(adb, "failure", out)
        except Exception as exc:
            diag["failure_screenshot"] = {"name": "failure", "png": False, "error": f"{type(exc).__name__}: {str(exc)[:300]}"}
    try:
        diag["logcat_tail"] = _tail(adb.shell("logcat -d", timeout=120, check=False, record=False))
    except Exception as exc:
        diag["logcat_tail"] = f"unavailable: {type(exc).__name__}"
    return diag


def run_arm(arm, apk, apk_sha, out, budget, log):
    out.mkdir(parents=True, exist_ok=True)
    adb = Adb(budget, log)
    result = {
        "arm": arm,
        "status": "fail",
        "failure": None,
        "device": None,
        "install": None,
        "offline": None,
        "launch_pid": None,
        "flow": {"steps": []},
        "screenshots": {},
        "maps_camera": None,
        "maps_final": None,
        "db": None,
        "logcat": None,
        "vm": None,
        "diagnostics": None,
        "network_restored": False,
    }
    failing = True
    try:
        actual = _sha(Path(apk).read_bytes())
        if actual != apk_sha:
            raise FlowError(f"APK sha256 {actual} != contract record {apk_sha}")
        result["device"] = ensure_device(adb)
        result["install"] = install(adb, apk, PACKAGE)
        set_network(adb, False)
        result["offline"] = assert_offline(adb)
        launch(adb, PACKAGE)
        result["launch_pid"] = app_pid(adb, PACKAGE, APP_START_TIMEOUT)
        drive_onboarding(adb, result, out, PACKAGE, apk, apk_sha)
        result["logcat"] = logcat_gate(adb, result["launch_pid"], PACKAGE)
        result["db"] = db_check(adb, PACKAGE, out)
        gates(result)
        failing = False
        result["status"] = "pass"
    except DbError as exc:
        result["db"] = exc.record
        result["failure"] = f"DbError: {exc}"[:1500]
    except Exception as exc:
        result["failure"] = f"{type(exc).__name__}: {exc}"[:1500]
    finally:
        try:
            result["diagnostics"] = diagnostics(adb, out, failing)
            if result["logcat"] is None:
                result["logcat"] = {"fatal_count": None, "fatal_lines": [], "tail": result["diagnostics"]["logcat_tail"]}
            logtext = adb.shell("logcat -d", timeout=120, check=False, record=False)
            result["vm"] = vm_probe(adb, logtext)
        except Exception as exc:
            result["vm"] = {"status": "unavailable", "libraries": [], "libraries_complete": False, "error": f"{type(exc).__name__}: {str(exc)[:300]}"}
        try:
            adb.shell(f"pm uninstall {PACKAGE}", timeout=120, check=False)
        except Exception:
            pass
        try:
            set_network(adb, True)
            result["network_restored"] = True
        except Exception as exc:
            result["network_restored"] = False
            result["network_restore_error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
            restore_network(log)
            result["network_restored"] = True
    return result


def run_all(eligible, out_root, results, end, log, checkpoint):
    """Run each eligible arm; fill `results` in place; always restore the network. Never raises."""
    budget = Budget(end)
    device_error = None
    try:
        adb = Adb(budget, log)
        device = ensure_device(adb)
        results["device"] = device
        results["tree_helper"] = install_tree_helper(adb, budget)
        for index, (arm, apk, apk_sha) in enumerate(eligible):
            remaining = len(eligible) - index
            share = max(budget.left(), 0) / remaining
            arm_budget = Budget(min(end, time.time() + share))
            results[arm] = {"status": "running", "failure": "arm did not finish before the step deadline"}
            checkpoint()
            results[arm] = run_arm(arm, apk, apk_sha, out_root / arm, arm_budget, log)
            checkpoint()
    except Exception as exc:
        device_error = f"{type(exc).__name__}: {str(exc)[:800]}"
    restored, restore_error = False, None
    try:
        restored = restore_network(log)
    except Exception as exc:
        restore_error = f"{type(exc).__name__}: {str(exc)[:300]}"
    return {
        "network_restored": restored,
        "restore_error": restore_error,
        "device_error": device_error,
    }
