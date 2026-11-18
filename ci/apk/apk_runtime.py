"""Runtime half of the Smooth APK feasibility driver (called by economics.py `runtime`).

Per contract-valid arm: install, offline setup, scripted English onboarding with
uiautomator waits on named states, camera-screen PNG and process maps, database check,
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
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

PACKAGE = "org.openfoodfacts.scanner"
DB_NAME = "smoothie.db"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
PNG_MAX_BYTES = int(2.5 * 1024 * 1024)
DIAG_TAIL = 4000
STEP_TIMEOUT = 150
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

# Named onboarding states: (name, labels that must be present, labels that must be absent, tap label).
ONBOARD = [
    ("welcome", ["Welcome !"], [], "Continue"),
    ("country", ["Next"], ["Welcome !"], "Next"),
    ("foods", ["Choose foods that are good for you"], ["Welcome !"], "Next"),
    ("planet", ["good for the planet"], ["Choose foods that are good for you"], "Next"),
    ("preferences", ["Next"], ["good for the planet"], "Next"),
    ("camera", ["Later"], [], "Later"),
]
FINAL_STATE = ("final", ["Search for a product", "Last scanned products"], [])


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


def dump_ui(adb, deadline=None):
    def limit(seconds):
        if deadline is None:
            return seconds
        remaining = deadline - time.time()
        if remaining <= 0:
            raise StepDeadline("UI step deadline reached")
        return min(seconds, remaining)

    adb.shell("rm -f /sdcard/window_dump.xml", timeout=limit(30), check=True)
    # A null root is reported on stderr with exit status zero.
    out = adb.shell("uiautomator dump /sdcard/window_dump.xml 2>&1", timeout=limit(90), check=True)
    if "ERROR" in out:
        raise DumpError(f"uiautomator reported an error: {_tail(out, 300)}")
    # exec-out can report a missing file on stdout with exit status zero.
    if adb.shell("test -s /sdcard/window_dump.xml && echo present", timeout=limit(30), check=False).strip() != "present":
        if deadline is not None and time.time() >= deadline:
            raise StepDeadline("UI step deadline reached")
        raise DumpError(f"uiautomator wrote no dump file: {_tail(out, 300)}")
    _, data = adb.run(["exec-out", "cat", "/sdcard/window_dump.xml"], timeout=limit(60))
    xml = _text(data)
    return xml, parse_nodes(xml)


def parse_nodes(xml):
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise FlowError(f"uiautomator XML unparseable: {exc}") from exc
    if root.tag != "hierarchy":
        raise FlowError(f"uiautomator XML root is {root.tag!r}, not hierarchy")
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
        raise FlowError("uiautomator returned no nodes")
    return nodes


def _labels(nodes):
    return [f"{node['text']} {node['content_desc']}".lower() for node in nodes]


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
            if all(any(p.lower() in lab for lab in labels) for p in present) and not any(
                a.lower() in lab for lab in labels for a in absent
            ):
                return xml, nodes
            seen, failure = sorted({lab.strip() for lab in labels if lab.strip()})[:40], None
        time.sleep(min(POLL_SECONDS, max(0, deadline - time.time())))
    if failure is not None:
        raise FlowError(f"step {step}: no usable UI dump: {failure}")
    raise FlowError(f"step {step}: wanted {present} absent {absent}; labels seen {seen}")


def tap_label(adb, nodes, label):
    want = label.lower()
    hits = [n for n in nodes if want in (n["text"].lower(), n["content_desc"].lower())]
    if not hits:
        hits = [n for n in nodes if want in n["text"].lower() or want in n["content_desc"].lower()]
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


def mapped_libraries(adb, package):
    pid = adb.shell(f"pidof -s {package}", timeout=30, check=True).strip()
    if not pid:
        raise FlowError("app process not found by pidof")
    maps = adb.shell(f"run-as {package} cat /proc/{pid}/maps", timeout=60, check=True)
    libs = sorted(
        {line.split()[-1].rsplit("/", 1)[-1] for line in maps.splitlines() if line.split() and line.split()[-1].endswith(".so")}
    )
    return {
        "pid": pid,
        "libraries": libs,
        "rive_native": "librive_native.so" in libs,
        "flutter": "libflutter.so" in libs,
        "sqlite": [lib for lib in libs if "sqlite" in lib.lower()],
    }


def drive_onboarding(adb, result, out, package):
    steps = result["flow"]["steps"]
    for name, present, absent, tap in ONBOARD:
        xml, nodes = wait_for(adb, name, present, absent, STEP_TIMEOUT)
        steps.append({"step": name, "xml_sha256": _sha(xml.encode("utf-8")), "nodes": len(nodes)})
        if name == "camera":
            result["screenshots"]["camera"] = screenshot(adb, "camera", out)
            result["maps_camera"] = mapped_libraries(adb, package)
        tap_label(adb, nodes, tap)
    name, present, absent = FINAL_STATE
    xml, nodes = wait_for(adb, name, present, absent, FINAL_TIMEOUT)
    steps.append({"step": name, "xml_sha256": _sha(xml.encode("utf-8")), "nodes": len(nodes)})
    result["screenshots"]["final"] = screenshot(adb, "final", out)
    result["maps_final"] = mapped_libraries(adb, package)


def install(adb, apk, package):
    adb.shell(f"pm uninstall {package}", timeout=120, check=False)
    _, out = adb.run(["install", "-r", str(apk)], timeout=900)
    text = _text(out)
    if "Success" not in text:
        raise AdbError(f"adb install did not report Success: {_tail(text, 400)}")
    return {"output_tail": _tail(text, 400)}


def launch(adb, package):
    adb.shell("logcat -c", timeout=30, check=False)
    out = adb.shell(f"monkey -p {package} -c android.intent.category.LAUNCHER 1", timeout=120, check=True)
    if "Events injected: 1" not in out:
        raise FlowError(f"launch not confirmed: {_tail(out, 300)}")


def logcat_gate(adb):
    text = adb.shell("logcat -d", timeout=120, check=True, record=False)
    matched = [line for line in text.splitlines() if FATAL_RE.search(line)]
    return {"fatal_count": len(matched), "fatal_lines": matched, "tail": _tail(text)}


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


def rpc(base, method, **params):
    query = urllib.parse.urlencode(params)
    url = f"{base}/{method}" + (f"?{query}" if query else "")
    with urllib.request.urlopen(url, timeout=20) as response:
        body = json.loads(response.read().decode("utf-8"))
    if "error" in body:
        raise FlowError(f"VM {method} error: {str(body['error'])[:300]}")
    return body.get("result") or {}


MAX_SCRIPTS = 2000
MIN_SOURCE_BUDGET = 30


def sha_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def vm_sources(base, isolate_id, budget):
    scripts = rpc(base, "getScripts", isolateId=isolate_id).get("scripts") or []
    if len(scripts) > MAX_SCRIPTS:
        raise FlowError(f"{len(scripts)} scripts exceed the {MAX_SCRIPTS} bound")
    sources = {}
    for script in scripts:
        if budget.left() < MIN_SOURCE_BUDGET:
            raise FlowError("out of budget while hashing VM script sources")
        obj = rpc(base, "getObject", isolateId=isolate_id, objectId=script["id"])
        text = obj.get("source")
        if not isinstance(text, str) or not script.get("uri"):
            raise FlowError(f"script {script.get('uri')!r} has no source text")
        sources[script["uri"]] = sha_text(text)
    return sources


def vm_probe(adb, logtext):
    rec = {
        "status": "unavailable",
        "libraries": [],
        "libraries_complete": False,
        "sources": {},
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
        vm = rpc(base, "getVM")
        isolates = vm.get("isolates") or []
        if not isolates:
            raise FlowError("VM reported no isolates")
        isolate_id = isolates[0]["id"]
        isolate = rpc(base, "getIsolate", isolateId=isolate_id)
        libraries = isolate.get("libraries") or []
        uris = sorted({lib["uri"] for lib in libraries if "uri" in lib})
        sources = vm_sources(base, isolate_id, adb.budget)
        tracked = rpc(base, "ext.flutter.inspector.isWidgetCreationTracked", isolateId=isolate_id)
        rec.update(
            status="ok",
            libraries=uris,
            libraries_complete=bool(uris) and isolate.get("type") == "Isolate",
            sources=sources,
            sources_complete=bool(uris) and set(uris) <= set(sources),
            widget_creation=json.dumps(tracked.get("result", tracked), sort_keys=True),
            isolate_id=isolate_id,
        )
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
        drive_onboarding(adb, result, out, PACKAGE)
        result["logcat"] = logcat_gate(adb)
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
