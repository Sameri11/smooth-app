#!/usr/bin/env python3
"""Bounded, identity-checked cache snapshots for the APK timing experiment."""
import argparse, hashlib, io, json, os, shutil, stat, subprocess, sys, tarfile, time
from pathlib import Path, PurePosixPath

RUNNER = Path(os.environ.get("RUNNER_TEMP", "."))
ROOT, TRANSPORT = RUNNER / "apk-timing", RUNNER / "apk-timing-cache"
WORKTREE = Path(__file__).resolve().parents[2]
GIB, HEADROOM = 1 << 30, 64 << 20
CAPS = {"stock-cold": 8 * GIB, "bazel-cold": 3 * GIB, "stock-lib": GIB}
PACKAGES = ("packages/smooth_app", "packages/app_store/apple_app_store", "packages/app_store/google_play", "packages/app_store/shared", "packages/app_store/uri_store", "packages/scanner/ml_kit", "packages/scanner/shared", "packages/scanner/zxing")
CREDENTIAL_NAMES = {".netrc", ".npmrc", ".pypirc", "credentials", "credentials.json", "remote-cache.bazelrc", "google-services.json", "key.properties", "id_rsa", "id_ed25519", "known_hosts", "auth.json", "token", "access_token", "refresh_token"}
def credential_name(name):
    low = name.lower()
    leaf = low.rsplit("/", 1)[-1]
    if leaf in CREDENTIAL_NAMES: return True
    if name == "home/.android/debug.keystore": return False
    disposable = low.startswith(("home/.gradle/", "home/.android/")) or any(
        low.startswith(p + suffix) for p in PACKAGES
        for suffix in ("/.dart_tool/", "/build/", "/android/.gradle/", "/android/.cxx/", "/android/app/.cxx/"))
    return disposable and low.endswith((".pem", ".p12", ".pfx", ".keystore"))
STOCK_CERT_SUFFIX = "/flutter_assets/assets/network/cert.pem"
STOCK_CERT_SIZE = 1911
STOCK_CERT_SHA256 = "c3c223f90ef6aabca1ed992400b9749d4a9b0cf7b5b47c38f55486b6ac53a40e"

def stock_cert_name(name):
    prefix = "packages/smooth_app/"
    if not name.startswith(prefix) or not name.endswith(STOCK_CERT_SUFFIX): return False
    middle = name[len(prefix):-len(STOCK_CERT_SUFFIX)]
    return middle == "build" or middle.startswith(("build/", ".dart_tool/")) or middle == ".dart_tool"

def checked_stock_cert(stream, member):
    data = stream.read(STOCK_CERT_SIZE + 1)
    if len(data) != STOCK_CERT_SIZE or hashlib.sha256(data).hexdigest() != STOCK_CERT_SHA256:
        raise CacheError("unexpected generated stock Flutter certificate bytes: " + member.name)
    return data
TRACKED = None
TRACKED_PARENTS = None
class CacheError(Exception):
    pass


def ancestor_identity(engine):
    return ":".join((required_env("GITHUB_SHA"), required_env("GITHUB_RUN_ID"),
                     required_env("GITHUB_RUN_ATTEMPT"), engine,
                     required_env("APK_ARM"), "cold"))

def required_env(key):
    value = os.environ.get(key, "")
    if not value or "\n" in value or "\r" in value: raise CacheError("missing/malformed identity " + key)
    return value

def generated_roots():
    return [(p + suffix, "generated", False) for p in PACKAGES for suffix in
            ("/.dart_tool", "/build", "/android/.gradle", "/android/.cxx", "/android/app/.cxx")]

def specs(engine, scenario):
    if engine == "stock" and scenario == "cold": return "cold", [("flutter", "sdk", True), ("cache-state/pub", "pub", True), ("home/.gradle", "gradle-home", False), ("home/.android/debug.keystore", "debug-keystore", False)] + generated_roots()
    if engine == "bazel" and scenario == "cold": return "cold", [("flutter", "sdk", True), ("cache-state/pub", "pub", True), ("cache-state/bazelisk", "bazelisk", True), ("bazel", "bazel-binary", True)]
    if engine == "stock" and scenario == "lib": return "lib", generated_roots()
    return None, []

def base_for(rel, engine):
    if rel == "flutter" or rel.startswith("flutter/") or rel == "cache-state/pub" or rel.startswith("cache-state/pub/") or rel == "cache-state/bazelisk" or rel.startswith("cache-state/bazelisk/") or rel == "bazel" or rel.startswith("bazel/"): return RUNNER
    if rel.startswith("packages/"): return ROOT / "trees" / engine
    return ROOT
def role_for(rel, engine):
    base = base_for(rel, engine)
    return "runner-temp" if base == RUNNER else "engine-tree" if base == ROOT / "trees" / engine else "apk-timing"

def tracked_paths():
    global TRACKED, TRACKED_PARENTS
    if TRACKED is None:
        res = subprocess.run(["git", "ls-files", "-z"], cwd=WORKTREE, check=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        TRACKED = set(res.stdout.decode().split("\0"))
        TRACKED_PARENTS = set()
        for path in TRACKED:
            parts = path.split("/")
            TRACKED_PARENTS.update("/".join(parts[:i]) for i in range(1, len(parts)))
    return TRACKED

def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()

def inside(path, base): return os.path.commonpath((str(path), str(base))) == str(base)

def walk(top, base):
    todo = [top]
    while todo:
        path = todo.pop()
        if path.name in ("docs", "src") and top == base / "home/.gradle":
            parts = path.relative_to(top).parts
            # Only the wrapper binaries are needed; the all distribution includes docs and sources.
            if (len(parts) == 6 and parts[:2] == ("wrapper", "dists")
                    and parts[2].startswith("gradle-") and parts[4].startswith("gradle-")):
                continue
        yield path
        if path.name == "init.d": continue
        if stat.S_ISDIR(path.lstat().st_mode): todo.extend(sorted(path.iterdir(), reverse=True))

def secret_values():
    return [v.encode() for k, v in os.environ.items() if v and any(s in k.upper() for s in ("TOKEN", "PASSWORD", "SECRET", "CREDENTIAL", "PRIVATE_KEY"))]

def guarded(stream, secrets, path):
    overlap = b""
    while True:
        block = stream.read(1 << 20)
        if not block:
            if any(s in overlap for s in secrets): raise CacheError("credential value found in " + str(path))
            return
        joined = overlap + block
        if any(s in joined for s in secrets): raise CacheError("credential value found in " + str(path))
        keep = max((len(s) for s in secrets), default=1) - 1
        overlap = joined[-keep:] if keep else b""
        yield block

class GuardedReader:
    def __init__(self, it): self.it, self.buf = it, b""
    def read(self, n=-1):
        while n < 0 or len(self.buf) < n:
            try: self.buf += next(self.it)
            except StopIteration: break
        if n < 0: out, self.buf = self.buf, b""; return out
        out, self.buf = self.buf[:n], self.buf[n:]; return out

def key(engine, scenario):
    suffix = "lib" if engine == "stock" and scenario in ("warm", "lib") else "cold"
    arm = required_env("APK_ARM") if engine == "bazel" else ""
    middle = f"{engine}-{arm}" if arm else engine
    return f"apk-current-{required_env('GITHUB_RUN_ID')}-{required_env('GITHUB_RUN_ATTEMPT')}-{required_env('GITHUB_SHA')}-{middle}-{suffix}"

def identity(engine, scenario):
    return {"schema": 1, "engine": engine, "scenario": scenario, "head": required_env("GITHUB_SHA"), "run_id": required_env("GITHUB_RUN_ID"), "run_attempt": required_env("GITHUB_RUN_ATTEMPT"), "arm": required_env("APK_ARM") if engine == "bazel" else None, "ancestor": "cold" if scenario in ("warm", "lib") else "self"}

def outputs(upload, cache_path, cache_key):
    text = f"upload={'true' if upload else 'false'}\npath={cache_path}\nkey={cache_key}\n"
    dest = os.environ.get("GITHUB_OUTPUT")
    if dest:
        with open(dest, "a", encoding="utf8") as f: f.write(text)
    else: sys.stdout.write(text)

def record(op):
    ROOT.mkdir(parents=True, exist_ok=True); path = ROOT / "cache.json"
    data = json.loads(path.read_text()) if path.is_file() else {"schema": 1, "operations": []}
    data["operations"].append(op); tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n"); os.replace(tmp, path)

def pack_archive(engine, root_specs, archive, archive_limit):
    tracked, secrets, rootmeta, count, raw = tracked_paths(), secret_values(), [], 0, 0
    proc = subprocess.Popen(["zstd", "-q", "-T2", "-3", "-f", "-o", str(archive)], stdin=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=proc.stdin, mode="w|", format=tarfile.PAX_FORMAT) as tar:
            for rel, label, required in root_specs:
                base = base_for(rel, engine); top = base / rel; present = os.path.lexists(top)
                if required and not present: raise CacheError("required root missing: " + rel)
                role = role_for(rel, engine)
                root = {"path": rel, "name": label, "base": role, "required": required, "present": present, "entries": 0, "raw_bytes": 0}
                rootmeta.append(root)
                if not present: continue
                realbase = Path(os.path.realpath(base))
                for path in walk(top, base):
                    name = path.relative_to(base).as_posix()
                    if role == "engine-tree" and name in tracked:
                        root.setdefault("excluded_tracked", []).append(name)
                        continue
                    if path.name == "init.d" and path.is_dir() and not path.is_symlink(): continue
                    cert = stock_cert_name(name)
                    if credential_name(name) and not cert:
                        raise CacheError("credential-like cache file: " + name)
                    info = tar.gettarinfo(str(path), arcname=name)
                    if cert:
                        if not info.isreg() or info.size != STOCK_CERT_SIZE:
                            raise CacheError("unexpected generated stock Flutter certificate type or size: " + name)
                        with path.open("rb") as f:
                            data = checked_stock_cert(f, info)
                        if any(secret in data for secret in secrets):
                            raise CacheError("credential value found in " + name)
                        tar.addfile(info, io.BytesIO(data))
                        raw += info.size; root["raw_bytes"] += info.size
                    elif info.issym():
                        target = Path(os.path.realpath(path))
                        if not inside(target, realbase):
                            raise CacheError("escaping source symlink: " + name)
                        if role == "engine-tree" and target.is_file() and target.relative_to(realbase).as_posix() in tracked:
                            raise CacheError("source symlink aliases tracked checkout content: " + name)
                        tar.addfile(info)
                    elif info.isreg() or info.islnk():
                        if info.islnk(): info.type, info.linkname, info.size = tarfile.REGTYPE, "", path.lstat().st_size
                        with path.open("rb") as f: tar.addfile(info, GuardedReader(guarded(f, secrets, path)))
                        raw += info.size; root["raw_bytes"] += info.size
                    elif info.isdir(): tar.addfile(info)
                    else: raise CacheError("unsupported source file type: " + name)
                    count += 1; root["entries"] += 1
                    if os.path.lexists(archive) and archive.stat().st_size > archive_limit:
                        sizes = ", ".join(f"{r['name']}={r['raw_bytes']}B/{r['entries']} entries" for r in rootmeta)
                        raise CacheError(f"compressed cache archive exceeds bounded upload limit ({archive.stat().st_size}>{archive_limit} bytes; roots: {sizes})")
    except Exception:
        try: proc.stdin.close()
        except BrokenPipeError: pass
        proc.wait()
        raise
    proc.stdin.close()
    if proc.wait(): raise CacheError("zstd compression failed")
    if not archive.is_file(): raise CacheError("zstd did not create cache archive")
    return {"name": archive.name.removesuffix(".tar.zst"), "file": archive.name, "base": "tree", "roots": rootmeta,
            "archive_bytes": archive.stat().st_size, "archive_sha256": digest(archive),
            "raw_bytes": raw, "entries": count}

def pack(engine, scenario, op):
    cachekey = key(engine, scenario); kind, roots = specs(engine, scenario)
    if not kind:
        op.update(status="skipped", reason="no snapshot for scenario"); outputs(False, TRANSPORT, cachekey); return
    cap = CAPS[f"{engine}-{kind}"]; TRANSPORT.mkdir(parents=True, exist_ok=True)
    for p in TRANSPORT.iterdir(): shutil.rmtree(p) if p.is_dir() and not p.is_symlink() else p.unlink()
    component = pack_archive(engine, roots, TRANSPORT / f"{engine}-{kind}.tar.zst", cap - HEADROOM)
    meta = {**identity(engine, scenario), "kind": kind, "cap_bytes": cap, "headroom_bytes": HEADROOM,
            "ancestor_identity": ancestor_identity(engine), "archive_bytes": component["archive_bytes"],
            "components": [component]}
    encoded = json.dumps(meta, sort_keys=True, indent=2) + "\n"; manifest_bytes = len(encoded.encode()); total = component["archive_bytes"] + manifest_bytes
    if total > cap - HEADROOM:
        sizes = ", ".join(f"{r['name']}={r['raw_bytes']}B/{r['entries']} entries" for r in component["roots"])
        raise CacheError(f"snapshot {total} exceeds cap less headroom {cap - HEADROOM} ({component['archive_bytes']} archive + {manifest_bytes} manifest; roots: {sizes})")
    (TRANSPORT / "manifest.json").write_text(encoded)
    op.update(status="ok", key=cachekey, cap_bytes=cap, headroom_bytes=HEADROOM, archive_bytes=component["archive_bytes"], manifest_bytes=manifest_bytes, manifest_sha256=hashlib.sha256(encoded.encode()).hexdigest(), combined_bytes=total, ancestor_identity=meta["ancestor_identity"], components=[component])
    excluded = [path for root in component["roots"] for path in root.get("excluded_tracked", [])]
    if excluded: op["warnings"] = ["tracked generated paths excluded individually: " + ", ".join(excluded)]
    outputs(True, TRANSPORT, cachekey)

def safe_member(name, roots):
    p = PurePosixPath(name)
    if p.is_absolute() or "\\" in name or any(x in ("", ".", "..") for x in name.split("/")): raise CacheError("unsafe archive member: " + repr(name))
    if not any(name == r or name.startswith(r + "/") for r in roots): raise CacheError("unknown archive root: " + name)
    return name

def destination(engine, name):
    return base_for(name, engine) / name
def destination_base(engine, name):
    return base_for(name, engine)

def inspect(engine, archive, roots):
    proc = subprocess.Popen(["zstd", "-q", "-d", "-c", str(archive)], stdout=subprocess.PIPE)
    seen, seen_parents = {}, set()
    count = raw = 0
    tracked_paths()
    try:
        with tarfile.open(fileobj=proc.stdout, mode="r|") as tar:
            for m in tar:
                name = safe_member(m.name, roots)
                in_tree = name.startswith("packages/")
                if in_tree and name in TRACKED:
                    raise CacheError("archive would overwrite tracked checkout content: " + name)
                if in_tree and name in TRACKED_PARENTS and not m.isdir():
                    raise CacheError("archive would replace tracked directory ancestor: " + name)
                cert = stock_cert_name(name)
                if credential_name(name) and not cert:
                    raise CacheError("credential-like archive member: " + name)
                if cert and (not m.isreg() or m.size != STOCK_CERT_SIZE):
                    raise CacheError("unexpected generated stock Flutter certificate type or size: " + name)
                if name in seen: raise CacheError("duplicate archive entry: "+name)
                parts = name.split("/")
                parents = ["/".join(parts[:i]) for i in range(1, len(parts))]
                if any(seen.get(parent, "dir") != "dir" for parent in parents):
                    raise CacheError("archive member nested under non-directory: " + name)
                kind = "dir" if m.isdir() else "symlink" if m.issym() else "file" if m.isreg() else "invalid"
                if name in seen_parents and kind != "dir":
                    raise CacheError("archive member replaces parent of another entry: " + name)
                seen[name] = kind
                seen_parents.update(parents)
                if m.isdir(): pass
                elif m.isreg():
                    f = tar.extractfile(m)
                    if cert:
                        checked_stock_cert(f, m)
                    else:
                        for _ in iter(lambda: f.read(1 << 20), b""): pass
                    raw += m.size
                elif m.issym():
                    if not inside(Path(os.path.realpath(destination(engine, name).parent / m.linkname)),
                                  Path(os.path.realpath(destination_base(engine, name)))):
                        raise CacheError("escaping archived symlink: " + name)
                else: raise CacheError("hardlink/device/unknown archive entry: "+name)
                count+=1
            while proc.stdout.read(1 << 20): pass
    except Exception:
        proc.stdout.close(); proc.kill(); proc.wait(); raise
    else:
        proc.stdout.close()
        if proc.wait(): raise CacheError("invalid zstd archive")
    return count,raw

def extract(engine, archive, roots):
    proc=subprocess.Popen(["zstd","-q","-d","-c",str(archive)],stdout=subprocess.PIPE); count=raw=0; dirs=[]
    try:
        with tarfile.open(fileobj=proc.stdout,mode="r|") as tar:
            for m in tar:
                name=safe_member(m.name,roots); target=destination(engine,name); parent=target.parent
                while not os.path.lexists(parent): parent=parent.parent
                base = destination_base(engine,name)
                ancestors=[]; check=parent
                while check != base and inside(check, base):
                    ancestors.append(check); check=check.parent
                for ancestor in ancestors:
                    if ancestor.is_symlink(): raise CacheError("extraction parent is a symlink: "+name)
                    if os.path.lexists(ancestor) and not ancestor.is_dir(): raise CacheError("extraction parent is not a directory: "+name)
                if not inside(Path(os.path.realpath(parent)),Path(os.path.realpath(base))):
                    raise CacheError("extraction parent escapes root: "+name)
                if m.isdir():
                    if os.path.lexists(target) and (target.is_symlink() or not target.is_dir()):
                        if name.startswith("packages/") and name in TRACKED_PARENTS: raise CacheError("refusing to replace tracked directory ancestor: " + name)
                        target.unlink()
                    target.mkdir(parents=True,exist_ok=True); dirs.append((target,m))
                elif m.isreg():
                    if target.is_dir() and not target.is_symlink():
                        if name.startswith("packages/") and name in TRACKED_PARENTS: raise CacheError("refusing to replace tracked directory ancestor: " + name)
                        shutil.rmtree(target)
                    elif os.path.lexists(target): target.unlink()
                    target.parent.mkdir(parents=True,exist_ok=True)
                    with tar.extractfile(m) as src,target.open("wb") as dst: shutil.copyfileobj(src,dst)
                    os.chmod(target,m.mode&0o777); os.utime(target,(m.mtime,m.mtime)); raw+=m.size
                elif m.issym():
                    if not inside(Path(os.path.realpath(target.parent/m.linkname)),Path(os.path.realpath(base))): raise CacheError("escaping symlink: "+name)
                    if os.path.lexists(target): target.unlink()
                    target.parent.mkdir(parents=True,exist_ok=True); os.symlink(m.linkname,target)
                else: raise CacheError("invalid archive member type: "+name)
                count+=1
            while proc.stdout.read(1 << 20): pass
    except Exception:
        proc.stdout.close(); proc.kill(); proc.wait(); raise
    proc.stdout.close()
    if proc.wait(): raise CacheError("zstd extraction failed")
    return count,raw

def restore(engine, scenario, op):
    requested=key(engine,scenario)
    if scenario=="cold": op.update(status="skipped",reason="cold starts from prepared tracked checkout"); outputs(False,TRANSPORT,requested); return
    _,roots=specs(engine,"cold"); raw=(TRANSPORT/"manifest.json").read_bytes(); meta=json.loads(raw)
    expected_identity=identity(engine,"cold")
    diff=[k for k,v in expected_identity.items() if meta.get(k)!=v]
    if diff: raise CacheError("snapshot identity mismatch: "+", ".join(diff))
    cap=CAPS[f"{engine}-cold"]
    if meta.get("cap_bytes")!=cap or meta.get("headroom_bytes")!=HEADROOM: raise CacheError("cap/headroom mismatch")
    expected_ancestor=ancestor_identity(engine)
    if meta.get("ancestor_identity")!=expected_ancestor: raise CacheError("ancestor identity mismatch")
    comps=meta.get("components")
    if not isinstance(comps,list) or len(comps)!=1: raise CacheError("invalid component list")
    c=comps[0]; expected=[r for r,_,_ in roots]
    if (set(meta)!={"schema","engine","scenario","head","run_id","run_attempt","arm","ancestor","kind","cap_bytes","headroom_bytes","ancestor_identity","archive_bytes","components"}
            or meta.get("kind")!="cold" or c.get("name")!=f"{engine}-cold"
            or set(c)!={"name","file","base","roots","archive_bytes","archive_sha256","raw_bytes","entries"}
            or c.get("base")!="tree" or [r.get("path") for r in c.get("roots",[]) ]!=expected):
        raise CacheError("snapshot manifest layout mismatch")
    if [(r.get("path"),r.get("name"),r.get("base"),r.get("required")) for r in c["roots"]] != [
            (rel,label,role_for(rel,engine),required) for rel,label,required in roots]:
        raise CacheError("snapshot root roles mismatch")
    filename=c.get("file","")
    if filename!=f"{engine}-cold.tar.zst": raise CacheError("unexpected archive filename")
    archive=TRANSPORT/filename
    if not archive.is_file() or archive.stat().st_size!=c.get("archive_bytes") or digest(archive)!=c.get("archive_sha256"): raise CacheError("archive size or SHA mismatch")
    total=c["archive_bytes"]+len(raw)
    if c["archive_bytes"] != meta.get("archive_bytes") or total>cap-HEADROOM: raise CacheError("aggregate size/cap mismatch")
    allowed=[r for r,_,_ in roots]; count,rawbytes=inspect(engine,archive,allowed)
    if count!=c.get("entries") or rawbytes!=c.get("raw_bytes"): raise CacheError("entry/raw counts mismatch")

    for rel,_,_ in roots:
        target=base_for(rel,engine)/rel; parent=target.parent
        while not os.path.lexists(parent): parent=parent.parent
        if not inside(Path(os.path.realpath(parent)),Path(os.path.realpath(base_for(rel,engine)))):
            raise CacheError("destination ancestor escapes tree: "+rel)
    actual,actualraw=extract(engine,archive,allowed)
    if (actual,actualraw)!=(count,rawbytes): raise CacheError("extraction differs from preflight counts")
    op.update(status="ok",key=key(engine,"cold"),cap_bytes=cap,headroom_bytes=HEADROOM,archive_bytes=c["archive_bytes"],manifest_bytes=len(raw),manifest_sha256=hashlib.sha256(raw).hexdigest(),combined_bytes=total,ancestor_identity=meta["ancestor_identity"],components=[{"file":filename,"archive_bytes":c["archive_bytes"],"archive_sha256":c["archive_sha256"],"entries":actual,"raw_bytes":actualraw,"roots":c["roots"]}])

def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("command",choices=("pack","restore")); p.add_argument("--engine",required=True,choices=("stock","bazel")); p.add_argument("--scenario",required=True,choices=("cold","warm","lib")); a=p.parse_args(argv)
    op={"command":a.command,"engine":a.engine,"scenario":a.scenario,"head":os.environ.get("GITHUB_SHA"),"run_id":os.environ.get("GITHUB_RUN_ID"),"run_attempt":os.environ.get("GITHUB_RUN_ATTEMPT"),"status":"error","error":None,"started_epoch":time.time(),"started_monotonic_ns":time.monotonic_ns(),"components":[]}; rc=0
    try: (pack if a.command=="pack" else restore)(a.engine,a.scenario,op)
    except Exception as e:
        op["error"]=str(e); rc=1; print("timing_cache.py failed: "+str(e),file=sys.stderr)
        try: outputs(False,TRANSPORT,key(a.engine,a.scenario))
        except Exception: pass
    finally:
        op["ended_epoch"]=time.time(); op["ended_monotonic_ns"]=time.monotonic_ns()
        op["duration_seconds"]=round((op["ended_monotonic_ns"]-op["started_monotonic_ns"])/1_000_000_000,6)
        try: record(op)
        except Exception as e: print("cannot persist cache metrics: "+str(e),file=sys.stderr); rc=1
    return rc

if __name__=="__main__": sys.exit(main())
