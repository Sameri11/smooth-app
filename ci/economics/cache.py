#!/usr/bin/env python3
"""Pack or restore immutable cache snapshots for the host timing pilot.

`cache.py pack|restore --engine flutter|bazel --scenario cold|warm|test|lib --rep 1|2|3`

- Cold pack writes the seed snapshot: every component for one engine and repetition.
  It is the unmutated baseline.
- Warm restore extracts the exact cold ancestor: same run, head, engine and repetition.
- Test and lib packs write only the build component. The manifest names the predeclared
  mutation whose build state it holds. Warm (unchanged) packs nothing.

Archives are zstd-compressed tar streams over explicit root lists. Restore verifies the
frozen inputs, the source identity and every archive's size and SHA256 before extracting any,
and rejects entries outside the declared roots, hardlinks, devices, and links that resolve
outside the base directory.
"""

import argparse
import collections
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import time

import probe

GIB = 1024 ** 3
CAPS = {"seed": 6 * GIB, "updated": 2 * GIB}
ENGINES = ("flutter", "bazel")
SCENARIOS = ("cold", "warm", "test", "lib")
REPS = (1, 2, 3)
BASELINE = {"kind": "baseline"}
# roots: (path relative to base, required). Optional roots are recorded as absent when missing.
Spec = collections.namedtuple("Spec", "name group file base roots")


class CacheError(Exception):
    pass


def require_env(name):
    value = os.environ.get(name, "")
    if not value:
        raise CacheError("%s is not set" % name)
    return value


def runner_temp():
    return Path(require_env("RUNNER_TEMP"))


def base_dir(name):
    return runner_temp() if name == "RUNNER_TEMP" else probe.ROOT


def build_specs(engine):
    sdk = Spec("sdk", "sdk", "sdk.tar.zst", "RUNNER_TEMP", [("flutter", True)])
    if engine == "flutter":
        generated = []
        for pkg in probe.PACKAGES:
            generated += [(pkg + "/.dart_tool", True), (pkg + "/build", False),
                          (pkg + "/.flutter-plugins-dependencies", False), (pkg + "/.flutter-plugins", False)]
        return [
            sdk,
            Spec("deps", "deps", "deps.tar.zst", "RUNNER_TEMP", [("cache-state/pub", True)]),
            Spec("build", "build", "build.tar.zst", "ROOT", generated),
        ]
    return [
        sdk,
        Spec("deps", "deps", "deps.tar.zst", "RUNNER_TEMP",
             [("cache-state/repository", True), ("cache-state/bazelisk", True),
              ("cache-state/pub", True), ("bazel", True)]),
        Spec("disk", "build", "build-disk.tar.zst", "RUNNER_TEMP", [("cache-state/disk", True)]),
        Spec("lock", "build", "build-lock.tar.zst", "ROOT", [("MODULE.bazel.lock", True)]),
    ]


def inside(path, base):
    return path == base or path.startswith(base + os.sep)


def link_inside(parent, linkname, base_real):
    """Whether a symlink in `parent` resolves, as the kernel resolves it now, inside the base."""
    return inside(os.path.realpath(os.path.join(os.path.realpath(parent), linkname)), base_real)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(*args):
    result = subprocess.run(["git", *args], cwd=probe.ROOT, capture_output=True, text=True)
    if result.returncode:
        raise CacheError("git %s exited %d" % (args[0], result.returncode))
    return result.stdout


def source_identity():
    """Checkout head plus a digest of the tracked Dart sources; the tree must be unaltered."""
    head = git("rev-parse", "HEAD").strip()
    if head != require_env("GITHUB_SHA"):
        raise CacheError("checkout HEAD %s differs from GITHUB_SHA" % head)
    if git("status", "--porcelain", "--untracked-files=no", "--", *probe.PACKAGES).strip():
        raise CacheError("tracked package files are modified")
    tracked = [path for path in git("ls-files", "-z", "--", *probe.PACKAGES).split("\0")
               if path.endswith(".dart")]
    digest = hashlib.sha256()
    for path in sorted(tracked):
        digest.update(("%s  %s\n" % (sha256_file(probe.ROOT / path), path)).encode())
    return {"head": head, "dart_files": len(tracked), "dart_sha256": digest.hexdigest()}


def state_variant(args):
    """The cached-state variant: cold is the unmutated baseline; edited packs name their mutation."""
    if args.scenario == "cold":
        return BASELINE
    report = json.loads((runner_temp() / "smooth-ci-evidence" / "result.json").read_text())
    if (report.get("engine"), report.get("scenario"), report.get("rep")) != (args.engine, args.scenario, args.rep):
        raise CacheError("timed result identity differs from the pack arguments")
    mutation = report.get("mutation")
    if not mutation or report.get("sources_restored") is not True:
        raise CacheError("edited state needs a predeclared mutation whose sources were restored")
    if mutation["restored_sha256"] != mutation["old_sha256"]:
        raise CacheError("mutated source %s did not restore to its original hash" % mutation["path"])
    keys = ("name", "path", "old_sha256", "new_sha256", "restored_sha256")
    return {"kind": "mutated", "verdict": report.get("verdict"),
            "mutation": {key: mutation[key] for key in keys}}


def walk(top):
    """Preorder entries under top, sorted; symlinks are yielded and never followed."""
    stack = [top]
    while stack:
        path = stack.pop()
        yield path
        if stat.S_ISDIR(os.lstat(path).st_mode):
            stack.extend(sorted((path / name for name in os.listdir(path)), reverse=True))


@contextlib.contextmanager
def span(sink, name):
    start_ns, start_epoch = time.monotonic_ns(), time.time()
    try:
        yield
    finally:
        sink.append({"name": name, "start_monotonic_ns": start_ns, "end_monotonic_ns": time.monotonic_ns(),
                     "start_epoch": start_epoch, "end_epoch": time.time()})


def shutdown_bazel():
    """Stops the exact fresh output base so its caches reach the disk cache before packing."""
    output_base = runner_temp() / "bazel-output"
    if not output_base.exists():
        return "no output base"
    binary = runner_temp() / "bazel"
    if not binary.is_file():
        raise CacheError("Bazelisk binary missing: %s" % binary)
    result = subprocess.run([str(binary), *probe.STARTUP, "--output_base=" + str(output_base), "shutdown"],
                            cwd=probe.ROOT, capture_output=True, text=True)
    if result.returncode:
        raise CacheError("bazel shutdown exited %d: %s" % (result.returncode, result.stderr[-2000:]))
    return "shut down"


def write_archive(spec, export):
    base = base_dir(spec.base)
    base_real = os.path.realpath(base)
    archive = export / spec.file
    if shutil.which("zstd") is None:
        raise CacheError("zstd is not on PATH")
    zstd = subprocess.Popen(["zstd", "-q", "-T2", "-3", "-f", "-o", str(archive)], stdin=subprocess.PIPE)
    roots, members, raw_bytes = [], 0, 0
    try:
        with tarfile.open(fileobj=zstd.stdin, mode="w|", format=tarfile.PAX_FORMAT) as tar:
            for rel, required in spec.roots:
                top = base / rel
                present = os.path.lexists(top)
                if not present and required:
                    raise CacheError("required root missing: %s" % top)
                roots.append({"path": rel, "required": required, "present": present})
                if not present:
                    continue
                for entry in walk(top):
                    info = tar.gettarinfo(str(entry), arcname=entry.relative_to(base).as_posix())
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    if info.issym() and not link_inside(entry.parent, info.linkname, base_real):
                        raise CacheError("symlink leaves base: %s" % entry)
                    if info.islnk():
                        # A hardlink's first copy may live in another archive, so store the content.
                        info.type, info.linkname, info.size = tarfile.REGTYPE, "", entry.lstat().st_size
                    if info.isreg():
                        with entry.open("rb") as data:
                            tar.addfile(info, data)
                        raw_bytes += info.size
                    elif info.isdir() or info.issym():
                        tar.addfile(info)
                    else:
                        raise CacheError("unsupported file type: %s" % entry)
                    members += 1
    except Exception:
        zstd.stdin.close()
        zstd.wait()
        raise
    zstd.stdin.close()
    if zstd.wait():
        raise CacheError("zstd exited %d" % zstd.returncode)
    return {"name": spec.name, "group": spec.group, "file": spec.file, "base": spec.base, "roots": roots,
            "archive_bytes": archive.stat().st_size, "archive_sha256": sha256_file(archive),
            "raw_bytes": raw_bytes, "members": members}


def member_path(name, roots):
    if name.startswith("/") or any(part in ("", ".", "..") for part in name.split("/")):
        raise CacheError("unsafe archive entry: %r" % name)
    if not any(name == root or name.startswith(root + "/") for root in roots):
        raise CacheError("archive entry outside declared roots: %r" % name)
    return name


def ensure_parent(target, base_real):
    existing = target.parent
    while not os.path.lexists(existing):
        existing = existing.parent
    if not inside(os.path.realpath(existing), base_real):
        raise CacheError("existing path resolves outside the base: %s" % existing)
    target.parent.mkdir(parents=True, exist_ok=True)


def replace_entry(target):
    """Clears a leftover non-directory entry; a real directory is never clobbered."""
    if os.path.isdir(target) and not os.path.islink(target):
        raise CacheError("restore target already exists: %s" % target)
    if os.path.lexists(target):
        os.unlink(target)


def extract_archive(archive, base, roots):
    base_real = os.path.realpath(base)
    directories, members, raw_bytes = [], 0, 0
    decoder = subprocess.Popen(["zstd", "-q", "-d", "-c", str(archive)], stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=decoder.stdout, mode="r|") as tar:
            for member in tar:
                target = base / member_path(member.name, roots)
                ensure_parent(target, base_real)
                members += 1
                if member.isdir():
                    if os.path.islink(target):
                        os.unlink(target)
                    if not os.path.isdir(target):
                        os.mkdir(target)
                    directories.append((target, member))
                elif member.isreg():
                    replace_entry(target)
                    with target.open("wb") as out:
                        shutil.copyfileobj(tar.extractfile(member), out)
                    os.chmod(target, member.mode & 0o777)
                    os.utime(target, (member.mtime, member.mtime))
                    raw_bytes += member.size
                elif member.issym():
                    if not link_inside(target.parent, member.linkname, base_real):
                        raise CacheError("symlink leaves the base: %s" % member.name)
                    replace_entry(target)
                    os.symlink(member.linkname, target)
                    os.utime(target, (member.mtime, member.mtime), follow_symlinks=False)
                else:
                    raise CacheError("unsupported archive entry type: %s" % member.name)
            while decoder.stdout.read(1 << 20):
                pass
        for path, member in reversed(directories):
            os.chmod(path, member.mode & 0o777)
            os.utime(path, (member.mtime, member.mtime))
    except Exception:
        decoder.kill()
        decoder.wait()
        raise
    decoder.stdout.close()
    if decoder.wait():
        raise CacheError("zstd -d exited %d" % decoder.returncode)
    return {"members": members, "raw_bytes": raw_bytes}


def check_namespace(meta, args):
    expected = {"schema": 1, "kind": "seed", "scenario": "cold", "engine": args.engine, "rep": args.rep,
                "run_id": require_env("GITHUB_RUN_ID"), "head": require_env("GITHUB_SHA"),
                "inputs_manifest_sha256": sha256_file(probe.MANIFEST), "state_variant": BASELINE}
    differs = sorted(key for key in expected if meta.get(key) != expected[key])
    if differs:
        raise CacheError("seed snapshot is not the exact baseline ancestor; differing fields: %s" % differs)


def emit(upload, export):
    lines = "upload=%s\npath=%s\n" % ("true" if upload else "false", export)
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a") as stream:
            stream.write(lines)
    else:
        sys.stdout.write(lines)


def restore(args, op):
    if args.scenario == "cold":
        op["status"], op["reason"] = "skipped", "cold starts from the stock state"
        return
    probe.load_manifest()
    specs = build_specs(args.engine)
    seed = runner_temp() / "seed"
    verified = []
    with span(op["spans"], "verification"):
        meta = json.loads((seed / "manifest.json").read_text())
        check_namespace(meta, args)
        if meta.get("source") != source_identity():
            raise CacheError("checkout source identity differs from the seed snapshot")
        components = {c["name"]: c for c in meta["components"]}
        if sorted(components) != sorted(spec.name for spec in specs):
            raise CacheError("seed components differ from the frozen layout")
        for spec in specs:
            entry = components[spec.name]
            if (entry["file"] != spec.file or entry["base"] != spec.base
                    or [r["path"] for r in entry["roots"]] != [path for path, _ in spec.roots]):
                raise CacheError("seed component %s differs from the frozen layout" % spec.name)
            archive = seed / entry["file"]
            if not archive.is_file() or archive.stat().st_size != entry["archive_bytes"]:
                raise CacheError("seed archive size mismatch: %s" % archive)
            if sha256_file(archive) != entry["archive_sha256"]:
                raise CacheError("seed archive digest mismatch: %s" % archive)
            verified.append((spec, entry, archive))
    with span(op["spans"], "preparation"):
        for spec, entry, _ in verified:
            base = base_dir(spec.base)
            base.mkdir(parents=True, exist_ok=True)
            for root in entry["roots"]:
                if root["present"]:
                    replace_entry(base / root["path"])
    with span(op["spans"], "extraction"):
        for spec, entry, archive in verified:
            roots = [root["path"] for root in entry["roots"] if root["present"]]
            with span(op["spans"], "extraction:" + spec.name):
                result = extract_archive(archive, base_dir(spec.base), roots)
            op["archives"].append({"name": spec.name, "file": entry["file"],
                                   "archive_bytes": entry["archive_bytes"],
                                   "archive_sha256": entry["archive_sha256"],
                                   "members": result["members"], "raw_bytes": result["raw_bytes"]})
    op["status"] = "ok"


def pack(args, op):
    export = runner_temp() / "cache-export"
    if args.scenario == "warm":
        op["status"], op["reason"] = "skipped", "unchanged warm state uploads nothing"
        emit(False, export)
        return
    probe.load_manifest()
    variant = state_variant(args)
    source = source_identity()
    kind = "seed" if args.scenario == "cold" else "updated"
    specs = build_specs(args.engine)
    selected = specs if kind == "seed" else [spec for spec in specs if spec.group == "build"]
    if export.exists():
        shutil.rmtree(export)
    export.mkdir(parents=True)
    if args.engine == "bazel":
        with span(op["spans"], "shutdown"):
            op["bazel_shutdown"] = shutdown_bazel()
    with span(op["spans"], "compression"):
        for spec in selected:
            with span(op["spans"], "compression:" + spec.name):
                op["archives"].append(write_archive(spec, export))
    total = sum(entry["archive_bytes"] for entry in op["archives"])
    cap = CAPS[kind]
    meta = {"schema": 1, "kind": kind, "scenario": args.scenario, "engine": args.engine, "rep": args.rep,
            "run_id": require_env("GITHUB_RUN_ID"), "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            "head": require_env("GITHUB_SHA"), "inputs_manifest_sha256": sha256_file(probe.MANIFEST),
            "source": source, "state_variant": variant, "cap_bytes": cap, "archive_bytes": total,
            "components": op["archives"]}
    text = json.dumps(meta, indent=2, sort_keys=True) + "\n"
    combined = total + len(text.encode())
    if combined > cap:
        raise CacheError("%s archives and manifest total %d bytes, over the %d byte cap"
                         % (kind, combined, cap))
    (export / "manifest.json").write_text(text)
    op["manifest_bytes"], op["combined_bytes"] = len(text.encode()), combined
    emit(True, export)
    op["status"] = "ok"


def record(op):
    evidence = runner_temp() / "smooth-ci-evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    path = evidence / "cache.json"
    doc = json.loads(path.read_text()) if path.exists() else {"schema": 1, "operations": []}
    doc["operations"].append(op)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def main(argv):
    parser = argparse.ArgumentParser(description="Pack or restore a host timing cache snapshot.")
    parser.add_argument("command", choices=("restore", "pack"))
    parser.add_argument("--engine", required=True, choices=ENGINES)
    parser.add_argument("--scenario", required=True, choices=SCENARIOS)
    parser.add_argument("--rep", required=True, type=int, choices=REPS)
    args = parser.parse_args(argv[1:])
    op = {"command": args.command, "engine": args.engine, "scenario": args.scenario, "rep": args.rep,
          "run_id": os.environ.get("GITHUB_RUN_ID"), "head": os.environ.get("GITHUB_SHA"),
          "status": "error", "error": None, "spans": [], "archives": [],
          "started_epoch": time.time(), "started_monotonic_ns": time.monotonic_ns()}
    code = 0
    try:
        (restore if args.command == "restore" else pack)(args, op)
    except Exception as error:
        op["error"] = str(error)
        print("cache.py %s failed: %s" % (args.command, error), file=sys.stderr)
        code = 1
    op["ended_monotonic_ns"] = time.monotonic_ns()
    op["ended_epoch"] = time.time()
    record(op)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
