#!/usr/bin/env python3
"""Pack or restore immutable cache snapshots for the host timing pilot.

`cache.py pack --engine flutter|bazel --scenario cold|warm|test|lib --rep 1|2|3`
`cache.py restore --engine ... --scenario ... --rep ... [--ancestor cold|test] [--component all|build]`

Both directions use the transport directory $RUNNER_TEMP/cache-export.

- Cold pack writes the seed: every component for one engine and repetition, from the unmutated
  baseline. Remote Bazel seeds hold the SDK, pub, repository, Bazelisk, the Bazel binary and the
  module lock; the disk action cache and the output base are never archived.
- Stock test and lib packs write only the build component, which holds the predeclared mutation
  named by the timed result. Warm packs and remote Bazel test and lib packs write nothing: remote
  writes are charged by the timed run.
- Restores verify the namespace, the declared predecessor, the source identity and every archive's
  size and SHA256 before extracting any. `--ancestor cold` (default) restores the seed; stock lib
  then overlays `--ancestor test --component build`. The overlay replaces every declared build root,
  so generated files from the seed do not survive into the test state.
Archives are zstd-compressed tar streams over explicit root lists. Restore rejects entries outside
the declared roots, hardlinks, devices, and links that resolve outside the base directory.
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
import timing

GIB = 1024 ** 3
MIB = 1024 ** 2
CAPS = {"seed": 3 * GIB, "updated": 1 * GIB}
# Reserved inside each cap for the manifest and the transport wrapper.
HEADROOM = 64 * MIB
ENGINES = ("flutter", "bazel")
SCENARIOS = ("cold", "warm", "test", "lib")
REPS = (1, 2, 3)
ANCESTORS = ("cold", "test")
COMPONENTS = ("all", "build")
# (scenario, ancestor, component) restores a job may perform. Cold starts from the stock state.
RESTORES = {("cold", "cold", "all"), ("warm", "cold", "all"), ("test", "cold", "all"),
            ("lib", "cold", "all"), ("lib", "test", "build")}
BASELINE = {"kind": "baseline"}
CREDENTIAL_NAMES = ("remote-cache.bazelrc", ".netrc")
# roots: (path relative to base, required). Optional roots are recorded as absent when missing.
Spec = collections.namedtuple("Spec", "name group file base roots")


class CacheError(Exception):
    pass


class TokenGuard:
    """Read-through stream that fails when the remote cache token appears, including across reads."""

    def __init__(self, stream, token, where):
        self.stream, self.token, self.where = stream, token, where
        self.tail = b""

    def read(self, size=-1):
        data = self.stream.read(size)
        if self.token:
            window = self.tail + data
            if self.token in window:
                raise CacheError("remote cache credential found in archive entry: %s" % self.where)
            self.tail = window[-(len(self.token) - 1):] if len(self.token) > 1 else b""
        return data


def require_env(name):
    value = os.environ.get(name, "")
    if not value:
        raise CacheError("%s is not set" % name)
    return value


def runner_temp():
    return Path(require_env("RUNNER_TEMP"))


def transport_dir():
    return runner_temp() / "cache-export"


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
    # No disk action cache and no output base: remote writes carry the action cache.
    return [
        sdk,
        Spec("deps", "deps", "deps.tar.zst", "RUNNER_TEMP",
             [("cache-state/repository", True), ("cache-state/bazelisk", True),
              ("cache-state/pub", True), ("bazel", True)]),
        Spec("lock", "deps", "lock.tar.zst", "ROOT", [("MODULE.bazel.lock", True)]),
    ]


def select(specs, component):
    return specs if component == "all" else [spec for spec in specs if spec.group == "build"]


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


def mutated_variant(scenario):
    """The build state a predeclared source edit leaves, derived from the timing spec without editing."""
    name = timing.MUTATION_FOR_SCENARIO[scenario]
    spec = timing.MUTATIONS[name]
    return {"kind": "mutated", "verdict": "pass",
            "mutation": {"name": name, "path": spec["path"], "old_sha256": spec["old_sha"],
                         "new_sha256": spec["new_sha"], "restored_sha256": spec["old_sha"]}}


def timed_state(args):
    """The state this pack holds, verified against the timed result that produced it."""
    report = json.loads((runner_temp() / "smooth-ci-evidence" / "result.json").read_text())
    if (report.get("engine"), report.get("scenario"), report.get("rep")) != (args.engine, args.scenario, args.rep):
        raise CacheError("timed result identity differs from the pack arguments")
    if report.get("verdict") != "pass" or report.get("sources_restored") is not True:
        raise CacheError("timed run did not pass with its sources restored")
    if args.scenario == "cold":
        if report.get("mutation") is not None:
            raise CacheError("cold timed run records a source mutation")
        return BASELINE
    expected = mutated_variant(args.scenario)
    if report.get("mutation") != expected["mutation"]:
        raise CacheError("timed mutation differs from the predeclared %s spec" % expected["mutation"]["name"])
    return expected


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
    token = os.environ.get("BAZEL_CACHE_TOKEN_RW", "").encode()
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
                    if entry.name in CREDENTIAL_NAMES:
                        raise CacheError("credential file inside a cache root: %s" % entry)
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
                            tar.addfile(info, TokenGuard(data, token, entry))
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


def clear_roots(base, rels, replace):
    """Removes each declared root before extraction. Without replace, an existing directory is an error;
    with replace (the test overlay), it is removed so stale generated files cannot survive."""
    base_real = os.path.realpath(base)
    for rel in rels:
        target = base / rel
        if not os.path.lexists(target):
            continue
        if not inside(os.path.realpath(target.parent), base_real):
            raise CacheError("existing root resolves outside the base: %s" % target)
        if os.path.isdir(target) and not os.path.islink(target):
            if not replace:
                raise CacheError("restore target already exists: %s" % target)
            shutil.rmtree(target)
        else:
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


def namespace(args, scenario, kind, state):
    """Identity every snapshot carries; the GitHub key and this manifest must both name it."""
    return {"schema": 1, "kind": kind, "scenario": scenario, "engine": args.engine, "rep": args.rep,
            "run_id": require_env("GITHUB_RUN_ID"), "run_attempt": require_env("GITHUB_RUN_ATTEMPT"),
            "head": require_env("GITHUB_SHA"), "inputs_manifest_sha256": sha256_file(probe.MANIFEST),
            "state_variant": state}


def predecessor(args):
    """The declared ancestor: the cold seed, or the stock test build an overlay replaces onto."""
    if args.ancestor == "cold":
        return "seed", "cold", BASELINE
    return "updated", "test", mutated_variant("test")


def check_request(args):
    if (args.scenario, args.ancestor, args.component) not in RESTORES:
        raise CacheError("no restore of %s from %s/%s is declared" % (args.scenario, args.ancestor, args.component))
    if args.engine == "bazel" and args.ancestor == "test":
        raise CacheError("remote Bazel keeps no test snapshot; lib restores the seed")


def check_predecessor(meta, args):
    kind, scenario, state = predecessor(args)
    expected = namespace(args, scenario, kind, state)
    expected.update({"cap_bytes": CAPS[kind], "headroom_bytes": HEADROOM})
    differs = sorted(key for key in expected if meta.get(key) != expected[key])
    if differs:
        raise CacheError("snapshot is not the declared %s ancestor; differing fields: %s" % (args.ancestor, differs))


def emit(upload, export):
    lines = "upload=%s\npath=%s\n" % ("true" if upload else "false", export)
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a") as stream:
            stream.write(lines)
    else:
        sys.stdout.write(lines)


def restore(args, op):
    check_request(args)
    if args.scenario == "cold":
        op["status"], op["reason"] = "skipped", "cold starts from the stock state"
        return
    probe.load_manifest()
    wanted = select(build_specs(args.engine), args.component)
    export = transport_dir()
    kind = predecessor(args)[0]
    verified = []
    with span(op["spans"], "verification"):
        manifest_text = (export / "manifest.json").read_text()
        meta = json.loads(manifest_text)
        check_predecessor(meta, args)
        if meta.get("source") != source_identity():
            raise CacheError("checkout source identity differs from the snapshot")
        components = {c["name"]: c for c in meta["components"]}
        if sorted(components) != sorted(spec.name for spec in wanted):
            raise CacheError("snapshot components differ from the declared layout: %s" % sorted(components))
        if sum(c["archive_bytes"] for c in meta["components"]) != meta["archive_bytes"]:
            raise CacheError("snapshot archive bytes differ from its components")
        if meta["archive_bytes"] + len(manifest_text.encode()) > CAPS[kind] - HEADROOM:
            raise CacheError("snapshot exceeds its cap less headroom")
        for spec in wanted:
            entry = components[spec.name]
            if (entry["file"] != spec.file or entry["base"] != spec.base
                    or [r["path"] for r in entry["roots"]] != [path for path, _ in spec.roots]):
                raise CacheError("component %s differs from the declared layout" % spec.name)
            archive = export / entry["file"]
            if not archive.is_file() or archive.stat().st_size != entry["archive_bytes"]:
                raise CacheError("archive size mismatch: %s" % archive)
            if sha256_file(archive) != entry["archive_sha256"]:
                raise CacheError("archive digest mismatch: %s" % archive)
            verified.append((spec, entry, archive))
    with span(op["spans"], "preparation"):
        for spec, _, _ in verified:
            clear_roots(base_dir(spec.base), [path for path, _ in spec.roots], args.ancestor == "test")
    with span(op["spans"], "extraction"):
        for spec, entry, archive in verified:
            roots = [root["path"] for root in entry["roots"] if root["present"]]
            with span(op["spans"], "extraction:" + spec.name):
                result = extract_archive(archive, base_dir(spec.base), roots)
            if result["members"] != entry["members"] or result["raw_bytes"] != entry["raw_bytes"]:
                raise CacheError("archive %s extracted %d members and %d bytes; manifest records %d and %d"
                                 % (spec.name, result["members"], result["raw_bytes"],
                                    entry["members"], entry["raw_bytes"]))
            op["archives"].append({"name": spec.name, "file": entry["file"],
                                   "archive_bytes": entry["archive_bytes"],
                                   "archive_sha256": entry["archive_sha256"],
                                   "members": result["members"], "raw_bytes": result["raw_bytes"]})
    op["predecessor"] = {"kind": meta["kind"], "scenario": meta["scenario"], "run_attempt": meta["run_attempt"],
                         "state_variant": meta["state_variant"], "cap_bytes": meta["cap_bytes"],
                         "headroom_bytes": meta["headroom_bytes"], "archive_bytes": meta["archive_bytes"],
                         "manifest_bytes": len(manifest_text.encode()),
                         "manifest_sha256": hashlib.sha256(manifest_text.encode()).hexdigest()}
    op["status"] = "ok"


def reset_transport(export):
    """Empties the task-owned transport directory; nothing outside it is touched."""
    if export.is_symlink() or export.is_file():
        export.unlink()
    elif export.exists():
        shutil.rmtree(export)
    export.mkdir(parents=True)


def pack(args, op):
    export = transport_dir()
    if args.scenario == "warm":
        op["status"], op["reason"] = "skipped", "unchanged warm state uploads nothing"
        emit(False, export)
        return
    if args.engine == "bazel" and args.scenario != "cold":
        op["status"], op["reason"] = "skipped", "remote Bazel edits are charged by the timed run; no snapshot"
        emit(False, export)
        return
    probe.load_manifest()
    state = timed_state(args)
    source = source_identity()
    kind = "seed" if args.scenario == "cold" else "updated"
    selected = select(build_specs(args.engine), "all" if kind == "seed" else "build")
    reset_transport(export)
    if args.engine == "bazel":
        with span(op["spans"], "shutdown"):
            op["bazel_shutdown"] = shutdown_bazel()
    with span(op["spans"], "compression"):
        for spec in selected:
            with span(op["spans"], "compression:" + spec.name):
                op["archives"].append(write_archive(spec, export))
    total = sum(entry["archive_bytes"] for entry in op["archives"])
    cap = CAPS[kind]
    limit = cap - HEADROOM
    meta = namespace(args, args.scenario, kind, state)
    meta.update({"source": source, "cap_bytes": cap, "headroom_bytes": HEADROOM, "archive_bytes": total,
                 "components": op["archives"]})
    text = json.dumps(meta, indent=2, sort_keys=True) + "\n"
    manifest_bytes = len(text.encode())
    combined = total + manifest_bytes
    if combined > limit:
        raise CacheError("%s archives and manifest total %d bytes, over the %d byte limit (cap %d less %d headroom)"
                         % (kind, combined, limit, cap, HEADROOM))
    (export / "manifest.json").write_text(text)
    op.update({"cap_bytes": cap, "headroom_bytes": HEADROOM, "limit_bytes": limit,
               "archive_bytes": total, "manifest_bytes": manifest_bytes, "combined_bytes": combined})
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
    parser.add_argument("--ancestor", choices=ANCESTORS, help="restore only: predecessor snapshot (default cold)")
    parser.add_argument("--component", choices=COMPONENTS, help="restore only: all or build (default all)")
    args = parser.parse_args(argv[1:])
    if args.command == "pack" and (args.ancestor or args.component):
        parser.error("--ancestor and --component apply to restore only")
    args.ancestor = args.ancestor or "cold"
    args.component = args.component or "all"
    op = {"command": args.command, "engine": args.engine, "scenario": args.scenario, "rep": args.rep,
          "ancestor": args.ancestor if args.command == "restore" else None,
          "component": args.component if args.command == "restore" else None,
          "run_id": os.environ.get("GITHUB_RUN_ID"), "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
          "head": os.environ.get("GITHUB_SHA"), "status": "error", "error": None, "spans": [], "archives": [],
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
