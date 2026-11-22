#!/usr/bin/env python3
"""Pack and restore this run's bounded pub dependency seed."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

FIXTURE_SHA = "0e1484478b62b527d26a83a52d6898504443dbb6"
SCHEMA = 1


def fail(message: str) -> None:
    raise RuntimeError(message)


def runner_paths() -> tuple[pathlib.Path, pathlib.Path]:
    temp = pathlib.Path(os.environ["RUNNER_TEMP"])
    if not temp.is_absolute() or temp.resolve() != temp:
        fail("RUNNER_TEMP must be an absolute, canonical path")
    pub = temp / "cache-state" / "pub"
    seed = temp / "host-dependency-seed"
    if any(path.resolve(strict=False) != path for path in (pub, seed)):
        fail("seed paths must not traverse symlinks")
    return pub, seed


def identity() -> dict[str, str]:
    run_id = os.environ["GITHUB_RUN_ID"]
    attempt = os.environ["GITHUB_RUN_ATTEMPT"]
    head = os.environ["GITHUB_SHA"]
    fixture = os.environ["HOST_FIXTURE_SHA"]
    if not run_id.isdecimal() or not attempt.isdecimal():
        fail("GitHub run ID and attempt must be decimal")
    if len(head) != 40 or any(c not in "0123456789abcdef" for c in head):
        fail("GITHUB_SHA must be a lowercase commit SHA")
    if fixture != FIXTURE_SHA:
        fail("HOST_FIXTURE_SHA does not match the expected host fixture")
    inputs = pathlib.Path("ci/benchmark/host/inputs.json")
    sdk_version = json.loads(inputs.read_text(encoding="utf-8"))["flutter"]["version"]
    if not isinstance(sdk_version, str) or not sdk_version:
        fail("host/inputs.json has no Flutter version")
    return {
        "run_id": run_id,
        "run_attempt": attempt,
        "head_sha": head,
        "fixture_sha": fixture,
        "sdk_version": sdk_version,
    }


def require_tools() -> None:
    if sys.version_info < (3, 12):
        fail("Python 3.12 or newer is required for safe tar extraction")
    for executable in ("tar", "zstd"):
        if shutil.which(executable) is None:
            fail(f"required executable not found: {executable}")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_directory(path: pathlib.Path, name: str) -> None:
    if not path.is_dir() or path.is_symlink():
        fail(f"expected a real directory for {name}: {path}")


def generated_package_outputs(pub: pathlib.Path) -> list[str]:
    package_roots = [root for pattern in ("hosted/*/*", "git/cache/*", "global_packages/*")
                     for root in pub.glob(pattern)]
    outputs = []
    for package in package_roots:
        if not package.is_dir() or package.is_symlink():
            continue
        for name in (".dart_tool", "build"):
            output = package / name
            if output.exists() or output.is_symlink():
                outputs.append(output.relative_to(pub.parent.parent).as_posix())
    return outputs


def pack() -> None:
    require_tools()
    started = time.monotonic()
    pub, seed = runner_paths()
    check_directory(pub, "pub cache")
    seed.mkdir(mode=0o700, parents=True, exist_ok=True)
    if seed.is_symlink() or any(seed.iterdir()):
        fail("seed output directory must be a real, empty directory")
    archive = seed / "seed.tar.zst"
    command = [
        "tar", "--sort=name", "--numeric-owner", "--owner=0", "--group=0",
        "--no-wildcards",
    ]
    command.extend(
        "--exclude=" + output for output in generated_package_outputs(pub)
    )
    command.extend(["-C", str(pub.parent.parent), "-cf", "-", "cache-state/pub"])
    tar = subprocess.Popen(command, stdout=subprocess.PIPE)
    assert tar.stdout is not None
    compressor = subprocess.Popen(
        ["zstd", "-3", "-T0", "-o", str(archive)], stdin=tar.stdout
    )
    tar.stdout.close()
    try:
        tar_status = tar.wait()
        compress_status = compressor.wait()
        if tar_status:
            fail(f"tar failed with exit code {tar_status}")
        if compress_status:
            fail(f"zstd failed with exit code {compress_status}")
    except BaseException:
        for process in (tar, compressor):
            if process.poll() is None:
                process.kill()
                process.wait()
        archive.unlink(missing_ok=True)
        raise
    compressed_bytes = archive.stat().st_size
    if compressed_bytes > 3 * 1024**3:
        archive.unlink(missing_ok=True)
        fail("compressed host dependency seed exceeds 3 GiB")
    record = {
        "schema": SCHEMA,
        "identity": identity(),
        "payload": {
            "file": archive.name,
            "bytes": compressed_bytes,
            "sha256": sha256_file(archive),
        },
        "pack_wall_seconds": round(time.monotonic() - started, 6),
    }
    (seed / "metadata.json").write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print("HOST_DEPENDENCY_SEED " + json.dumps(record, sort_keys=True, separators=(",", ":")))


def restore() -> None:
    require_tools()
    started = time.monotonic()
    pub, seed = runner_paths()
    if seed.is_symlink() or not seed.is_dir():
        fail("dependency seed directory is missing or unsafe")
    metadata_path = seed / "metadata.json"
    archive = seed / "seed.tar.zst"
    if metadata_path.is_symlink() or archive.is_symlink():
        fail("dependency seed files must not be symlinks")
    record = json.loads(metadata_path.read_text(encoding="utf-8"))
    if record.get("schema") != SCHEMA or record.get("identity") != identity():
        fail("dependency seed identity does not match this workflow run")
    payload = record.get("payload")
    if not isinstance(payload, dict) or payload.get("file") != archive.name:
        fail("dependency seed metadata has an unexpected payload")
    size = archive.stat().st_size
    if size != payload.get("bytes") or size > 3 * 1024**3:
        fail("dependency seed payload size does not match metadata or exceeds 3 GiB")
    if sha256_file(archive) != payload.get("sha256"):
        fail("dependency seed SHA256 mismatch")
    if pub.exists():
        fail("restore destination already exists; refusing to overwrite runner state")
    stage = pathlib.Path(tempfile.mkdtemp(prefix="host-seed-", dir=seed))
    try:
        with subprocess.Popen(["zstd", "-q", "-d", "-c", str(archive)], stdout=subprocess.PIPE) as decoder:
            assert decoder.stdout is not None
            with tarfile.open(fileobj=decoder.stdout, mode="r|") as bundle:
                for member in bundle:
                    if member.name != "cache-state/pub" and not member.name.startswith("cache-state/pub/"):
                        fail(f"unexpected path in seed archive: {member.name!r}")
                    bundle.extract(member, path=stage, filter="data")
            if decoder.wait():
                fail("zstd failed while decoding dependency seed")
        staged_pub = stage / "cache-state" / "pub"
        check_directory(staged_pub, "restored pub cache")
        pub.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staged_pub, pub)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    result = {
        "identity": record["identity"],
        "payload": record["payload"],
        "restore_wall_seconds": round(time.monotonic() - started, 6),
    }
    print("HOST_DEPENDENCY_RESTORE " + json.dumps(result, sort_keys=True, separators=(",", ":")))


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in ("pack", "restore"):
        fail("usage: host_dependency_seed.py {pack|restore}")
    if sys.argv[1] == "pack":
        pack()
    else:
        restore()


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, RuntimeError) as error:
        print(f"host dependency seed: {error}", file=sys.stderr)
        sys.exit(1)
