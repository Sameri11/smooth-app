#!/usr/bin/env python3
"""Name exact run-owned snapshots and retire completed repetition cohorts."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def identity():
    values = {key: os.environ[key] for key in
              ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA", "ENGINE", "SCENARIO", "REPETITION")}
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        if not re.fullmatch(r"[1-9][0-9]*", values[key]):
            raise ValueError("Invalid " + key)
    if not re.fullmatch(r"[0-9a-f]{40}", values["GITHUB_SHA"]):
        raise ValueError("Invalid head")
    if values["ENGINE"] not in ("flutter", "bazel") or values["SCENARIO"] not in ("cold", "warm", "test", "lib"):
        raise ValueError("Invalid workload")
    if values["REPETITION"] not in ("1", "2", "3"):
        raise ValueError("Invalid repetition")
    return values


def prefix(values):
    return "host-replay-{GITHUB_RUN_ID}-{GITHUB_RUN_ATTEMPT}-{GITHUB_SHA}-".format(**values)


def api(path, method="GET"):
    result = subprocess.run(["gh", "api", "--method", method, path],
                            check=True, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout.strip() else None


def main():
    values = identity()
    base = prefix(values)
    if sys.argv[1:] == ["keys"]:
        key = base + values["ENGINE"] + "-" + values["REPETITION"] + "-"
        with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
            stream.write("seed=" + key + "cold\nupdated=" + key + values["SCENARIO"] + "\n")
        return
    if sys.argv[1:] not in (["retire"], ["verify"]):
        raise ValueError("Expected keys, retire or verify")
    retiring = sys.argv[1] == "retire"
    if retiring and (values["ENGINE"] != "flutter" or values["SCENARIO"] != "cold"):
        raise ValueError("Retirement is owned by the stock cold stage")
    repository = os.environ["GITHUB_REPOSITORY"]
    if repository != "Sameri11/smooth-app":
        raise ValueError("Unexpected repository")
    allowed = {base + engine + "-" + str(rep) + "-" + scenario
               for rep in range(1, int(values["REPETITION"]))
               for engine in ("flutter", "bazel") for scenario in ("cold", "test", "lib")}
    entries_all = []
    page = 1
    while True:
        data = api("repos/" + repository + "/actions/caches?per_page=100&page=" + str(page))
        entries = data["actions_caches"] if "actions_caches" in data else data["caches"]
        entries_all.extend(entries)
        if len(entries) < 100:
            break
        page += 1
    evidence = Path(os.environ["RUNNER_TEMP"]) / "smooth-ci-evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    if not retiring:
        expected = base + values["ENGINE"] + "-" + values["REPETITION"] + "-" + values["SCENARIO"]
        matches = [entry for entry in entries_all if entry["key"] == expected]
        if len(matches) != 1:
            raise ValueError("Published snapshot not uniquely visible: " + expected)
        cap = (3 if values["SCENARIO"] == "cold" else 1) * 1024 ** 3
        if not 0 < matches[0]["size_in_bytes"] <= cap:
            raise ValueError("Published snapshot exceeds transport cap")
        task_bytes = sum(entry["size_in_bytes"] for entry in entries_all if entry["key"].startswith(base))
        if task_bytes > 8 * 1024 ** 3:
            raise ValueError("Run-owned cache storage exceeds 8 GiB")
        (evidence / "cache-publication.json").write_text(json.dumps({
            "transport": "github_actions_cache", "snapshot": matches[0],
            "snapshot_cap_bytes": cap, "task_cache_bytes_at_check": task_bytes,
            "task_cache_cap_bytes": 8 * 1024 ** 3
        }, indent=2) + "\n")
        return
    selected = [entry for entry in entries_all if entry["key"] in allowed]
    for entry in selected:
        api("repos/" + repository + "/actions/caches/" + str(entry["id"]), "DELETE")
    (evidence / "cache-retirement.json").write_text(json.dumps({
        "prefix": base, "prior_repetitions_only": True,
        "deleted": [{key: entry[key] for key in ("id", "key", "size_in_bytes")} for entry in selected]
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
