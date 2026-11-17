#!/usr/bin/env python3
"""Reduce a Bazel 9.2.0 JSON trace to fixed-whitelist aggregates.

Input is the uncompressed trace that `bazel --profile=<path>.json` writes
(JsonTraceFileWriter.java). Output holds integer microsecond values keyed by
whitelisted names only. Event names, args, paths, labels, thread names and
otherData never reach the output.

Source (bazelbuild/bazel tag 9.2.0):
- JsonTraceFileWriter.java: {"otherData", "traceEvents"}; bytes are ISO-8859-1.
- Profiler.java TaskData.writeTraceData: ph "X" with dur when duration > 0,
  ph "i" without dur otherwise; cat is the ProfilerTask description; ts/dur
  are integer microseconds. ts is relative to profile start and may be negative.
- ThreadMetadata.java: ph "M". CounterSeriesTraceData.java: ph "C".
- ProfilePhase.java, BuildTool.java, ExecutionTool.java, AnalysisPhaseRunner.java:
  build phase markers (ph "i"). BlazeRuntime.java: client spans (ph "X").
- Profiler.stop(): "Finishing" instant (cat "general information") closes the last phase.

Sums across categories and groups are not additive; unions are wall-clock
coverage within one category or group.
"""

import argparse
import json
import os
import sys

SCHEMA = "rules-flutter-ci-profile-summary/1"
MAX_INPUT_BYTES = 256 * 1024 * 1024
MAX_EVENTS = 2_000_000
MAX_MICROS = 10**15
GZIP_MAGIC = b"\x1f\x8b"
KNOWN_PHASES = ("X", "i", "M", "C")

PHASE_CAT = "build phase marker"
INFO_CAT = "general information"
FINISHING = "Finishing"

# Build phase markers are instants; each lasts until the next marker.
PHASE_MARKERS = {
    "Launch Blaze": "launch",
    "Initialize command": "init",
    "Evaluate target patterns": "target_pattern_eval",
    "Load and analyze dependencies": "load_analyze",
    "Load, analyze dependencies and build artifacts": "load_analyze_execute",
    "Analyze licenses": "license",
    "Prepare for build": "prepare",
    "Build artifacts": "execute",
    "Complete build": "finish",
}
ANALYSIS_MARKERS = ("load_analyze", "load_analyze_execute")

# Client-side spans, logged as X events in the build phase category.
CLIENT_SPANS = {
    "Launch Blaze": "launch_blaze",
    "Extracting Bazel binary": "extract_binary",
    "Blocking on busy Bazel server (in client)": "busy_server_wait_client",
    "Blocking on busy Bazel server (in server)": "busy_server_wait_server",
}

# ProfilerTask descriptions (the cat field) grouped by cost family.
CATEGORY_GROUPS = {
    "remote": {
        "remote output download": "remote_output_download",
        "remote network": "remote_network",
        "Remote execution file fetching": "remote_file_fetch",
        "remote action cache check": "remote_cache_check",
        "Remote execution upload time": "remote_upload",
        "Remote execution queuing time": "remote_queue",
        "Remote execution setup": "remote_setup",
        "Remote execution process wall time": "remote_process_wall",
        "remote action execution": "remote_execution",
        "Local parse to prepare for remote execution": "remote_local_parse",
        "RPC": "rpc",
        "calling credential helper": "credential_helper",
    },
    "local_execution": {
        "local action execution": "local_execution",
        "Local execution process wall time": "local_process_wall",
        "local execution in worker": "worker_execution",
        "setting up inputs for worker": "worker_setup",
        "borrowing a worker": "worker_borrow",
        "waiting for response from worker": "worker_wait_response",
        "copying outputs from worker": "worker_copy_outputs",
    },
    "action_processing": {
        "action processing": "action",
        "action dependency checking": "action_check",
        "complete action execution": "action_complete",
        "action resource lock": "action_lock",
        "update action information": "action_update",
        "discover inputs": "discover_inputs",
        "include scanner": "include_scanner",
        "Staging per-action file system": "action_fs_staging",
    },
    "analysis": {
        "package creation": "package_creation",
        "skyframe evaluator": "skyframe_evaluator",
        "bazel module processing": "bzlmod",
        "Fetching repository": "repository_fetch",
        "Starlark Parser": "starlark_parser",
        "Starlark user function call": "starlark_user_fn",
        "Starlark builtin function call": "starlark_builtin_fn",
        "Starlark compiled user function call": "starlark_compiled_fn",
        "Starlark repository function call": "starlark_repository_fn",
        "filesystem traversal": "filesystem_traversal",
    },
    "runtime": {
        "thread wait": "thread_wait",
        "gc notification": "gc_notification",
    },
}
CATEGORY_KEY = {
    desc: key for table in CATEGORY_GROUPS.values() for desc, key in table.items()
}
KEY_GROUP = {
    key: group for group, table in CATEGORY_GROUPS.items() for key in table.values()
}

LIMITS = [
    "Phase markers are instants. A phase lasts until the next marker; the last phase "
    "lasts until the Finishing event. A null duration means that closing event is absent.",
    "Loading and analysis, and execution when interleaved, share one phase. No separate "
    "loading or analysis time is reported.",
    "client_spans come from the launcher. launch_blaze is a startup estimate, not an "
    "isolated server start or first install.",
    "Category durations are instrumented spans. Remote download and RPC spans are not "
    "network byte or request totals.",
    "summed_task_us adds task work and may overlap. union_us is wall-clock coverage within "
    "one category or group. Do not add values across categories or groups.",
    "Per-category thresholds omit short spans; default slim-profile merging can also "
    "replace spans and drop children after the trace grows. Category coverage is a lower "
    "bound. This reducer assumes no --record_full_profiler_data or --noslim_profile override; "
    "the trace does not record these options.",
    "Counter (C), metadata (M), merged, critical-path and other INFO events are not "
    "aggregated. unrecognized_events counts dropped duration and instant events.",
]


class ProfileError(Exception):
    """Failure with a fixed message; never includes trace content."""


def _reject_constant(_name):
    raise ProfileError("trace contains a non-finite JSON number")


def load_document(path):
    if os.path.getsize(path) > MAX_INPUT_BYTES:
        raise ProfileError("trace exceeds the size bound")
    with open(path, "rb") as handle:
        raw = handle.read()
    if raw[:2] == GZIP_MAGIC:
        raise ProfileError("gzip traces are not accepted; pass the uncompressed .json profile")
    try:
        # Bazel writes ISO-8859-1 bytes; UTF-8 decoding would reject valid traces.
        return json.loads(raw.decode("iso-8859-1"), parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        raise ProfileError("trace is not valid JSON") from None


def _trace_events(document):
    if not isinstance(document, dict) or not isinstance(document.get("traceEvents"), list):
        raise ProfileError("trace has no traceEvents array")
    events = document["traceEvents"]
    if len(events) > MAX_EVENTS:
        raise ProfileError("trace exceeds the event bound")
    return events


def _bounded_int(event, field, index):
    value = event.get(field)
    # type() check rejects bool and float; Gson writes ts and dur as integers.
    if type(value) is not int or abs(value) > MAX_MICROS:
        raise ProfileError(f"event {index}: {field} is not a bounded integer")
    return value


def _duration(event, ph, index):
    if ph == "X":
        dur = _bounded_int(event, "dur", index)
        if dur < 0:
            raise ProfileError(f"event {index}: negative dur")
        return dur
    if "dur" in event and _bounded_int(event, "dur", index) != 0:
        raise ProfileError(f"event {index}: instant event has a duration")
    return 0


def _parse_event(index, event):
    """Return (ph, cat, name, ts, dur); cat is None for M and C events."""
    if not isinstance(event, dict):
        raise ProfileError(f"event {index} is not an object")
    ph = event.get("ph")
    name = event.get("name")
    if ph not in KNOWN_PHASES or not isinstance(name, str):
        raise ProfileError(f"event {index}: unsupported ph or name")
    if ph in ("M", "C"):
        if ph == "C":
            _bounded_int(event, "ts", index)
        return ph, None, name, 0, 0
    cat = event.get("cat")
    if not isinstance(cat, str):
        raise ProfileError(f"event {index}: missing cat")
    ts = _bounded_int(event, "ts", index)
    return ph, cat, name, ts, _duration(event, ph, index)


def _record_phase(ph, name, ts, dur, markers, client):
    if ph == "i" and name in PHASE_MARKERS:
        markers.append((ts, PHASE_MARKERS[name]))
    elif ph == "X" and name in CLIENT_SPANS:
        key = CLIENT_SPANS[name]
        if key in client:
            raise ProfileError("duplicate client span")
        client[key] = {"start_us": ts, "duration_us": dur}
    else:
        raise ProfileError("unrecognized build phase event")


def _check_coverage(markers, spans):
    keys = {key for _, key in markers}
    if "init" not in keys or not keys.intersection(ANALYSIS_MARKERS):
        raise ProfileError("trace lacks required build phase markers")
    if not spans:
        raise ProfileError("trace has no recorded duration events")


def _phases(markers, finishing):
    markers = sorted(markers)
    phases = []
    for position, (start, key) in enumerate(markers):
        if position + 1 < len(markers):
            end = markers[position + 1][0]
        else:
            end = finishing
        if end is not None and end < start:
            raise ProfileError("build phase markers are out of order")
        phases.append(
            {
                "phase": key,
                "start_us": start,
                "duration_us": None if end is None else end - start,
            }
        )
    return phases


def union_length(spans):
    total = 0
    cur_start = cur_end = None
    for start, end in sorted(spans):
        if cur_end is None or start > cur_end:
            if cur_end is not None:
                total += cur_end - cur_start
            cur_start, cur_end = start, end
        elif end > cur_end:
            cur_end = end
    if cur_end is not None:
        total += cur_end - cur_start
    return total


def _category_stats(spans_by_key):
    return {
        key: {
            "group": KEY_GROUP[key],
            "count": len(spans),
            "summed_task_us": sum(end - start for start, end in spans),
            "union_us": union_length(spans),
            "max_us": max(end - start for start, end in spans),
        }
        for key, spans in spans_by_key.items()
    }


def _group_stats(spans_by_key):
    grouped = {}
    for key, spans in spans_by_key.items():
        grouped.setdefault(KEY_GROUP[key], []).extend(spans)
    return {
        group: {"count": len(spans), "union_us": union_length(spans)}
        for group, spans in grouped.items()
    }


def summarize(document):
    events = _trace_events(document)
    counts = dict.fromkeys(KNOWN_PHASES, 0)
    markers, client, spans = [], {}, {}
    finishing = None
    unrecognized = 0
    for index, event in enumerate(events):
        ph, cat, name, ts, dur = _parse_event(index, event)
        counts[ph] += 1
        if ph in ("M", "C"):
            continue
        if cat == PHASE_CAT:
            _record_phase(ph, name, ts, dur, markers, client)
        elif cat == INFO_CAT and ph == "i" and name == FINISHING:
            if finishing is not None:
                raise ProfileError("trace has more than one Finishing event")
            finishing = ts
        elif cat in CATEGORY_KEY:
            key = CATEGORY_KEY[cat]
            spans.setdefault(key, []).append((ts, ts + dur))
        else:
            unrecognized += 1
    _check_coverage(markers, spans)
    return {
        "schema": SCHEMA,
        "units": "microseconds, integers",
        "event_counts": counts,
        "phases": _phases(markers, finishing),
        "phases_closed": finishing is not None,
        "client_spans": client,
        "categories": _category_stats(spans),
        "groups": _group_stats(spans),
        "unrecognized_events": unrecognized,
        "limits": LIMITS,
    }


def write_summary(path, summary):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temp, path)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Reduce a Bazel 9.2.0 JSON trace.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        write_summary(args.output, summarize(load_document(args.input)))
    except ProfileError as error:
        print(f"profile: {error}", file=sys.stderr)
        return 1
    except OSError:
        print("profile: cannot read the input or write the output", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
