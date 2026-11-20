# Stock vs Bazel debug APK benchmark

## Question

For one frozen Android app revision, is a validated debug APK faster to build with stock Flutter/Gradle or the repository's Bazel rules under cold and warm dependency conditions? Bazel also measures reuse after a Dart edit; stock has no distinct edit run because its warm scenario is a clean build.

## Engines and commands

Each job runs on `ubuntu-24.04`. The stock command is:

```text
flutter build apk --debug --target-platform android-x64 --target lib/entrypoints/android/main_google_play.dart --no-pub
```

The Bazel build is `//packages/smooth_app/android/app:smooth_app` with `--nosystem_rc --nohome_rc --noworkspace_rc`, an isolated output base, `--disk_cache=`, the checked-in Maven downloader config, `--repository_cache=<empty per-job directory>`, Flutter/Android repository environment, `--android_platforms=@rules_android//:x86_64`, Flutter debug mode, `-c fastbuild`, Android manifest permission merge, Java 17 toolchain/runtime, desugar, no color/curses, `--jobs=128`, experimental per-mnemonic metrics, and `--@@protobuf+//bazel/toolchains:prefer_prebuilt_protoc`. The authenticated remote-cache rc enables remote caching, not remote execution. Cold disables cache hits and uploads local results; warm/edit accepts remote hits. The build also uses `--remote_download_outputs=toplevel`, a BEP stream, a profile and `--worker_quit_after_build`, and requires `--lockfile_mode=error`.

The app is checked out at the selected app commit. The workflow scripts are checked out independently from the workflow commit, and the resolved rules commit is recorded. A single preparation job probes the Bazel target using the same `bazel_argv` command flags as the timed build, with remote caching disabled and `--nobuild --lockfile_mode=error`; it uses a scratch output base and repository cache. Only if that fails does it retry with `--lockfile_mode=update`. The job records whether it regenerated the lock, its diff stat and hash, and passes the gzip+base64 lock to rows as a checked job output. Rows apply it and re-fingerprint their prepared tree before the row clock starts. The timed build retains `--lockfile_mode=error`. The checked-in module overlay and baseline lock supply the root Maven mirror installs and no-op make, m4 and pkgconfig foreign tools.
The overlay anchors are specific to the default app revision `6e7408f`. A different `app_ref` must preserve those `MODULE.bazel` anchors; its lock is probed and, if needed, regenerated once in the preparation job before the rows start.

## Scenarios and caches

- **Cold:** fresh runner, no restored seed, and the normal first build. Cold repeat 0 alone writes the seed. Other cold repeats have no seed restore and cannot publish.
- **Warm:** fresh runner, dependency seed restored, unchanged app source. No project build outputs are restored for either engine.
- **Bazel Dart edit:** fresh runner restores that same cold/0 seed, changes one Dart library implementation while preserving behavior, then builds and validates the APK.

The stock seed contains the Flutter SDK, pub cache, the Gradle user home's `~/.gradle/caches/` and `~/.gradle/wrapper/`, and the debug keystore. Those two directories are what GitHub's Gradle example for `actions/cache`, `actions/setup-java` with `cache: gradle`, and `gradle/actions/setup-gradle` with its basic provider save: downloaded dependencies, transforms, compiled build scripts and wrapper distributions. They are copied whole; other `~/.gradle/` entries such as `daemon/`, `native/` and `init.d/` (where each row installs the benchmark's Maven Central mirror script) are not seeded. Project-local Gradle state is not seeded either: the app's `build/` and `.gradle/` directories are absent, and the SDK seed excludes them for Flutter's included Gradle plugin (`packages/flutter_tools/gradle/{build,.gradle,.kotlin}`); the SDK's `.dart_tool` remains. The app leaves Gradle's local build cache at its default (off), so `caches/` holds no task outputs. The exact top-level inventory is recorded in the cold seed proof. Stock warm is therefore a fresh clean build over dependency caches. The previous baseline restored project build directories; its measurements below are historical and not directly comparable to the new stock warm baseline. The actual stock archive-plus-manifest size is recorded in the proof and report; it varies with dependency-cache contents.

The Bazel seed contains the Flutter SDK, pub cache, Bazelisk and Bazel binary only (about 1.9 GB in the previous setup). It restores no output base, disk cache or repository cache; analysis reruns and build outputs are obtained through Bazel's correctness-checked remote action cache. Each engine receives its normal CI caching rather than an artificially identical cache layout.

Under this clean-build definition stock warm and a Dart edit are the same scenario: stock CI has no incremental source-edit action cache and rebuilds the project from zero. Thus the workflow has stock cold and warm rows only. Its `edit` comparison uses stock warm rows (`stock_rows_from: warm`) against Bazel edit rows; the latter measure Bazel's incremental remote-action reuse.

Seed keys preserve the run/attempt/workflow-commit/engine/cold identity. The remote-cache salt includes run id, run attempt, workflow commit and cold repeat; warm/edit readers use repeat zero. Thus cold repeats cannot reuse one another's remote actions or prior runs, while readers can reuse cold/0 outputs. The remote backend is not purged.

Both engines use Google's Maven Central mirror. Bazel uses the downloader rewrite config; stock uses a Gradle init script that rewrites Central URLs in place, preserving repository order. The checked-in Bazel overlay also places the Central mirror first in the root installs' repository lists and keeps the baseline module lock; this avoids Central throttling without changing repository order outside those installs. Google and Plugin Portal remain available for their non-Central artifacts. The mirror's local cold Gradle proof took longer than the no-script proof, so that latency is not treated as representative of CI performance.

## Timing and cost

The required-result clock begins at each row's provider job start and ends after the APK passes package, SDK, debug-signature and native-library validation. It includes row setup, seed restoration, locked pub preparation, build and validation. The lock preparation job is outside the row clocks; no lock probe or other Bazel command runs in the rows outside the timed build. Full-job time runs from row provider job start through completion, including Bazel server shutdown, cleanup and evidence steps, and is therefore comparable to the previous baseline's full-job timing boundaries. The report gives both APK-result and full-job medians.

The workflow records actual runner vCPU count and RAM in every proof; standard `ubuntu-24.04` public runners are expected to report 4 vCPU / 16 GiB. Public compute has no charge. Cost is a comparison proxy: full-job minutes rounded up separately per job, multiplied by $0.006 per minute for a 2-core runner or $0.012 per minute for a 4-core runner.

The Bazel proof also records the critical-path total from its final build summary, profile build-phase components, and counts plus summed action-processing durations for key Android/Flutter mnemonics. Remote-cache-check events are excluded. The profile does not provide an explicit cached-versus-executed flag for these action-processing spans, so the mnemonic totals are not claimed as cache misses; local/remote location is recorded only when the trace's strategy field says so, otherwise it is unknown.

## Validity and verdict

A valid run requires all requested rows, successful proof collection, exact seed restoration for every reader, an empty Bazel repository cache, correctly salted remote-cache rows, bounded seed packs, identical Bazel cold/warm APK digests, identical Bazel edit digests that differ from cold, stock warm equal to cold/0, and the stock signature-only cold-repeat rule. Fresh stock cold jobs create independent debug keystores, so cold APK bytes may differ: cold/1+ must share cold/0's unsigned identity (kernel, size, member count and native inventory) while carrying a different signer. This debug-signature caveat is not an APK parity failure. Invalid runs are recorded with `valid: false` and no verdicts.

At n≥3, an engine is faster only when its validated-APK median is at least 10 seconds lower and its slowest row beats the other engine's fastest row. Otherwise the result is “no clear difference.” The edit comparison explicitly pairs stock warm rows with Bazel edit rows. Cross-engine APK hashes are reported, not required to match.

## Current baseline

Run `44767702298` (`results/44767702298-1.json` on `benchmark-results`): workflow commit `44be453`, app revision `6e7408f`, rules_flutter `6ab5ab9`, 4 vCPU / 16 GiB public runners, three repeats, clean-build stock warm. The Dart edit row compares Bazel edit rows against stock warm rows.

| Scenario | Stock validated APK median (rows) | Bazel validated APK median (rows) | Full-job medians (stock / Bazel) | Bazel critical path median | Result |
|---|---|---|---|---|---|
| Cold | 591.7 s (591.7, 503.9, 625.7) | 840.3 s (840.3, 810.8, 1039.3) | 644 / 914 s | 524.7 s | Stock faster |
| Warm | 371.2 s (313.1, 371.2, 413.3) | 288.6 s (299.2, 226.3, 288.6) | 384 / 317 s | 27.6 s | Bazel faster |
| Dart edit | 371.2 s (stock warm rows) | 348.5 s (348.5, 373.8, 305.6) | 384 / 371 s | 105.5 s | No clear difference |

Stock used 6 jobs and 55 rounded minutes, Bazel 9 jobs and 86; the 4-core cost proxies were $0.66 and $1.03. Seeds were 5.13 GB (stock) and 1.92 GB (Bazel). Bazel cold/warm APKs were all `749a34170ea8…` and edit APKs `e24aefe28e6a…`, the same digests as the historical baseline. Stock warm matched cold/0, and independent cold jobs had equal unsigned identity and different debug signers.

## Historical baseline

First recorded results: run `44709431697`, app revision `6e7408f`, 4 vCPU / 16 GiB public runners, three repeats per engine/scenario. This is a historical baseline under the previous definition: stock warm and Dart-edit seeds restored project build directories. Those stock timings are not directly comparable to the clean-build stock warm/edit comparison now used; the new stock warm measurements form a new baseline.

| Scenario | Stock validated APK median (rows) | Bazel validated APK median (rows) | Full-job medians (stock / Bazel) | Historical result |
|---|---|---|---|---|
| Cold | 490.8 s (487.0, 498.1, 490.8) | 1073.5 s (820.1, 1125.0, 1073.5) | 511 / 1135 s | Stock faster |
| Warm | 275.9 s (275.9, 230.3, 279.3) | 246.3 s (225.4, 246.3, 277.3) | 287 / 271 s | No clear difference |
| Dart edit | 280.6 s (280.6, 286.7, 245.3) | 321.7 s (323.1, 293.1, 321.7) | 292 / 340 s | Stock faster |

Those 9 stock jobs used 59 rounded minutes and 9 Bazel jobs used 87; the 4-core cost proxies were $0.708 and $1.044. Bazel cold/warm hashes matched across rows; edit hashes matched one another and differed from cold. Stock warm matched cold/0, and independent cold jobs had equal unsigned identity and different debug signers.

## Limits

The sample is small (normally n=3). The remote-cache backend is shared, despite per-run/repeat salts; network and hosted-runner variance remain. The local Gradle mirror proof showed higher elapsed time than its uncontrolled no-mirror comparison; it verifies repository routing and correctness, not representative mirror latency. Warm cache sizes and contents differ by design between engines. The app, Flutter/Android toolchain and resolved rules revisions are recorded so results remain scoped to their exact inputs.

## Running and reading results

On the default branch, use **Actions → Stock vs Bazel debug APK benchmark → Run workflow**. Set `rules_ref` (default `main`), `app_ref` (default `6e7408fda8e46bc97a0d8f2b33a801cf27c8dabe`) and `repeats` (1–5; default 3). The first job resolves `rules_ref` to one commit SHA passed to every build. The workflow summary shows verdicts, APK/full-job medians, every row, runner vCPU/RAM, costs, hashes, provenance and any lock diff. The complete record is committed as `results/<run-id>-<attempt>.json` on the `benchmark-results` branch. A run with fewer than three repeats reports no verdicts.
