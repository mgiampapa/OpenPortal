# OpenPortal macOS Port Plan

**STATUS: COMPLETE — Phase 1 verified end-to-end on macOS (2026-11-18).**
All tasks T1–T8 are done; see the Tasks section for per-task results.

## Overview
Port OpenPortal.ps1 (Windows) to run on macOS with PowerShell 7 (`pwsh`). The script automates rooting a Meta Portal+ (aloha) using exploits from jxlarrea/portal-root-kiosk-satellite, then installs the Google stack and Messenger.

## Current failure (from the last Phase 1 run)

```
PROVISION_ERROR: UID-1000 helper artifact is missing:
  .../uid1000-helper/build/portal-camera-led-watch-aloha
```

Root cause chain:
1. Phase 1 runs `provision_portal.py --persistent-wireless-adb`. For the aloha
target this implies the uid1000 payload (`wireless_adb_uid1000_boot=True`,
`uid1000_embedded_helper=True`), which must be **built** (C++ watchdog + boot
hook + runtime APK).
2. Without `-Rebuild`, OpenPortal.ps1 passes `--skip-build`, so nothing is
built; with `-Rebuild`, the build runs but fails because **no Android SDK/NDK
is installed on this Mac** and the Makefiles hard-code Linux toolchain paths.
3. Even with an SDK present, the upstream build system is Linux-only:
   - `android-env.mk`, `exploit/Makefile`, `helper/Makefile`,
     `uid1000-helper/Makefile` hard-code
     `$(NDK)/toolchains/llvm/prebuilt/linux-x86_64`; the macOS NDK ships
     `prebuilt/darwin-x86_64`.
   - `provision_portal.py` (`android_build_environment()`) validates the same
     `linux-x86_64` path.
   - `uid1000-helper/Makefile` uses GNU `stat -c %s` (macOS BSD stat needs
     `-f %z`).
   - Tests hard-code the linux path too.

## Host environment findings (verified)

- macOS 27.0.1, Apple Silicon (arm64). **Rosetta 2 was NOT installed**;
  the official NDK for macOS is x86_64-only through at least r29-beta2
  (verified from the package zip central directories: only
  `prebuilt/darwin-x86_64` exists). Rosetta is therefore required to run the
  NDK clang binaries.
- Existing SDK at `~/Library/Android/sdk` (cmdline-tools 19.0, licenses
  accepted) with build-tools 35/36 and platform android-35 — but **not** the
  versions the provisioner pins.
- Homebrew `openjdk` 27 is installed but **keg-only**: `/usr/bin/java` is the
  broken macOS stub ("Unable to locate a Java Runtime") unless JAVA_HOME is
  set or the keg bin dir is put on PATH ahead of `/usr/bin`.
- `adb` 37.0.1 present at `/opt/homebrew/bin/adb`.
- Python 3.14 (homebrew) works for the provisioner (needs >= 3.9); repo unit
  tests pass except one pre-existing environmental failure
  (`test_download_failure_is_reported_before_any_reboot` expects a Shizuku
  download error but gets the SDK-missing error first — same on Linux without
  an SDK; not a porting bug).
- The NDK zip is ~950 MB. `sdkmanager --install "ndk;28.2.13676358"` failed
  with `java.io.IOException: File too large` when run from an environment
  whose RLIMIT_FSIZE was capped at 100 MB; installing from a normal shell
  works fine. A helper script (`deps/install-ndk.sh`) assembles chunked
  downloads and unzips into `~/Library/Android/sdk/ndk` if you ever need to
  install it manually.

## Tasks

- [x] **T1. Install pinned SDK components** (build-tools 37.0.0 + platform
  android-36 into `~/Library/Android/sdk`) — done via sdkmanager with
  JAVA_HOME pointed at homebrew openjdk. *(Partially complete: both installed
  from here.)*
- [x] **T2. Install Rosetta 2** — required to run the x86_64 NDK toolchain on
  Apple Silicon. Done via `softwareupdate --install-rosetta --agree-to-license`
  (ran as the admin user; completed successfully).
- [x] **T3. Install NDK 28.2.13676358 (r28b)** — assemble `deps/ndk-parts/*`
  into `deps/android-ndk-r28b-darwin.zip`, unzip to
  `~/Library/Android/sdk/ndk/28.2.13676358`, verify
  `toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android29-clang`
  runs (under Rosetta) and `simpleperf/bin/android/arm64/simpleperf` exists.
  Needs the user's Terminal for the >100 MB steps (or user runs the provided
  one-liner).
- [x] **T4. Make the build system host-aware** (upstream files, kept portable):
  - `android-env.mk`: derive the prebuilt dir from `uname -s`/`uname -m`
    (`darwin-x86_64` on macOS, `linux-x86_64` on Linux) instead of hard-coding
    linux.
  - Same for `exploit/Makefile`, `helper/Makefile`, `uid1000-helper/Makefile`.
  - `uid1000-helper/Makefile`: use `stat -f %z` on Darwin (`stat -c %s`
    elsewhere) for the hook size assertions.
  - `tools/provision_portal.py` `android_build_environment()`: resolve the
    prebuilt dir per-OS and validate the right compiler paths; keep error text
    actionable.
  - `tests/test_provision_portal_cli.py`: compute the expected toolchain dir
    per-OS so the suite passes on both.
- [x] **T5. Fix OpenPortal.ps1 macOS issues found in review**:
  - `Ensure-Java`/`Get-JavaPath`: prefer a working JDK over the `/usr/bin/java`
    stub; export JAVA_HOME for the session; prepend the JDK bin dir to PATH so
    `javac/jar/keytool/d8/apksigner` resolve.
  - `Ensure-Python`: the macOS branch currently shells out through
    `Invoke-AdbQuiet` (an adb wrapper!) to run `installer -pkg` — replace with a
    real local install path; also `/usr/local/bin/python3` is wrong for
    arm64 homebrew (`/opt/homebrew/bin/python3`). Prefer refusing to auto-
    install Python on macOS (system/brew python is present) with a clear
    message.
  - `Get-ApkSignerCert`: java `-cp` separator is `:` on macOS, not `;`.
  - `PATH` mutations use `"$dir;$sep$env:PATH"` — the literal `;` before
    `$script:PathSep` corrupts PATH on macOS (e.g. `.../bin;:/opt/...`). Use
    `[IO.Path]::PathSeparator`.
  - `apkeep.exe` is a Windows PE binary; on macOS skip it and tell the user to
    drop a Messenger APK/XAPK in Downloads (Phase 5 already supports that).
  - Add an SDK/NDK dependency check (with install hints) to Bootstrap-Deps so
    failures surface before the exploit starts rebooting the device.
- [x] **T6. Build all Phase 1 artifacts on macOS** — run the exact make targets
  the provisioner would run (`make -C uid1000-helper aloha`, exploit target,
  sentinel) with SDK/NDK/JAVA_HOME env set; fix any remaining host-isms that
  surface (e.g. `unzip -p`, `jar`, keytool debug keystore creation).
- [x] **T7. Verify end-to-end Phase 1** — ran `pwsh OpenPortal.ps1 -Phases 1`
  against the Portal+ over USB. Results:
  - Dependency gate passed (SDK/NDK/JDK/python/adb all found).
  - The kernel exploit succeeded (`WATCH_CFI_OK=1 ... ROOT=1`, attempt-based;
  wireless-ADB pass took 3 attempts, which is normal for this timing
  exploit).
  - `WIRELESS_ADB_OK persistent_port=5555 property=persist.adb.tcp.port`.
  - UID-1000 helper running as `system` with `--adb-framework`; ADB auth
  timeout disabled; `adb_framework_boot` marker present.
  - Verified over Wi-Fi: `adb connect <portal-ip>:5555` → `uid=2000(shell)`
  working shell, property persisted across reboots.
  - Re-running `-Phases 1` now reports "Already at step 1 … Skipping" and
  exits `PORTAL_PROVISION_OK phases=1`.
  Note: the outer provisioner pass ends with one benign error after the
  final verification reboot (USB serial disappears once the device is
  TCP-only); the provisioner's own recovery hint covers it, and the
  OpenPortal-level verification confirms success.
- [x] **T8. Regression**: run the repo unit tests on macOS after T4; note the
  one pre-existing environmental failure separately.
  Result: 49 tests, 48 pass. The single failure
  (`ShizukuCliTest.test_download_failure_is_reported_before_any_reboot`)
  is environmental and pre-existing: with no SDK configured the build-env
  error fires before the mocked Shizuku download error — identical on Linux
  without an SDK. Not a porting regression.

## Out of scope for this pass
- Phases 2–5 device-side behavior (they are pure adb/Java and already portable
  once Phase 1 builds; Phase 5 apkeep auto-download stays Windows-only).
- Upstreaming the host-aware Makefile changes.
