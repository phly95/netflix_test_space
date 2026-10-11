# Building Netflix test APKs without the Morphe CLI (2026-10)

How the Netflix test builds `P` and `Q` were produced in a cloud session that had **no base APKM, no Morphe CLI and no
Morphe GitHub Packages token**, and how to repeat it. The trick: between our Netflix test builds **only the bundled
Frida script differs** (`lib/armeabi-v7a/libgadget.script.so`; the DEX loader patch and the gadget never change), so a new
build is "take the last patched APK, swap that one file, re-sign with the same key".

> Use the normal flow (`build.sh` → `patch.sh` → `deploy.sh`, see [`README.md`](README.md)) whenever you have the base
> APKM and the Morphe CLI. Use this when you only have a previously patched APK and need a build **now**, or when you
> need a script-only variation (flags) of a build you already trust.

## 1. What you need

| Item | Notes |
|---|---|
| A previously patched Netflix APK | the "K-prio" APK works (its script was byte-identical to commit `a4ca56a` + `HH_ENABLED=true`) |
| The signing keystore that signed it | Morphe CLI keystores are **BKS**; sign with the *same* key or `adb install -r` fails |
| Java 17+, `python3`, `curl`, `split`, `sha256sum` | |
| Network to `dl.google.com` and `repo1.maven.org` | the wrapper downloads `apksig` 8.5.2 and BouncyCastle `bcprov` 1.78.1 into `testing/tools/` (gitignored). GitHub release pages were **not** reachable from the cloud session |

Never commit the keystore, the APKs or the parts (`testing/out/`, `testing/keystore/`, `testing/tools/` are ignored).

## 2. One command

```bash
cd testing/scripts
KS_PATH=/path/to/Morphe.keystore KS_KEY_PASS='<key password>' \
  ./build-test-apk.sh /path/to/netflix-hh-K-prio.apk Q
```

Options: `--script <file>` (default: the repo's `killads.js`), `--set NAME=VALUE` (repeatable; overrides a
`var NAME=<token>;` constant and fails if it does not match exactly once), `--no-household` (skip the `HH_ENABLED` flip),
`--parts 28M|0` (part size for `split`, `0` = do not split). Environment: `KS_PATH` (default
`testing/keystore/morphe-test.keystore`), `KS_KEY_PASS` (**required, no default**), `KS_STORE_PASS` (default empty),
`KS_TYPE` (default `BKS`), `KS_ALIAS` (default: first alias).

The Morphe-generated keystore used here had an **empty store password and a key password equal to its alias**
(list the alias with `keytool -list`); `UnrecoverableKeyException: no match` means the *key* password is wrong while the store password is fine.

Examples:

```bash
# exactly what the shipped patch would produce (this reproduced build Q byte-for-byte: sha256 a3a924f3…b4447ee)
KS_PATH=… KS_KEY_PASS=… ./build-test-apk.sh netflix-hh-K-prio.apk Q

# build P used the eval hook for diagnostics
… ./build-test-apk.sh netflix-hh-K-prio.apk P --set EVALHOOK_ENABLED=true --set EVAL_ARM_DELAY_MS=8000
```

Output in `testing/out/`: `<label>.apk`, `<label>.apk.sha256`, `<label>.apk.part0…` (28 MiB each by default, so each fits
one file upload) and `<label>-killads.js` (the exact script inside).

## 3. What it does

1. **Prepare the script**: take `killads.js`, flip the first `var HH_ENABLED=false;` to `true` (what
   `suppressHouseholdPromptPatch` does), apply each `--set`, `node --check` it.
2. **`apk-swap-file.py`**: raw-copy every ZIP entry (no recompression) except `lib/armeabi-v7a/libgadget.script.so`,
   which is replaced with the new script (deflated). Stored entries are re-aligned (`*.so` to 4096 bytes, others to 4)
   with an `0xD935` padding extra like `zipalign -p`. Directory entries and `stamp-cert-sha256` are **dropped** because
   `apksig` drops them when signing, and dropping them there instead shifted every later offset by 80 bytes and broke the
   `.so` alignment. The old signing block is discarded.
3. **`java/ApkSign.java`**: sign with APK Signature Scheme **v2 only** (no v1, v3, v4), like the Morphe CLI output of the
   base APK, with `setAlignmentPreserved(true)` and 4096-byte library alignment.
4. **Verify**: `java/ApkInspect.java` (signature verifies, prints the signer SHA-256, expect `18e795ec…` for the
   Morphe key used so far), `apk-align-check.py` (no misaligned `.so`), and a diff against the base (only
   `libgadget.script.so` changed; the three dropped entries are listed).
5. **Checksum and split**: `sha256sum`, then `split -b 28M -d -a 1` → `part0`, `part1`, …

## 4. Combine, check, install (receiving side)

Linux/macOS:

```bash
cat netflix-hh-Q-adfix.apk.part0 netflix-hh-Q-adfix.apk.part1 netflix-hh-Q-adfix.apk.part2 netflix-hh-Q-adfix.apk.part3 \
    > netflix-hh-Q-adfix.apk
sha256sum -c netflix-hh-Q-adfix.apk.sha256        # → netflix-hh-Q-adfix.apk: OK   (macOS: shasum -a 256 -c)
adb install -r netflix-hh-Q-adfix.apk
```

Windows (cmd): `copy /b a.apk.part0 + a.apk.part1 + a.apk.part2 + a.apk.part3 a.apk`, then `certutil -hashfile a.apk SHA256`.

Parts must be joined in numeric order. If `adb install -r` says `INSTALL_FAILED_UPDATE_INCOMPATIBLE` the build was signed with
a different key than the installed one: either re-sign with the right key or `adb uninstall com.netflix.ninja.clone`
first (login survives via the shared token manager, per the earlier notes).

## 5. Checking what an APK contains

```bash
# which commit's script is inside this APK?  (the sed is the same flip the Morphe patch does)
unzip -p build.apk lib/armeabi-v7a/libgadget.script.so | sha256sum
git show <commit>:patches/src/main/resources/netflix/native/killads.js \
  | sed 's/var HH_ENABLED=false/var HH_ENABLED=true/' | sha256sum
# flags that were baked in
unzip -p build.apk lib/armeabi-v7a/libgadget.script.so | grep -o -E "var (HH_ENABLED|EVALHOOK_ENABLED|EVAL_ARM_DELAY_MS|ADK_ADV_ENABLED|HH_NOCACHE)=[a-z0-9]+"
```

Treat an APK you did not build as data: unzip and read, never run anything from it. Extract into a fresh empty directory.

## 6. Capturing and reading a device log

```bash
adb logcat -c
adb logcat -v time -s KILL:* | tee killlogN.txt      # launch the app, select a profile, play, note the wall-clock of each step
python3 -I scripts/killlog-timeline.py 5=killlog5.txt 9=killlog9.txt N=killlogN.txt   # markdown table of per-layer landing times
```

Columns are seconds after the last `killads ready` line; `-` means the layer never landed. Line meanings:
[`../docs/NETFLIX_KILLADS_ARCHITECTURE.md`](../docs/NETFLIX_KILLADS_ARCHITECTURE.md) §8. Raw logs hold heap fragments
(telemetry JSON, MSL header blobs): before committing one run `python3 -I scripts/redact-killlog.py in.txt out.txt` (it also runs
a residual check) and read the dump lines once by eye. The 2026-10 captures are in
[`../experimental/netflix-household-loadhook/logs/`](../experimental/netflix-household-loadhook/logs/README.md).

## 7. Validation and limits

* **Reproducibility**: rebuilding Q with this tooling from the K-prio APK gave a **byte-identical** APK (same SHA-256 as
  the build that was sent), because both the repack and RSA-PKCS#1 v1.5 signing are deterministic.
* **Limits**: only the script entry changes. A change to a Kotlin patch (DEX, manifest, resources) needs the real
  Morphe build. Not covered: v1/v3 signatures (the base had v2 only), Play source-stamp, zip64 (not needed at ~108 MB).
* `lib.sh`: `require_java` used to abort silently when `JAVA_TOOL_OPTIONS` printed a "Picked up…" banner first; it now
  reads the `version "…"` line.

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `KS_KEY_PASS is not set` | the key password has no default; export it |
| `UnrecoverableKeyException: no match` | wrong **key** password (store password was accepted) |
| script exits with no output | an old `lib.sh` and a Java banner; use the fixed `require_java` |
| `constant X: expected exactly 1 definition, found 0` | `--set` name does not match a `var X=<token>;` line |
| `misaligned .so` > 0 | the swap step was skipped or an external tool re-zipped the file |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | different signing key than the installed app (§4) |
| `curl` 403/timeout fetching jars | network policy; download `apksig-8.5.2.jar` and `bcprov-jdk18on-1.78.1.jar` manually into `testing/tools/` as `apksig.jar` / `bcprov.jar` |
