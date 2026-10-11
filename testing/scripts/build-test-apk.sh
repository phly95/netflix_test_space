#!/usr/bin/env bash
# Builds a signed Netflix TEST APK by swapping the bundled Frida script inside an ALREADY-PATCHED APK, then
# splits it into upload-sized parts. No Morphe CLI, no base APKM and no Gradle build are needed: the script is
# the only thing that differs between our Netflix test builds (the DEX/loader patches never change).
#
#   KS_KEY_PASS=<key password> ./build-test-apk.sh <patched-base.apk> <label> [options]
#
#   --script <file>     killads.js to bundle (default: patches/.../netflix/native/killads.js)
#   --set NAME=VALUE    override a `var NAME=<old>;` constant in the script (repeatable), e.g.
#                       --set EVALHOOK_ENABLED=true --set EVAL_ARM_DELAY_MS=8000
#   --no-household      do NOT flip HH_ENABLED (default: flip it, exactly like suppressHouseholdPromptPatch)
#   --parts <size>      part size for `split -b` (default 28M; 0 = do not split)
#
# Environment: KS_PATH (default testing/keystore/morphe-test.keystore), KS_KEY_PASS (required),
#              KS_STORE_PASS (default empty), KS_TYPE (default BKS), KS_ALIAS (default: first alias).
# Output (testing/out/, gitignored): <label>.apk, <label>.apk.sha256, <label>.apk.part0.. and <label>-killads.js
# See testing/NETFLIX_TEST_APK_BUILD.md.

source "$(dirname "$0")/lib.sh"

BASE="${1:-}"; LABEL="${2:-}"
[[ -n "$BASE" && -n "$LABEL" ]] || die "Usage: KS_KEY_PASS=... ./build-test-apk.sh <patched-base.apk> <label> [--script f] [--set N=V] [--no-household] [--parts 28M]"
shift 2
SCRIPT_SRC="$REPO_ROOT/patches/src/main/resources/netflix/native/killads.js"
HH_FLIP=1; PARTS=28M; SETS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --script) SCRIPT_SRC="$2"; shift 2 ;;
        --set) SETS+=("$2"); shift 2 ;;
        --no-household) HH_FLIP=0; shift ;;
        --parts) PARTS="$2"; shift 2 ;;
        *) die "Unknown option: $1" ;;
    esac
done
[[ -f "$BASE" ]] || die "Base APK not found: $BASE"
[[ -f "$SCRIPT_SRC" ]] || die "Script not found: $SCRIPT_SRC"
[[ -n "${KS_KEY_PASS:-}" ]] || die "KS_KEY_PASS is not set (the key password has no default)."
KS_PATH="${KS_PATH:-$KEYSTORE}"
[[ -f "$KS_PATH" ]] || die "Keystore not found: $KS_PATH (set KS_PATH). Sign with the SAME key as the installed build or 'adb install -r' will fail."
require_java
command -v python3 >/dev/null || die "python3 not found."

# ── tools: apksig (Google Maven) + BouncyCastle (Maven Central, for the BKS keystore) ──
APKSIG="$TOOLS_DIR/apksig.jar"; BCPROV="$TOOLS_DIR/bcprov.jar"; CLASSES="$TOOLS_DIR/classes"
[[ -s "$APKSIG" ]] || { info "Fetching apksig ..."; curl -fsSL -o "$APKSIG" "https://dl.google.com/dl/android/maven2/com/android/tools/build/apksig/8.5.2/apksig-8.5.2.jar"; }
[[ -s "$BCPROV" ]] || { info "Fetching bcprov ..."; curl -fsSL -o "$BCPROV" "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.78.1/bcprov-jdk18on-1.78.1.jar"; }
mkdir -p "$CLASSES"
javac -cp "$APKSIG:$BCPROV" -d "$CLASSES" "$SCRIPT_DIR/java/ApkSign.java" "$SCRIPT_DIR/java/ApkInspect.java" 2>&1 | grep -v "Picked up" || true

# ── 1. prepare the script: the HH flip + constant overrides, each must match exactly once ──
OUT_SCRIPT="$OUT_DIR/$LABEL-killads.js"
SETS_JOINED="$(printf '%s\n' "${SETS[@]:-}")"
python3 -I - "$SCRIPT_SRC" "$OUT_SCRIPT" "$HH_FLIP" "$SETS_JOINED" <<'PY' || die "Script preparation failed"
import re, sys
src, out, hh, sets = sys.argv[1], sys.argv[2], sys.argv[3] == '1', [s for s in sys.argv[4].split('\n') if s]
b = open(src, 'rb').read()
def sub(b, name, value):
    pat = re.compile(rb'var ' + re.escape(name.encode()) + rb'=[A-Za-z0-9_.\-]+;')
    n = len(pat.findall(b))
    if n != 1:
        sys.exit('constant %s: expected exactly 1 definition, found %d' % (name, n))
    return pat.sub(('var %s=%s;' % (name, value)).encode(), b, count=1)
if hh:
    b = sub(b, 'HH_ENABLED', 'true')          # what suppressHouseholdPromptPatch does (first occurrence)
for s in sets:
    name, _, value = s.partition('=')
    b = sub(b, name, value)
open(out, 'wb').write(b)
print('script: %d bytes' % len(b))
PY
command -v node >/dev/null && node --check "$OUT_SCRIPT" && ok "script syntax OK"
grep -o -E "var (HH_ENABLED|EVALHOOK_ENABLED|EVAL_ARM_DELAY_MS|ADK_ADV_ENABLED|HH_NOCACHE|AD_DIAG|HH_DUMPS)=[A-Za-z0-9_]+" "$OUT_SCRIPT" | tr '\n' ' '; echo

# ── 2. swap the script entry, 3. sign (v2), 4. verify ──
UNSIGNED="$OUT_DIR/$LABEL.unsigned.apk"; FINAL="$OUT_DIR/$LABEL.apk"
python3 -I "$SCRIPT_DIR/apk-swap-file.py" "$BASE" lib/armeabi-v7a/libgadget.script.so "$OUT_SCRIPT" "$UNSIGNED"
rm -f "$FINAL"
KS_KEY_PASS="$KS_KEY_PASS" java -cp "$APKSIG:$BCPROV:$CLASSES" ApkSign "$KS_PATH" "$UNSIGNED" "$FINAL" 2>&1 | grep -v "Picked up"
rm -f "$UNSIGNED"
java -cp "$APKSIG:$CLASSES" ApkInspect "$FINAL" 2>&1 | grep -v "Picked up" || die "Signature verification failed"
python3 -I "$SCRIPT_DIR/apk-align-check.py" "$FINAL" | tail -1
python3 -I - "$BASE" "$FINAL" <<'PY'
import sys, zipfile
a, b = zipfile.ZipFile(sys.argv[1]), zipfile.ZipFile(sys.argv[2])
A = {i.filename: (i.CRC, i.file_size) for i in a.infolist()}; B = {i.filename: (i.CRC, i.file_size) for i in b.infolist()}
print('vs base: changed', [n for n in A if n in B and A[n] != B[n]], '| dropped', sorted(set(A) - set(B)), '| added', sorted(set(B) - set(A)))
PY

# ── 5. checksum + parts ──
( cd "$OUT_DIR" && rm -f "$LABEL.apk.part"* && sha256sum "$LABEL.apk" > "$LABEL.apk.sha256" && cat "$LABEL.apk.sha256" )
if [[ "$PARTS" != "0" ]]; then
    ( cd "$OUT_DIR" && split -b "$PARTS" -d -a 1 "$LABEL.apk" "$LABEL.apk.part" && ls -l "$LABEL.apk.part"* | awk '{printf "  %-40s %s\n",$9,$5}' )
    NP="$(ls "$OUT_DIR/$LABEL.apk.part"* | wc -l)"; JOIN=""
    for ((i=0;i<NP;i++)); do JOIN+="$LABEL.apk.part$i "; done
    ok "Combine on the receiving side:  cat ${JOIN}> $LABEL.apk && sha256sum -c $LABEL.apk.sha256 && adb install -r $LABEL.apk"
fi
