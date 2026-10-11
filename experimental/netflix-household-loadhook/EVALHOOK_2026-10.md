# Household prompt 1-2 s into playback — diagnosis + eval load-hook fix (2026-10)

Target: Netflix ATV `13.0.1 build 25028` (armeabi-v7a). Built and host-tested only. **Not yet
verified on a device.**

> **Status (2026-10-11, after device logs killlog5-7 — see the last section).** The eval hook and
> `HH_NOCACHE` described under "Fix" below are **opt-in and off by default** (`EVALHOOK_ENABLED=false`,
> `HH_NOCACHE=0`); the Morphe patch only flips `HH_ENABLED`. The shipping household suppression is the
> async heap sweeps, now scheduled household-first.

## Symptom
With "Suppress Household Prompt" on, the household prompt still shows **a second or two after an
episode or video starts**.

## Diagnosis
1. **The heap-scan race is lost at play time.** Every household edit rewrites JS *source* in the heap,
   which only works if it lands before V8 compiles the function (on its first call). Route 2
   (`doRouteOnFetchedInterstitial`) lives in a module evaluated **on play**. That load, the
   interstitial fetch and the start of playback all happen together; the reply arrives ~1-2 s later,
   and the gate compiles from the unpatched source. Meanwhile the route-2 sweep was running at 1 s
   intervals, each pass scanning all memory, queued behind `apply()`/`observe()` on the one Frida
   thread (`hhYield` only covers the first 30 s after launch).
2. **The fallback stopped too early.** `fastCLCS` stopped re-scanning route 2 after the first hit
   (`frDone`) and gave up after 1400 passes (~20-30 min). A re-evaluated module is a fresh unpatched
   copy, so the 2nd episode, or any play after the cap, was never patched. `fastHH` and `apply()`
   also exit for good once done, so `neuterMhuRenders` never sees modules that load later.
3. **The V8 script cache can override source edits.** `libnetflix.so` ships `V8ScriptCache.cpp`, and
   its embedded bootstrap JS caches every script:
   `nr.script.addEventListener("script",(e=>{0!==e.version&&e.usedCache||e.cache(1)}))` and, on
   `uiLoaded`, `e.cache(100)`, which stores the bytecode compiled *so far*. V8 checks a cache against
   its source mostly by **length**, and all our edits keep the length the same, so a stale cache
   built from unpatched source is still accepted.

## Fix (killads.js, all under the existing HH_ENABLED opt-in)
- **EVAL load-hook.** Hooks the Gibbon2Bridge `eval` callback prologue `0x137626c`, which was proven
  live on .211 (ABI_DECODE §7) and matches this build byte for byte; the prologue signature is checked
  at runtime, and a mismatch means no hook. In `onEnter` it finds the script String with a bounded
  walk (r0/r1/r2, one hop) and checks it is a V8 one-byte string (len @+8, chars @+12). It then applies
  the CLCS dispatcher, route-2, HH flag/render and MHU edits **inside that one string only**, before
  V8 compiles it. Each group of edits only runs if a cheap marker is present first. Every edit is
  verify-before-write and keeps the length the same.
- **Script cache off (`HH_NOCACHE`).** Rewrites the bootstrap's cache listener into a one-shot
  `nr.script.clearScriptCache()` and the `uiLoaded` `e.cache(100)` into a no-op, both keeping the
  length. This is done in the eval'd bootstrap source and in libnetflix.so's data segment. Trade-off:
  a slightly slower warm boot.
- **Fallback sweep.** `fastCLCS` now keeps sweeping for unpatched copies all session (rewrites are
  safe to repeat): every 150 ms for 6 s after any eval, otherwise every 2 s.
- Arming: `android_dlopen_ext` onLeave for libnetflix.so (before JNI_OnLoad), plus a 100 ms poll as
  a backstop.

## Verify on device
`adb logcat -s KILL:*`, then look for:
- `EVALHOOK armed @…`. A `prologue signature mismatch` line means a different Netflix build, so only
  the heap-scan fallback runs.
- `PATCH EVAL(so): script cache listener -> clearScriptCache()` and/or `PATCH EVAL#n: …`.
- On play: `PATCH EVAL#n: route2 doRouteOnFetchedInterstitial !v->!0` should appear **before** the
  gate would have shown, followed by `EVAL#n: k household edit(s) applied pre-compile`.
- If no `PATCH EVAL#…` route-2 line appears on play but `PATCH CLCS(route2): wrote` does, the hook
  isn't reading that module in place. Capture the log and check the String walk.

Host test (no device): `node test_evalhook.js ../../patches/src/main/resources/netflix/native/killads.js`.

## Known unknowns
- The String walk (r0/r1/r2 + one hop) follows the §7 probe; the exact register path at the prologue
  was not pinned down. If eval is ever called with a `uint8array` the walk finds nothing, and the
  fallback sweep is all that's left.
- Whether `clearScriptCache` also deletes the on-disk entries hasn't been confirmed. New caches are no
  longer produced either way.
- A third play-time route (for example post-play or autoplay of the next episode through a different
  saga) would not be covered by these anchors.

## Scheduling findings (device logs killlog2-4, host repro) — read before touching the scanners

The hang and most of the "household still shows" failures were **JS-thread starvation**, not pattern
mismatches. Frida runs all script code on one thread and `Memory.scanSync` holds it for the whole scan
(~2.4s per full-heap pattern on the Onn TV, ~550 `rw-` ranges).

| Observation | Where |
|---|---|
| One `fastHH` pass (4 HH anchors + 16 MHU names, all `scanSync`) blocked the thread **39s**; the dispatcher break, every timer and the diagnostics starved behind it | killlog3 |
| `apply()` (~15 patterns) and `fastMASTER` (every 120ms) run multi-second synchronous passes for the whole session; `MASTER` cannot land on the current 13.0.1 JS (`M2-MISS`) so `fastMASTER` never stops | killlog2-3 |
| Async `Memory.scan` queue showed `scans=2+11741` and barely moved: each scan **completes by calling back into the JS thread**, and back-to-back sync ad-kill steps left only a ~25ms slot between them | killlog4 |
| An eval hook's `onEnter` (even empty) waits for the same JS lock on Netflix's own thread: 600 calls took 5.4s vs 1.3s with a scanSync loop running (host repro), and the first device builds hung at the splash | host + device |

What the code does now: household scans use async `Memory.scan` with a 2-in-flight pool, household jobs
have priority over diagnostics, ranges under 32KB are skipped, and the ad-kill work (`apply`,
`fastMASTER`, `dumpMASTER`) is deferred for the first 60s and only runs while no household scan is
pending (then throttled to once per 120s). The household module is found with ONE seed scan (`MHU_`) and
one detector anchor per cycle; a fresh copy triggers a full recheck 300ms later.

Host tests: `test_evalhook.js` (mock) and a real-frida run of the actual script against a process with
~1500 small ranges, 400MB of heap and household modules appearing at +0s, +40s and +98s (all patched
within ~10s each, queue draining between cycles).

Still unknown (needs a device log): which route shows the household screen right after profile select —
the dispatcher labels are broken but the screen still came up. `HHDIAG` lines dump the real routing JS
(`pushClcsInterstitialGate` callers seen so far: the `growthPush` saga and the playback-exit path).

## Ads on current 13.0.1 JS (killlog5): re-anchored ad-kill, run on the async pool

K fixed the household layers on device (gate labels +15.6s, all 4 account-sharing edits, all 16 MHU screens
within ~1s of being found, route2 +24.5s) but ads leaked through. Two causes:
1. The sync ad-kill (`apply`/`fastMASTER`) was deferred by the household gate and barely ran.
2. Netflix's served JS drifted, so the exact anchors no longer match (dumps in the log):
   - manifest->adverts normaliser: `null==(h=r.manifest.adverts.adBreaks)?void 0:h.map(function(e,t){var i=c.normalize(e.locationMs)` —
     1-char local and args `(e,t)`; the old ADV/ADVw anchors need a 2-char local and `(a,b)`.
   - `getAdMetadata`: `getAds(e);if(t){...}else{if(!e.adverts||!e.adverts.adBreaks.length)return;i=e.adverts.adBreaks.map(function(e){...` —
     the else branch is no longer a bare `else return;` (old M2), hence `MASTERw M2-MISS`.

`fastADK` (household builds) replaces them with regex-matched, length-preserving, verify-before-write edits:
`h=r.manifest.adverts.adBreaks` -> `h=[]<spaces>` (ADV2); `if(t){` -> `if(0){` plus the else branch's
`i=e.adverts.adBreaks.map(` -> `i=[]<spaces>.map(` (MASTER2: M2 first, M1 second; M1 alone is the old v1 crash).
B (pause) and DAI exact anchors are kept (B still matches). Host test executes the real function text before and
after patching: original yields the ad breaks, patched yields `[]`, ad-free content still returns `undefined`.

## Eval hook, second attempt (async patcher, covers ads too) — device result pending

killlog6 (build M): every layer landed but slowly on a cold start (gate +19s, HH +33s, route2 +36s, ads +19-40s):
the sweeps cost ~11 range-scans per cycle on ~550 ranges. A user who presses play within ~35s of launch beats them,
and a re-evaluated play-time module costs another sweep cycle. Patching each script as Netflix evaluates it removes
the scan latency. The first hook builds hung at the splash only because the JS lock was held by multi-second
synchronous scans (host repro in the table above); all household/ad scanning is now async, so the hook's onEnter
(which only locates the source String and queues it) no longer waits long for the lock.

`hhPatchSource` runs the same match handlers as the sweeps (household + ad) over the one source string as async
worker-thread scans at TOP priority (priority 0 > sweeps 1 > diagnostics 2), so a multi-MB source never blocks Netflix's
eval thread or Frida's JS thread. Opt-in (`EVALHOOK_ENABLED`), armed `EVAL_ARM_DELAY_MS` after launch. Verify in the log:
`EVALHOOK armed`, then `PATCH EVAL#n:` / `EVAL#n: k edit(s) applied` lines when a module is evaluated.

## Device logs killlog5-7: why household came back at profile select (2026-10-11)

killlog5 is build `a4ca56a` (the "K-prio" APK: its bundled script is byte-identical to that commit with
only `HH_ENABLED=true`, no eval hook, no cache patch) — household suppression worked. killlog6 added
`fastADK` (`02fc47d`); killlog7 also had the eval hook on (armed at +8s). Seconds after launch:

| Layer | killlog5 | killlog6 (+fastADK) | killlog7 (+hook) |
|---|---|---|---|
| Dispatcher labels broken | 15.6 | 19.1 | 19.8 |
| HH flags (first) | 15.6 | 25.8 | 24.8 |
| MHU 16/16 neutered | 21.5 | 31.7 | 30.4 |
| HH all flipped | 23.0 | 33.1 | 31.4 |
| Route 2 written | 26.6 | 36.5 | 33.8 |
| Ad-kill ADV / MASTER | not running | 19.3 / 20.7 | 20.0 / 21.2 |

- Everything but the dispatcher slid ~10s. Sweep backlog at +18s was 2,963 jobs (killlog5) vs 5,002
  (killlog6). *Correction (2026-10-11, later):* a sweep is only 191 jobs (RANGESTAT: 191 of 595 rw- ranges are
  >=32K), not the ~510 first assumed, so the 2,039-job difference is ~10 sweeps, more than one ad-kill cycle.
  The ad-kill sweeps queued ahead of the household passes in the single FIFO queue are still the best-supported
  cause (inference), and fixing that restored killlog5 timings in killlog9. In killlog6/7 the pool never drained
  (diagnostic queue stuck at ~1,960 jobs, 0 HHDIAG dumps vs 18 in killlog5).
- The playback code (route 2) and `getAdMetadata` are resident at boot, not loaded on play, so a video-start
  check runs through the already-patched copy *if route 2 landed first*. The exposed window is a play before
  route 2 lands (+26.6s good, +36.5s bad). Whether a later play re-evaluates the module is still unproven.
- killlog5 HHDIAG (real routing JS): the gate-stack dispatcher (labels broken), plus direct
  `pushClcsInterstitialGate` callers in the `growthPush` saga, the playback-exit path and
  `pushClcsPostPlaybackInterstitialGate`; `QueryType.Lolomo` exists. killlog5 worked without covering them.
- Eval hook (killlog7): 186 evals, **0 edits**; every patch came from the sweeps. It armed at +8s, probably
  after the big boot modules, and it did not log whether the String walk found anything.
- `libnetflix.so` in the working APK still has the hook prologue signature at `0x137626c` and both bootstrap
  cache-producer strings verbatim, and contains none of the household JS (it is server-delivered).

Changes made for build P (host tests: `node test_evalhook.js ../../patches/src/main/resources/netflix/native/killads.js`):
1. `fastADK` is held until `clcsDone && hhDone && frDone && mhuHits>0` (safety timeout `ADK_HH_WAIT_MS`=30s).
2. Four scan queues: hook 0, household 1, ad-kill 2, diagnostics 3. Once both families are queued they
   *share* the pool (the family with fewer scans running goes next). Strict household priority was rejected:
   the persistent household detectors alone use nearly the whole pool and would starve the ad-kill.
3. `aScanAll` scans the biggest ranges first. `DAI` (never matched in any log) only runs in the first two
   cycles and then every 12th; steady-state ad-kill cadence 5s -> 8s.
4. Diagnostics: `RANGESTAT` (range count/bytes by size bucket, once), `RANGEHIT` (size of the range that held
   each anchor), `EVALSRC#n` (length + head of located scripts, or r0-r2 when none), and HHSTATUS now shows
   `scans=run+household/ads/diag`, `eval=calls/withSource` and `adk=held|on|idle`. Use RANGEHIT to pick
   `AS_MIN_RANGE` from data.

Next device run: capture through profile select and **two** plays, and note the wall-clock time of each press.
Acceptance vs killlog5: gate <= +15.6s, HH/MHU landed before the select, route 2 <= +26.6s, ADV/MASTER
within ~10s after `fastADK: starting`.

## killlog8 (build P): household fixed, ads still leaking (2026-10-11)

**Household: no prompt.** Dispatcher +17.5s, HH flags +18.6-23.5s, `fastADK` held until +30.0s (that was the
30s safety timeout: it also required MHU, which stayed `0/16` all session; MHU is only the blank-screen fallback and
the dispatcher + HH flags + route 2 sufficed, so build Q no longer requires it; route 2 landed +30.2s), then ADV +31.4s, MASTER +35.3s, B +40.3s. At +41-43s the sweep found and patched **51 more copies** of the
dispatcher anchor in small (48KB) ranges (`PATCH CLCS(fast): ... x51`). Cause **unconfirmed**: it may be fresh module
text re-created by the profile switch, or copies in the Frida runtime's own heap (the script text contains the
anchor literal). killlog9 shows no such event, so do not rely on it.
`RANGEHIT` sizes: dispatcher 1.9MB and 48KB, HH flags/render 256KB, route 2 and B 564KB, ad modules 4.6MB; 79 of
the 191 scanned ranges (>=32K) hold 224 of 236MB. Keep `AS_MIN_RANGE`=32K (a 256K floor would have missed those 48KB
hits); big-first ordering is the useful part.

**Ads: leaked in pre-roll and mid-roll although every ad edit landed before the first play**, and no fresh player
copy appeared afterwards (the ad detector re-matched only the already-patched copy). So the edits ran but were not
enough. Root cause found by reading the code against the design notes: with ADV2 applied
`adverts.adBreaks.length` is always 0, so MASTER2's kept `if(!e.adverts||!e.adverts.adBreaks.length)return;` guard
fired for every title and `getAdMetadata` returned **undefined**: the half-emptied state the notes forbid
("return a valid empty, never undefined"; the old M2 was `else b=[]`). The host test missed it because it fed the
function a populated `adBreaks`. Not yet confirmed on device.

Build Q changes:
1. MASTER2 now also turns the early `return;` into a 7-byte no-op, so every title yields `[]` (order: map
   source, guard, then `if(0)` last). New tests cover the ADV-emptied state and show the old guard returns
   undefined in it.
2. ADV2 is opt-in (`ADK_ADV_ENABLED=false`): the proven config killed ads with MASTER alone and left the
   manifest normaliser intact; ADV removes the breaks themselves, which the Aug notes link to `tvq-pb-101`.
3. `ADDIAG` (read-only recon on the ad queue, after the ad-kill starts): dumps the JS around `getAdMetadata`,
   `emptyAdBreakComplete`, `enrichAdsWithEmbeddedExtension`, `createAdsPlaygraph`, `_syncAdsLength`,
   `prepareAdBreakStates`, `StatefulAdBreak`; telemetry hits become short `ADDIAG-DATA` windows (they show
   whether e.g. `emptyAdBreakComplete` fired). Also logs the full patched `getAdMetadata` body once
   (`ADK MASTER body (patched)`), so the return expression and the consumers can be read next time.
4. `HH_DUMPS=false`: the household routing dumps (already captured in killlog5) no longer queue 2000 diagnostic jobs.

**Eval hook finding (killlog7/8):** the String walk works but only for evals that pass a String: 22 of 776 evals
located a source (MSL `headerdata` JSON, a 337KB `FX2Modules` bundle, a 231KB bootstrap), none with an anchor. The
big modules come through `nrdp.gibbon.loadScript`, which sets `format="uint8array"`, so `eval` receives a
**Uint8Array backing store, not a String**; the walk cannot see those. A hook that handles typed arrays (find the
JSArrayBuffer backing pointer + byte length) is the next step if a pre-compile hook is still wanted; with the sweeps
catching fresh copies it is no longer needed for household. Build Q ships with the hook off (repo default).

## killlog9 (build Q): household fine, the main ad kill never landed (2026-10-11)

Household timings are back to the last-good build (dispatcher +15.6s, HH flags +16.7s, route 2 +27.2s; MHU 16/16),
no prompt. `fastADK` started at +27.6s (the "household landed" condition, no timeout) and only B landed (+32s).
**No `PATCH ADK MASTER` line at all and `master=false` through +183s**: the `getAds(?);if(?){var ` pattern never
matched, so Q's MASTER2 fix has not run on a device. The ADDIAG recon found `getAdMetadata`, `StatefulAdBreak`,
`emptyAdBreakComplete`, `_syncAdsLength` and `prepareAdBreakStates` only inside method-name tables (compiled
class data), never in source text, while in killlog8 the same text sat in a 4.6MB range. The user saw one ad at the
start of the first episode, which matches Netflix's normal ad-tier pre-roll and cannot be credited to the kill.
Full analysis, hypotheses and next steps: `docs/NETFLIX_HOUSEHOLD_ADKILL_2026-10_HANDOFF.md`.
