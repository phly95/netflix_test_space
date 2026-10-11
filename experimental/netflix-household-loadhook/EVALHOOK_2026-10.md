# Household prompt 1-2 s into playback — diagnosis + eval load-hook fix (2026-10)

Target: Netflix ATV `13.0.1 build 25028` (armeabi-v7a). Built and host-tested only. **Not yet
verified on a device.**

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
