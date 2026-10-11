# Netflix `killads.js` — how the in-process patcher works (2026-10)

_Applies to `patches/src/main/resources/netflix/native/killads.js` as of commit `deb4e74`, Netflix ATV
`13.0.1 build 25028` (armeabi-v7a, V8 13.2). For the story of how it got here and what is still open see
[`NETFLIX_HOUSEHOLD_ADKILL_2026-10_HANDOFF.md`](NETFLIX_HOUSEHOLD_ADKILL_2026-10_HANDOFF.md); for the higher-level ad
pipeline see [`NETFLIX_ATV_SYSTEM_DESIGN.md`](NETFLIX_ATV_SYSTEM_DESIGN.md)._

## 1. Delivery chain

```
Morphe patches (this repo)                         on the device
─────────────────────────                          ─────────────
bundleGadgetPatch  → lib/armeabi-v7a/libgadget.so            Frida gadget, SCRIPT mode
                     lib/armeabi-v7a/libgadget.script.so  ←  killads.js (bundled text, loaded by the gadget)
                     lib/armeabi-v7a/libgadget.config.so     {"interaction":{"type":"script","path":"libgadget.script.so","on_change":"reload"}}
loadGadgetPatch    → Application.onCreate: System.loadLibrary("gadget")   (index 0, as early as possible)
suppressHouseholdPromptPatch (opt-in)  → rewrites the first "HH_ENABLED=false" in libgadget.script.so to "=true"
```

`suppressHouseholdPromptPatch` flips **only** `HH_ENABLED`. Every other flag in this document is at its repo default in
a shipped build. Output goes to logcat tag `KILL` (`adb logcat -s KILL:*`).

## 2. Constraints that shape every decision

1. **Netflix's logic is downloaded JavaScript**, evaluated by V8 inside `libnetflix.so`. It re-minifies server-side
   without an app update, so exact byte anchors drift (see `NETFLIX_ATV_SYSTEM_DESIGN.md` §9). Anchors are therefore
   regex/wildcard-tolerant where possible.
2. **We edit source text that sits in the heap.** V8 compiles a function lazily from the script's source string on its
   *first call*. A patch only takes effect if it lands before that first call (or after bytecode flushing). A fresh copy
   of a module is fresh, unpatched text again.
3. **Every edit is length-preserving and verify-before-write** (read the expected bytes, write only if they match). The
   engine's string offsets and positions must not move. Edits are idempotent: re-scanning a patched copy finds nothing.
4. **Frida runs script code on ONE thread**, and `Memory.scanSync` holds it for the whole scan (~2.4 s per full-heap pattern
   on the Onn). A hook's `onEnter` on Netflix's own thread must wait for that same lock. Result: synchronous sweeps
   starved timers (39 s block in killlog3) and an early eval hook hung the splash screen.
5. **Memory.scan (async) runs on a worker thread** and only calls back into JS per match. Host measurement (frida 17): worst
   JS-thread gap 21 ms vs 672 ms for `scanSync`, and a hooked function on another thread was not slowed.
6. **Never re-patch live memory in a loop** (Aug notes: it corrupted the running bundle). Patches are written once per
   copy; the persistent loops only look for *new* unpatched copies.

## 3. The scan pool and scheduler

```
scan targets   = rw- ranges, 32 KB … 128 MB     (RANGESTAT: 191 of ~595 ranges, ~235 MB; 79 ranges ≥256 KB hold 223 MB)
one "sweep"    = one pattern over every target  = 191 range jobs
pool           = AS_MAX = 2 scans in flight, jobs picked from four queues
```

| Queue | Priority name | Used by |
|---|---|---|
| 0 | eval-hook sources | `hhPatchSource` (top priority; only when the hook is on) |
| 1 | household sweeps | `fastCLCS`, `fastHH` (HH anchors + MHU seed) |
| 2 | ad-kill sweeps | `fastADK`, `adDiag` |
| 3 | diagnostics | `hhDiag` (off by default) |

**Picking rule (`aScanPick`)**: queue 0 first; if both 1 and 2 are non-empty, take the family with *fewer scans
currently running* (ties → household); else whichever is non-empty; queue 3 only when 1 and 2 are empty. This is a
fair share, not strict priority: the persistent household detectors alone use nearly the whole pool, so strict priority
would starve the ad-kill (the original ad leak in killlog5).

**Big ranges first** (`aScanAll` sorts by size, descending): script sources are multi-MB allocations, so a first hit
comes sooner. **No ad-kill until household has landed** (`adkHold`): `fastADK` waits until `clcsDone && hhDone &&
frDone` (30 s safety timeout, `ADK_HH_WAIT_MS`). In killlog6/7, starting it at +0.3 s delayed every household layer by
~10 s, past the profile select.

Cadences: `fastCLCS` 150 ms until the dispatcher is broken, then every 2 s (persistent); `fastHH` 1 s (4 s after 60
passes), 8 s once done and MHU neutered, 300 ms right after a fresh module copy is detected; `fastADK` 2.5 s until the
kills land (8 s after 60 cycles), then `ADK_LIGHT_MS` = 8 s, with B every 4th cycle and DAI only in cycles 1-2 and every
12th; `hhStatus` every 5 s for 5 min; `adDiag` ≤4 passes 15 s apart.

## 4. The layers

| Layer | Purpose | Anchor (scan) | Edit | State / log line | Device status |
|---|---|---|---|---|---|
| **Dispatcher** (`fastCLCS`) | gate stack never routes the household interstitial | `case"clcsInterstitialGate":case"clcsInterstitialPreProfileGate":` | flip the leading `c` at offsets 5 and 32 → `x` | `clcsDone`; `PATCH CLCS(fast): gate case-labels broken xN` | verified (killlog5, 8, 9) |
| **Route 2** (`fastCLCS`) | playback interstitial fetch exits instead of routing the household gate | `doRouteOnFetchedInterstitial:fetchDgsData"}),!` + `<var>){` | `!v` → `!0` | `frDone`; `DIAG route2 anchor RESIDENT`, `PATCH CLCS(route2)` | patched before first play; effect on a real household challenge not observed in a log |
| **HH flags / render gates** (`fastHH`) | account-sharing redux never activates the challenge | `setAccountSharingFlags)({isActiveMisdetectionSession:!0`, `…isNetflixHouseholdAvailable:!0`, `(y=null!=f&&f,`, `w=null!=h&&h)` | `0→1` (writes `!1`), `f→0`, `h→0` | `hhDone`; `PATCH HH: …` | verified |
| **MHU render neuter** (`fastHH`) | blank-screen fallback for 16 `MHU_*` screens | one `MHU_` seed scan, then `<NAME>,render:function(e){var …\n` | decls → `return null;` + spaces | `mhuHits`, `PATCH MHU: …` | landed 16/16 in killlog5-7, 9; **0/16 in killlog8 with no prompt** (not required) |
| **Ad-kill B** (`fastADK`) | pause-screen ad overlay | `void 0:e.displayAd` | `e.displayAd` → `void 0` + pad | `bDone`; `PATCH ADK B` | lands (+32-40 s) |
| **Ad-kill MASTER2** (`fastADK`) | `getAdMetadata` returns `[]` for every title | `getAds(?);if(?){var ` then the else-branch regex (§5) | 3 edits: `i=X.adverts.adBreaks.map(` → `i=[]<sp>.map(`; early `return;` → `      ;`; `if(t)` → `if(0)` last | `masterDone`; `PATCH ADK MASTER…`, `ADK MASTER body (patched)` | **landed in killlog8 but ads leaked; never landed in killlog9** |
| **Ad-kill ADV2** (opt-in) | empties `adverts.adBreaks` at the manifest normaliser | `.manifest.adverts.adBreaks)?void 0:` | `h=r.manifest.adverts.adBreaks` → `h=[]<spaces>` | `advDone`; `PATCH ADK ADV` | off by default (`ADK_ADV_ENABLED`) |
| **Ad-kill DAI** | `applyDaiPrefetch` guard | `return e&&0!==e.size?a.map` | `!==` → `===` | `daiDone` | **never matched in any log** |
| **Eval hook** (opt-in) | patch each script's source String before compile | hook at `libnetflix.so+0x137626c` | the same handlers, scoped to one String | `EVALHOOK armed`, `EVAL#n: k edit(s)` | arms and runs; patched nothing (§6) |
| **Legacy A / A2 / MASTER (old)** | pre-refactor ad seams | see `killads.js` header | unchanged | only when `HH_ENABLED=false` | not exercised in household builds |

MASTER2 detail. The current `getAdMetadata` (13.0.1, dumped in killlog1/2/4) is:

```js
getAds(e);if(t){ …legacy: build StatefulAdBreaks from t, enrich, applyDaiPrefetch, mergeReplacedAds… }
else{ if(!e.adverts||!e.adverts.adBreaks.length)return;
      i=e.adverts.adBreaks.map(function(e){…return new eX(i,ed({isHydrated:!!i.ads||i.embedded,canHydrate:!!i.adBreakToken&&!i.embedded,isPreroll:…}))}) }
return i=this.adBreakHydrator.enrichAds(i…)…
```

`MASTER2` forces the else branch (`if(0)`), makes its map source `[]`, and turns the early `return;` into `      ;`. The last edit matters:
with `ADV2` on, `adBreaks.length` is always 0 and the original guard would return `undefined` for every title (killlog8).
The design rule (`NETFLIX_ATV_SYSTEM_DESIGN.md` §8): *return a valid empty list, never `undefined`*. Write order is map
source → guard → `if(0)` so a partial state is never the harmful one.

## 5. Netflix JS reference excerpts (minified, from device dumps)

Short quotes only; no app source is committed. Variable names drift; the anchors above key on stable tokens.

**Gate-stack dispatcher** (killlog5; already broken: `xlcs…`). `profileSelectionTransitionAnimation` is a different case
and is never touched, so "who's watching" keeps working:
```js
e.forEach(function(e){var s=e.componentName,u={isInitialGate:0===t.length}
switch(s){case"onramp":…pushOnRamp(e,u)  case"umsGate":case"standardUmsGate":…pushUmsGate({umsAlert:e},u)
case"clcsInterstitialGate":case"clcsInterstitialPreProfileGate":t.push(pushClcsInterstitialGate(e,u))
case"profileSelectionTransitionAnimation":…pushProfileSelectionTransitionAnimation(e,u)}})
```
**Interstitial fetch builder**: `componentName: e!==QueryType.ProfileGate ? "clcsInterstitialGate" : "clcsInterstitialPreProfileGate"`,
`presentOnProfileGate: e===QueryType.ProfileGate`; household messages are `T=["ACCOUNT_BORROWER_VALIDATION","TERMS_OF_USE_UMA"]`;
the query-type map includes `QueryType.Lolomo → "clcsInterstitialLolomoQuery"` (a third delivery path the patch does not cover).

**Route 2** (`doRouteOnFetchedInterstitial`, patched form `!0`): fetch with `QueryType.PlayBackAsync`, log
`doRouteOnFetchedInterstitial:fetchDgsData`, `if(!0){goto 24}`; the unpatched branches would `replaceWithCLCS`
(`pushClcsInterstitialGate`/`replaceWithClcsInterstitialGate`) or `replaceWithUMS`.

**Other direct callers of `pushClcsInterstitialGate`** (bypass the dispatcher): the `growthPush` saga
(`GrowthClcsPushInitiate`, `QueryType.PushInitiate`, then `pushClcsInterstitialGate(k.initialScreen)`), the playback-exit
path (`setPlaybackStateOnExit` … `B.push(pushClcsInterstitialGate(x))`) and `pushClcsPostPlaybackInterstitialGate`.
Not covered by any layer; not needed in killlog5/8/9.

**Account-sharing consumer** (the HH render gates): `return"ready"===g&&(y=null!=f&&f,w=null!=h&&h),{accountSharingStatus:g,
misdetectionAvailable:y, netflixHouseholdAvailable:w,…}`; sagas dispatch
`setAccountSharingFlags({isActiveMisdetectionSession:!0})` / `({isNetflixHouseholdAvailable:!0})`.

**Ad normaliser** (ADV): `r.adverts=(0,m._)({},r.manifest.adverts,{adBreaks:(null==(h=r.manifest.adverts.adBreaks)?void 0:h.map(function(e,t){var i=c.normalize(e.locationMs),…`

**Ad-state vocabulary** (killlog9 name tables, still present in the current build): `getAdsForViewable,
getStatefulAdbreakByAdInfo, getAdBreakAtContentLocation, getAdBreakAtUnnormalizedLocation, getAdBreakByTriggerId,
prepareAdBreakStates, resetAdsState, propagateAdBreakState, getAdMetadata, enrichAdsForLinear,
coalesceEmbeddedOnAdBreaks, enrichAdsWithUiOverlays, applyDaiPrefetch, mergeReplacedAds,
enrichAdsWithEmbeddedExtension, reportReplacedAdsMismatches, calculateManifestWindowsForViewable, init, rebuild,
markAdError`; around `emptyAdBreakComplete`: `canSeek, getPlayerControlState, resolvePerAdPlayerControlState, hasAds,
getStatefulAdsForViewable, adBreakFallback, explicitAdBreakComplete, adBreakPassed, emptyAdBreakComplete,
anonymousAdBreakComplete, adBreakEnding, playerChanged, onPlaybackEnding, onAdSegmentDropped, isEndOfPlaygraph,
inAdBreak, adComposer, adsState`; around `_syncAdsLength`: `updateAdBreak, getAdBreakTriggerId, getAdBreakOffsetForAd,
statefulAdBreak, isPreroll, contentTimestamp, unnormalizedLocationMs, segmentationTypeId, sequenceId,
segmentCategories, _adBreak, adBreakTriggerId, adBreakIndex`. So `_syncAdsLength` and `prepareAdBreakStates` (the legacy
A/A2 seams) still exist in 13.0.1.

## 6. The eval hook

* **Target**: the `Gibbon2Bridge` `eval` callback prologue, `libnetflix.so + 0x137626c` (ARM, not Thumb). The signature
  `[+0]=0xe92d48f0 push{r4-r7,fp,lr}`, `[+0x14]=0xe1a07002`, `[+0x18]=0xe1a04001` is checked at runtime; a mismatch means
  "not armed". Verified present in the working APK's `libnetflix.so`.
* **Source lookup**: a bounded walk from `r0/r1/r2` (first 16 words, one hop of 8) for a V8 `SeqOneByteString` (length at
  `+8`, Latin-1 chars at `+12`, 32-bit, no pointer compression). Edits run as async worker scans at queue 0, deferred by
  `setTimeout(0)` so `onEnter` stays a few hundred reads.
* **Why it patched nothing** (killlog7/8): the walk located a String in only 22 of 776 evals (MSL `headerdata` JSON, a
  337 KB `FX2Modules` bundle, a 231 KB bootstrap), none with an anchor. `nrdp.gibbon.loadScript` sets
  `format="uint8array"`, so the big modules reach `eval` as a **Uint8Array backing store**, not a String. Extending the hook
  means finding the `JSArrayBuffer` backing pointer and byte length.
* **Boot-safety history**: arming through `android_dlopen_ext` hung the splash (builds A/B; `onLeave` rewrites a return
  address libdl uses). Polling arm at +8 s (killlog7/8) ran 700+ evals without a hang. `EVAL_ARM_DELAY_MS` default
  is 60 s, after most profile selects, so even when enabled it targets play-time modules only.
* **Cache producers** (`HH_NOCACHE`): `nr.script.addEventListener("script",(e=>{0!==e.version&&e.usedCache||e.cache(1)}))`
  and the `uiLoaded` sweep `e&&(e.version<100||!e.usedCache)&&e.cache(100)` live in the bootstrap JS embedded in
  `libnetflix.so` (each exactly once). Patching them from Frida at +60 s is too late for scripts already loaded; a static
  patch of the `.so` at build time has no race (untried).

## 7. Flags and constants (repo defaults)

| Name | Default | Meaning |
|---|---|---|
| `HH_ENABLED` | `false` (the opt-in patch sets `true`) | household suppression + async ad-kill instead of the legacy synchronous ad-kill |
| `MHU_ENABLED` | `= HH_ENABLED` | neuter the 16 `MHU_*` renders |
| `ADK_ADV_ENABLED` | `false` | also empty `adverts.adBreaks` (breaks removed, not only ads) |
| `ADK_HH_WAIT_MS` | `30000` | ad-kill safety timeout while waiting for household |
| `ADK_LIGHT_MS` | `8000` | steady-state ad-kill cadence |
| `AS_MAX` / `AS_MIN_RANGE` | `2` / `32768` | scans in flight / smallest range scanned |
| `HH_DIAG` / `HH_DUMPS` | `true` / `false` | `HHSTATUS` every 5 s / household routing JS dumps |
| `AD_DIAG` | `true` | `ADDIAG` ad-consumer recon after the ad-kill starts |
| `EVALHOOK_ENABLED` / `EVAL_ARM_DELAY_MS` | `false` / `60000` | eval hook opt-in / arm delay |
| `HH_NOCACHE` | `0` | `1` = stop new caches, `2` = also `clearScriptCache()` (only through the hook) |
| `EVAL_DEFER` / `EVAL_ARM_DLOPEN` / `EVAL_ONENTER_NOOP` | `true` / `false` / `false` | defer the scan off the eval thread / dlopen arm (breaks boot) / diagnostic no-op hook |
| `CLCS_PROBE_ENABLED` | `false` | old blocking recon probe (starves the ad-kill) |
| `FP_ENABLED`, `GAID_ENABLED` | `false` | privacy opt-ins (other patch) |

`build-test-apk.sh --set NAME=VALUE` overrides any `var NAME=<token>;` for a test build.

## 8. Log reference (`adb logcat -s KILL:*`)

| Line | Meaning |
|---|---|
| `RANGESTAT rw-ranges=N >=32K:n(MB) >=256K … >=8M …` | once at +0.1 s: how many ranges / bytes each size class holds |
| `RANGEHIT <pattern> rangeSize=S base=B +Tms` | an anchor was found in a range of size S (first 4 per pattern, 48 total) |
| `HHSTATUS +Ts clcs=… route2=… hh=… mhu=x/16 ads[adv master b dai] fcPass hhPass scans=R+h/a/d (household/ads/diag) eval=calls/withSource adk=held|on|idle` | every 5 s: layers landed, passes, jobs queued per family, eval hook counters, ad-kill state |
| `PATCH CLCS(fast): … xN` | dispatcher labels broken (N = matches seen, not writes) |
| `PATCH CLCS(route2)`, `DIAG route2 anchor RESIDENT` | route 2 found / written |
| `PATCH HH: flag:… / render:…` | account-sharing edits |
| `PATCH MHU: <NAME> render->null` | MHU screens neutered |
| `fastHH: all HH anchors flipped by pass N` | `hhDone` |
| `fastADK: starting at +Tms (household landed=… clcs hh route2 mhu)` | ad-kill released (`landed=false` ⇒ timeout) |
| `PATCH ADK ADV / MASTER / B` | ad-kill edits (`verify=OK` after the `if(0)` write) |
| `ADK MASTER body (patched) @…` | the full patched `getAdMetadata` text (once) |
| `ADK master: … shape UNEXPECTED, no write` | M1 matched but the else-branch regex did not |
| `ADDIAG <marker> #n` / `ADDIAG-DATA` / `ADDIAG done after N passes` | recon: source hits / short telemetry windows |
| `EVALHOOK armed @…`, `EVALSRC#n len=… head=…` / `none located r0 r1 r2`, `EVAL#n: k edit(s)` | eval hook |
| `ANCHOR MAP …` | legacy-style summary every 20 s ×8 (A/A2/ADV/DAI/MASTER/B flags) |

Healthy household run (killlog5/9): dispatcher ≈ +15.6 s, HH flags ≈ +16 s, route 2 ≈ +27 s, then `fastADK: starting … landed=true`.

## 9. Host test harness

`experimental/netflix-household-loadhook/test_evalhook.js <killads.js> [bootstrap.bin]` (83 checks) mocks the Frida API
over one Buffer, lays out V8 32-bit `SeqOneByteString`s, and checks: pool limits, queue picking and fair share,
big-first order, the ad-kill hold/timeout, DAI/B cadence, every household edit, the ad edits, **execution of the real
`getAdMetadata` text before and after patching**, the eval-hook walk, and the diagnostics. Blind spots: it cannot
reproduce V8 compile timing or code-cache behaviour, and it only feeds the patched function the states the test writes
(this is how the ADV × guard `undefined` bug slipped through; the regression test now covers it). `AS_MIN_RANGE` is set to
0 inside the test. Run it on the exact script you ship: `node test_evalhook.js <extracted libgadget.script.so>`.
