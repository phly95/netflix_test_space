# Netflix household prompt + ad-kill — 2026-10 handoff

_State as of 2026-10-11 (end of the cloud session `01TcYfEa…`). Target: `com.netflix.ninja.clone` `13.0.1 build 25028`
(armeabi-v7a, Onn 4K). Written so the next session can pick this up cold. Companion docs:_

- _How the script works now → [`NETFLIX_KILLADS_ARCHITECTURE.md`](NETFLIX_KILLADS_ARCHITECTURE.md)_
- _How the test APKs were built, split and installed → [`../testing/NETFLIX_TEST_APK_BUILD.md`](../testing/NETFLIX_TEST_APK_BUILD.md)_
- _Earlier research and the running log of findings → [`../experimental/netflix-household-loadhook/`](../experimental/netflix-household-loadhook/README.md)_

> **Scope.** Client-side only, inside the app. The household *detection* is server-side and public-IP driven; this
> work only keeps the prompt off the screen (see `NETFLIX_ANNOUNCEMENT.md`, "Will this stop the traveling prompt?").

## 0. Where things stand

| Area | Status | Evidence |
|---|---|---|
| Household prompt at profile select | **Fixed, device-verified** on builds P and Q | no prompt in killlog8/9; layers land within ~1s of the last-good build (killlog5) |
| Household prompt at video start (route 2) | Patched before the first play in every good run; a *second* play was never logged | route 2 written +27s (Q) |
| Pause-screen ad (hook B) | Lands (+32s in Q) | `PATCH ADK B` in killlog6-9 |
| **Main ad kill (`getAdMetadata` → `[]`)** | **Not verified.** Landed in killlog8 but ads still played; in killlog9 it never landed at all | no `PATCH ADK MASTER` line in killlog9, `master=false` for 183s |
| Ads the user actually saw (Q) | one ad at the start of the first episode of a show | consistent with Netflix's normal ad-tier pre-roll, so **not evidence the kill works** |
| Eval (pre-compile) hook | Works mechanically, **patches nothing** | killlog7/8: 22 of 776 evals gave a String, none with an anchor |

Short version: the household regression was a **scheduling** problem and is solved. The ad kill is an **open
question** (§6), and the single remaining ad is not proof of anything.

## 1. Builds and logs

The user labels device builds with letters and keeps the logcat of each run (`adb logcat -s KILL:*`). Raw logs are
**not** committed: they contain heap fragments (telemetry JSON, MSL header blobs). The tables here were produced
with [`testing/scripts/killlog-timeline.py`](../testing/scripts/killlog-timeline.py).

| Label | Source | Log | What it was | Household | Ads |
|---|---|---|---|---|---|
| – | v1.37.x sync scanners | killlog1 | `apply`/`fastHH`/`fastMASTER`, synchronous `scanSync` | race lost | – |
| F | `10ddffa`-ish | killlog2 | dispatcher break at +7.8s, but HH flags never landed, MHU one screen per 2s from +37s | prompt after profile select | – |
| – | between `10ddffa` and `10906f2` | killlog3 | one `fastHH` pass held the JS lock for 39s | prompt | – |
| – | `10906f2` | killlog4 | async scans, queue of 11,741 jobs barely moving | nothing landed | – |
| **K** ("K-prio") | **`a4ca56a`** | **killlog5** | household-first scheduling, ad-kill deferred; APK script byte-identical to this commit | **works** | leak (ad-kill barely ran) |
| M | `02fc47d` | killlog6 | adds `fastADK` (re-anchored async ad-kill) | **prompt returns at profile select** | – |
| O (inferred) | `673d10c` + hook flags | killlog7 | eval hook armed at +8s | prompt | – |
| **P** | `af03dab` + hook on, arm 8s | killlog8 | household-first scheduling, `fastADK` held | **works** | pre-roll + mid-roll still play |
| **Q** | `deb4e74`, hook off | killlog9 | MASTER2 returns `[]`, ADV opt-in, ad recon | **works** | one ad at show start; kill did not land |

Mapping of logs 1-4 to commits is inferred from the commit messages; logs 5-9 are certain (5 by byte comparison,
8 and 9 by the flags in the logs).

## 2. What happened, in order

### 2.1 Before this session (commits `8906c0e` … `673d10c`, 2026-10-11 04:04-06:25)
An earlier session chased "the household prompt shows 1-2 s into playback" with a **pre-compile eval hook**
(hook the Gibbon2Bridge `eval` callback at `libnetflix.so+0x137626c`, rewrite the script's source before V8
compiles it). Builds A and B (hook armed through an `android_dlopen_ext` interposer) **hung at the splash**; C
(no hook) booted. The hook's `onEnter` runs on Netflix's own thread and waits for Frida's single JS lock, which the
heap sweeps held for whole seconds. That led to: late arming, sliced sweeps, then replacing every `scanSync` with an
**async `Memory.scan` pool** (2 in flight), household priority, and a 60 s deferral of the ad-kill. Build K
(`a4ca56a`) was the first where all household layers landed on device (killlog5), but ads leaked because the
ad-kill barely ran. `02fc47d` re-anchored the ad-kill to the drifted JS and ran it on the same async pool
(`fastADK`); `673d10c` made the eval hook patch ads as well.

### 2.2 The report that started this session
"Household now triggers on profile select" - right after the ad-kill work. The user then pointed out the decisive
fact: *the version right before the ad attempt was the one that worked*.

### 2.3 Reading code and docs first
Only `killads.js` (plus docs/tests) differs between `a4ca56a` and HEAD, so the regression surface was one file.
Findings from reading it:

- the eval hook was **not shipping**: `EVALHOOK_ENABLED=false`, and the Kotlin patch only flips `HH_ENABLED`
  (the EVALHOOK doc and a Kotlin comment claimed otherwise; both were corrected);
- even when enabled it armed at +60 s, after most profile selects, and `HH_NOCACHE` would patch the bootstrap
  after it had already run;
- `fastADK` armed at +300 ms, shared the household queue, and had **no `hhYield`/`adkDefer` check**.

### 2.4 Quantifying it with the logs (killlog5/6/7)
Every household layer except the dispatcher slid by ~10 s once `fastADK` existed (§3). The ad-kill's own patches
landed *before* the household flags (+19-21 s vs +25-30 s). Backlog at +18 s: 2,963 queued jobs (killlog5) vs 5,002
(killlog6), and in killlog6/7 the queue never drained (0 `HHDIAG` dumps vs 18).

### 2.5 The working APK
The user supplied K-prio as four `.apk.part*` files. Reassembling and unzipping it (as data, never executed) showed
`libgadget.script.so` is **byte-identical to `killads.js` at `a4ca56a` with only `HH_ENABLED=true`**, with
`EVALHOOK_ENABLED=false`, `HH_NOCACHE=0`. Same APK: v2-signed by `CN=Morphe`, `.so` files stored 4096-aligned,
`libnetflix.so` still has the hook prologue signature at `0x137626c`, both bootstrap cache-producer strings
verbatim, and **none of the household JS** (it is delivered by the server at runtime, so nothing static can fix it).

### 2.6 Fix 1 → build P (`af03dab`)
- `fastADK` is **held** until dispatcher + HH flags + route 2 (+MHU, later dropped) have landed; 30 s safety timeout.
- Four scan queues (hook 0, household 1, ad-kill 2, diagnostics 3); once both families are queued they **share**
  the pool (the family with fewer scans running goes next). Strict household priority was rejected on paper: the
  persistent household detectors alone use nearly the whole pool and would starve the ad-kill.
- Biggest ranges are scanned first; DAI (never matched in any log) runs rarely; ad-kill cadence 5 s → 8 s.
- New diagnostics: `RANGESTAT`, `RANGEHIT`, `EVALSRC`, richer `HHSTATUS`.
- Host tests 53 → 71. The tests also caught a bug in my first version (the "all landed" cadence was computed when
  the cycle *started*).
- Build P = this script with `EVALHOOK_ENABLED=true`, `EVAL_ARM_DELAY_MS=8000` (to get hook diagnostics).

### 2.7 killlog8 (P)
Household: no prompt. But **pre-roll and mid-roll still played although ADV, MASTER and B all landed before the
first play**, and no fresh player copy appeared afterwards. Reading the ad code against the design notes
(`NETFLIX_ATV_SYSTEM_DESIGN.md` §8: "return a valid empty, never `undefined`") exposed the defect: with ADV2
applied `adverts.adBreaks.length` is always 0, so MASTER2's kept early-return guard
`if(!e.adverts||!e.adverts.adBreaks.length)return;` fired for **every** title and `getAdMetadata` returned
`undefined`, the half-emptied state the notes forbid. The host test missed it because it fed a populated `adBreaks`.
Also found: `fastADK` had started at exactly +30.0 s, i.e. by the safety timeout, because it waited for MHU screens
(`mhu=0/16` all session). MHU is only the blank-screen fallback layer.

### 2.8 Fix 2 → build Q (`deb4e74`)
MASTER2 now also turns the early `return;` into a 7-byte no-op so every title yields `[]` (write order: map
source, guard, `if(0)` last); ADV2 is opt-in (`ADK_ADV_ENABLED=false`); MHU no longer gates the ad-kill start;
`ADDIAG` recon dumps the ad consumers; `HH_DUMPS=false`. Host tests 71 → 83, including a regression that shows the
old guard returning `undefined` in exactly the killlog8 state.

### 2.9 killlog9 (Q)
Household: no prompt; timings reproduce killlog5 (§3). Ads: **MASTER never landed.** The `getAds(?);if(?){var `
pattern matched nothing for 183 s (it matched in killlog8). `ADDIAG` found `getAdMetadata`, `StatefulAdBreak`,
`emptyAdBreakComplete`, `_syncAdsLength` and `prepareAdBreakStates` only in **method-name tables** (compiled class
data), never in source text. So Q's MASTER2 fix has never executed on a device.

## 3. Evidence

Seconds after launch, from `killlog-timeline.py`:

| layer | 5 (K) | 6 (+fastADK) | 7 (+hook) | 8 (P) | 9 (Q) |
|---|---|---|---|---|---|
| dispatcher labels broken | 15.6 | 19.1 | 19.8 | 17.5 | 15.6 |
| HH flags (first) | 15.6 | 25.8 | 24.8 | 18.6 | 16.7 |
| HH render gate (last) | 20.1 | 30.4 | 28.9 | 23.5 | 21.6 |
| MHU screens (first) | 21.5 | 31.7 | 30.4 | - | 23.5 |
| HH all flipped | 23.0 | 33.1 | 31.4 | 26.6 | 24.3 |
| route 2 resident | 24.5 | 35.4 | 32.6 | 29.7 | 26.9 |
| route 2 written | 26.6 | 36.5 | 33.8 | 30.2 | 27.2 |
| fastADK starts | - | - | - | 30.0 (timeout) | 27.6 |
| ad-kill ADV | - | 19.3 | 20.0 | 31.4 | off |
| ad-kill MASTER (if(0)) | - | 20.7 | 21.2 | 35.3 | **never** |
| ad-kill B (pause ad) | - | 40.0 | 36.4 | 40.3 | 32.0 |

`RANGESTAT` (logged once, +0.1 s): 595-596 rw- ranges; **191 are ≥32 KB (235 MB)**, 79 ≥256 KB hold 223 of those
235 MB, 37 ≥1 MB, 9 ≥8 MB. A sweep is therefore ~191 range jobs. `RANGEHIT` sizes of the ranges that held anchors:
dispatcher 1.9 MB (and one 48 KB hit in killlog8), HH flags/render gates 256 KB, route 2 and pause-ad 308-564 KB,
ad modules 4.6 MB (killlog8). A 256 KB floor would have missed the 48 KB hits, so `AS_MIN_RANGE` stays 32 KB.

## 4. Established vs. inferred

| Claim | Confidence | Basis |
|---|---|---|
| The household regression came from the ad-kill sharing the household queue | **High** | one-file diff; ~10 s uniform slip; restored by holding the ad-kill (killlog9 ≈ killlog5 within ~1.3 s) |
| The exact mechanism is "ad-kill sweeps queued ahead of the household pass" | Medium | consistent with backlog numbers; the one-cycle arithmetic first quoted was wrong (§5) |
| The eval hook cannot see the big modules because `loadScript` passes a `Uint8Array` | Medium | `loadScript` sets `format="uint8array"` (LOADHOOK_PLAN §4b); 22/776 evals located a String |
| Returning `undefined` from `getAdMetadata` is why P leaked ads | **Low-medium** | follows from the code and the design notes, but never observed; `getAdMetadata`-returns-`undefined` is also the normal value for ad-free titles |
| Why the player source vanished in killlog9 | **Unknown** | three candidates, §6 |
| 51 extra dispatcher copies at +41-43 s in killlog8 were fresh module text from the profile switch | Low | seen once; Frida's own heap holds the anchor literal too |

## 5. Mistakes and corrections (so nobody repeats them)

1. **Misread the F-build datum.** "Dispatcher broken at +7.8 s yet the prompt still came" was blamed on an uncovered
   route (growthPush / Lolomo). It was HH/MHU starvation by a 39 s synchronous pass. The extra routes exist (see the JS
   excerpts in `NETFLIX_KILLADS_ARCHITECTURE.md`), but killlog5 worked without covering them.
2. **Range count.** I assumed ~510 ranges per sweep (so "4 ad-kill sweeps ≈ 2,000 jobs"); `RANGESTAT` says 191
   (≈764 jobs). The 2,039-job backlog difference is ~10 sweeps, not one cycle. Notes and a code comment were
   corrected; the pushed commit message of `af03dab` still says "~2000 range jobs".
3. **The ADK design was flawed before I touched it.** `02fc47d`'s MASTER2 + ADV2 interaction returned `undefined`;
   `af03dab` (P) inherited it. The host test fed it inputs the real state never produces.
4. **MHU requirement** delayed the ad-kill to the 30 s timeout in P.
5. **Cadence bug** in my first scheduler version (caught by the new tests, never shipped).
6. **The "fresh copy at profile select" story** (EVALHOOK doc, killlog8 section) is unconfirmed; it is flagged there.
7. **"The hook is part of the fix"** (older docs/Kotlin comment) was never true of the shipped patch.

## 6. Open question: where is the player source, and does the kill work?

Facts: killlog8 found the source (`.manifest.adverts…`, `getAds(e);if(t){…`) in one 4.6 MB range at +31-35 s,
before any play. killlog9 found no ASCII source anywhere, only name tables, for seven different ad markers.
Candidates (not yet distinguished):

1. **Loaded from Netflix's V8 code cache** on the second launch (`nr.script` `e.cache(1)` / `e.cache(100)`; V8's
   cache check is length-based), so there is no readable source and, worse, the compiled bytecode may predate our edit.
2. **The script became two-byte (UTF-16)** (one non-Latin-1 character does it); every ASCII anchor then misses.
3. **The source is an external string in a read-only file mapping**, outside the `rw-` ranges the sweeps scan.

Cheapest discriminators, in order:

1. **No build needed:** watch the same show 15-20 min (or seek into a break). Mid-rolls present ⇒ the kill is not
   working; absent ⇒ something suppresses them and we can stop.
2. **Diagnostic build (ad queue only, cannot affect household):** scan UTF-16LE `getAdMetadata` in `rw-`, ASCII in
   `r--`/`r-x` file mappings (log protection, size, file path), and log what `Memory.scan` sees for `getAds(`.
3. **If it is the code cache:** the bootstrap strings that produce the cache are verbatim in `libnetflix.so`, so they
   can be patched statically at patch time (no timing race); a stale cache on disk then needs one `pm clear`.
4. Later, if wanted: make the eval hook understand `Uint8Array` (find the `JSArrayBuffer` backing store + length),
   which would also catch fresh copies before compile. Not needed for household any more.
5. Legacy ad seams `_syncAdsLength` / `prepareAdBreakStates` still exist as method names (killlog9); re-anchoring
   A/A2 onto the async ad queue is an option if their source can be found.

If the user is happy with one pre-roll per show, **stopping here is reasonable**: household is solved and nothing in
Q hurts it.

## 7. Resuming

```bash
# 1. host tests (no device)
node experimental/netflix-household-loadhook/test_evalhook.js patches/src/main/resources/netflix/native/killads.js
# 2. build a signed test APK from the working K-prio APK and split it (see testing/NETFLIX_TEST_APK_BUILD.md)
KS_PATH=… KS_KEY_PASS=… testing/scripts/build-test-apk.sh netflix-hh-K-prio.apk R --set ADK_ADV_ENABLED=false
# 3. after a device run, compare against killlog5 / killlog9
python3 -I testing/scripts/killlog-timeline.py 5=killlog5.txt 9=killlog9.txt new=killlogN.txt
```

Acceptance for household (killlog5/9): dispatcher ≤ +16 s, HH flags ≤ +17 s, route 2 ≤ +28 s, `fastADK: starting` after
that with `household landed=true`. Keep the K-prio APK: it is the only way to build test APKs without the base APKM.

## 8. What changed in the repo

| Commit | What |
|---|---|
| `8906c0e`…`673d10c` | earlier session: eval hook, async scan pool, household-first, `fastADK` |
| `af03dab` | ad-kill held until household lands; four queues with fair share; big-first; diagnostics (P) |
| `deb4e74` | MASTER2 valid-empty, ADV opt-in, MHU not required, ADDIAG, `HH_DUMPS` (Q) |
| `1a1a4af` | fastADK arming log no longer claims ADV; stale range-count comment fixed (log text/comment only) |
| `41e9995` | `testing/scripts/` APK swap/sign/split tooling and the KILL log timeline tool; `lib.sh` Java-banner fix |
| `518f3fe` | these docs |
