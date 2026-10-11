# netflix-household-loadhook — household prompt + ad-kill research (Netflix ATV 13.0.1)

Research, probes and the host test for keeping Netflix's household ("you're traveling") prompt off the screen and for
the async ad-kill that shares its scanner. **Production code is not here**: it is
`patches/src/main/resources/netflix/native/killads.js`. Start with the handoff:

> **[`docs/NETFLIX_HOUSEHOLD_ADKILL_2026-10_HANDOFF.md`](../../docs/NETFLIX_HOUSEHOLD_ADKILL_2026-10_HANDOFF.md)** - what
> happened, what is established vs. guessed, what is open, how to resume.
> Mechanics: [`docs/NETFLIX_KILLADS_ARCHITECTURE.md`](../../docs/NETFLIX_KILLADS_ARCHITECTURE.md). Building and sending
> test APKs: [`testing/NETFLIX_TEST_APK_BUILD.md`](../../testing/NETFLIX_TEST_APK_BUILD.md).

## Status in one line (2026-10-11)

Household suppression is **fixed and device-verified** (it is a scheduling problem: the heap sweeps must land before the
profile select). The main **ad kill is unverified** (`getAdMetadata` source not found in the last device log). The
**eval (pre-compile) hook** works mechanically but patches nothing, because `loadScript` hands `eval` a `Uint8Array`.

## Files

| File | What it is | Status |
|---|---|---|
| [`EVALHOOK_2026-10.md`](EVALHOOK_2026-10.md) | running log of the 2026-10 work: diagnosis, scheduling findings, ad re-anchor, killlog5-9 | **current**; later sections correct earlier ones |
| [`LOADHOOK_PLAN.md`](LOADHOOK_PLAN.md) | 2026-08 plan for a pre-compile load-hook; engine is **V8 (not Hermes)**, eval entrypoint found | historical; the plan's "Hermes" framing is wrong |
| [`ABI_DECODE_2026-09-15.md`](ABI_DECODE_2026-09-15.md) | `FunctionCallbackInfo`/String layout decode, live proof of the `+12` String read, eval prologue `0x137626c` | §7, §10 hold; **§8/§9 (code-cache theory) were retracted by §10** |
| [`test_evalhook.js`](test_evalhook.js) | host test (83 checks) with a mocked Frida API over a Buffer | **current**; run it on the exact shipped script |
| [`enum_bridge.py`](enum_bridge.py), [`gibbon2bridge-methods.txt`](gibbon2bridge-methods.txt) | static enumeration of `Gibbon2Bridge` natives: `eval` is the only compile entry (no `loadScript`/`compile`/`run`) | reusable |
| [`logs/`](logs/README.md) | the nine redacted `KILL` captures (killlog1-9) behind the handoff, with what each shows and what was redacted | evidence; do not edit |
| [`lolomo_probe.js`](lolomo_probe.js) | read-only recon for Nikflix #131 (`CLCSInterstitialLolomo`); never bundled | no result recorded |

Run the host test: `node test_evalhook.js ../../patches/src/main/resources/netflix/native/killads.js`
(optional 2nd argument: a slice of the real `libnetflix.so` bootstrap JS).

## Lessons that cost the most to learn

1. **One Frida JS thread.** Sweeps, timers and any hook `onEnter` on Netflix's thread share one lock. Use async
   `Memory.scan` (2 in flight), never `scanSync` in a persistent loop, and never do real work inside the eval callback.
2. **Order matters more than speed.** Household must land first; the ad-kill (started at launch) pushed every household
   layer ~10 s later and brought the prompt back at profile select. Fair-share the pool *after* both are queued.
3. **Count your jobs.** A sweep is 191 range jobs (not ~510); `RANGESTAT` and `RANGEHIT` tell you, so log them before
   reasoning about backlog arithmetic.
4. **Test the real interaction, not the unit.** The ADV2 × MASTER2 `undefined` bug passed a host test that fed the
   function a state the device never produces.
5. **A log line "labels broken at +7.8 s" says nothing about the other layers.** Check all of `clcs/hh/route2/mhu` in
   `HHSTATUS` at the moment the prompt appears.
6. **"One ad at the start" is not evidence.** Netflix's ad tier plays a pre-roll anyway; check that the patch actually
   landed (`PATCH ADK MASTER`) before crediting it.
7. **Download-time source is not static.** The server re-minifies; the same session can see different shapes and even a
   missing source (killlog8 vs killlog9).
8. Keep the working APK. It is the only way to build test APKs without the base APKM (see the testing doc).
