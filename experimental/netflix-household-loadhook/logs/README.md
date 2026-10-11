# Device logs (`adb logcat -s KILL:*`), 2026-10-11 - redacted

The nine captures behind [`../../../docs/NETFLIX_HOUSEHOLD_ADKILL_2026-10_HANDOFF.md`](../../../docs/NETFLIX_HOUSEHOLD_ADKILL_2026-10_HANDOFF.md).
Taken by the user on an Onn 4K running the cloned Netflix (`com.netflix.ninja.clone`, 13.0.1 build 25028) while testing
successive builds of `killads.js`. Timestamps are the device's clock (`adb logcat -v time`), month-day only. Lines are
otherwise **unedited**: the logs are lossy, so `�` (U+FFFD) and `\uXXXX` in the dump lines are real capture artefacts.

| File | Build | Window | What it shows |
|---|---|---|---|
| [`killlog1.txt`](killlog1.txt) | old synchronous scanners (v1.37.x style), 1 process shown | 01:13-01:17 | HH flags landing one per ~3 s; `MASTERw M2-MISS` dump (current `getAdMetadata` body); the first 6 lines belong to an earlier process |
| [`killlog2.txt`](killlog2.txt) | "F" (`10ddffa`-era) | 01:21-01:22 | dispatcher broken at +7.8 s, but HH flags never land and MHU screens trickle in from +37 s; `ADVw DUMP` (ad normaliser text) |
| [`killlog3.txt`](killlog3.txt) | between `10ddffa` and `10906f2` | 01:31-01:32 | one `fastHH` pass blocks the JS thread ~39 s |
| [`killlog4.txt`](killlog4.txt) | `10906f2` (async scans, no priorities) | 01:45-01:46 | 11,741 queued scan jobs barely moving; first `HHDIAG` dumps |
| [`killlog5.txt`](killlog5.txt) | **K / `a4ca56a`** (the last-good build) | 01:59-02:01 (109 s) | every household layer lands by +27 s; the 18 `HHDIAG` dumps of the real routing JS |
| [`killlog6.txt`](killlog6.txt) | M / `02fc47d` (+ `fastADK`) | 02:17-02:18 (43 s) | household layers ~10 s later; the ad-kill lands before them |
| [`killlog7.txt`](killlog7.txt) | O (inferred) / `673d10c` + hook flags | 02:27-02:29 | eval hook armed at +8 s; 186 evals, 0 edits |
| [`killlog8.txt`](killlog8.txt) | **P** / `af03dab` + hook on | 11:00-11:03 (168 s) | household fixed; ADV/MASTER/B landed yet ads leaked; 51-match dispatcher event at +43 s; `EVALSRC` lines |
| [`killlog9.txt`](killlog9.txt) | **Q** / `deb4e74` | 11:20-11:23 (183 s) | household fixed; **`MASTER` never landed**; `ADDIAG` finds ad vocabulary only in name tables |

(The `killlogN` numbering is the user's; killlog1's upload was just `killlog.txt`.) Builds A/B/C and any other lettered
build were not captured. Mapping of logs 1-4 to commits is inferred from commit messages.

## What was redacted, and how

By [`testing/scripts/redact-killlog.py`](../../../testing/scripts/redact-killlog.py), after scanning every log for
emails, IPv4, MAC, UUID, URLs, long numbers, locale and token keywords and reading every distinct word that is not
already in the repo (all were Netflix minified identifiers, memory addresses or JSON escapes):

| Rule | Where it fired | Replaced with |
|---|---|---|
| `acceptLanguage` value (region hint) | killlog5 ×1 | `<locale>` |
| telemetry `id` / `time` / `clientSendTime` (event ids, epoch ms) | killlog5 ×17 | `<redacted>` |
| raw heap bytes trailing the telemetry envelope | killlog5 ×2 (807 and 1,136 chars) | `<N chars of heap bytes elided>` |
| MSL `headerdata` ciphertext after the `eyJjaXBoZXJ0ZXh0Ijoi` (`{"ciphertext":"`) prefix | killlog8 ×16 (`EVALSRC` heads) | `<ciphertext-redacted>` |

Nothing fired in killlog1-4, 6, 7, 9; those are byte-identical to the originals. Kept deliberately because the analysis
needs them: memory addresses (ASLR, change every run), process ids, our own `PATCH`/`HHSTATUS` lines and the app's
minified identifiers. The final `--check` pass finds no email, IP, MAC, UUID, URL, 10+ digit number, locale value or
ciphertext. If you capture a new kind of dump, read it once by eye before committing it.

## Using them

```bash
python3 -I testing/scripts/killlog-timeline.py 5=killlog5.txt 8=killlog8.txt 9=killlog9.txt   # per-layer landing times
python3 -I testing/scripts/redact-killlog.py killlogN.txt killlogN.redacted.txt                # redact a new capture
python3 -I testing/scripts/redact-killlog.py --check killlog*.txt                              # residual check only
```
