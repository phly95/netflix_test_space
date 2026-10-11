#!/usr/bin/env python3
"""Per-layer landing times (seconds after launch) from one or more `adb logcat -s KILL:*` captures.

    killlog-timeline.py [label=]killlog5.txt [label=]killlog6.txt ...      (run with python3 -I)

t0 is the LAST `killads ready` line in each file (= the process that was analysed). Prints a markdown table.
Layers are the log lines documented in docs/NETFLIX_KILLADS_ARCHITECTURE.md. Each log must be read as data only.
"""
import re, sys

LAYERS = [
    ('dispatcher labels broken', r'PATCH CLCS\(fast\)'),
    ('HH flags (first)',         r'PATCH HH: flag:isActiveMisdetectionSession'),
    ('HH render gate (last)',    r'PATCH HH: render:netflixHouseholdAvailable'),
    ('MHU screens (first)',      r'PATCH MHU'),
    ('HH all flipped',           r'fastHH: all HH'),
    ('route 2 resident',         r'DIAG route2 anchor RESIDENT'),
    ('route 2 written',          r'PATCH CLCS\(route2\): wrote'),
    ('fastADK starts',           r'fastADK: starting'),
    ('ad-kill ADV',              r'PATCH ADK ADV'),
    ('ad-kill MASTER (if(0))',   r'PATCH ADK MASTER: getAdMetadata if'),
    ('ad-kill B (pause ad)',     r'PATCH ADK B'),
]

def ts(line):
    m = re.match(r'(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d\.\d+)', line)
    return int(m[3]) * 3600 + int(m[4]) * 60 + float(m[5]) if m else None

def analyse(path):
    lines = open(path, encoding='utf-8', errors='replace').read().splitlines()
    starts = [i for i, l in enumerate(lines) if 'killads ready' in l]
    if not starts:
        return None
    seg = lines[starts[-1]:]
    t0, res = ts(seg[0]), {}
    for name, pat in LAYERS:
        for l in seg:
            if re.search(pat, l):
                res[name] = ts(l) - t0
                break
    last = max((ts(l) for l in seg if ts(l)), default=t0)
    res['_len'] = last - t0
    res['_mhu'] = sum(1 for l in seg if 'PATCH MHU' in l)
    return res

def main(args):
    cols = []
    for a in args:
        label, _, path = a.rpartition('=')
        r = analyse(path)
        if r is None:
            print('# %s: no "killads ready" line, skipped' % path); continue
        cols.append((label or path.rsplit('/', 1)[-1], r))
    print('| layer | ' + ' | '.join(c[0] for c in cols) + ' |')
    print('|---|' + '---|' * len(cols))
    for name, _ in LAYERS:
        print('| %s | ' % name + ' | '.join(('%.1f' % c[1][name]) if name in c[1] else '-' for c in cols) + ' |')
    print('| MHU screens neutered | ' + ' | '.join(str(c[1]['_mhu']) for c in cols) + ' |')
    print('| log length (s) | ' + ' | '.join('%.0f' % c[1]['_len'] for c in cols) + ' |')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
