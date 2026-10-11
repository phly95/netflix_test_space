#!/usr/bin/env python3
"""Redact a device capture of the Netflix `KILL` logcat tag before it is committed or shared.

    redact-killlog.py <in.txt> <out.txt>       redact, print per-rule counts, then run the residual check
    redact-killlog.py --check <file>...        residual check only (exit 1 if anything personal is left)

The logs are mostly our own lines. The exception is the HHDIAG/ADDIAG dumps, which print a window of the app's heap
around a marker, so they can carry telemetry and network fragments. Rules (applied in this order):

  heap    raw heap bytes that trail the telemetry envelope ("...clientSendTime":N}<bytes>")   -> <N chars of heap bytes elided>
  locale  the value of "acceptLanguage"                                                       -> <locale>
  ids     telemetry "id" / "time" / "clientSendTime" numbers with >= 10 digits               -> <redacted>
  msl     base64 after the MSL prefix eyJjaXBoZXJ0ZXh0Ijoi (= '{"ciphertext":"')             -> <ciphertext-redacted>

Everything else (memory addresses, process ids, the app's minified identifiers, our own PATCH/HHSTATUS lines) is
kept: it is what the analysis needs. Run with `python3 -I`. Review the output once by eye for a new kind of dump.
"""
import re, sys

HEAP = re.compile(r'(\\"clientSendTime\\":\d+\})(.*)(")\s*$')
LOCALE = re.compile(r'(\\?"acceptLanguage\\?":\\?")[^"\\]*')
IDS = re.compile(r'((?:\\")?(?:id|time|clientSendTime)\\":)\d{10,}')   # the opening quote may be cut off by the dump window
MSL = re.compile(r'(eyJjaXBoZXJ0ZXh0Ijoi)[A-Za-z0-9+/_=\-]+')

RESIDUAL = {
    'email': re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+'),
    'ipv4': re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])'),
    'mac': re.compile(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'),
    'uuid': re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'),
    'url': re.compile(r'https?://\S+'),
    'long number': re.compile(r'(?<![\w.])\d{10,}(?![\w.])'),
    'locale value': re.compile(r'acceptLanguage\\?":\\?"(?!<locale>)[^"\\]'),
    'msl ciphertext': re.compile(r'eyJjaXBoZXJ0ZXh0Ijoi(?!<ciphertext-redacted>)[A-Za-z0-9+/_=\-]'),
}

def redact(text):
    counts = dict.fromkeys(('heap', 'locale', 'ids', 'msl'), 0)
    out = []
    for line in text.split('\n'):
        if 'CompactConsolidatedLoggingEnvelope' in line:
            m = HEAP.search(line)
            if m:
                line = line[:m.start(2)] + '<%d chars of heap bytes elided>' % len(m.group(2)) + line[m.end(2):]
                counts['heap'] += 1
        line, n = LOCALE.subn(r'\1<locale>', line); counts['locale'] += n
        line, n = IDS.subn(r'\1<redacted>', line); counts['ids'] += n
        line, n = MSL.subn(r'\1<ciphertext-redacted>', line); counts['msl'] += n
        out.append(line)
    return '\n'.join(out), counts

def check(path):
    text, bad = open(path, encoding='utf-8', errors='replace').read(), 0
    for name, rx in RESIDUAL.items():
        hits = rx.findall(text)
        if hits:
            bad += len(hits)
            print('  RESIDUAL %-14s %d  e.g. %r' % (name, len(hits), hits[0][:60]))
    print('%s: %s' % (path, 'clean' if not bad else '%d residual hit(s)' % bad))
    return bad

if __name__ == '__main__':
    a = sys.argv[1:]
    if len(a) >= 2 and a[0] == '--check':
        sys.exit(1 if sum(check(p) for p in a[1:]) else 0)
    if len(a) != 2:
        sys.exit(__doc__)
    text, counts = redact(open(a[0], encoding='utf-8', errors='replace').read())
    open(a[1], 'w', encoding='utf-8', newline='').write(text)
    print('%s -> %s  %s' % (a[0], a[1], ' '.join('%s=%d' % kv for kv in counts.items())))
    sys.exit(1 if check(a[1]) else 0)
