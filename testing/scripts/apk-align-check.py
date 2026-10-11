#!/usr/bin/env python3
"""Check that every STORED native library in an APK starts on a 4096-byte boundary (required when the app
runs with extractNativeLibs=false). Exit code 1 if any is misaligned.

    apk-align-check.py <file.apk>          (run with python3 -I)
"""
import struct, sys, zipfile

def main(path):
    z, f, bad = zipfile.ZipFile(path), open(path, 'rb'), 0
    for i in z.infolist():
        f.seek(i.header_offset)
        n, e = struct.unpack('<HH', f.read(30)[26:30])
        data = i.header_offset + 30 + n + e
        if i.compress_type == 0 and i.filename.endswith('.so'):
            ok = data % 4096 == 0
            bad += not ok
            print('%-52s data@%-10d %s' % (i.filename, data, 'OK' if ok else 'MISALIGNED'))
    print('misaligned .so:', bad)
    sys.exit(1 if bad else 0)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
