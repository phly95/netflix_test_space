#!/usr/bin/env python3
"""Replace ONE entry in an APK and leave every other entry byte-identical.

    apk-swap-file.py <in.apk> <entry-name> <new-file> <out.apk>

Used to turn an already-patched Netflix APK into a new test build by swapping only the bundled Frida
script (lib/armeabi-v7a/libgadget.script.so) without needing the base APKM or the Morphe CLI.

What it does (and why):
  * raw-copies every other entry (no recompression) using the central directory's sizes/CRCs;
  * re-aligns STORED entries (4096 for *.so, 4 otherwise) with an 0xD935 padding extra, like `zipalign -p`;
  * DROPS directory entries and `stamp-cert-sha256`. apksig drops them when it signs, and doing it here keeps
    the offsets (and therefore the .so alignment) stable through signing;
  * discards the old APK Signing Block, so the output MUST be re-signed (ApkSign.java).
Run with `python3 -I`. No third-party modules.
"""
import struct, sys, zlib

def main(src, repl_name, repl_file, out):
    data = open(src, 'rb').read()
    i = data.rfind(b'PK\x05\x06')
    _, _, _, _, nent, cdsize, cdoff, _ = struct.unpack('<4s4H2LH', data[i:i + 22])
    if nent == 0xFFFF or cdoff == 0xFFFFFFFF:
        sys.exit('zip64 archives are not handled')
    recs, off = [], cdoff
    for _ in range(nent):
        f = struct.unpack('<4s6H3L5H2L', data[off:off + 46])
        assert f[0] == b'PK\x01\x02'
        (_, vmade, vneed, flags, method, mtime, mdate, crc, csize, usize,
         nlen, elen, clen, disk, iattr, eattr, lho) = f
        p = off + 46
        recs.append(dict(vmade=vmade, vneed=vneed, flags=flags, method=method, mtime=mtime, mdate=mdate,
                         crc=crc, csize=csize, usize=usize, name=data[p:p + nlen],
                         cextra=data[p + nlen:p + nlen + elen], cmt=data[p + nlen + elen:p + nlen + elen + clen],
                         disk=disk, iattr=iattr, eattr=eattr, lho=lho))
        off = p + nlen + elen + clen
    recs = [r for r in recs if not (r['name'].endswith(b'/') or r['name'] == b'stamp-cert-sha256')]
    nent = len(recs)
    new, hit, outb = open(repl_file, 'rb').read(), 0, bytearray()
    for r in sorted(recs, key=lambda r: r['lho']):
        l = struct.unpack('<4s5H3L2H', data[r['lho']:r['lho'] + 30])
        assert l[0] == b'PK\x03\x04'
        start = r['lho'] + 30 + l[9] + l[10]
        payload = data[start:start + r['csize']]
        if r['name'].decode() == repl_name:
            c = zlib.compressobj(9, zlib.DEFLATED, -15)
            payload = c.compress(new) + c.flush()
            r.update(method=8, vneed=20, crc=zlib.crc32(new) & 0xffffffff, csize=len(payload), usize=len(new))
            hit += 1
        align = 0
        if r['method'] == 0 and r['csize'] > 0:
            align = 4096 if r['name'].endswith(b'.so') else 4
        base, extra = len(outb) + 30 + len(r['name']), b''
        if align and base % align:
            pad = (-base) % align
            if pad < 4:
                pad += align
            extra = struct.pack('<HH', 0xD935, pad - 4) + b'\0' * (pad - 4)
        r['newoff'] = len(outb)
        outb += struct.pack('<4s5H3L2H', b'PK\x03\x04', r['vneed'], r['flags'] & ~8, r['method'], r['mtime'],
                            r['mdate'], r['crc'], r['csize'], r['usize'], len(r['name']), len(extra))
        outb += r['name'] + extra + payload
    if hit != 1:
        sys.exit('entry %r found %d times (expected exactly 1)' % (repl_name, hit))
    cd0 = len(outb)
    for r in recs:
        outb += struct.pack('<4s6H3L5H2L', b'PK\x01\x02', r['vmade'], r['vneed'], r['flags'] & ~8, r['method'],
                            r['mtime'], r['mdate'], r['crc'], r['csize'], r['usize'], len(r['name']),
                            len(r['cextra']), len(r['cmt']), r['disk'], r['iattr'], r['eattr'], r['newoff'])
        outb += r['name'] + r['cextra'] + r['cmt']
    outb += struct.pack('<4s4H2LH', b'PK\x05\x06', 0, 0, nent, nent, len(outb) - cd0, cd0, 0)
    open(out, 'wb').write(outb)
    print('wrote %s (%d bytes, %d entries)' % (out, len(outb), nent))

if __name__ == '__main__':
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    main(*sys.argv[1:5])
