# Design notes

Why the lab is built the way it is, what is faithful to CVE-2018-12533, and what is a
simplification. Read this if you want to understand the choices rather than just run the steps.

---

## The vulnerability

CVE-2018-12533 is **EL injection**, not a deserialization gadget chain in the usual sense.
RichFaces' `Paint2DResource` carries component state in the resource URL. That state is a Java
serialized object graph containing a `MethodExpression`. When the resource is painted, the
runtime evaluates the expression's EL string — and that string came from the client, in a URL,
with no integrity check.

The deserialization is how the expression is *delivered*. The code execution is the EL
evaluation. Confusing the two leads to the wrong mental model, and to mitigations (allow-list
serialization filters) that address delivery but not the actual root cause: an expression string
being evaluated without provenance.

So the lab reproduces both halves, because both are needed for the exploit to work.

**Disclosure record.** CVE-2018-12533 / GHSA-4j38-wjhf-884r, also tracked as JBoss RF-14310 and
Red Hat Bugzilla 1584490. Affected: `org.richfaces:richfaces-core` **3.1.0 through 3.3.4**,
CWE-94, CVSS 3.1 9.8. The GitHub advisory lists `patched_versions: None` — there is no fixed
upstream release in the advisories. Red Hat shipped fixes downstream in JBoss EAP 5 as
`richfaces-*.SP3_patch_02` builds (RHSA-2018:2663 / RHSA-2018:2664). There is no "fixed in 4.7.4":
`org.richfaces:richfaces-all:4.7.4` does not exist on Maven Central, and the 4.x line is outside
the affected range. If you are remediating, check the JBoss/EAP errata for your platform rather
than a version number.

---

## What is faithful

### The wire format is byte-compatible

`lab.rf.RichFactors` implements the remapped-base64 + zlib layer, and `poc/p2d.py` decodes it
with the original algorithm. A blob produced here decodes with the reference decoder, and the
patcher's byte expectations hold — including the `0x7A` `TC_BLOCKDATALONG` path for expressions
longer than 255 bytes.

The class names written into the stream are the real ones, so the annotated graph looks like the
genuine article:

```
org.richfaces.renderkit.html.Paint2DResource$ImageData
javax.faces.component.StateHolderSaver
org.richfaces.component.tag.TagMethodExpression
com.sun.faces.el.MethodExpressionImpl
```

### The gadget graph matches the report

Same shape, same two EL sites in the same two holders, same serialized expression string in both.
`tools/inspect_blob.py` resolves it end to end.

### The EL engine is a stock EL 3.0

`javax.el` from Tomcat's `el-api.jar` / `jasper-el.jar`, with a resolver chain equivalent to
JSF's: implicit objects, `MapELResolver`, `BeanELResolver`, `StaticFieldELResolver`. Method
invocation, map property access, and `getClass()` reachability all behave as they did in the
RichFaces 3.3.3 / JSF 1.2 era.

Using EL 3.0 rather than EL 4.0 was deliberate: EL 4.0 tightened several resolver behaviours
that this chain depends on.

### The expression string is fixed

`FlagService.DEFAULT_EL` is always `#{userLoginController.paintCaptcha}`, never randomised.
The patcher searches for that exact text, so it must be byte-stable across requests. This is
also what makes the PoC deterministic.

### Two distinct `String` instances

`TagMethodExpression` gives its delegate a fresh `String`:

```java
this.me = new MethodExpressionImpl(new String(attr));
```

This is not cosmetic. `ObjectOutputStream` writes each object once and emits a back-reference for
later occurrences of the same instance. Sharing one `String` would collapse both EL sites into a
single copy in the stream, and the PoC — which requires exactly two sites — would reject the
blob. Real RichFaces builds these two expressions from separately parsed strings, so the genuine
resource stream does carry the EL twice.

This was the single hardest detail to get right; it is easy to mistake for a parser bug.

### The sink order is preserved

EL runs while the image is painted, and headers set from EL are flushed before the image body is
committed. That is what makes header-based exfiltration possible on an `image/jpeg` response, and
it is the property the whole exploit depends on.

---

## Environment details that matter

### `--add-opens java.base/java.lang=ALL-UNNAMED` — supplied by Tomcat, not by us

This is the one that is easy to get wrong twice, so it is worth writing down carefully.

**The underlying fact.** On JDK 9+ `java.lang.ProcessImpl` is package-private, so SpEL's
reflective call to `getInputStream()` fails on a plain JVM:

```
InaccessibleObjectException: Unable to make public java.io.InputStream
java.lang.ProcessImpl.getInputStream() accessible: module java.base does not "opens java.lang"
```

In 2018 the target ran on a JDK 6/7/8 with no module system, so `setAccessible` succeeded and the
chain worked. The `--add-opens` flag restores that behaviour.

**Why the lab does not set it.** Because Tomcat already does. `bin/catalina.sh` contains:

```sh
JDK_JAVA_OPTIONS="$JDK_JAVA_OPTIONS --add-opens=java.base/java.lang=ALL-UNNAMED"
JDK_JAVA_OPTIONS="$JDK_JAVA_OPTIONS --add-opens=java.base/java.lang.invoke=ALL-UNNAMED"
JDK_JAVA_OPTIONS="$JDK_JAVA_OPTIONS --add-opens=java.base/java.lang.reflect=ALL-UNNAMED"
JDK_JAVA_OPTIONS="$JDK_JAVA_OPTIONS --add-opens=java.base/java.io=ALL-UNNAMED"
JDK_JAVA_OPTIONS="$JDK_JAVA_OPTIONS --add-opens=java.base/java.util=ALL-UNNAMED"
JDK_JAVA_OPTIONS="$JDK_JAVA_OPTIONS --add-opens=java.base/java.util.concurrent=ALL-UNNAMED"
JDK_JAVA_OPTIONS="$JDK_JAVA_OPTIONS --add-opens=java.rmi/sun.rmi.transport=ALL-UNNAMED"
```

`JDK_JAVA_OPTIONS` is read by the JVM itself at startup, so those take effect with no cooperation
from the Dockerfile. Confirm it in a running container:

```bash
docker exec paint2d-lab sh -c 'tr "\0" "\n" < /proc/1/environ | grep JDK_JAVA_OPTIONS'
```

**The trap.** An earlier draft of this lab *did* put `--add-opens` in `CATALINA_OPTS`, and this
document then claimed the flag was mandatory and that the lab was unexploitable without it. That
claim was derived from a standalone `java -cp ...` harness, not from the lab, and it was wrong:
removing the flag from the Dockerfile changed nothing, and `tools/verify.sh` still passed
18/18. The lesson is that the symptom reproduces outside Tomcat and the fix is already in place
inside it.

If you ever do need the flag — a bare JVM harness, or a container whose base image ships a
`catalina.sh` predating that block — it surfaces as an `X-Lab-ElError` header, which makes it easy
to diagnose:

```bash
python3 poc/p2d.py whoami
# [!] no X-Out header (EL error: ELException: ...InaccessibleObjectException...)
```

### SpEL in the shared class realm

`paint2d-lab` stages `spring-expression`, `spring-core`, and `spring-jcl` into
`$CATALINA_HOME/lib`, not just `WEB-INF/lib`.

JSF loads application libraries and the EL engine from the same realm. Tomcat does not: the EL
engine lives in the common loader, application jars load in an isolated webapp loader, and the
EL engine's `forName` cannot see `WEB-INF/lib`. Symptom before the fix:

```
java.lang.ClassNotFoundException: org.springframework.expression.spel.standard.SpelExpressionParser
```

even though the jar is present in the WAR.

Two details in `Paint2DResourceServlet`:

- the context classloader is pinned to the webapp loader around the EL evaluation, so reflective
  lookups resolve consistently regardless of which thread Tomcat dispatches onto;
- the session scope map is a plain mutable `HashMap` in `HttpSession`, because the chain stores
  arbitrary objects in it across requests. JSF scopes are richer; this is what the chain needs.

### `labuser`, uid 1003

The original target ran as an unprivileged account with uid 1003. Matching that means `id`
reads `uid=1003(labuser)`, which makes the lab feel like the real thing and confirms you are
executing in the service account rather than as root.

### An unfiltered `ObjectInputStream`

Deliberate, and commented as such. A deserialization filter would block the exploit and destroy
the lab's purpose. This is the part to fix in a real system — and it is not sufficient on its
own, for the reason in the first section.

---

## What is simplified

Honest accounting of the gaps:

| Aspect | Lab | Reality |
|---|---|---|
| Framework | Plain servlets reproducing the JSF pipeline | A real JSF + RichFaces stack |
| Rendering | The EL result is ignored; a captcha JPEG is painted regardless | A real renderer would draw what the expression returns |
| `StateHolderSaver` | Two fields, no JSF `StateHolder` contract | Full `javax.faces` state API |
| FacesContext | Only the surface the PoC touches | The whole JSF context and its scopes |
| EL chain | `Runtime.exec(String)` | Same — no shell is involved either way |
| Concurrency | Single shared session map per session | Same as the PoC needs |

The renderer simplification is worth calling out: in a real deployment the expression's return
value usually becomes the image content, so a successful injection can also alter what is rendered.
The lab ignores the return value and only keeps the side effects, which is the smallest change
that still demonstrates the vulnerability.

### Why not a real RichFaces 3.3.3 + Mojarra stack

It was considered first and rejected:

- `org.richfaces:richfaces-all:3.3.3` is not on Maven Central (404); it lives in JBoss repositories
  whose availability is not something a public lab should depend on.
- Pinning a JSF 1.2-era stack means pinning an EOL JDK, an EOL Tomcat, and a Mojarra build that
  no longer publishes cleanly, all in a container people are expected to be able to build.
- The end result would be less legible. The interesting content is the chain from blob to command
  execution — six steps in `docs/WALKTHROUGH.md` (steps 0–5), eight server-side operations in
  `docs/WIRE-FORMAT.md` §6 — and all of it is present here with no framework noise around it.

The trade-off is fidelity of the *stack* versus fidelity of the *exploit*. This lab keeps the
exploit exact and the stack minimal.

---

## The CTF layer

`lab.web.FlagService` classifies each request by the primitive it *executes*, then awards the
matching flag. It reads state; it never changes it. The vulnerability is fully present with the
scoring layer removed.

Three details make the scoring honest rather than decorative.

**1. Classify before the EL runs.** `Paint2DResourceServlet` calls `observe()` *before*
`el.evaluate()`. The chain spans three requests and the session accumulates, so classifying
afterwards would find the freshly stored expression already in the session — and then credit the
request that merely called `parseExpression` with having executed it. `parseExpression("1+1")`
runs nothing, and it must not earn an RCE flag. `tools/verify.sh` asserts this as a regression
test.

**2. Blank out string literals before matching.** The SpEL payload travels as an EL string
literal, so the file-read or command text is *quoted*, not executed, by the request that stores
it. Without stripping literals, "this request plans to read a file" is indistinguishable from
"this request read a file":

```java
String body = stripStringLiterals(expression);   // literals blanked, offsets preserved
```

**3. Judge the stored expression, not the request.** A parsed SpEL object exposes
`getExpressionString()`, so the request that only *evaluates* it can be judged by what it ran:

```java
if (evaluates && stored != null) {
    if (mentions(stored, "FileInputStream", "FileReader", "Files.", "Scanner")) level = "4";
    else if (mentions(stored, "Runtime", "ProcessBuilder", "exec("))              level = "3";
    else                                                                      level = "2";  // e.g. "1+1"
}
```

That last `else` is what keeps "RCE confirmed" meaningful: evaluating a harmless expression still
proves you reached the interpreter, but not that you ran a process.

---

## Reproducing the original research PoC

`poc/p2d.py` keeps the original algorithm — same RichFactors decode, same `patch_el`, same
three-step chain. It differs from the research PoC in five deliberate ways:

| Change | Why |
|---|---|
| default target `http://127.0.0.1:8080` | the lab, not a production host |
| `X-Lab-Research` instead of `X-HackerOne-Research` | the HackerOne program header is a disclosure-policy artifact, not part of the vulnerability |
| `--delay` default `5.0` → `0.0` | the 5s pacing existed to dodge the F5 bot protection in front of the real target; a local lab has no such filter |
| `--header` mode | pure-EL header write, as a rung that does not need SpEL |
| `--allow-remote` guard | refuses non-loopback targets unless explicitly overridden |

Note there is no "session header" difference: the original already tracked `JSESSIONID`, and so
does this one.

The original script still runs against the lab unmodified apart from `-t`:

```bash
python3 p2d.py -t http://localhost:8080 whoami
```

---

## Extending it

Ideas that build on this lab:

- **Detection.** Add logging around deserialization and EL evaluation; the observable signals are
  listed at the end of `docs/WALKTHROUGH.md`.
- **A hardened variant.** Add a deserialization filter, sign the blob, or reject expressions that
  are not in an allow-list, and watch each approach fail for a different reason. This makes a
  good teaching exercise: a filter blocks delivery but not the missing provenance check.
- **A second sink.** The same `ElEngine` would evaluate an expression arriving over WebSocket or
  in a JSON field; the primitive is identical.
- **Spoofing the account.** Change the Dockerfile's uid to see how much of the impact narrative
  depends on the specific service-account identity.
