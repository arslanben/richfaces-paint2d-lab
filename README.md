# RichFaces Paint2DResource — CVE-2018-12533 CTF lab

A self-contained, deliberately vulnerable lab that reproduces an **unauthenticated remote code
execution** chain end to end:

> RichFaces `Paint2DResource` deserializes attacker-controlled Java state from the captcha
> resource URL, then evaluates the `MethodExpression` EL found inside it while painting the
> image.

Everything the original research PoC needed is present: the RichFactors blob format, the two
serialized EL sites, `TC_BLOCKDATA` length-framing, SpEL on the classpath, and a service account
at **uid 1003** so `id` output looks familiar.

**The lab's own `poc/p2d.py` is algorithmically identical to the research PoC**, and the research
PoC runs against it unmodified — only the `-t` target changes.

---

## Quick start

```bash
# build and run
docker compose up -d --build --force-recreate

# confirm it is alive
curl -s http://localhost:8080/ETOPUPGUI/lab/health
# {"status":"ok","vulnerable":"CVE-2018-12533"}
```

Then, from the repository root:

```bash
python3 poc/p2d.py whoami          # labuser
python3 poc/p2d.py id              # uid=1003(labuser) gid=1003(labuser) groups=1003(labuser)
python3 poc/p2d.py hostname
python3 poc/p2d.py --header --value one        # EL injection without SpEL
python3 poc/p2d.py --show-flags whoami          # prints the flag for the technique used
```

No Python packages are required — the PoC is stdlib only.

> **`--force-recreate` is not optional.** `docker compose up -d --build` will build a new image
> and then leave the *already-running* container alone. Compose decides whether to recreate a
> container by comparing the **service definition** — and that definition still says
> `image: paint2d-lab:latest`, a string that did not change — not by resolving the tag to a new
> image ID. So you end up with `paint2d-lab:latest` pointing at your fix while the running lab
> keeps serving the old code, which looks exactly like "my fix had no effect". Measured on this
> project: after a rebuild the tag moved to a different image ID, the running container's image
> ID stayed behind, and Compose reported nothing to do. If you are iterating on `lab/src`, always
> use `--force-recreate`. Check what is actually running:
>
> ```bash
> docker inspect paint2d-lab --format '{{.Image}}'        # the container's image
> docker images --no-trunc -q paint2d-lab:latest         # the image the tag points at
> ```
>
> If those disagree, the running lab is stale. `tools/verify.sh` warns when they do.

To stop:

```bash
docker compose down
```

---

## What you are attacking

`GET /ETOPUPGUI/pages/login.jsf` returns a login page whose captcha `<img src=...>` carries a
RichFactors blob:

```
/ETOPUPGUI/a4j/s/3_3_3.Finalorg.richfaces.renderkit.html.Paint2DResource/DATA/<blob>.jsf
```

When you request that URL back, the server:

1. decodes the blob (remapped base64 → zlib inflate),
2. Java-deserializes it **with no integrity check**,
3. walks the restored state down to a `MethodExpression`,
4. **evaluates whatever EL string it finds**, and
5. paints the captcha JPEG, flushing any response headers the EL set.

**Step 4 is the vulnerability.** The code execution is the EL evaluation; deserialization is only
how the expression is delivered. The missing integrity check in step 2 is what makes it
reachable — an allow-list deserialization filter would block delivery without addressing the root
cause. See [`docs/DESIGN-NOTES.md`](docs/DESIGN-NOTES.md) for that distinction.

### Gadget chain in the stream

```
Paint2DResource$ImageData
  └─ StateHolderSaver
       └─ { "value": TagMethodExpression      ← EL site 1  (attr)
              └─ MethodExpressionImpl          ← EL site 2  (expr)
```

Both expression holders are serialized with the same text,
`#{userLoginController.paintCaptcha}`, each as a raw-UTF `TC_BLOCKDATA` segment. That is why the
PoC insists on finding **exactly two** sites and rewrites both, fixing the segment length
prefixes as it goes.

---

## The technique ladder

Each rung is worth a flag. `GET /ETOPUPGUI/lab/flags` lists them, and
`tools/inspect_blob.py` prints the stream structure for you.

| # | Technique | Flag |
|---|---|---|
| 1 | Decode the blob, patch both EL sites, write an arbitrary response header | `flag{el-injection}` |
| 2 | Put a `SpelExpressionParser` into the session scope from EL | `flag{spel-bootstrap}` |
| 3 | Parse and evaluate a SpEL expression → command execution | `flag{rce-confirmed}` |
| 4 | Use the same primitive to read a file | `flag{rce-file-read}` |

Full step-by-step walkthrough with the exact requests:
[`docs/WALKTHROUGH.md`](docs/WALKTHROUGH.md).

---

## Tools

| Tool | Purpose |
|---|---|
| `poc/p2d.py` | The exploit. `--header` for pure EL injection, otherwise runs a command. `--show-flags` prints the CTF flag for the technique it just used. |
| `tools/inspect_blob.py` | Decodes a blob and annotates the object graph and both EL sites. |
| `tools/check_blob.py` | Asserts the blob invariants the PoC depends on. |
| `tools/verify.sh` | End-to-end check of the whole lab against a running container. |

```bash
# what does the server actually send?
BLOB=$(curl -s http://localhost:8080/ETOPUPGUI/pages/login.jsf \
       | grep -o 'Paint2DResource/DATA/[^"]*' | head -1 \
       | sed 's#.*/DATA/##; s#\.jsf$##')
python3 tools/inspect_blob.py "$BLOB"
```

---

## Verification

```bash
./tools/verify.sh http://localhost:8080
```

Checks lab availability, the context-path links on the hint page, blob structure, unauthenticated
command execution as `labuser`, the one-shot EL injection, the full CTF flag ladder, and that a
bare `parseExpression` is *not* credited as RCE. It also warns if the running container is on a
different image than `paint2d-lab:latest`.

---

## Repository layout

```
lab/                      the vulnerable application
  Dockerfile              multi-stage: Maven build -> Tomcat 9 runtime
  pom.xml
  src/main/java/
    lab/rf/RichFactors    the remapped-base64 + zlib codec
    lab/faces/            EL engine and the FacesContext facade
    lab/web/              servlets (login, Paint2DResource sink, lab info)
    org/richfaces/...     stand-ins for the RichFaces classes named in the stream
    javax/faces/...       stand-in for javax.faces.component.StateHolderSaver
    com/sun/faces/...     stand-in for com.sun.faces.el.MethodExpressionImpl
  src/main/webapp/WEB-INF/web.xml
poc/p2d.py                the exploit
tools/                    inspect_blob.py, check_blob.py, verify.sh
docs/                     WALKTHROUGH, WIRE-FORMAT, DESIGN-NOTES
```

---

## Notes on fidelity

These environment details are reproduced deliberately; see
[`docs/DESIGN-NOTES.md`](docs/DESIGN-NOTES.md) for the full rationale.

- **Service account `labuser`, uid 1003** — matches the account id in the original disclosure,
  so `id` reads `uid=1003(labuser)`.
- **No `--add-opens` in the Dockerfile** — worth knowing why, because it is easy to add one here
  for the wrong reason. On JDK 9+ `java.lang.ProcessImpl` is package-private, so
  `Runtime.exec().getInputStream()` throws `InaccessibleObjectException` when SpEL calls it
  reflectively; the 2018-era JDK had no module system, so the original chain just worked. It is
  tempting to add `--add-opens java.base/java.lang=ALL-UNNAMED` to "fix" that — but Tomcat's own
  `bin/catalina.sh` already puts exactly that flag (and six more) into `JDK_JAVA_OPTIONS`, which
  the JVM consumes automatically. The lab sets nothing, and `tools/verify.sh` passes with the flag
  absent. You would only hit `InaccessibleObjectException` running a bare `java -cp ...` outside
  Tomcat.
- **SpEL in the shared class realm** — `spring-expression` is placed in `$CATALINA_HOME/lib`
  next to the EL engine, because JSF loads application libraries and the EL engine from the same
  realm. Under Tomcat's default isolation, EL-driven `forName` lookups cannot see `WEB-INF/lib`
  jars at all.
- **`ObjectInputStream` with no filter** — the original deserialized client state without
  validation, and reproducing that is the point.
- **Deployed as `ETOPUPGUI.war`** — the context path is `/ETOPUPGUI` because the original PoC
  hardcodes it. The Dockerfile healthcheck and the hint page must carry that prefix too.

---

## Safety

This lab is **intentionally vulnerable**.

- Do not deploy it on any reachable network.
- Do not point it at, or use it to test, any system you do not own or have written permission
  to test.
- `poc/p2d.py` refuses non-loopback targets unless you pass `--allow-remote`.
- The container runs as an unprivileged user and binds only port 8080.

## Scope

CVE-2018-12533 (GHSA-4j38-wjhf-884r) affects `org.richfaces:richfaces-core` **3.1.0 through
3.3.4**, CWE-94, CVSS 3.1 9.8. The published advisories list **no patched upstream version**;
Red Hat shipped fixes downstream in JBoss EAP 5 (RHSA-2018:2663 / RHSA-2018:2664) as
`richfaces-*.SP3_patch_02` builds. The technique is historical and is reproduced here for
defensive study, detection engineering, and training.

## License

MIT. See [LICENSE](LICENSE).
