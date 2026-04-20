#!/usr/bin/env bash
set -euo pipefail

SUITE_URL="${SUITE_URL:-https://localhost:8443}"
IDENTITY_HEALTH="${IDENTITY_HEALTH:-http://localhost:5150/health}"
TIMEOUT="${TIMEOUT:-120}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Helpers ──────────────────────────────────────────────────────────────────

log()  { echo "[$(date +%H:%M:%S)] $*"; }
fail() { echo "[ERROR] $*" >&2; exit 1; }

wait_for() {
  local url="$1" label="$2" elapsed=0
  log "Waiting for $label at $url..."
  while ! curl -sf --max-time 3 -k "$url" > /dev/null 2>&1; do
    sleep 2
    elapsed=$((elapsed + 2))
    if [[ $elapsed -ge $TIMEOUT ]]; then
      fail "$label did not become ready within ${TIMEOUT}s"
    fi
  done
  log "$label is ready."
}

api() {
  curl -sf -k "$@"
}

# ── Drive a single browser interaction (login flow) ───────────────────────────
# Given an AUTH_URL, performs the full OIDC login flow via curl,
# ending with delivering the authorization code to the conformance callback.
drive_browser() {
  local AUTH_URL="$1"
  local PERSISTENT_COOKIE="${2:-}"  # optional persistent cookie file for multi-round tests
  local COOKIE_FILE
  if [ -n "$PERSISTENT_COOKIE" ]; then
    COOKIE_FILE="$PERSISTENT_COOKIE"
  else
    COOKIE_FILE=$(mktemp /tmp/rt_cookies_XXXXXX)
  fi

  log "    [browser] Driving auth URL: ${AUTH_URL:0:200}..."

  # Step 1: GET authorize → may go to login page OR directly to callback
  local STEP1_URL
  STEP1_URL=$(curl -sk -c "$COOKIE_FILE" -b "$COOKIE_FILE" \
    -L --max-redirs 10 \
    -w '%{url_effective}' \
    -o /tmp/rt_login.html \
    "$AUTH_URL")
  log "    [browser] Step1 landed at: ${STEP1_URL:0:200}"

  # Check if we landed directly on the consent page (existing session, login_hint matched, etc.)
  if echo "$STEP1_URL" | grep -q 'authorize/consent'; then
    log "    [browser] Auth redirected directly to consent page: ${STEP1_URL:0:200}"
    local CSRF3c LOGIN_ID3c
    CSRF3c=$(grep -o 'name="csrf_token" value="[^"]*"' /tmp/rt_login.html | sed 's/.*value="\([^"]*\)".*/\1/' | head -1)
    LOGIN_ID3c=$(grep -o 'name="login_id" value="[^"]*"' /tmp/rt_login.html | sed 's/.*value="\([^"]*\)".*/\1/' | head -1)
    log "    [browser] Consent login_id=$LOGIN_ID3c csrf=${CSRF3c:0:20}..."
    log "    [browser] Consent page snippet: $(grep -o 'login_id[^<]*' /tmp/rt_login.html | head -3)"
    local REDIR6c CONSENT_HTTP_CODE
    CONSENT_HTTP_CODE=$(curl -sk -c "$COOKIE_FILE" -b "$COOKIE_FILE" \
      -X POST "http://localhost:5150/oauth2/authorize/consent" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      --data-urlencode "login_id=$LOGIN_ID3c" \
      --data-urlencode "csrf_token=$CSRF3c" \
      --data-urlencode "decision=approve" \
      -D /tmp/rt_consent_hdr.txt \
      -o /tmp/rt_consent_resp.html \
      -w '%{http_code}')
    log "    [browser] Consent POST HTTP code: $CONSENT_HTTP_CODE"
    REDIR6c=$(grep -i '^location:' /tmp/rt_consent_hdr.txt 2>/dev/null | tr -d '\r\n' | sed 's/^[Ll]ocation: //')
    log "    [browser] Consent redirect: ${REDIR6c:0:200}"
    if [ -z "$REDIR6c" ]; then
      log "    [browser] ERROR: No redirect after direct consent POST"
      [ -z "$PERSISTENT_COOKIE" ] && rm -f "$COOKIE_FILE" 2>/dev/null || true
      rm -f /tmp/rt_*.html /tmp/rt_*_hdr.txt 2>/dev/null || true
      return 1
    fi
    local CODE7c
    CODE7c=$(curl -sk -c "$COOKIE_FILE" -b "$COOKIE_FILE" \
      -L --max-redirs 5 \
      -w '%{http_code}' \
      -o /tmp/rt_callback.html \
      "$REDIR6c" 2>/dev/null || echo "000")
    log "    [browser] Callback delivered, HTTP code: $CODE7c"
    local IMPLICIT_URL_C
    IMPLICIT_URL_C=$(python3 -c "
import re, sys
try:
    content = open('/tmp/rt_callback.html').read().replace('\\\/', '/')
    m = re.search(r'(https://[^\"]+/implicit/[^\"]+)', content)
    print(m.group(1) if m else '')
except: print('')
" 2>/dev/null || echo "")
    if [ -n "$IMPLICIT_URL_C" ]; then
      log "    [browser] Posting empty fragment to implicit URL: ${IMPLICIT_URL_C:0:80}..."
      curl -sk -X POST -H "Content-type: text/plain" -d "" -w '%{http_code}' -o /dev/null "$IMPLICIT_URL_C" > /dev/null 2>&1 || true
    fi
    [ -z "$PERSISTENT_COOKIE" ] && rm -f "$COOKIE_FILE" 2>/dev/null || true
    rm -f /tmp/rt_*.html /tmp/rt_*_hdr.txt 2>/dev/null || true
    return 0
  fi

  # Check if we landed on the callback URL (prompt=none error, auto-approve, etc.)
  if echo "$STEP1_URL" | grep -q 'test/a/identity/callback'; then
    log "    [browser] Auth redirected directly to callback: ${STEP1_URL:0:100}"
    # Deliver the callback response + post implicit URL
    local CODE7
    CODE7=$(curl -sk -c "$COOKIE_FILE" -b "$COOKIE_FILE" \
      -L --max-redirs 5 \
      -w '%{http_code}' \
      -o /tmp/rt_callback.html \
      "$STEP1_URL" 2>/dev/null || echo "000")
    log "    [browser] Callback delivered, HTTP code: $CODE7"
    local IMPLICIT_URL
    IMPLICIT_URL=$(python3 -c "
import re, sys
try:
    content = open('/tmp/rt_callback.html').read().replace('\\\/', '/')
    m = re.search(r'(https://[^\"]+/implicit/[^\"]+)', content)
    print(m.group(1) if m else '')
except: print('')
" 2>/dev/null || echo "")
    if [ -n "$IMPLICIT_URL" ]; then
      log "    [browser] Posting empty fragment to implicit URL: ${IMPLICIT_URL:0:80}..."
      curl -sk -X POST \
        -H "Content-type: text/plain" \
        -d "" \
        -w '%{http_code}' \
        -o /dev/null \
        "$IMPLICIT_URL" > /dev/null 2>&1 || true
    fi
    [ -z "$PERSISTENT_COOKIE" ] && rm -f "$COOKIE_FILE" 2>/dev/null || true
    rm -f /tmp/rt_*.html /tmp/rt_*_hdr.txt 2>/dev/null || true
    return 0
  fi

  local LOGIN_ID CSRF1
  LOGIN_ID=$(echo "$STEP1_URL" | sed 's/.*login_id=\([^&]*\).*/\1/')
  CSRF1=$(grep -o 'name="csrf_token" value="[^"]*"' /tmp/rt_login.html | sed 's/.*value="\([^"]*\)".*/\1/' | head -1)
  if [ -z "$LOGIN_ID" ] || [ -z "$CSRF1" ]; then
    log "    [browser] ERROR: Could not extract login_id or csrf_token from login page"
    [ -z "$PERSISTENT_COOKIE" ] && rm -f "$COOKIE_FILE" 2>/dev/null || true
    rm -f /tmp/rt_*.html /tmp/rt_*_hdr.txt 2>/dev/null || true
    return 1
  fi

  # Step 2: POST identifier
  local REDIR2
  curl -sk -c "$COOKIE_FILE" -b "$COOKIE_FILE" \
    -X POST "http://localhost:5150/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "identifier=conformance-test@example.com" \
    --data-urlencode "csrf_token=$CSRF1" \
    --data-urlencode "login_id=$LOGIN_ID" \
    -D /tmp/rt_id_hdr.txt \
    -o /tmp/rt_id.html \
    -w '%{http_code}' > /dev/null
  REDIR2=$(grep -i '^location:' /tmp/rt_id_hdr.txt 2>/dev/null | tr -d '\r\n' | sed 's/^[Ll]ocation: //')
  if [ -z "$REDIR2" ]; then
    log "    [browser] ERROR: No redirect after identifier POST"
    [ -z "$PERSISTENT_COOKIE" ] && rm -f "$COOKIE_FILE" 2>/dev/null || true
    rm -f /tmp/rt_*.html /tmp/rt_*_hdr.txt 2>/dev/null || true
    return 1
  fi

  # Step 3: GET password page
  curl -sk -c "$COOKIE_FILE" -b "$COOKIE_FILE" \
    -o /tmp/rt_pass.html \
    "http://localhost:5150${REDIR2}"
  local LOGIN_ID2 IDENT2 CSRF2
  LOGIN_ID2=$(grep -o 'name="login_id" value="[^"]*"' /tmp/rt_pass.html | sed 's/.*value="\([^"]*\)".*/\1/' | head -1)
  IDENT2=$(grep -o 'name="identifier" value="[^"]*"' /tmp/rt_pass.html | sed 's/.*value="\([^"]*\)".*/\1/' | head -1)
  CSRF2=$(grep -o 'name="csrf_token" value="[^"]*"' /tmp/rt_pass.html | sed 's/.*value="\([^"]*\)".*/\1/' | head -1)

  # Step 4: POST password
  local REDIR4
  curl -sk -c "$COOKIE_FILE" -b "$COOKIE_FILE" \
    --max-time 30 \
    -X POST "http://localhost:5150/login/password" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "credential=ConformanceTest1!" \
    --data-urlencode "csrf_token=$CSRF2" \
    --data-urlencode "login_id=$LOGIN_ID2" \
    --data-urlencode "identifier=$IDENT2" \
    -D /tmp/rt_pw_hdr.txt \
    -o /tmp/rt_pw.html \
    -w '%{http_code}' > /dev/null
  REDIR4=$(grep -i '^location:' /tmp/rt_pw_hdr.txt 2>/dev/null | tr -d '\r\n' | sed 's/^[Ll]ocation: //')
  if [ -z "$REDIR4" ]; then
    log "    [browser] ERROR: No redirect after password POST"
    [ -z "$PERSISTENT_COOKIE" ] && rm -f "$COOKIE_FILE" 2>/dev/null || true
    rm -f /tmp/rt_*.html /tmp/rt_*_hdr.txt 2>/dev/null || true
    return 1
  fi

  # Step 5: GET consent page
  local CONSENT_URL
  if echo "$REDIR4" | grep -q '^http'; then
    # Replace identity:5150 with localhost:5150 for WSL access
    CONSENT_URL=$(echo "$REDIR4" | sed 's|http://identity:5150|http://localhost:5150|g')
  else
    CONSENT_URL="http://localhost:5150${REDIR4}"
  fi
  curl -sk -c "$COOKIE_FILE" -b "$COOKIE_FILE" \
    -o /tmp/rt_consent.html \
    "$CONSENT_URL"
  local CSRF3 LOGIN_ID3
  CSRF3=$(grep -o 'name="csrf_token" value="[^"]*"' /tmp/rt_consent.html | sed 's/.*value="\([^"]*\)".*/\1/' | head -1)
  LOGIN_ID3=$(grep -o 'name="login_id" value="[^"]*"' /tmp/rt_consent.html | sed 's/.*value="\([^"]*\)".*/\1/' | head -1)

  # Step 6: POST consent (approve)
  local REDIR6
  curl -sk -c "$COOKIE_FILE" -b "$COOKIE_FILE" \
    -X POST "http://localhost:5150/oauth2/authorize/consent" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "login_id=$LOGIN_ID3" \
    --data-urlencode "csrf_token=$CSRF3" \
    --data-urlencode "decision=approve" \
    -D /tmp/rt_consent_hdr.txt \
    -o /tmp/rt_consent_resp.html \
    -w '%{http_code}' > /dev/null
  REDIR6=$(grep -i '^location:' /tmp/rt_consent_hdr.txt 2>/dev/null | tr -d '\r\n' | sed 's/^[Ll]ocation: //')
  if [ -z "$REDIR6" ]; then
    log "    [browser] ERROR: No redirect after consent POST"
    [ -z "$PERSISTENT_COOKIE" ] && rm -f "$COOKIE_FILE" 2>/dev/null || true
    rm -f /tmp/rt_*.html /tmp/rt_*_hdr.txt 2>/dev/null || true
    return 1
  fi

  # Step 7: Deliver callback to conformance server
  # localhost.emobix.co.uk resolves to 127.0.0.1 which maps to nginx:8443 from WSL
  local CODE7
  CODE7=$(curl -sk -c "$COOKIE_FILE" -b "$COOKIE_FILE" \
    -L --max-redirs 5 \
    -w '%{http_code}' \
    -o /tmp/rt_callback.html \
    "$REDIR6" 2>/dev/null || echo "000")

  log "    [browser] Callback delivered, HTTP code: $CODE7"

  # Step 8: Extract and POST to implicit submit URL (JS step the browser would do)
  # The callback page contains JS that POSTs the URL fragment to an /implicit/ URL.
  # For code flow, there's no fragment so we POST empty string.
  local IMPLICIT_URL
  IMPLICIT_URL=$(python3 -c "
import re, sys
try:
    content = open('/tmp/rt_callback.html').read().replace('\\\/', '/')
    m = re.search(r'(https://[^\"]+/implicit/[^\"]+)', content)
    print(m.group(1) if m else '')
except: print('')
" 2>/dev/null || echo "")

  if [ -n "$IMPLICIT_URL" ]; then
    log "    [browser] Posting empty fragment to implicit URL: ${IMPLICIT_URL:0:80}..."
    curl -sk -X POST \
      -H "Content-type: text/plain" \
      -d "" \
      -w '%{http_code}' \
      -o /dev/null \
      "$IMPLICIT_URL" > /dev/null 2>&1 || true
  fi

  [ -z "$PERSISTENT_COOKIE" ] && rm -f "$COOKIE_FILE" 2>/dev/null || true
  rm -f /tmp/rt_*.html /tmp/rt_*_hdr.txt 2>/dev/null || true
  return 0
}

# ── Drive all browser interactions for a test until it finishes ───────────────
drive_test() {
  local TEST_ID="$1"
  local MAX_BROWSER_ROUNDS=10
  local ROUND=0
  # Persistent cookie file shared across all browser rounds for this test
  local PERSISTENT_COOKIE
  PERSISTENT_COOKIE=$(mktemp /tmp/rt_test_cookies_XXXXXX)

  while [ $ROUND -lt $MAX_BROWSER_ROUNDS ]; do
    # Check current status
    local STATUS
    STATUS=$(api "${SUITE_URL}/api/info/${TEST_ID}" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','UNKNOWN'))" || echo "UNKNOWN")

    if [ "$STATUS" = "FINISHED" ] || [ "$STATUS" = "INTERRUPTED" ]; then
      rm -f "$PERSISTENT_COOKIE" 2>/dev/null || true
      return 0
    fi

    if [ "$STATUS" = "WAITING" ]; then
      # Get browser URL
      local BROWSER_RESP URLS
      BROWSER_RESP=$(api "${SUITE_URL}/api/runner/browser/${TEST_ID}" 2>/dev/null || echo '{}')
      URLS=$(echo "$BROWSER_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); urls=d.get('urls',[]); print(urls[0] if urls else '')" || echo "")

      if [ -z "$URLS" ]; then
        log "    [browser] No browser URL available, waiting..."
        sleep 2
        ROUND=$((ROUND + 1))
        continue
      fi

      # Drive the browser flow (with persistent cookies)
      if ! drive_browser "$URLS" "$PERSISTENT_COOKIE"; then
        log "    [browser] Browser flow failed"
        rm -f "$PERSISTENT_COOKIE" 2>/dev/null || true
        return 1
      fi

      sleep 3
      ROUND=$((ROUND + 1))
      continue
    fi

    # Still RUNNING/CONFIGURED etc — wait
    sleep 2
    ROUND=$((ROUND + 1))
  done

  rm -f "$PERSISTENT_COOKIE" 2>/dev/null || true
  log "    [browser] Max rounds ($MAX_BROWSER_ROUNDS) reached without finishing"
  return 1
}

# ── Main ─────────────────────────────────────────────────────────────────────

log "Starting Docker Compose stack..."
docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d

# Wait for services
wait_for "$IDENTITY_HEALTH" "identity"
wait_for "${SUITE_URL}/api/plan" "conformance-suite"

# Create test plan
log "Creating test plan..."
PLAN_NAME="oidcc-basic-certification-test-plan"
VARIANT='{"server_metadata":"discovery","client_registration":"static_client"}'
VARIANT_ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$VARIANT")

PLAN_RESPONSE=$(api -X POST \
  -H "Content-Type: application/json" \
  -d @"$SCRIPT_DIR/conformance-config.json" \
  "${SUITE_URL}/api/plan?planName=${PLAN_NAME}&variant=${VARIANT_ENC}")
PLAN_ID=$(echo "$PLAN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

[[ -z "$PLAN_ID" || "$PLAN_ID" == "null" ]] && fail "Failed to create test plan. Response: $PLAN_RESPONSE"
log "Plan ID: $PLAN_ID"

# Fetch module list
PLAN_JSON=$(api "${SUITE_URL}/api/plan/${PLAN_ID}")
MODULE_COUNT=$(echo "$PLAN_JSON" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('modules', [])))")
[[ -z "$MODULE_COUNT" || "$MODULE_COUNT" -eq 0 ]] && fail "No modules found in plan $PLAN_ID"

# Start modules one at a time
log "Starting $MODULE_COUNT test modules sequentially..."
declare -a ALL_TEST_IDS=()
for i in $(seq 0 $((MODULE_COUNT - 1))); do
  TEST_MODULE=$(echo "$PLAN_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['modules'][$i]['testModule'])")
  log "  Module [$((i+1))/$MODULE_COUNT]: $TEST_MODULE"

  RESP=$(curl -sk "${SUITE_URL}/api/runner?test=${TEST_MODULE}&plan=${PLAN_ID}" \
    -X POST -w "\nHTTP:%{http_code}" || true)
  HTTP_CODE=$(echo "$RESP" | grep -o 'HTTP:[0-9]*' | cut -d: -f2)
  TEST_ID=$(echo "$RESP" | grep -v 'HTTP:' | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id',''))" 2>/dev/null || true)

  if [[ "$HTTP_CODE" != "201" && "$HTTP_CODE" != "200" ]]; then
    log "    WARNING: $TEST_MODULE returned HTTP $HTTP_CODE, skipping"
    continue
  fi

  log "    Test ID: $TEST_ID"
  ALL_TEST_IDS+=("$TEST_ID")

  # Persistent cookie file for this test (shared across browser rounds)
  TEST_COOKIE_FILE=$(mktemp /tmp/rt_test_cookies_XXXXXX)
  DRIVEN_URLS=""  # newline-separated list of URLs we've already driven

  # Drive browser interactions until test finishes (or times out)
  ELAPSED=0
  while true; do
    STATUS=$(api "${SUITE_URL}/api/info/${TEST_ID}" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','UNKNOWN'))" || echo "UNKNOWN")

    if [[ "$STATUS" == "FINISHED" || "$STATUS" == "INTERRUPTED" ]]; then
      RESULT=$(api "${SUITE_URL}/api/info/${TEST_ID}" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('result','UNKNOWN'))" || echo "UNKNOWN")
      log "    -> $STATUS ($RESULT)"
      break
    fi

    if [[ "$STATUS" == "WAITING" ]]; then
      # Get ALL pending browser URLs and drive any we haven't driven yet
      BROWSER_RESP=$(api "${SUITE_URL}/api/runner/browser/${TEST_ID}" 2>/dev/null || echo '{}')
      ALL_URLS=$(echo "$BROWSER_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); [print(u) for u in d.get('urls',[])]" || echo "")
      DROVE_ONE=0
      while IFS= read -r AUTH_URL; do
        [ -z "$AUTH_URL" ] && continue
        # Skip URLs we've already driven
        if echo "$DRIVEN_URLS" | grep -qF "$AUTH_URL"; then
          continue
        fi
        DRIVEN_URLS="${DRIVEN_URLS}${AUTH_URL}"$'\n'
        AUTH_URL_LOCAL=$(echo "$AUTH_URL" | sed 's|http://identity:5150|http://localhost:5150|g')
        drive_browser "$AUTH_URL_LOCAL" "$TEST_COOKIE_FILE" || true
        DROVE_ONE=1
        sleep 2
        break  # Drive one at a time, then re-check status
      done <<< "$ALL_URLS"
      if [[ $DROVE_ONE -eq 0 ]]; then
        sleep 2
      fi
    else
      sleep 2
    fi

    ELAPSED=$((ELAPSED + 2))
    if [[ $ELAPSED -ge 120 ]]; then
      log "    -> TIMEOUT waiting for $TEST_MODULE ($STATUS)"
      break
    fi
  done
  rm -f "$TEST_COOKIE_FILE" 2>/dev/null || true
done

# Collect results
log "Collecting results..."
PASSED=0
FAILED=""
WARNINGS=""

for tid in "${ALL_TEST_IDS[@]}"; do
  INFO=$(api "${SUITE_URL}/api/info/${tid}" 2>/dev/null || echo '{}')
  RESULT=$(echo "$INFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('result','UNKNOWN'))" || echo "UNKNOWN")
  NAME=$(echo "$INFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('testName','unknown'))" || echo "unknown")
  case "$RESULT" in
    PASSED)  PASSED=$((PASSED + 1)) ;;
    WARNING) WARNINGS="${WARNINGS}${tid} (${NAME})\n" ;;
    FAILED)  FAILED="${FAILED}${tid} (${NAME})\n" ;;
    *)       WARNINGS="${WARNINGS}${tid} (${NAME}: ${RESULT})\n" ;;
  esac
done

log "Results:"
log "  PASSED:  $PASSED / ${#ALL_TEST_IDS[@]}"

if [[ -n "$WARNINGS" ]]; then
  log "  WARNING:"
  echo -e "$WARNINGS" | while IFS= read -r line; do
    [[ -n "$line" ]] && log "    - $line"
  done
fi

EXIT_CODE=0
if [[ -n "$FAILED" ]]; then
  log "  FAILED:"
  echo -e "$FAILED" | while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    tid=$(echo "$line" | awk '{print $1}')
    log "    - $line"
    api "${SUITE_URL}/api/log/${tid}" 2>/dev/null \
      | python3 -c "
import sys,json
try:
    for entry in json.load(sys.stdin):
        if entry.get('result') == 'FAILURE':
            print('      [FAILURE]', entry.get('msg',''))
except: pass
" || true
  done
  EXIT_CODE=1
fi

log "Done. Exit code: $EXIT_CODE"
exit $EXIT_CODE
