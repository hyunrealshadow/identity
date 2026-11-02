#!/bin/sh
set -eu

: "${IDENTITY_INTERNAL_API_URL:?set IDENTITY_INTERNAL_API_URL}"
runtime=/run/identity-console
umask 077
rm -f "$runtime/config.json"
headers=$(mktemp "$runtime/.headers.XXXXXX")
response=$(mktemp "$runtime/.response.XXXXXX")
config=$(mktemp "$runtime/.config.XXXXXX")
trap 'rm -f "$headers" "$response" "$config"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 131' QUIT

write_headers() {
    if [ -n "${IDENTITY_WORKLOAD_TOKEN_FILE:-}" ]; then
        token=$(cat "$IDENTITY_WORKLOAD_TOKEN_FILE")
        token=${token%"$(printf '\r')"}
    else
        token=${IDENTITY_WORKLOAD_TOKEN:-}
    fi
    if [ "${#token}" -lt 32 ] || printf '%s' "$token" | LC_ALL=C grep -q '[[:space:]]'; then
        echo 'Console workload token is missing or invalid' >&2
        exit 1
    fi
    printf 'Authorization: Bearer %s\n' "$token" > "$headers"
    unset token
}

protocols='=https'
if [ "${IDENTITY_INTERNAL_API_ALLOW_HTTP:-false}" = true ]; then
    protocols='=http,https'
fi
if [ -n "${IDENTITY_CA_FILE:-}" ]; then
    export CURL_CA_BUNDLE="$IDENTITY_CA_FILE"
fi
while :; do
    write_headers
    status=$(curl --silent --show-error --proto "$protocols" \
        --connect-timeout 5 --max-time 15 --retry 5 --retry-connrefused --retry-delay 2 --retry-max-time 60 \
        --header "@$headers" --header 'Accept: application/json' \
        --output "$response" --write-out '%{http_code}' \
        "${IDENTITY_INTERNAL_API_URL%/}/internal/workloads/self/runtime-configuration")
    if [ "$status" != 404 ]; then break; fi
    echo 'Waiting for Identity installation and Console settings' >&2
    sleep 5
done
unset IDENTITY_WORKLOAD_TOKEN
if [ "$status" != 200 ]; then
    echo 'Identity did not return Console runtime configuration' >&2
    exit 1
fi

# Reject Login credentials, unexpected fields and incomplete responses before publishing.
jq --exit-status '
    ["issuer", "graphqlUrl", "clientId", "redirectUri", "postLogoutRedirectUri",
     "accountUrl", "scope", "displayName", "environment"] as $fields |
    if type == "object" and (keys == ($fields | sort)) and
       all(.[]; type == "string" and length > 0)
    then . else error("Invalid Console runtime configuration") end
' "$response" > "$config"
chmod 644 "$config"
mv -f "$config" "$runtime/config.json"
rm -f "$headers" "$response"
trap - EXIT HUP INT TERM QUIT
exec "$@"
