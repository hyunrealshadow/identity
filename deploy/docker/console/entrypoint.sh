#!/bin/sh
set -eu

: "${IDENTITY_INTERNAL_API_URL:?set IDENTITY_INTERNAL_API_URL}"
runtime=/run/identity-console
umask 077
headers=$(mktemp "$runtime/.headers.XXXXXX")
response=$(mktemp "$runtime/.response.XXXXXX")
nginx_config=$(mktemp "$runtime/.nginx.XXXXXX")
trap 'rm -f "$headers" "$response" "$nginx_config"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 131' QUIT

port=${PORT:-8080}
case "$port" in
    ''|*[!0-9]*) echo 'Console PORT must be a valid TCP port' >&2; exit 1 ;;
esac
if [ "${#port}" -gt 5 ] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ] || [ "$port" -eq 8081 ]; then
    echo 'Console PORT must be between 1 and 65535, excluding health port 8081' >&2
    exit 1
fi
listen=$port
tls=''
case "${IDENTITY_CONSOLE_TLS_ENABLED:-false}" in
    true)
        if [ ! -r /etc/identity/console-tls/tls.crt ] || [ ! -r /etc/identity/console-tls/tls.key ]; then
            echo 'Console TLS requires a readable certificate and private key' >&2
            exit 1
        fi
        listen="$port ssl"
        tls='ssl_certificate /etc/identity/console-tls/tls.crt; ssl_certificate_key /etc/identity/console-tls/tls.key; ssl_protocols TLSv1.2 TLSv1.3;'
        ;;
    false) ;;
    *) echo 'IDENTITY_CONSOLE_TLS_ENABLED must be true or false' >&2; exit 1 ;;
esac
render_nginx() {
    sed -e "s/@CONSOLE_LISTEN@/$listen/" -e "s|@CONSOLE_TLS@|$tls|" \
        -e "s|@IDENTITY_RUNTIME_URL@|$1|" -e "s|@IDENTITY_TLS@|$2|" \
        /etc/nginx/nginx.conf.template > "$nginx_config"
}
# Fail fast on listener and certificate errors before waiting for Identity.
render_nginx http://127.0.0.1:9 ''
nginx -t -q -c "$nginx_config"

internal_url=${IDENTITY_INTERNAL_API_URL%/}
if ! printf '%s' "$internal_url" | LC_ALL=C grep -Eq '^https?://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$'; then
    echo 'IDENTITY_INTERNAL_API_URL must be an http(s) URL without credentials, query or fragment' >&2
    exit 1
fi
runtime_url="$internal_url/internal/workloads/self/runtime-configuration"
upstream_tls=''
case "$internal_url" in
    https://*)
        ca_file=${IDENTITY_CA_FILE:-/etc/ssl/certs/ca-certificates.crt}
        if [ ! -r "$ca_file" ] || printf '%s' "$ca_file" | grep -q '[|;[:space:]]'; then
            echo 'Identity CA file is missing or unreadable' >&2
            exit 1
        fi
        upstream_tls="proxy_ssl_verify on; proxy_ssl_verify_depth 4; proxy_ssl_server_name on; proxy_ssl_protocols TLSv1.2 TLSv1.3; proxy_ssl_trusted_certificate $ca_file;"
        ;;
    http://*)
        if [ "${IDENTITY_INTERNAL_API_ALLOW_HTTP:-false}" != true ]; then
            echo 'IDENTITY_INTERNAL_API_URL must use HTTPS unless IDENTITY_INTERNAL_API_ALLOW_HTTP=true' >&2
            exit 1
        fi
        ;;
esac

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
        "$runtime_url")
    if [ "$status" != 404 ]; then break; fi
    echo 'Waiting for Identity installation and Console settings' >&2
    sleep 5
done
if [ "$status" != 200 ]; then
    echo 'Identity did not return Console runtime configuration' >&2
    exit 1
fi

# Reject Login credentials, unexpected fields and incomplete responses before
# serving. console-config.js applies the same check to every later response.
jq --exit-status '
    ["issuer", "graphqlUrl", "clientId", "redirectUri", "postLogoutRedirectUri",
     "accountUrl", "scope", "displayName", "environment"] as $fields |
    if type == "object" and (keys == ($fields | sort)) and
       all(.[]; type == "string" and length > 0)
    then . else error("Invalid Console runtime configuration") end
' "$response" > /dev/null
rm -f "$headers" "$response"

# Rendered only after Identity answered, so its host name resolves.
render_nginx "$runtime_url" "$upstream_tls"
chmod 644 "$nginx_config"
mv -f "$nginx_config" "$runtime/nginx.conf"
nginx -t -c "$runtime/nginx.conf"
trap - EXIT HUP INT TERM QUIT
exec "$@"
