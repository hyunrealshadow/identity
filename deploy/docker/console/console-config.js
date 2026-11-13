// Serves /console/config.json from Identity on every request.
//
// The workload credential is read per request so a rotated token file takes
// effect without a restart. Only the exact browser-visible Console fields are
// published; any other response (for example a Login runtime configuration
// returned to a misconfigured credential) is withheld.
import fs from 'fs';

const FIELDS = [
    'accountUrl', 'clientId', 'displayName', 'environment', 'graphqlUrl',
    'issuer', 'postLogoutRedirectUri', 'redirectUri', 'scope',
];

function token() {
    const file = process.env.IDENTITY_WORKLOAD_TOKEN_FILE;
    const value = (file ? fs.readFileSync(file, 'utf8') : process.env.IDENTITY_WORKLOAD_TOKEN || '')
        .replace(/[\r\n]+$/, '');
    if (value.length < 32 || /\s/.test(value)) {
        return '';
    }
    return value;
}

function authorization(r) {
    try {
        const value = token();
        return value ? `Bearer ${value}` : '';
    } catch (_) {
        r.error('Console workload token is unreadable');
        return '';
    }
}

function valid(body) {
    if (body === null || typeof body !== 'object' || Array.isArray(body)) {
        return false;
    }
    const keys = Object.keys(body).sort();
    return keys.length === FIELDS.length
        && keys.every((key, index) => key === FIELDS[index])
        && FIELDS.every((key) => typeof body[key] === 'string' && body[key].length > 0);
}

function unavailable(r, reason) {
    r.error(`Console runtime configuration unavailable: ${reason}`);
    r.headersOut['Content-Type'] = 'application/json';
    r.return(503, '{"error":"console_configuration_unavailable"}');
}

async function config(r) {
    let reply;
    try {
        reply = await r.subrequest('/_identity/runtime-configuration', { method: 'GET' });
    } catch (_) {
        return unavailable(r, 'subrequest failed');
    }
    if (reply.status !== 200) {
        return unavailable(r, `upstream status ${reply.status}`);
    }
    let body;
    try {
        body = JSON.parse(reply.responseText);
    } catch (_) {
        return unavailable(r, 'invalid JSON');
    }
    if (!valid(body)) {
        return unavailable(r, 'unexpected fields');
    }
    r.headersOut['Content-Type'] = 'application/json';
    r.return(200, JSON.stringify(body));
}

export default { authorization, config };
