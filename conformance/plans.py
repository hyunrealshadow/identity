"""Conformance test plan configurations."""

DISCOVERY_URL = "https://identity:5150/.well-known/openid-configuration"

PLANS = {
    "basic": {
        "alias": "identity",
        "description": "Identity server Basic OP conformance",
        "server": {"discoveryUrl": DISCOVERY_URL},
        "client": {
            "client_id": "00000001-0000-0000-0000-000000000001",
            "client_secret": "conformance-basic-secret-at-least-32-bytes",
        },
        "client2": {
            "client_id": "00000002-0000-0000-0000-000000000001",
            "client_secret": "conformance-secret-2",
        },
        "client_secret_post": {
            "client_id": "00000002-0000-0000-0000-000000000001",
            "client_secret": "conformance-secret-2",
        },
    },
    "implicit": {
        "alias": "identity",
        "description": "Identity server Implicit OP conformance",
        "server": {"discoveryUrl": DISCOVERY_URL},
        "client": {
            "client_id": "00000003-0000-0000-0000-000000000001",
            "client_secret": "conformance-implicit-secret",
        },
        "client2": {
            "client_id": "00000004-0000-0000-0000-000000000001",
            "client_secret": "conformance-implicit-secret-2",
        },
        "client_secret_post": {
            "client_id": "00000004-0000-0000-0000-000000000001",
            "client_secret": "conformance-implicit-secret-2",
        },
    },
    "hybrid": {
        "alias": "identity",
        "description": "Identity server Hybrid OP conformance",
        "server": {"discoveryUrl": DISCOVERY_URL},
        "client": {
            "client_id": "00000005-0000-0000-0000-000000000001",
            "client_secret": "conformance-hybrid-secret",
        },
        "client2": {
            "client_id": "00000006-0000-0000-0000-000000000001",
            "client_secret": "conformance-hybrid-secret-2",
        },
        "client_secret_post": {
            "client_id": "00000006-0000-0000-0000-000000000001",
            "client_secret": "conformance-hybrid-secret-2",
        },
    },
    "config": {
        "alias": "identity-config",
        "description": "Identity server Config OP conformance",
        "server": {"discoveryUrl": DISCOVERY_URL},
        "client": {
            "client_id": "00000001-0000-0000-0000-000000000001",
            "client_secret": "conformance-basic-secret-at-least-32-bytes",
        },
        "client2": {
            "client_id": "00000002-0000-0000-0000-000000000001",
            "client_secret": "conformance-secret-2",
        },
        "client_secret_post": {
            "client_id": "00000002-0000-0000-0000-000000000001",
            "client_secret": "conformance-secret-2",
        },
    },
    "formpost-basic": {
        "alias": "identity-formpost-basic",
        "description": "Identity server Form Post Basic OP conformance",
        "server": {"discoveryUrl": DISCOVERY_URL},
        "client": {
            "client_id": "00000001-0000-0000-0000-000000000001",
            "client_secret": "conformance-basic-secret-at-least-32-bytes",
        },
        "client2": {
            "client_id": "00000002-0000-0000-0000-000000000001",
            "client_secret": "conformance-secret-2",
        },
        "client_secret_post": {
            "client_id": "00000002-0000-0000-0000-000000000001",
            "client_secret": "conformance-secret-2",
        },
    },
    "formpost-implicit": {
        "alias": "identity-formpost-implicit",
        "description": "Identity server Form Post Implicit OP conformance",
        "server": {"discoveryUrl": DISCOVERY_URL},
        "client": {
            "client_id": "00000003-0000-0000-0000-000000000001",
            "client_secret": "conformance-implicit-secret",
        },
        "client2": {
            "client_id": "00000004-0000-0000-0000-000000000001",
            "client_secret": "conformance-implicit-secret-2",
        },
        "client_secret_post": {
            "client_id": "00000004-0000-0000-0000-000000000001",
            "client_secret": "conformance-implicit-secret-2",
        },
    },
    "formpost-hybrid": {
        "alias": "identity-formpost-hybrid",
        "description": "Identity server Form Post Hybrid OP conformance",
        "server": {"discoveryUrl": DISCOVERY_URL},
        "client": {
            "client_id": "00000005-0000-0000-0000-000000000001",
            "client_secret": "conformance-hybrid-secret",
        },
        "client2": {
            "client_id": "00000006-0000-0000-0000-000000000001",
            "client_secret": "conformance-hybrid-secret-2",
        },
        "client_secret_post": {
            "client_id": "00000006-0000-0000-0000-000000000001",
            "client_secret": "conformance-hybrid-secret-2",
        },
    },
    "rp-init-logout": {
        "alias": "identity-rp-init-logout",
        "description": "Identity server RP-Initiated Logout OP conformance",
        "server": {"discoveryUrl": DISCOVERY_URL},
        "client": {
            "client_id": "00000001-0000-0000-0000-000000000001",
            "client_secret": "conformance-basic-secret-at-least-32-bytes",
        },
    },
    "session": {
        "alias": "identity-session",
        "description": "Identity server Session Management OP conformance",
        "server": {"discoveryUrl": DISCOVERY_URL},
        "client": {
            "client_id": "00000001-0000-0000-0000-000000000001",
            "client_secret": "conformance-basic-secret-at-least-32-bytes",
        },
    },
    "backchannel": {
        "alias": "identity-backchannel",
        "description": "Identity server Back-Channel Logout OP conformance",
        "server": {"discoveryUrl": DISCOVERY_URL},
        "client": {
            "client_id": "00000001-0000-0000-0000-000000000001",
            "client_secret": "conformance-basic-secret-at-least-32-bytes",
        },
    },
}


def get_plan(profile: str) -> dict:
    if profile not in PLANS:
        msg = f"Unknown profile: {profile}"
        raise ValueError(msg)
    return PLANS[profile]


__all__ = ["PLANS", "get_plan", "DISCOVERY_URL"]
