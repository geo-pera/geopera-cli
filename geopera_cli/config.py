"""Configuration: defaults, env vars, and the credential store location.

Resolution precedence for the API base URL (highest first):
    1. an explicit --api-url flag (passed into resolve_api_url)
    2. the GEOPERA_API_URL environment variable
    3. the api_url stored in the active profile of credentials.json
    4. the built-in default (https://api.geopera.com)
"""

from __future__ import annotations

import os
from pathlib import Path

# Built-in default — the production Geopera API.
DEFAULT_API_URL = "https://api.geopera.com"

# OAuth realm path prefix. The backend mounts the Keycloak-shaped endpoints
# at /realms/public/protocol/openid-connect/* (see auth_keycloak.py).
REALM_PATH = "/realms/public/protocol/openid-connect"

# Public client id the CLI identifies as during the device flow. There is no
# client secret — this is a public (native) client per RFC 8628.
CLIENT_ID = "geopera-cli"

# Default OAuth scope requested at login.
DEFAULT_SCOPE = "openid profile"

# Refresh the access token this many seconds before it actually expires so a
# command never fires a request with a token that dies mid-flight.
REFRESH_LEEWAY_SECONDS = 30

# Environment variable names.
ENV_API_URL = "GEOPERA_API_URL"
ENV_API_TOKEN = "GEOPERA_API_TOKEN"  # opaque bearer/api-key override (no store)
ENV_PROFILE = "GEOPERA_PROFILE"

# Credential store: ~/.config/geopera/credentials.json (dir 0700, file 0600).
CONFIG_DIR = Path(os.path.expanduser("~")) / ".config" / "geopera"
CREDENTIALS_PATH = CONFIG_DIR / "credentials.json"

DEFAULT_PROFILE = "default"


def resolve_profile(flag_profile: str | None = None) -> str:
    """Resolve the active profile name: --profile > GEOPERA_PROFILE > default."""
    return flag_profile or os.environ.get(ENV_PROFILE) or DEFAULT_PROFILE


def resolve_api_url(flag_api_url: str | None, stored_api_url: str | None) -> str:
    """Resolve the API base URL by precedence (see module docstring)."""
    return (
        flag_api_url
        or os.environ.get(ENV_API_URL)
        or stored_api_url
        or DEFAULT_API_URL
    ).rstrip("/")


def realm_url(api_url: str, endpoint: str) -> str:
    """Build a full OAuth endpoint URL, e.g. realm_url(api, 'token')."""
    return f"{api_url.rstrip('/')}{REALM_PATH}/{endpoint.lstrip('/')}"
