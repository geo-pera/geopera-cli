"""Credential store + auth context.

The store is a single JSON file at ~/.config/geopera/credentials.json. Multiple
identities are namespaced as top-level keys by *profile* name, e.g.::

    {
      "default": {
        "api_url": "https://api.geopera.com",
        "auth": {"type": "oauth", "access_token": "...", "refresh_token": "...",
                 "expires_at": 1234567890, "scope": "openid profile",
                 "issuer": "https://api.geopera.com"}
      },
      "staging": {
        "api_url": "https://staging.api.geopera.com",
        "auth": {"type": "api_key", "api_key": "gpra_..."}
      }
    }

load_client() turns the active profile into a geopera.AuthenticatedClient,
transparently refreshing an OAuth access token that is at/near expiry.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

import httpx

from . import config

try:
    # The published SDK. The CLI is a thin shell over its AuthenticatedClient.
    from geopera import AuthenticatedClient
except ImportError as exc:  # pragma: no cover - import guard
    raise RuntimeError(
        "The 'geopera' SDK is required. Install it with: pip install geopera"
    ) from exc


# ---------------------------------------------------------------------------
# Store read / write (mode-hardened)
# ---------------------------------------------------------------------------

def _ensure_dir() -> None:
    """Create ~/.config/geopera with mode 0700 (owner-only)."""
    os.makedirs(config.CONFIG_DIR, mode=0o700, exist_ok=True)
    # makedirs honours `mode` only for the leaf it creates and is subject to
    # umask; chmod unconditionally to guarantee 0700.
    try:
        os.chmod(config.CONFIG_DIR, 0o700)
    except OSError:
        pass


def _read_store() -> dict[str, Any]:
    """Load the full credentials.json (all profiles). Empty dict if absent."""
    if not config.CREDENTIALS_PATH.exists():
        return {}
    try:
        with open(config.CREDENTIALS_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _write_store(store: dict[str, Any]) -> None:
    """Atomically write the full store with file mode 0600."""
    _ensure_dir()
    tmp = config.CREDENTIALS_PATH.with_suffix(".json.tmp")
    # Open with 0600 from the start so the secret is never briefly world-readable.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(store, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, config.CREDENTIALS_PATH)
        os.chmod(config.CREDENTIALS_PATH, 0o600)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_profile(profile: str) -> dict[str, Any]:
    """Return the stored entry for a profile (api_url + auth), or {} if none."""
    return _read_store().get(profile, {})


def save_profile(profile: str, entry: dict[str, Any]) -> None:
    """Persist a profile entry, leaving other profiles untouched."""
    store = _read_store()
    store[profile] = entry
    _write_store(store)


def clear_profile(profile: str) -> bool:
    """Remove a profile's auth (keeps api_url). Returns True if anything changed."""
    store = _read_store()
    entry = store.get(profile)
    if not entry or "auth" not in entry:
        return False
    entry.pop("auth", None)
    store[profile] = entry
    _write_store(store)
    return True


# ---------------------------------------------------------------------------
# Token refresh (OAuth)
# ---------------------------------------------------------------------------

def _needs_refresh(auth: dict[str, Any]) -> bool:
    """True if the OAuth access token is missing or within the leeway window."""
    expires_at = auth.get("expires_at")
    if not expires_at:
        return False
    return time.time() >= (float(expires_at) - config.REFRESH_LEEWAY_SECONDS)


def refresh_oauth(api_url: str, auth: dict[str, Any]) -> dict[str, Any]:
    """Exchange the stored refresh_token for a fresh access (and refresh) token.

    The backend rotates the refresh token on every use, so BOTH tokens are
    replaced. Returns the updated auth dict (caller persists it).
    """
    refresh_token = auth.get("refresh_token")
    if not refresh_token:
        raise AuthError("Session expired and no refresh token is stored. Run 'geopera login'.")

    resp = httpx.post(
        config.realm_url(api_url, "token"),
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": config.CLIENT_ID,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30.0,
    )
    if resp.status_code != 200:
        raise AuthError(
            "Token refresh failed (your session may have been revoked). "
            "Run 'geopera login' to sign in again."
        )

    payload = resp.json()
    return _auth_from_token_response(api_url, payload, fallback=auth)


def _auth_from_token_response(
    api_url: str, payload: dict[str, Any], fallback: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Build an oauth auth entry from a token endpoint response."""
    fallback = fallback or {}
    expires_in = payload.get("expires_in")
    expires_at = time.time() + float(expires_in) if expires_in else None
    return {
        "type": "oauth",
        "access_token": payload["access_token"],
        # The backend rotates the refresh token; keep the old one only if the
        # response omits a new one.
        "refresh_token": payload.get("refresh_token", fallback.get("refresh_token")),
        "expires_at": expires_at,
        "scope": payload.get("scope", fallback.get("scope", config.DEFAULT_SCOPE)),
        "issuer": api_url,
    }


# ---------------------------------------------------------------------------
# Building the SDK client
# ---------------------------------------------------------------------------

class AuthError(Exception):
    """Raised when no usable credentials are available."""


class AuthContext:
    """Resolved auth for the active profile + a ready-to-use SDK client."""

    def __init__(self, profile: str, api_url: str, auth: dict[str, Any]):
        self.profile = profile
        self.api_url = api_url
        self.auth = auth

    @property
    def is_api_key(self) -> bool:
        return self.auth.get("type") == "api_key"

    def client(self) -> AuthenticatedClient:
        """Construct the SDK AuthenticatedClient for this auth context.

        - api_key  -> X-API-Key header, no prefix (kernel accepts X-API-Key)
        - oauth    -> Authorization: Bearer <access_token>
        """
        if self.is_api_key:
            return AuthenticatedClient(
                base_url=self.api_url,
                token=self.auth["api_key"],
                prefix="",
                auth_header_name="X-API-Key",
            )
        return AuthenticatedClient(
            base_url=self.api_url,
            token=self.auth["access_token"],
            prefix="Bearer",
            auth_header_name="Authorization",
        )

    def bearer_headers(self) -> dict[str, str]:
        """Raw auth header for direct httpx calls (userinfo, logout, op)."""
        if self.is_api_key:
            return {"X-API-Key": self.auth["api_key"]}
        return {"Authorization": f"Bearer {self.auth['access_token']}"}


def load_context(
    profile: str | None = None, api_url_flag: str | None = None
) -> AuthContext:
    """Load the active profile, refreshing the OAuth token if near expiry.

    Honours the GEOPERA_API_TOKEN env override (opaque bearer/api-key) so an
    ephemeral CI token can be used without writing to the store.
    """
    profile = config.resolve_profile(profile)
    entry = load_profile(profile)

    # Env-token escape hatch: use an opaque token straight from the environment.
    env_token = os.environ.get(config.ENV_API_TOKEN)
    if env_token:
        api_url = config.resolve_api_url(api_url_flag, entry.get("api_url"))
        # A 'gpra_' value is an API key; anything else is treated as a bearer.
        if env_token.startswith("gpra_"):
            auth = {"type": "api_key", "api_key": env_token}
        else:
            auth = {"type": "oauth", "access_token": env_token, "expires_at": None}
        return AuthContext(profile, api_url, auth)

    auth = entry.get("auth")
    if not auth:
        raise AuthError(
            f"Not logged in (profile '{profile}'). Run 'geopera login' first."
        )

    api_url = config.resolve_api_url(api_url_flag, entry.get("api_url"))

    # Proactive refresh for OAuth tokens near expiry.
    if auth.get("type") == "oauth" and _needs_refresh(auth):
        auth = refresh_oauth(api_url, auth)
        entry["auth"] = auth
        entry.setdefault("api_url", api_url)
        save_profile(profile, entry)

    return AuthContext(profile, api_url, auth)


def force_refresh(ctx: AuthContext) -> AuthContext:
    """Refresh after a 401 and persist. Raises AuthError if not refreshable."""
    if ctx.is_api_key:
        raise AuthError("API key rejected (401). Check the key or create a new one.")
    new_auth = refresh_oauth(ctx.api_url, ctx.auth)
    entry = load_profile(ctx.profile)
    entry["auth"] = new_auth
    entry.setdefault("api_url", ctx.api_url)
    save_profile(ctx.profile, entry)
    return AuthContext(ctx.profile, ctx.api_url, new_auth)
