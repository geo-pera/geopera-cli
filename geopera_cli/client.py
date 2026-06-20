"""Wire-level calls layered over the SDK's AuthenticatedClient.

Two kinds of call live here:

  * Operation dispatch (`invoke_op`) — POST /v1/op/{operation_id}. This goes
    through the SDK's AuthenticatedClient.get_httpx_client(), which already
    attaches the right auth header (Bearer or X-API-Key). A single helper
    therefore reaches every one of the ~227 operations with zero
    per-op code, honouring the backend-first principle: the CLI sends params,
    the backend produces output.

  * Identity / OAuth wire (`userinfo`, `device_authorize`, `poll_token`,
    `logout`) — these are the only endpoints outside the generated op surface,
    so they are issued with plain httpx against the realm path.

invoke_op transparently refreshes an expired OAuth token once on a 401 and
retries, so refresh is automatic for every command.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from . import auth, config


class OpError(Exception):
    """An operation returned a problem+json error or other non-2xx response."""

    def __init__(self, status: int, message: str, detail: dict[str, Any] | None = None):
        self.status = status
        self.message = message
        self.detail = detail or {}
        super().__init__(message)


# ---------------------------------------------------------------------------
# Operation dispatch
# ---------------------------------------------------------------------------

def invoke_op(ctx: auth.AuthContext, operation_id: str, body: Any) -> Any:
    """POST /v1/op/{operation_id} with `body`, returning the parsed JSON.

    Uses the SDK's authenticated httpx client. On a 401 with OAuth creds, the
    token is refreshed once and the call retried.
    """
    sdk = ctx.client()
    url = f"/v1/op/{operation_id}"

    response = sdk.get_httpx_client().request(
        "post", url, json=body, headers={"Content-Type": "application/json"}
    )

    if response.status_code == 401 and not ctx.is_api_key:
        # Token might have expired between proactive check and the call.
        ctx = auth.force_refresh(ctx)
        sdk = ctx.client()
        response = sdk.get_httpx_client().request(
            "post", url, json=body, headers={"Content-Type": "application/json"}
        )

    return _parse(response, operation_id)


def _parse(response: httpx.Response, operation_id: str) -> Any:
    """Return parsed JSON on 2xx; raise OpError (problem+json aware) otherwise."""
    if 200 <= response.status_code < 300:
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            return response.text

    # Error path — surface problem+json detail/title when present.
    detail: dict[str, Any] = {}
    try:
        detail = response.json()
    except ValueError:
        detail = {"raw": response.text}

    message = (
        detail.get("detail")
        or detail.get("title")
        or detail.get("message")
        or detail.get("error_description")
        or detail.get("error")
        or f"{operation_id} failed with HTTP {response.status_code}"
    )
    raise OpError(response.status_code, str(message), detail)


# ---------------------------------------------------------------------------
# Identity / OAuth wire (outside the op surface)
# ---------------------------------------------------------------------------

def userinfo(ctx: auth.AuthContext) -> dict[str, Any]:
    """GET userinfo with the loaded credentials. Refreshes once on a 401."""
    url = config.realm_url(ctx.api_url, "userinfo")
    resp = httpx.get(url, headers=ctx.bearer_headers(), timeout=30.0)
    if resp.status_code == 401 and not ctx.is_api_key:
        ctx = auth.force_refresh(ctx)
        resp = httpx.get(url, headers=ctx.bearer_headers(), timeout=30.0)
    if resp.status_code != 200:
        raise OpError(resp.status_code, "userinfo failed — credentials may be invalid")
    return resp.json()


def device_authorize(
    api_url: str, scope: str, pkce_challenge: str | None = None
) -> dict[str, Any]:
    """Start the RFC 8628 device flow. Returns the device authorization response."""
    data: dict[str, str] = {"client_id": config.CLIENT_ID, "scope": scope}
    if pkce_challenge:
        data["code_challenge"] = pkce_challenge
        data["code_challenge_method"] = "S256"

    resp = httpx.post(
        config.realm_url(api_url, "auth/device"),
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30.0,
    )
    if resp.status_code != 200:
        raise OpError(
            resp.status_code,
            "Device authorization failed. The server may not support the device "
            "flow yet — try 'geopera login --api-key <key>' instead.",
        )
    return resp.json()


# Sentinel returns for poll_token so the caller's loop can branch cleanly.
PENDING = "authorization_pending"
SLOW_DOWN = "slow_down"


def poll_token(
    api_url: str,
    device_code: str,
    pkce_verifier: str | None = None,
) -> dict[str, Any] | str:
    """Poll the token endpoint once.

    Returns the token payload on success, or one of the sentinel strings
    PENDING / SLOW_DOWN to keep polling. Raises OpError on a terminal error
    (access_denied, expired_token, ...).
    """
    data: dict[str, str] = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": device_code,
        "client_id": config.CLIENT_ID,
    }
    if pkce_verifier:
        data["code_verifier"] = pkce_verifier

    resp = httpx.post(
        config.realm_url(api_url, "token"),
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30.0,
    )
    if resp.status_code == 200:
        return resp.json()

    try:
        payload = resp.json()
    except ValueError:
        payload = {}
    err = payload.get("error", "")

    if err == "authorization_pending":
        return PENDING
    if err == "slow_down":
        return SLOW_DOWN
    if err in ("access_denied", "expired_token"):
        raise OpError(
            resp.status_code,
            {
                "access_denied": "Login was denied in the browser.",
                "expired_token": "The login request expired. Run 'geopera login' again.",
            }[err],
        )
    raise OpError(
        resp.status_code,
        payload.get("error_description") or err or "Device login failed.",
    )


def logout_oauth(api_url: str, auth_entry: dict[str, Any]) -> None:
    """Best-effort RP-initiated logout for an OAuth session (ignore failures)."""
    refresh_token = auth_entry.get("refresh_token")
    if not refresh_token:
        return
    try:
        httpx.post(
            config.realm_url(api_url, "logout"),
            data={"client_id": config.CLIENT_ID, "refresh_token": refresh_token},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10.0,
        )
    except httpx.HTTPError:
        pass


def wait_for_device_authorization(
    api_url: str,
    device: dict[str, Any],
    pkce_verifier: str | None,
    on_tick=None,
) -> dict[str, Any]:
    """Poll until the user authorizes, the request expires, or it is denied.

    `on_tick` (if given) is called once per poll so the caller can render a
    spinner. Honours `interval`, `slow_down`, and `expires_in` as the deadline.
    """
    interval = int(device.get("interval", 5))
    deadline = time.time() + int(device.get("expires_in", 600))
    device_code = device["device_code"]

    while time.time() < deadline:
        if on_tick:
            on_tick()
        time.sleep(interval)
        result = poll_token(api_url, device_code, pkce_verifier)
        if result == PENDING:
            continue
        if result == SLOW_DOWN:
            interval += 5
            continue
        return result  # token payload

    raise OpError(408, "Login timed out before authorization completed.")
