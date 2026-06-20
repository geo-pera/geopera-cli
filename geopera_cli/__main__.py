"""geopera — command-line interface for the Geopera geospatial data platform.

The CLI is a thin auth + dispatch shell over the published `geopera` SDK. The
only CLI-resident logic is auth: the device flow, token refresh, and the
Bearer / X-API-Key choice. Every capability is reached through
/v1/op/{operation_id}, so a new backend operation is instantly usable as
`geopera op <new.op>` with zero CLI changes.
"""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import os
import secrets
import sys
import threading
import time
import webbrowser
from typing import Optional

import typer

from . import auth, client, config

app = typer.Typer(
    name="geopera",
    help="Command-line interface for the Geopera geospatial data platform.",
    no_args_is_help=True,
    add_completion=True,
)

err = typer.echo


# ---------------------------------------------------------------------------
# Shared options
# ---------------------------------------------------------------------------

ProfileOpt = typer.Option(
    None,
    "--profile",
    help="Stored identity to use (env: GEOPERA_PROFILE). Default: 'default'.",
)
ApiUrlOpt = typer.Option(
    None,
    "--api-url",
    help=f"API base URL override (env: GEOPERA_API_URL). Default: {config.DEFAULT_API_URL}.",
)


def _fail(message: str, code: int = 1) -> None:
    """Print an error to stderr and exit non-zero."""
    typer.secho(f"Error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code)


def _print_json(value) -> None:
    typer.echo(json.dumps(value, indent=2, sort_keys=False, default=str))


def _pkce_pair() -> tuple[str, str]:
    """Generate a PKCE (verifier, S256 challenge) pair."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


class _Spinner:
    """A tiny stderr spinner used while polling for device authorization."""

    def __init__(self, message: str):
        self.message = message
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        for frame in itertools.cycle("|/-\\"):
            if self._stop.is_set():
                break
            sys.stderr.write(f"\r{self.message} {frame}")
            sys.stderr.flush()
            time.sleep(0.1)

    def __enter__(self) -> "_Spinner":
        if sys.stderr.isatty():
            self._thread.start()
        return self

    def __exit__(self, *args) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=0.3)
        if sys.stderr.isatty():
            sys.stderr.write("\r" + " " * (len(self.message) + 4) + "\r")
            sys.stderr.flush()


# ---------------------------------------------------------------------------
# login
# ---------------------------------------------------------------------------

@app.command()
def login(
    api_key: Optional[str] = typer.Option(
        None,
        "--api-key",
        help="Skip the device flow and store an API key. Use '-' to read from stdin.",
    ),
    api_url: Optional[str] = ApiUrlOpt,
    no_browser: bool = typer.Option(
        False, "--no-browser", help="Do not auto-open the verification URL."
    ),
    scope: str = typer.Option(
        config.DEFAULT_SCOPE, "--scope", help="OAuth scope to request."
    ),
    profile: Optional[str] = ProfileOpt,
):
    """Authenticate. Device flow by default; --api-key for headless use."""
    profile = config.resolve_profile(profile)
    stored = auth.load_profile(profile)
    resolved_url = config.resolve_api_url(api_url, stored.get("api_url"))

    if api_key is not None:
        _login_api_key(profile, resolved_url, api_key)
        return

    _login_device(profile, resolved_url, scope, no_browser)


def _login_api_key(profile: str, api_url: str, api_key: str) -> None:
    """Validate and store an API key (kept out of shell history when piped)."""
    if api_key == "-":
        api_key = sys.stdin.readline().strip()
    if not api_key:
        _fail("No API key provided.")

    if not api_key.startswith("gpra_"):
        typer.secho(
            "Note: this key has no 'gpra_' prefix. It will still work, but new "
            "Geopera keys are expected to start with 'gpra_'.",
            fg=typer.colors.YELLOW,
            err=True,
        )

    ctx = auth.AuthContext(profile, api_url, {"type": "api_key", "api_key": api_key})
    try:
        info = client.userinfo(ctx)
    except client.OpError as exc:
        _fail(f"API key validation failed: {exc.message}")

    auth.save_profile(
        profile,
        {"api_url": api_url, "auth": {"type": "api_key", "api_key": api_key}},
    )
    who = info.get("geopera_principal_id") or info.get("sub") or "api key"
    typer.secho(f"Logged in as {who} (API key, profile '{profile}').", fg=typer.colors.GREEN)


def _login_device(profile: str, api_url: str, scope: str, no_browser: bool) -> None:
    """RFC 8628 device authorization grant with PKCE."""
    verifier, challenge = _pkce_pair()
    try:
        device = client.device_authorize(api_url, scope, challenge)
    except client.OpError as exc:
        _fail(exc.message)

    user_code = device.get("user_code", "")
    verification_uri = device.get("verification_uri", "")
    complete = device.get("verification_uri_complete") or verification_uri

    typer.echo()
    typer.secho("  To sign in, visit:", bold=True)
    typer.secho(f"    {complete}", fg=typer.colors.CYAN)
    typer.echo()
    typer.secho("  And confirm this code:", bold=True)
    typer.secho(f"    {user_code}", fg=typer.colors.GREEN, bold=True)
    typer.echo()

    if not no_browser and complete:
        try:
            webbrowser.open(complete)
        except Exception:  # noqa: BLE001 - browser launch is best-effort
            pass

    with _Spinner("Waiting for authorization..."):
        try:
            token = client.wait_for_device_authorization(api_url, device, verifier)
        except client.OpError as exc:
            _fail(exc.message)

    auth_entry = auth._auth_from_token_response(api_url, token)
    auth.save_profile(profile, {"api_url": api_url, "auth": auth_entry})

    # Confirm with a userinfo round-trip.
    ctx = auth.AuthContext(profile, api_url, auth_entry)
    try:
        info = client.userinfo(ctx)
        who = info.get("sub") or "user"
    except client.OpError:
        who = "user"
    typer.secho(f"Logged in as {who} (profile '{profile}').", fg=typer.colors.GREEN)


# ---------------------------------------------------------------------------
# logout
# ---------------------------------------------------------------------------

@app.command()
def logout(profile: Optional[str] = ProfileOpt):
    """Clear the active profile's stored credentials."""
    profile = config.resolve_profile(profile)
    entry = auth.load_profile(profile)
    auth_entry = entry.get("auth", {})

    if auth_entry.get("type") == "oauth":
        client.logout_oauth(entry.get("api_url", config.DEFAULT_API_URL), auth_entry)

    if auth.clear_profile(profile):
        typer.secho(f"Logged out (profile '{profile}').", fg=typer.colors.GREEN)
    else:
        typer.echo(f"No stored credentials for profile '{profile}'.")


# ---------------------------------------------------------------------------
# whoami
# ---------------------------------------------------------------------------

@app.command()
def whoami(
    api_url: Optional[str] = ApiUrlOpt,
    profile: Optional[str] = ProfileOpt,
    raw: bool = typer.Option(False, "--json", help="Print the raw userinfo JSON."),
):
    """Show the authenticated principal, org, and scopes."""
    try:
        ctx = auth.load_context(profile, api_url)
        info = client.userinfo(ctx)
    except (auth.AuthError, client.OpError) as exc:
        _fail(str(getattr(exc, "message", exc)))

    if raw:
        _print_json(info)
        return

    typer.secho(f"sub:             {info.get('sub', '-')}", fg=typer.colors.GREEN)
    typer.echo(f"principal_type:  {info.get('geopera_principal_type', '-')}")
    typer.echo(f"org_id:          {info.get('geopera_org_id', '-')}")
    typer.echo(f"scope:           {info.get('scope', '-')}")
    typer.echo(f"api_url:         {ctx.api_url}")
    typer.echo(f"profile:         {ctx.profile}")


# ---------------------------------------------------------------------------
# op — generic operation dispatch
# ---------------------------------------------------------------------------

@app.command()
def op(
    operation_id: Optional[str] = typer.Argument(
        None, help="Operation id, e.g. orders.estimate or catalog.federated_search."
    ),
    body: Optional[str] = typer.Argument(
        None, help="JSON request body. Use '-' to read from stdin."
    ),
    file: Optional[str] = typer.Option(
        None, "--file", "-f", help="Read the JSON body from a file."
    ),
    list_ops: bool = typer.Option(
        False, "--list", help="List available operation ids and exit."
    ),
    api_url: Optional[str] = ApiUrlOpt,
    profile: Optional[str] = ProfileOpt,
):
    """Invoke any operation: POST /v1/op/OPERATION_ID with a JSON body."""
    if list_ops:
        _list_operations(api_url, profile)
        return

    if not operation_id:
        _fail("OPERATION_ID is required (or use --list).")

    payload = _resolve_body(body, file)

    try:
        ctx = auth.load_context(profile, api_url)
        result = client.invoke_op(ctx, operation_id, payload)
    except auth.AuthError as exc:
        _fail(str(exc))
    except client.OpError as exc:
        # problem+json -> readable message + non-zero exit.
        detail = exc.detail.get("detail") or exc.detail.get("title")
        msg = f"[{exc.status}] {exc.message}"
        if detail and detail != exc.message:
            msg += f" — {detail}"
        _fail(msg, code=2)

    _print_json(result)


def _resolve_body(body: Optional[str], file: Optional[str]):
    """Resolve the JSON body from --file, stdin ('-'), positional arg, or {}."""
    if file:
        try:
            with open(file, encoding="utf-8") as fh:
                raw = fh.read()
        except OSError as exc:
            _fail(f"Cannot read --file: {exc}")
    elif body == "-":
        raw = sys.stdin.read()
    elif body:
        raw = body
    else:
        return {}

    raw = raw.strip()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        _fail(f"Invalid JSON body: {exc}")


def _list_operations(api_url: Optional[str], profile: Optional[str]) -> None:
    """List operation ids from the live OpenAPI document."""
    try:
        ctx_url = config.resolve_api_url(
            api_url, auth.load_profile(config.resolve_profile(profile)).get("api_url")
        )
    except Exception:  # noqa: BLE001
        ctx_url = config.resolve_api_url(api_url, None)

    import httpx

    try:
        resp = httpx.get(f"{ctx_url}/openapi.json", timeout=30.0)
        resp.raise_for_status()
        paths = resp.json().get("paths", {})
    except (httpx.HTTPError, ValueError) as exc:
        _fail(f"Could not fetch operation list: {exc}")

    ops = sorted(
        p[len("/v1/op/") :] for p in paths if p.startswith("/v1/op/")
    )
    for op_id in ops:
        typer.echo(op_id)
    typer.secho(f"\n{len(ops)} operations.", fg=typer.colors.BLUE, err=True)


# ---------------------------------------------------------------------------
# orders — curated subcommand (thin alias over `op`)
# ---------------------------------------------------------------------------

orders_app = typer.Typer(help="Curated order commands (thin aliases over `op`).")
app.add_typer(orders_app, name="orders")


@orders_app.command("list")
def orders_list(
    api_url: Optional[str] = ApiUrlOpt,
    profile: Optional[str] = ProfileOpt,
    raw: bool = typer.Option(False, "--json", help="Print raw JSON instead of a table."),
):
    """List your orders (alias for `op orders.list`)."""
    try:
        ctx = auth.load_context(profile, api_url)
        result = client.invoke_op(ctx, "orders.list", {})
    except auth.AuthError as exc:
        _fail(str(exc))
    except client.OpError as exc:
        _fail(f"[{exc.status}] {exc.message}", code=2)

    rows = result.get("orders", result) if isinstance(result, dict) else result
    if raw or not isinstance(rows, list):
        _print_json(result)
        return

    if not rows:
        typer.echo("No orders.")
        return

    for row in rows:
        oid = row.get("id", "-")
        name = row.get("display_name") or row.get("name") or "-"
        status = row.get("status", "-")
        typer.echo(f"{oid:<38}  {status:<14}  {name}")


def main() -> None:  # console-script-friendly entry (pyproject uses `app`)
    app()


if __name__ == "__main__":
    main()
