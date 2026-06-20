# geopera-cli

Command-line interface for the [Geopera](https://docs.geopera.com) geospatial
data platform.

`geopera-cli` is a **thin auth + dispatch shell** over the published
[`geopera` Python SDK](https://github.com/geo-pera/geopera-python). The only
logic that lives in the CLI is authentication — the OAuth device flow, token
refresh, and the choice between a `Bearer` token and an `X-API-Key` header.
Every actual capability is reached through the generic kernel endpoint
`POST /v1/op/{operation_id}`, so any of the ~227 operations is callable with no
per-command code, and a new backend operation is instantly usable as
`geopera op <new.op>` with zero CLI changes.

## Install

```bash
pip install geopera-cli
```

This pulls in the `geopera` SDK, `typer`, and `httpx`.

## Quick start

```bash
# Sign in (opens your browser; RFC 8628 device flow)
geopera login

# Who am I?
geopera whoami

# Price-preview an order (generic op dispatch)
geopera op orders.estimate '{"aoi": {...}, "product": "..."}'

# Search across every registered public data source
geopera op catalog.federated_search '{"bbox": [...], "datetime": "..."}'

# List every available operation id
geopera op --list

# Curated alias with table output
geopera orders list
```

## Commands

| Command | Description |
| --- | --- |
| `geopera login` | Device-flow login (default). `--api-key KEY` stores a key instead (`-` reads from stdin). `--api-url URL`, `--no-browser`, `--scope`. |
| `geopera logout` | Clear the active profile's stored credentials (best-effort OAuth logout). |
| `geopera whoami` | Show principal / org / scope (validates the session). `--json` for raw output. |
| `geopera op OPERATION_ID [JSON]` | Generic kernel dispatch. Body from positional arg, `--file`, or `-` (stdin). `--list` enumerates operations. |
| `geopera orders list` | Curated alias over `op orders.list` with table formatting. |

Global flags `--profile NAME` (env `GEOPERA_PROFILE`) and `--api-url URL`
(env `GEOPERA_API_URL`) are accepted on every command.

## Authentication

### Device flow (default)

`geopera login` performs the OAuth 2.0 Device Authorization Grant
([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)) with PKCE:

1. Requests a device + user code from
   `{api_url}/realms/public/protocol/openid-connect/auth/device`.
2. Prints the user code and opens the verification URL in your browser
   (skip with `--no-browser`).
3. Polls the token endpoint until you approve, then stores the access and
   refresh tokens.

Access tokens are refreshed automatically — proactively when within 30s of
expiry, and reactively on any `401` — using the stored refresh token. The
backend rotates the refresh token, so both tokens are rewritten on each
refresh.

### API key (headless)

```bash
geopera login --api-key gpra_xxxxxxxx
# or, keeping the key out of shell history:
printf '%s' "$GEOPERA_KEY" | geopera login --api-key -
```

API keys are sent as `X-API-Key`, which the Geopera kernel accepts on every
authenticated endpoint.

### Profiles

Multiple identities are namespaced by profile:

```bash
geopera login --profile staging --api-url https://staging.api.geopera.com
geopera --help                      # default profile
GEOPERA_PROFILE=staging geopera whoami
geopera whoami --profile staging
```

## Credential store

Credentials live in `~/.config/geopera/credentials.json` (directory `0700`,
file `0600`). Each top-level key is a profile:

```json
{
  "default": {
    "api_url": "https://api.geopera.com",
    "auth": {
      "type": "oauth",
      "access_token": "...",
      "refresh_token": "...",
      "expires_at": 1750000000,
      "scope": "openid profile",
      "issuer": "https://api.geopera.com"
    }
  }
}
```

For an API key profile the `auth` block is
`{"type": "api_key", "api_key": "gpra_..."}`.

### Environment overrides

- `GEOPERA_API_URL` — base URL override (below `--api-url`, above the stored value).
- `GEOPERA_PROFILE` — active profile name.
- `GEOPERA_API_TOKEN` — opaque bearer/API-key for ephemeral (e.g. CI) use,
  bypassing the store. A value starting with `gpra_` is treated as an API key.

## Configuration precedence

API base URL: `--api-url` flag → `GEOPERA_API_URL` → stored `api_url` →
`https://api.geopera.com`.

## License

[MIT](./LICENSE)
