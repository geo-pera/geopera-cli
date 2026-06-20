"""geopera-cli — command-line interface for the Geopera platform.

A thin auth + dispatch shell over the published `geopera` SDK. Every capability
is reached through /v1/op/{operation_id}; the only CLI-resident logic is auth
(device flow, token refresh, and the Bearer / X-API-Key choice).
"""

__version__ = "0.1.0"
