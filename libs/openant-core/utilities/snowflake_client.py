"""
Snowflake Cortex Anthropic Client Factory

Creates an anthropic.Anthropic client that routes through Snowflake's Cortex
Messages API instead of hitting Anthropic directly.

Authentication (checked in order):
    1. SNOWFLAKE_TOKEN env var  — Pre-acquired OAuth token (e.g. from CI)
    2. SNOWFLAKE_PAT env var    — Programmatic Access Token (legacy)
    3. OAuth browser flow       — Opens browser for interactive login

Required Environment Variables:
    SNOWFLAKE_ACCOUNT: Snowflake account identifier
                       (e.g. SFCOGSOPS-SNOWHOUSE_AWS_US_WEST_2)

Required for OAuth (method 3):
    SNOWFLAKE_USER:    Snowflake username

Optional:
    SNOWFLAKE_TOKEN:   Pre-acquired OAuth access token
    SNOWFLAKE_PAT:     Snowflake Programmatic Access Token (legacy)
    SNOWFLAKE_ROLE:    Snowflake role for OAuth scope

Model Mapping:
    Snowflake Cortex supports the following Claude models:
        claude-opus-4-6, claude-sonnet-4-6,
        claude-opus-4-5, claude-sonnet-4-5, claude-haiku-4-5,
        claude-4-opus, claude-4-sonnet, claude-3-7-sonnet, claude-3-5-sonnet

    The codebase historically used dated model IDs (e.g. claude-opus-4-20250514).
    These are mapped to Snowflake-compatible names automatically.

Usage:
    from utilities.snowflake_client import create_cortex_client, map_model_name

    client = create_cortex_client()
    response = client.messages.create(
        model=map_model_name("claude-opus-4-20250514"),
        max_tokens=8192,
        messages=[{"role": "user", "content": "Hello"}],
    )
"""

import os
import re
import httpx
import anthropic
from dotenv import load_dotenv


# Matches an 8-digit date suffix at the end of a model ID, e.g. "-20250514".
# Cortex rejects these; we use the regex to refuse pass-through and force the
# caller to add a proper alias to MODEL_NAME_MAP.
_DATED_MODEL_SUFFIX = re.compile(r"-\d{8}$")


# Map model IDs → Snowflake Cortex model names. Snowflake uses shorter names
# without date suffixes, so any dated Anthropic ID (e.g. "claude-opus-4-20250514")
# must be translated. The set of canonical Cortex names lives at the bottom
# of the map; the dated-ID aliases above resolve into them.
MODEL_NAME_MAP: dict[str, str] = {
    # --- Dated Anthropic IDs → Cortex equivalents -------------------------
    # Opus 4 series
    "claude-opus-4-20250514": "claude-opus-4-6",
    "claude-opus-4-5-20250929": "claude-opus-4-5",
    # Sonnet 4 series
    "claude-sonnet-4-20250514": "claude-sonnet-4-6",
    "claude-sonnet-4-5-20250929": "claude-sonnet-4-5",
    # Haiku 4 series
    "claude-haiku-4-5-20251001": "claude-haiku-4-5",
    # 3.x series
    "claude-3-7-sonnet-20250219": "claude-3-7-sonnet",
    "claude-3-5-sonnet-20241022": "claude-3-5-sonnet",
    "claude-3-5-sonnet-20240620": "claude-3-5-sonnet",

    # --- Canonical Cortex names (passthrough) ------------------------------
    "claude-opus-4-6": "claude-opus-4-6",
    "claude-sonnet-4-6": "claude-sonnet-4-6",
    "claude-opus-4-5": "claude-opus-4-5",
    "claude-sonnet-4-5": "claude-sonnet-4-5",
    "claude-haiku-4-5": "claude-haiku-4-5",
    "claude-4-opus": "claude-4-opus",
    "claude-4-sonnet": "claude-4-sonnet",
    "claude-3-7-sonnet": "claude-3-7-sonnet",
    "claude-3-5-sonnet": "claude-3-5-sonnet",
}


def map_model_name(model: str) -> str:
    """Map a model identifier to its Snowflake Cortex equivalent.

    Args:
        model: Model name (e.g. "claude-opus-4-20250514" or "claude-opus-4-6").

    Returns:
        Snowflake-compatible model name.

    Raises:
        ValueError: If the model name is not recognized.
    """
    mapped = MODEL_NAME_MAP.get(model)
    if mapped:
        return mapped

    # Dated Anthropic IDs we don't have an explicit alias for: refuse
    # rather than passing through, because Cortex will reject them at
    # request time with a less helpful error.
    if _DATED_MODEL_SUFFIX.search(model):
        raise ValueError(
            f"Unknown dated model ID: {model}. "
            f"Snowflake Cortex does not accept dated Anthropic IDs. "
            f"Add an alias to MODEL_NAME_MAP or use one of: "
            f"{', '.join(sorted(set(MODEL_NAME_MAP.values())))}"
        )

    # Otherwise assume it's already a Cortex-shaped name (no date suffix).
    if model.startswith("claude-"):
        return model

    raise ValueError(
        f"Unknown model: {model}. "
        f"Supported models: {', '.join(sorted(set(MODEL_NAME_MAP.values())))}"
    )


def _get_snowflake_base_url() -> str:
    """Build the Snowflake Cortex Messages API base URL.

    The anthropic SDK appends /v1/messages to the base_url, so we provide
    the path up to /api/v2/cortex which results in:
        https://<account>.snowflakecomputing.com/api/v2/cortex/v1/messages
    """
    account = os.getenv("SNOWFLAKE_ACCOUNT")
    if not account:
        raise ValueError(
            "SNOWFLAKE_ACCOUNT not found in environment. "
            "Set it to your Snowflake account identifier "
            "(e.g. SFCOGSOPS-SNOWHOUSE_AWS_US_WEST_2)."
        )

    # Normalize: if user passed the full URL, strip it
    if account.startswith("https://"):
        account = account.replace("https://", "").rstrip("/")
        if ".snowflakecomputing.com" in account:
            account = account.split(".snowflakecomputing.com")[0]

    return f"https://{account}.snowflakecomputing.com/api/v2/cortex"


def _resolve_bearer_token() -> tuple[str, str]:
    """Resolve a Bearer token for Snowflake Cortex API calls.

    Returns:
        Tuple of (token, token_type) where token_type is one of:
        - "OAUTH" for OAuth access tokens
        - "PROGRAMMATIC_ACCESS_TOKEN" for PATs
    """
    # 1. Pre-acquired OAuth token (from CI, Go CLI, or env)
    token = os.getenv("SNOWFLAKE_TOKEN")
    if token:
        return token, "OAUTH"

    # 2. Legacy PAT
    pat = os.getenv("SNOWFLAKE_PAT")
    if pat:
        return pat, "PROGRAMMATIC_ACCESS_TOKEN"

    # 3. OAuth browser flow
    from utilities.snowflake_auth import get_access_token

    token = get_access_token()
    return token, "OAUTH"


class _TokenManager:
    """Manages OAuth token lifecycle with automatic refresh.

    For PATs (which don't have a refresh mechanism), returns the static token.
    For OAuth tokens, checks expiry and refreshes before each request.
    """

    def __init__(self, token: str, token_type: str):
        self._token = token
        self._token_type = token_type

    @property
    def token(self) -> str:
        if self._token_type != "OAUTH":
            return self._token
        from utilities.snowflake_auth import get_access_token
        self._token = get_access_token()
        return self._token

    @property
    def token_type(self) -> str:
        return self._token_type

    def invalidate_and_refresh(self) -> str:
        """Force a token refresh (call after a 401)."""
        if self._token_type != "OAUTH":
            return self._token
        from utilities.snowflake_auth import _load_cached_token, _save_cached_token, get_access_token
        cached = _load_cached_token()
        if cached:
            cached["expires_at"] = 0
            _save_cached_token(cached)
        self._token = get_access_token()
        return self._token


# Singleton token manager and cached client.
_token_manager: _TokenManager | None = None
_cached_http_client: httpx.Client | None = None


def _inject_auth_header(request: httpx.Request) -> None:
    """Event hook that injects a fresh Bearer token on every outgoing request."""
    if _token_manager is None:
        return
    request.headers["Authorization"] = f"Bearer {_token_manager.token}"
    request.headers["X-Snowflake-Authorization-Token-Type"] = _token_manager.token_type


def _get_http_client(token: str, token_type: str) -> httpx.Client:
    """Get or create a cached httpx.Client with auto-refreshing auth headers."""
    global _cached_http_client, _token_manager
    if _token_manager is None:
        _token_manager = _TokenManager(token, token_type)
    else:
        _token_manager._token = token
        _token_manager._token_type = token_type

    if _cached_http_client is None:
        _cached_http_client = httpx.Client(
            event_hooks={"request": [_inject_auth_header]},
        )
    return _cached_http_client


def create_cortex_client() -> anthropic.Anthropic:
    """Create an Anthropic client routed through Snowflake Cortex.

    Uses the Snowflake Messages API which is 100% compatible with
    the Anthropic Python SDK (messages.create, tool use, streaming, etc.).

    Authentication is resolved in order:
        1. SNOWFLAKE_TOKEN env var (pre-acquired OAuth token)
        2. SNOWFLAKE_PAT env var (legacy Programmatic Access Token)
        3. OAuth browser flow (interactive, opens browser)

    The OAuth token is automatically refreshed when it expires during
    long-running pipeline operations.

    Environment variables required:
        SNOWFLAKE_ACCOUNT: Account identifier

    Returns:
        anthropic.Anthropic client configured for Snowflake Cortex.
    """
    load_dotenv()

    token, token_type = _resolve_bearer_token()
    base_url = _get_snowflake_base_url()

    return anthropic.Anthropic(
        api_key="not-used",  # Required by SDK but Snowflake uses Bearer auth
        base_url=base_url,
        http_client=_get_http_client(token, token_type),
    )
