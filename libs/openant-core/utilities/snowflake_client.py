"""
Snowflake Cortex Anthropic Client Factory

Creates an anthropic.Anthropic client that routes through Snowflake's Cortex
Messages API instead of hitting Anthropic directly. This allows using a
Snowflake PAT (Programmatic Access Token) for authentication.

Required Environment Variables:
    SNOWFLAKE_PAT:     Snowflake Programmatic Access Token
    SNOWFLAKE_ACCOUNT: Snowflake account identifier
                       (e.g. SFCOGSOPS-SNOWHOUSE_AWS_US_WEST_2)

Optional:
    SNOWFLAKE_USER:    Snowflake username (informational only)

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
import httpx
import anthropic
from dotenv import load_dotenv


# Map old Anthropic model IDs → Snowflake Cortex model names.
# Snowflake uses shorter names without date suffixes.
MODEL_NAME_MAP: dict[str, str] = {
    # Dated Anthropic IDs used throughout the codebase
    "claude-opus-4-20250514": "claude-opus-4-6",
    "claude-sonnet-4-20250514": "claude-sonnet-4-6",
    # Already Snowflake-compatible names (passthrough)
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

    # If it looks like it could already be a valid Cortex name, pass through
    if model.startswith("claude-"):
        return model

    raise ValueError(
        f"Unknown model: {model}. "
        f"Supported models: {', '.join(sorted(MODEL_NAME_MAP.keys()))}"
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


def _get_snowflake_pat() -> str:
    """Get the Snowflake PAT from environment."""
    pat = os.getenv("SNOWFLAKE_PAT")
    if not pat:
        raise ValueError(
            "SNOWFLAKE_PAT not found in environment. "
            "Generate a Programmatic Access Token in Snowsight: "
            "Settings → Authentication → Programmatic Access Tokens."
        )
    return pat


# Cache a single httpx.Client so we reuse connections.
_cached_http_client: httpx.Client | None = None


def _get_http_client(pat: str) -> httpx.Client:
    """Get or create a cached httpx.Client with Bearer auth."""
    global _cached_http_client
    if _cached_http_client is None:
        _cached_http_client = httpx.Client(
            headers={"Authorization": f"Bearer {pat}"},
        )
    return _cached_http_client


def create_cortex_client() -> anthropic.Anthropic:
    """Create an Anthropic client routed through Snowflake Cortex.

    Uses the Snowflake Messages API which is 100% compatible with
    the Anthropic Python SDK (messages.create, tool use, streaming, etc.).

    Environment variables required:
        SNOWFLAKE_PAT:     Programmatic Access Token
        SNOWFLAKE_ACCOUNT: Account identifier

    Returns:
        anthropic.Anthropic client configured for Snowflake Cortex.
    """
    load_dotenv()

    pat = _get_snowflake_pat()
    base_url = _get_snowflake_base_url()

    return anthropic.Anthropic(
        api_key="not-used",  # Required by SDK but Snowflake uses Bearer auth
        base_url=base_url,
        http_client=_get_http_client(pat),
        default_headers={"Authorization": f"Bearer {pat}"},
    )
