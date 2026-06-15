"""
Snowflake OAuth Browser Authentication

Implements the OAuth 2.0 Authorization Code flow with PKCE for local
applications, using Snowflake's built-in LOCAL_APPLICATION client.

This opens the user's browser for authentication and receives the callback
on a local HTTP server. No Snowflake admin setup is required — the
LOCAL_APPLICATION integration is built into every Snowflake account.

Token caching:
    Tokens are cached to ~/.config/openant/oauth_token.json so the browser
    flow only triggers on first use or when the refresh token expires.

Usage:
    from utilities.snowflake_auth import get_access_token

    token = get_access_token(account="ORG-ACCOUNT", user="USER")
    # Use token as Bearer in Cortex API calls
"""

import base64
import hashlib
import json
import os
import secrets
import sys
import threading
import time
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlencode, urlparse, parse_qs

import httpx


# Snowflake's built-in OAuth client for local applications.
# No security integration setup required.
_OAUTH_CLIENT_ID = "LOCAL_APPLICATION"
_OAUTH_CLIENT_SECRET = "LOCAL_APPLICATION"

_TOKEN_CACHE_FILENAME = "oauth_token.json"

# How many seconds before expiry to consider a token stale and refresh it.
_REFRESH_BUFFER_SECONDS = 120


def _config_dir() -> str:
    """Return the openant config directory (~/.config/openant/)."""
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return os.path.join(xdg, "openant")
    return os.path.join(os.path.expanduser("~"), ".config", "openant")


def _token_cache_path() -> str:
    return os.path.join(_config_dir(), _TOKEN_CACHE_FILENAME)


def _load_cached_token() -> dict | None:
    path = _token_cache_path()
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _save_cached_token(token_data: dict) -> None:
    dir_path = _config_dir()
    os.makedirs(dir_path, mode=0o700, exist_ok=True)
    path = _token_cache_path()
    with open(path, "w") as f:
        json.dump(token_data, f, indent=2)
    os.chmod(path, 0o600)


def _account_hostname(account: str) -> str:
    """Convert account identifier to hostname (underscores become hyphens)."""
    return account.replace("_", "-")


def _generate_pkce() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge (S256)."""
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


class _OAuthCallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler that captures the OAuth authorization code from the redirect."""

    auth_code: str | None = None
    error: str | None = None

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if "code" in params:
            _OAuthCallbackHandler.auth_code = params["code"][0]
            self._respond(
                200,
                "<html><body><h2>Authentication successful!</h2>"
                "<p>You can close this browser tab and return to your terminal.</p>"
                "</body></html>",
            )
        elif "error" in params:
            error_desc = params.get("error_description", [params["error"]])[0]
            _OAuthCallbackHandler.error = error_desc
            self._respond(
                400,
                f"<html><body><h2>Authentication failed</h2>"
                f"<p>{error_desc}</p></body></html>",
            )
        else:
            self._respond(400, "<html><body><p>Unexpected callback</p></body></html>")

    def _respond(self, code: int, body: str):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        pass  # Suppress request logging


def _do_browser_auth(account: str, user: str, role: str | None = None) -> dict:
    """Run the full OAuth browser flow. Returns token response dict."""
    hostname = _account_hostname(account)
    base_url = f"https://{hostname}.snowflakecomputing.com"

    code_verifier, code_challenge = _generate_pkce()

    # Start local server on a random available port
    server = HTTPServer(("127.0.0.1", 0), _OAuthCallbackHandler)
    port = server.server_address[1]
    redirect_uri = f"http://127.0.0.1:{port}"

    # Build authorization URL
    params = {
        "client_id": _OAUTH_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "login_name": user,
    }
    if role:
        params["scope"] = f"session:role:{role}"

    auth_url = f"{base_url}/oauth/authorize?{urlencode(params)}"

    # Reset handler state
    _OAuthCallbackHandler.auth_code = None
    _OAuthCallbackHandler.error = None

    print(
        f"Opening browser for Snowflake authentication...",
        file=sys.stderr,
    )
    print(f"If the browser doesn't open, visit: {auth_url}", file=sys.stderr)

    # Open browser in a thread to avoid blocking
    threading.Thread(target=webbrowser.open, args=(auth_url,), daemon=True).start()

    # Wait for callback (timeout after 5 minutes)
    server.timeout = 300
    while _OAuthCallbackHandler.auth_code is None and _OAuthCallbackHandler.error is None:
        server.handle_request()

    server.server_close()

    if _OAuthCallbackHandler.error:
        raise RuntimeError(
            f"Snowflake OAuth authentication failed: {_OAuthCallbackHandler.error}"
        )

    if not _OAuthCallbackHandler.auth_code:
        raise RuntimeError("OAuth authentication timed out. Please try again.")

    # Exchange authorization code for tokens
    token_url = f"{base_url}/oauth/token-request"
    token_data = {
        "grant_type": "authorization_code",
        "code": _OAuthCallbackHandler.auth_code,
        "redirect_uri": redirect_uri,
        "client_id": _OAUTH_CLIENT_ID,
        "code_verifier": code_verifier,
    }

    resp = httpx.post(
        token_url,
        data=token_data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Basic "
            + base64.b64encode(
                f"{_OAUTH_CLIENT_ID}:{_OAUTH_CLIENT_SECRET}".encode()
            ).decode(),
        },
        timeout=30.0,
    )

    if resp.status_code != 200:
        raise RuntimeError(
            f"Token exchange failed (HTTP {resp.status_code}): {resp.text}"
        )

    token_resp = resp.json()

    # Store metadata alongside the token
    cached = {
        "access_token": token_resp["access_token"],
        "refresh_token": token_resp.get("refresh_token", ""),
        "token_type": token_resp.get("token_type", "Bearer"),
        "expires_at": time.time() + token_resp.get("expires_in", 3600),
        "account": account,
        "user": user,
    }
    if role:
        cached["role"] = role

    _save_cached_token(cached)
    print("Authentication successful.", file=sys.stderr)
    return cached


def _refresh_token(account: str, refresh_token: str) -> dict | None:
    """Attempt to refresh the access token using a refresh token."""
    hostname = _account_hostname(account)
    base_url = f"https://{hostname}.snowflakecomputing.com"
    token_url = f"{base_url}/oauth/token-request"

    resp = httpx.post(
        token_url,
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": _OAUTH_CLIENT_ID,
        },
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Basic "
            + base64.b64encode(
                f"{_OAUTH_CLIENT_ID}:{_OAUTH_CLIENT_SECRET}".encode()
            ).decode(),
        },
        timeout=30.0,
    )

    if resp.status_code != 200:
        return None

    token_resp = resp.json()
    return {
        "access_token": token_resp["access_token"],
        "refresh_token": token_resp.get("refresh_token", refresh_token),
        "token_type": token_resp.get("token_type", "Bearer"),
        "expires_at": time.time() + token_resp.get("expires_in", 3600),
    }


def get_access_token(
    account: str | None = None,
    user: str | None = None,
    role: str | None = None,
) -> str:
    """Get a valid OAuth access token, refreshing or re-authenticating as needed.

    Resolution order:
        1. SNOWFLAKE_TOKEN env var (pre-acquired token, e.g. from CI)
        2. Cached token (refreshed automatically if expired)
        3. Browser-based OAuth flow (interactive)

    Args:
        account: Snowflake account identifier. Falls back to SNOWFLAKE_ACCOUNT env var.
        user: Snowflake username. Falls back to SNOWFLAKE_USER env var.
        role: Snowflake role for OAuth scope. Falls back to SNOWFLAKE_ROLE env var.

    Returns:
        A valid access token string.
    """
    # Check for pre-set token (e.g. from CI or Go CLI passing it through)
    env_token = os.getenv("SNOWFLAKE_TOKEN")
    if env_token:
        return env_token

    account = account or os.getenv("SNOWFLAKE_ACCOUNT")
    user = user or os.getenv("SNOWFLAKE_USER")
    role = role or os.getenv("SNOWFLAKE_ROLE")

    if not account:
        raise ValueError(
            "SNOWFLAKE_ACCOUNT not found. "
            "Set it via environment variable or run: openant config set snowflake-account"
        )
    if not user:
        raise ValueError(
            "SNOWFLAKE_USER is required for OAuth authentication. "
            "Set it via environment variable or run: openant config set snowflake-user"
        )

    # Try cached token
    cached = _load_cached_token()
    if cached and cached.get("account") == account:
        expires_at = cached.get("expires_at", 0)

        # Token still valid
        if time.time() < expires_at - _REFRESH_BUFFER_SECONDS:
            return cached["access_token"]

        # Try refresh
        refresh = cached.get("refresh_token")
        if refresh:
            refreshed = _refresh_token(account, refresh)
            if refreshed:
                cached.update(refreshed)
                _save_cached_token(cached)
                return cached["access_token"]

    # Fall through to browser auth
    token_data = _do_browser_auth(account, user, role)
    return token_data["access_token"]


def clear_cached_token() -> None:
    """Remove the cached OAuth token (for logout)."""
    path = _token_cache_path()
    if os.path.exists(path):
        os.remove(path)
        print("OAuth token cache cleared.", file=sys.stderr)
