"""
Netflix Password Changer — Beta Feature
Integrates with the Telegram bot to allow changing Netflix account passwords
using the account's NetflixId cookie + current password.
"""
import base64
import json
import os
import time
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

try:
    import requests as _req
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    _req = None  # type: ignore

try:
    from proxy_manager import proxy_manager as _proxy_manager
    _PROXY_ENABLED = True
except Exception:
    _proxy_manager = None  # type: ignore
    _PROXY_ENABLED = False

GRAPHQL_URL = "https://web.prod.cloud.netflix.com/graphql"
APP_VERSION  = "v1db76858"

_BASE_HEADERS = {
    "accept":                              "*/*",
    "accept-language":                     "en-US,en;q=0.9",
    "content-type":                        "application/json",
    "origin":                              "https://www.netflix.com",
    "referer":                             "https://www.netflix.com/",
    "sec-fetch-dest":                      "empty",
    "sec-fetch-mode":                      "cors",
    "sec-fetch-site":                      "same-site",
    "sec-ch-ua":                           '"Not/A)Brand";v="8", "Chromium";v="141", "Google Chrome";v="141"',
    "sec-ch-ua-mobile":                    "?0",
    "sec-ch-ua-platform":                  '"Windows"',
    "user-agent":                          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.7390.55 Safari/537.36",
    "x-netflix.context.app-version":       APP_VERSION,
    "x-netflix.context.locales":           "en-bd",
    "x-netflix.context.ui-flavor":         "akira",
    "x-netflix.request.attempt":           "1",
    "x-netflix.request.client.context":    '{"appstate":"foreground"}',
    "x-netflix.request.originating.url":   "https://www.netflix.com/password",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _b64url_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64url_dec(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def _rand(n: int) -> bytes:
    return os.urandom(n)


def _new_req_id() -> str:
    return _rand(16).hex()


def _new_uuid() -> str:
    b = bytearray(_rand(16))
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    return f"{b[0:4].hex()}-{b[4:6].hex()}-{b[6:8].hex()}-{b[8:10].hex()}-{b[10:16].hex()}"


def _get_proxy() -> dict | None:
    if _PROXY_ENABLED and _proxy_manager and _proxy_manager.changepw_proxy_enabled:
        return _proxy_manager.get_proxies_dict()
    return None


def _build_session(login_url: str) -> "_req.Session":
    """Visit the NFToken login URL to populate browser session cookies."""
    session = _req.Session()
    session.verify = False
    proxy = _get_proxy()
    if proxy:
        session.proxies = proxy
    session.get(
        login_url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        },
        allow_redirects=True,
        timeout=30,
    )
    return session


def _ale_provision(session: "_req.Session", priv_key) -> tuple:
    """
    RSA-OAEP-256 key exchange with Netflix ALE (Authenticated Lightweight Encryption).
    Returns (ale_token, session_key_bytes, kid).
    """
    spki = priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    body = {
        "operationName": "AleProvision",
        "variables": {
            "keyProvisionReq": {
                "ver": 1,
                "scheme": "A128GCM",
                "type": "CLCS",
                "keyx": {
                    "scheme": "RSA-OAEP-256",
                    "data": {"pubkey": _b64url_enc(spki)},
                },
            }
        },
        "extensions": {
            "persistedQuery": {
                "id": "40fdbbd2-af28-4962-bb30-e0025648e2de",
                "version": 102,
            }
        },
    }

    headers = {
        **_BASE_HEADERS,
        "x-netflix.context.operation-name": "AleProvision",
        "x-netflix.request.id": _new_req_id(),
        "x-netflix.request.toplevel.uuid": _new_uuid(),
    }

    resp = session.post(GRAPHQL_URL, json=body, headers=headers, timeout=30)
    resp.raise_for_status()

    data = resp.json()
    prov        = data["data"]["keyProvision"]
    ale_token   = prov["token"]
    wrapped_key = prov["keyx"]["data"]["wrappedkey"]
    kid         = prov["keyx"]["kid"]

    session_key = priv_key.decrypt(
        _b64url_dec(wrapped_key),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ale_token, session_key, kid


def _jwe_encrypt(plaintext: str, session_key: bytes, kid: str) -> str:
    """Encrypt plaintext as a compact A128GCM JWE token."""
    header_b64 = _b64url_enc(
        json.dumps({"alg": "dir", "enc": "A128GCM", "kid": kid}, separators=(",", ":")).encode()
    )
    iv           = _rand(12)
    ct_and_tag   = AESGCM(session_key).encrypt(iv, plaintext.encode("utf-8"), header_b64.encode("ascii"))
    ciphertext   = ct_and_tag[:-16]
    tag          = ct_and_tag[-16:]
    return ".".join([header_b64, "", _b64url_enc(iv), _b64url_enc(ciphertext), _b64url_enc(tag)])


def _graphql_change_password(
    session: "_req.Session",
    ale_token: str,
    session_key: bytes,
    kid: str,
    old_pw: str,
    new_pw: str,
) -> dict:
    """Send the ChangePassword GraphQL mutation with AES-GCM-encrypted passwords."""
    body = {
        "operationName": "ChangePassword",
        "variables": {
            "currentPassword":      {"isEncrypted": True, "value": _jwe_encrypt(old_pw, session_key, kid)},
            "newPassword":          {"isEncrypted": True, "value": _jwe_encrypt(new_pw, session_key, kid)},
            "confirmedNewPassword": {"isEncrypted": True, "value": _jwe_encrypt(new_pw, session_key, kid)},
            "signOutOfAllDevices":  False,
        },
        "extensions": {
            "persistedQuery": {
                "id": "aef2660a-b945-4926-880b-5bae3f7c3586",
                "version": 102,
            }
        },
    }
    headers = {
        **_BASE_HEADERS,
        "x-netflix.context.operation-name": "ChangePassword",
        "x-netflix.context.ale.token":      ale_token,
        "x-netflix.request.id":             _new_req_id(),
        "x-netflix.request.toplevel.uuid":  _new_uuid(),
    }
    resp = session.post(GRAPHQL_URL, json=body, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def change_netflix_password(netflix_id: str, old_password: str, new_password: str) -> dict:
    """
    Change the password for a Netflix account identified by its NetflixId cookie.

    Args:
        netflix_id:   The raw NetflixId cookie value.
        old_password: The account's current password.
        new_password: The desired new password.

    Returns dict with keys:
        success  (bool)   — True if password was changed.
        message  (str)    — Human-readable result or error.
        raw      (dict|None) — Raw Netflix API response.
    """
    if not _CRYPTO_AVAILABLE:
        return {
            "success": False,
            "message": (
                "The <b>cryptography</b> library is not installed.\n"
                "Ask the bot admin to run: <code>pip install cryptography</code>"
            ),
            "raw": None,
        }
    if _req is None:
        return {"success": False, "message": "requests library not available.", "raw": None}

    # ── Step 1: Authenticate via NFToken ──────────────────────────────────
    try:
        from checker import generate_nftoken
        nft = generate_nftoken({"NetflixId": netflix_id})
        if not nft.get("success"):
            return {
                "success": False,
                "message": f"Authentication failed: {nft.get('error', 'NFToken generation failed')}",
                "raw": None,
            }
        login_url = nft["pc_url"]
    except Exception as exc:
        return {"success": False, "message": f"Auth step error: {exc}", "raw": None}

    # ── Step 2: Build browser session using NFToken login URL ─────────────
    try:
        session = _build_session(login_url)
    except Exception as exc:
        return {"success": False, "message": f"Session setup failed: {exc}", "raw": None}

    # ── Step 3: ALE key exchange (RSA-OAEP-256) ───────────────────────────
    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    try:
        ale_token, session_key, kid = _ale_provision(session, priv_key)
    except Exception as exc:
        return {"success": False, "message": f"Key exchange failed: {exc}", "raw": None}

    # ── Step 4: Submit encrypted password change ──────────────────────────
    time.sleep(1)
    try:
        raw = _graphql_change_password(session, ale_token, session_key, kid, old_password, new_password)
    except Exception as exc:
        return {"success": False, "message": f"API request failed: {exc}", "raw": None}

    # ── Parse response ────────────────────────────────────────────────────
    # Map Netflix error codes → user-friendly messages
    _ERROR_MESSAGES = {
        "INCORRECT_PASSWORD":        "❌ Current password is wrong. Double-check and try again.",
        "PASSWORD_TOO_SHORT":        "❌ New password is too short (Netflix requires at least 8 chars).",
        "PASSWORD_TOO_COMMON":       "❌ New password is too common. Choose a stronger password.",
        "PASSWORD_SAME_AS_CURRENT":  "❌ New password must be different from the current password.",
        "ACCOUNT_LOCKED":            "❌ Account is locked. Try logging in on Netflix.com first.",
        "RATE_LIMIT":                "❌ Too many attempts. Wait a few minutes and try again.",
        "SESSION_EXPIRED":           "❌ Session expired. The cookie may have been revoked.",
        "INVALID_PASSWORD":          "❌ Password is invalid (bad characters or too long).",
    }

    # Top-level GraphQL errors
    errors = raw.get("errors")
    if errors:
        msgs = "; ".join(e.get("message", "?") for e in errors[:2])
        return {"success": False, "message": f"Netflix error: {msgs}", "raw": raw}

    node = raw.get("data", {}).get("growthChangePassword", {})
    typename = node.get("__typename", "")

    # Success: Netflix redirects to account page
    if node.get("userJourneyNodeName") == "YOUR_ACCOUNT" or (
        typename and "Error" not in typename and "error" not in typename
        and typename not in ("", "null")
    ):
        return {"success": True, "message": "Password changed successfully!", "raw": raw}

    # Known error type from Netflix
    if typename == "GrowthMutationError":
        code = node.get("errorCode", "UNKNOWN")
        friendly = _ERROR_MESSAGES.get(code, f"Netflix refused the request (code: {code})")
        return {"success": False, "message": friendly, "raw": raw}

    # Any other error typename
    if typename and "Error" in typename:
        code = node.get("errorCode") or node.get("message") or typename
        return {"success": False, "message": f"Netflix error: {code}", "raw": raw}

    return {
        "success": False,
        "message": f"Unexpected response (type: {typename or 'unknown'}) — password may not have changed.",
        "raw": raw,
    }
