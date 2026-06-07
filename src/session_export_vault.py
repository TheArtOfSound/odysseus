"""Local encrypted export format for Odysseus session artifacts.

This module intentionally uses established primitives from ``cryptography`` and
keeps the vault format self-contained JSON so exported artifacts remain portable
between Odysseus instances without server-side state.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

VAULT_SCHEMA = "ODYSSEUS-SESSION-VAULT-V1"
KDF_ALGORITHM = "PBKDF2-HMAC-SHA256"
AEAD_ALGORITHM = "AES-256-GCM"
DEFAULT_KDF_ITERATIONS = 600_000
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32
MAX_PASSPHRASE_BYTES = 1024


class SessionVaultError(ValueError):
    """Raised when a vault cannot be created, parsed, or verified."""


def canonical_json_bytes(value: Any) -> bytes:
    """Return a stable UTF-8 JSON encoding for hashing and AEAD AAD."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise SessionVaultError(f"invalid base64 field: {field}") from exc


def _require_passphrase(passphrase: str) -> bytes:
    if not isinstance(passphrase, str) or not passphrase:
        raise SessionVaultError("passphrase is required")
    raw = passphrase.encode("utf-8")
    if len(raw) > MAX_PASSPHRASE_BYTES:
        raise SessionVaultError("passphrase is too long")
    return raw


def _derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    raw = _require_passphrase(passphrase)
    if iterations < 100_000:
        raise SessionVaultError("kdf iteration count is below the accepted minimum")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(raw)


def _aad_for_vault(vault: dict[str, Any]) -> bytes:
    """Build associated data covering all cleartext vault metadata.

    The ciphertext is excluded, but the schema, KDF parameters, metadata, and
    plaintext fingerprint are authenticated. Changing any of them makes decrypt
    fail with the same generic tamper/wrong-passphrase error.
    """

    return canonical_json_bytes(
        {
            "schema": vault.get("schema"),
            "created_at": vault.get("created_at"),
            "kdf": vault.get("kdf"),
            "crypto": {
                "algorithm": (vault.get("crypto") or {}).get("algorithm"),
                "nonce": (vault.get("crypto") or {}).get("nonce"),
            },
            "metadata": vault.get("metadata", {}),
            "plaintext_sha256": vault.get("plaintext_sha256"),
        }
    )


def create_session_vault(
    payload: dict[str, Any],
    passphrase: str,
    *,
    metadata: dict[str, Any] | None = None,
    iterations: int = DEFAULT_KDF_ITERATIONS,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Encrypt a session payload and return ``(vault, receipt)``.

    ``payload`` must be JSON-serializable. ``receipt`` is safe to display; it
    does not include the passphrase or plaintext payload.
    """

    payload_bytes = canonical_json_bytes(payload)
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    created_at = datetime.now(timezone.utc).isoformat()
    plaintext_sha256 = sha256_hex(payload_bytes)

    vault: dict[str, Any] = {
        "schema": VAULT_SCHEMA,
        "created_at": created_at,
        "kdf": {
            "algorithm": KDF_ALGORITHM,
            "iterations": iterations,
            "salt": _b64e(salt),
        },
        "crypto": {
            "algorithm": AEAD_ALGORITHM,
            "nonce": _b64e(nonce),
        },
        "metadata": metadata or {},
        "plaintext_sha256": plaintext_sha256,
    }

    key = _derive_key(passphrase, salt, iterations)
    aad = _aad_for_vault(vault)
    ciphertext = AESGCM(key).encrypt(nonce, payload_bytes, aad)
    vault["aad_sha256"] = sha256_hex(aad)
    vault["ciphertext"] = _b64e(ciphertext)
    vault_sha256 = sha256_hex(canonical_json_bytes(vault))

    receipt = {
        "schema": VAULT_SCHEMA,
        "status": "created",
        "created_at": created_at,
        "payload_type": (metadata or {}).get("payload_type", "session"),
        "plaintext_sha256": plaintext_sha256,
        "vault_sha256": vault_sha256,
        "aad_sha256": vault["aad_sha256"],
        "metadata": metadata or {},
    }
    return vault, receipt


def decrypt_session_vault(
    vault: dict[str, Any],
    passphrase: str,
    *,
    reveal_payload: bool = True,
) -> dict[str, Any]:
    """Verify and decrypt a session vault.

    Returns a verification result. The plaintext payload is included only when
    ``reveal_payload`` is true. Any wrong passphrase or authenticated-field
    modification raises ``SessionVaultError`` with a generic message.
    """

    if not isinstance(vault, dict):
        raise SessionVaultError("vault must be a JSON object")
    if vault.get("schema") != VAULT_SCHEMA:
        raise SessionVaultError("unsupported vault schema")

    kdf = vault.get("kdf") or {}
    crypto = vault.get("crypto") or {}
    if kdf.get("algorithm") != KDF_ALGORITHM:
        raise SessionVaultError("unsupported kdf")
    if crypto.get("algorithm") != AEAD_ALGORITHM:
        raise SessionVaultError("unsupported cipher")

    salt = _b64d(kdf.get("salt", ""), "kdf.salt")
    nonce = _b64d(crypto.get("nonce", ""), "crypto.nonce")
    ciphertext = _b64d(vault.get("ciphertext", ""), "ciphertext")
    iterations = int(kdf.get("iterations", 0))

    if len(salt) != SALT_BYTES:
        raise SessionVaultError("invalid salt length")
    if len(nonce) != NONCE_BYTES:
        raise SessionVaultError("invalid nonce length")

    aad = _aad_for_vault(vault)
    expected_aad_hash = vault.get("aad_sha256")
    if expected_aad_hash and not hmac.compare_digest(expected_aad_hash, sha256_hex(aad)):
        raise SessionVaultError("vault authentication metadata mismatch")

    key = _derive_key(passphrase, salt, iterations)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise SessionVaultError("wrong passphrase or tampered vault") from exc

    actual_plaintext_hash = sha256_hex(plaintext)
    expected_plaintext_hash = vault.get("plaintext_sha256", "")
    if not hmac.compare_digest(actual_plaintext_hash, expected_plaintext_hash):
        raise SessionVaultError("vault plaintext hash mismatch")

    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise SessionVaultError("vault plaintext is not valid JSON") from exc

    vault_sha256 = sha256_hex(canonical_json_bytes(vault))
    result: dict[str, Any] = {
        "ok": True,
        "schema": VAULT_SCHEMA,
        "status": "verified",
        "created_at": vault.get("created_at"),
        "plaintext_sha256": expected_plaintext_hash,
        "vault_sha256": vault_sha256,
        "aad_sha256": sha256_hex(aad),
        "metadata": vault.get("metadata", {}),
    }
    if reveal_payload:
        result["payload"] = payload
    return result


def verify_session_vault(vault: dict[str, Any], passphrase: str) -> dict[str, Any]:
    """Verify a vault without returning plaintext."""

    return decrypt_session_vault(vault, passphrase, reveal_payload=False)
