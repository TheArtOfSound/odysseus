"""
vault_routes.py

Vaultwarden / Bitwarden CLI integration — config and unlock endpoints.
Stores the BW_SESSION key in data/vault.json with restrictive permissions.

Also exposes local encrypted session export endpoints. Those endpoints are
owner-scoped and do not use the Bitwarden CLI/session key.
"""

import json
import logging
import os
import shutil
import asyncio
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from core.database import ChatMessage as DbChatMessage
from core.database import Session as DbSession
from core.database import SessionLocal
from core.middleware import require_admin
from core.platform_compat import IS_WINDOWS, safe_chmod, which_tool
from src.auth_helpers import _auth_disabled, effective_user
from src.session_export_vault import (
    SessionVaultError,
    create_session_vault,
    decrypt_session_vault,
    verify_session_vault,
)

logger = logging.getLogger(__name__)

VAULT_FILE = Path("data/vault.json")


def _find_bw() -> str:
    """Locate the bw binary, checking PATH and common npm-global locations.

    On Windows the Bitwarden CLI shim is `bw.cmd`/`bw.exe`, resolved by
    which_tool via PATHEXT.
    """
    p = which_tool("bw")
    if p:
        return p
    if IS_WINDOWS:
        appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
        for candidate in (
            os.path.join(appdata, "npm", "bw.cmd"),
            os.path.join(appdata, "npm", "bw.exe"),
        ):
            if os.path.isfile(candidate):
                return candidate
        return "bw"
    home = os.path.expanduser("~")
    for candidate in (
        f"{home}/.npm-global/bin/bw",
        f"{home}/.nvm/versions/node/*/bin/bw",
        "/usr/local/bin/bw",
        "/opt/homebrew/bin/bw",
    ):
        if "*" in candidate:
            import glob
            for m in glob.glob(candidate):
                if os.path.isfile(m) and os.access(m, os.X_OK):
                    return m
        elif os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return "bw"  # fall back to PATH lookup (will FileNotFoundError, handled below)


def _load_config() -> dict:
    if VAULT_FILE.exists():
        try:
            data = json.loads(VAULT_FILE.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            pass
    return {}


def _save_config(cfg: dict):
    VAULT_FILE.parent.mkdir(parents=True, exist_ok=True)
    VAULT_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    # POSIX: restrict the BW_SESSION store to 0o600. Windows: no-op (profile dir
    # is ACL-restricted already).
    safe_chmod(str(VAULT_FILE), 0o600)


async def _run_bw(args: list, session: str = None, input_text: str = None,
                  bw_password: str = None) -> tuple:
    env = {}
    env.update(os.environ)
    if session:
        env["BW_SESSION"] = session
    # Secrets must never be passed as argv — process arguments are world-readable
    # via `ps` / `/proc/<pid>/cmdline` to any local user. Keep --passwordenv
    # support for bw commands that need it; unlock/login callers should prefer
    # stdin so the master password is not left in the child environment either.
    if bw_password is not None:
        env["BW_PASSWORD"] = bw_password
    bw_path = _find_bw()
    try:
        proc = await asyncio.create_subprocess_exec(
            bw_path, *args,
            stdin=asyncio.subprocess.PIPE if input_text else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
    except FileNotFoundError:
        return "", "bw CLI not installed (install `nodejs-bitwarden-cli` or `bitwarden-cli`)", 127
    except Exception as e:
        return "", f"Failed to launch bw: {e}", 1
    try:
        stdout, stderr = await proc.communicate(input=input_text.encode() if input_text else None)
    except Exception as e:
        return "", f"bw subprocess error: {e}", 1
    return stdout.decode(errors="replace").strip(), stderr.decode(errors="replace").strip(), proc.returncode


class VaultConfig(BaseModel):
    server_url: str = ""
    email: str = ""


class VaultUnlockRequest(BaseModel):
    master_password: str


class VaultLoginRequest(BaseModel):
    email: str
    master_password: str


class SessionVaultExportRequest(BaseModel):
    passphrase: str
    include_hidden: bool = False


class SessionVaultVerifyRequest(BaseModel):
    vault: dict[str, Any]
    passphrase: str
    reveal_payload: bool = False


def _iso(value) -> str | None:
    if not value:
        return None
    try:
        return value.isoformat()
    except Exception:
        return None


def _json_object(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _require_session_owner(request: Request, session_id: str) -> None:
    user = effective_user(request)
    if not user and not _auth_disabled():
        raise HTTPException(401, "Authentication required")

    db = SessionLocal()
    try:
        row = db.query(DbSession.owner).filter(DbSession.id == session_id).first()
        if row is None:
            raise HTTPException(404, f"Session {session_id} not found")
        if not _auth_disabled() and row.owner != user:
            # Match other session routes: do not reveal cross-owner existence.
            raise HTTPException(404, f"Session {session_id} not found")
    finally:
        db.close()


def _load_session_payload(session_id: str, include_hidden: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    db = SessionLocal()
    try:
        row = db.query(DbSession).filter(DbSession.id == session_id).first()
        if not row:
            raise HTTPException(404, f"Session {session_id} not found")

        db_messages = (
            db.query(DbChatMessage)
            .filter(DbChatMessage.session_id == session_id)
            .order_by(DbChatMessage.timestamp)
            .all()
        )
        messages = []
        for msg in db_messages:
            meta = _json_object(getattr(msg, "meta_data", None))
            if meta.get("hidden") and not include_hidden:
                continue
            entry: dict[str, Any] = {
                "role": getattr(msg, "role", "") or "",
                "content": getattr(msg, "content", "") or "",
            }
            timestamp = _iso(getattr(msg, "timestamp", None))
            if timestamp:
                entry["timestamp"] = timestamp
            if meta:
                entry["metadata"] = meta
            messages.append(entry)

        session = {
            "id": row.id,
            "name": row.name or "",
            "model": row.model or "",
            "endpoint_url": row.endpoint_url or "",
            "mode": getattr(row, "mode", None),
            "folder": getattr(row, "folder", None),
            "created_at": _iso(getattr(row, "created_at", None)),
            "updated_at": _iso(getattr(row, "updated_at", None)),
            "last_message_at": _iso(getattr(row, "last_message_at", None)),
            "message_count": len(messages),
        }
        payload = {
            "type": "odysseus.session.export",
            "format_version": 1,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "include_hidden": include_hidden,
            "session": session,
            "messages": messages,
        }
        metadata = {
            "payload_type": "session",
            "session_id": row.id,
            "session_name": row.name or "",
            "message_count": len(messages),
            "include_hidden": include_hidden,
        }
        return payload, metadata
    finally:
        db.close()


def setup_vault_routes():
    router = APIRouter(prefix="/api/vault", tags=["vault"])

    @router.get("/config")
    async def get_config(request: Request):
        """Return vault config (no sensitive fields)."""
        require_admin(request)
        cfg = _load_config()
        return {
            "server_url": cfg.get("server_url", ""),
            "email": cfg.get("email", ""),
            "unlocked": bool(cfg.get("session")),
            "unlocked_at": cfg.get("unlocked_at", ""),
            "bw_installed": await _check_bw_installed(),
        }

    @router.post("/config")
    async def save_config(req: VaultConfig, request: Request):
        """Save vault URL + email. Runs 'bw config server' to point at Vaultwarden."""
        require_admin(request)
        cfg = _load_config()
        cfg["server_url"] = req.server_url.strip().rstrip("/")
        cfg["email"] = req.email.strip()

        if cfg["server_url"]:
            _, stderr, rc = await _run_bw(["config", "server", cfg["server_url"]])
            if rc != 0:
                return {"ok": False, "error": f"bw config failed: {stderr[:300]}"}

        _save_config(cfg)
        return {"ok": True}

    @router.post("/login")
    async def login(req: VaultLoginRequest, request: Request):
        """Log in to Vaultwarden (required once per account)."""
        require_admin(request)
        cfg = _load_config()
        # Update email
        cfg["email"] = req.email
        _save_config(cfg)

        stdout, stderr, rc = await _run_bw(
            ["login", req.email, "--raw"],
            input_text=req.master_password + "\n",
        )
        if rc != 0:
            # Already logged in is OK
            if "already logged in" in stderr.lower():
                return {"ok": True, "already": True}
            return {"ok": False, "error": f"Login failed: {stderr[:300]}"}
        # bw login --raw prints session key on success (when 2FA disabled)
        if stdout:
            cfg["session"] = stdout
            cfg["unlocked_at"] = datetime.utcnow().isoformat()
            _save_config(cfg)
        return {"ok": True}

    @router.post("/unlock")
    async def unlock(req: VaultUnlockRequest, request: Request):
        """Unlock the vault and save the session key."""
        require_admin(request)
        # Pass the master password on stdin, not argv. argv is visible through
        # `ps` / /proc/<pid>/cmdline; stdin also avoids leaving the secret in
        # the child process environment.
        stdout, stderr, rc = await _run_bw(
            ["unlock", "--raw"],
            input_text=req.master_password + "\n",
        )
        if rc != 0:
            return {"ok": False, "error": f"Unlock failed: {stderr[:300]}"}
        session = stdout.strip()
        if not session:
            return {"ok": False, "error": "bw returned empty session"}
        cfg = _load_config()
        cfg["session"] = session
        cfg["unlocked_at"] = datetime.utcnow().isoformat()
        _save_config(cfg)
        return {"ok": True, "message": "Vault unlocked"}

    @router.post("/lock")
    async def lock(request: Request):
        """Lock the vault (clear session from config)."""
        require_admin(request)
        cfg = _load_config()
        cfg.pop("session", None)
        cfg.pop("unlocked_at", None)
        _save_config(cfg)
        # Also tell bw to lock
        await _run_bw(["lock"])
        return {"ok": True, "message": "Vault locked"}

    @router.post("/logout")
    async def logout(request: Request):
        """Log out of the Bitwarden CLI completely."""
        require_admin(request)
        await _run_bw(["logout"])
        cfg = _load_config()
        cfg.pop("session", None)
        cfg.pop("email", None)
        cfg.pop("unlocked_at", None)
        _save_config(cfg)
        return {"ok": True}

    @router.post("/session/{session_id}/export")
    async def export_session_vault(session_id: str, req: SessionVaultExportRequest, request: Request):
        """Export a caller-owned session as an encrypted, tamper-evident vault."""
        _require_session_owner(request, session_id)
        payload, metadata = _load_session_payload(session_id, req.include_hidden)
        user = effective_user(request)
        metadata["exported_by"] = user or "auth-disabled"
        try:
            vault, receipt = create_session_vault(payload, req.passphrase, metadata=metadata)
        except SessionVaultError as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"ok": True, "vault": vault, "receipt": receipt}

    @router.post("/session/verify")
    async def verify_exported_session_vault(req: SessionVaultVerifyRequest, request: Request):
        """Verify/decrypt a local encrypted session vault.

        By default this proves integrity without returning plaintext. Set
        reveal_payload=true when the caller intentionally wants the decrypted
        session export payload returned.
        """
        try:
            if req.reveal_payload:
                result = decrypt_session_vault(req.vault, req.passphrase, reveal_payload=True)
            else:
                result = verify_session_vault(req.vault, req.passphrase)
        except SessionVaultError as exc:
            return {"ok": False, "status": "invalid", "error": str(exc)}
        return result

    return router


async def _check_bw_installed() -> bool:
    try:
        proc = await asyncio.create_subprocess_exec(
            _find_bw(), "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        return proc.returncode == 0
    except Exception:
        return False
