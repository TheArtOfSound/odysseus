"""Routes for local encrypted session export.

These endpoints are separate from the Bitwarden/Vaultwarden integration in
``routes/vault_routes.py``. They do not use any stored Bitwarden session key and
operate only on caller-owned Odysseus sessions.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from core.database import ChatMessage as DbChatMessage
from core.database import Session as DbSession
from core.database import SessionLocal
from src.auth_helpers import _auth_disabled, effective_user
from src.session_export_vault import (
    SessionVaultError,
    create_session_vault,
    decrypt_session_vault,
    verify_session_vault,
)


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


def setup_session_vault_routes():
    router = APIRouter(prefix="/api/vault/session", tags=["session-vault"])

    @router.post("/{session_id}/export")
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

    @router.post("/verify")
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
