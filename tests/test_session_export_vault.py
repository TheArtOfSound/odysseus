import copy

import pytest

from src.session_export_vault import (
    VAULT_SCHEMA,
    SessionVaultError,
    create_session_vault,
    decrypt_session_vault,
    verify_session_vault,
)


def _payload():
    return {
        "type": "odysseus.session.export",
        "session": {"id": "s1", "name": "demo", "model": "local-test"},
        "messages": [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "world"},
        ],
    }


def test_create_and_decrypt_session_vault_round_trip():
    vault, receipt = create_session_vault(
        _payload(),
        "correct horse battery staple",
        metadata={"payload_type": "session", "session_id": "s1"},
        iterations=100_000,
    )

    assert vault["schema"] == VAULT_SCHEMA
    assert receipt["status"] == "created"
    assert "ciphertext" in vault
    assert "correct horse" not in str(vault)

    result = decrypt_session_vault(vault, "correct horse battery staple")
    assert result["ok"] is True
    assert result["status"] == "verified"
    assert result["payload"] == _payload()


def test_verify_session_vault_omits_plaintext_payload():
    vault, _ = create_session_vault(_payload(), "passphrase", iterations=100_000)

    result = verify_session_vault(vault, "passphrase")

    assert result["ok"] is True
    assert "payload" not in result


def test_wrong_passphrase_fails():
    vault, _ = create_session_vault(_payload(), "right", iterations=100_000)

    with pytest.raises(SessionVaultError, match="wrong passphrase|tampered"):
        decrypt_session_vault(vault, "wrong")


def test_tampered_ciphertext_fails():
    vault, _ = create_session_vault(_payload(), "passphrase", iterations=100_000)
    tampered = copy.deepcopy(vault)
    tampered["ciphertext"] = tampered["ciphertext"][:-4] + "AAAA"

    with pytest.raises(SessionVaultError):
        decrypt_session_vault(tampered, "passphrase")


def test_tampered_metadata_fails_before_decrypt():
    vault, _ = create_session_vault(
        _payload(),
        "passphrase",
        metadata={"payload_type": "session", "session_id": "s1"},
        iterations=100_000,
    )
    tampered = copy.deepcopy(vault)
    tampered["metadata"]["session_id"] = "s2"

    with pytest.raises(SessionVaultError, match="metadata mismatch"):
        decrypt_session_vault(tampered, "passphrase")


def test_malformed_vault_is_rejected():
    with pytest.raises(SessionVaultError):
        decrypt_session_vault({"schema": VAULT_SCHEMA}, "passphrase")
