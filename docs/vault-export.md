# Local encrypted session export

Odysseus stores private, user-owned work: chats, agent runs, research outputs,
documents, and model experiments. Local encrypted session export gives users a
portable archive format without changing that privacy model.

The first version is backend-only and intentionally small.

## What it does

A session export flow turns persisted session history into a JSON payload, then
wraps it in an encrypted vault object:

```text
session data -> encrypted artifact -> verification receipt -> later verification
```

The server returns both:

- a vault JSON object containing encrypted session content
- a receipt containing only fingerprints and metadata

The receipt can be stored separately from the vault. It does not include the
passphrase or plaintext session data.

## API surface

### Export a session

```http
POST /api/vault/session/{session_id}/export
Content-Type: application/json

{
  "passphrase": "long local passphrase",
  "include_hidden": false
}
```

The caller must own the session. The response contains:

```json
{
  "ok": true,
  "vault": { "schema": "ODYSSEUS-SESSION-VAULT-V1" },
  "receipt": { "status": "created" }
}
```

### Verify a vault

```http
POST /api/vault/session/verify
Content-Type: application/json

{
  "vault": { "schema": "ODYSSEUS-SESSION-VAULT-V1" },
  "passphrase": "long local passphrase",
  "reveal_payload": false
}
```

By default, verification does not return plaintext. Set `reveal_payload` to
`true` when the caller intentionally wants to decrypt and display/import the
session payload.

## Format

The vault schema is `ODYSSEUS-SESSION-VAULT-V1`.

The vault stores:

- schema and creation time
- KDF parameters
- AEAD cipher parameters
- cleartext metadata
- plaintext SHA-256 fingerprint
- authenticated-data SHA-256 fingerprint
- ciphertext

The cleartext metadata is authenticated as AEAD associated data. Changing the
schema, KDF parameters, cipher parameters, metadata, nonce, plaintext hash, or
ciphertext causes verification/decryption to fail.

## Cryptographic primitives

This implementation uses Python's existing `cryptography` dependency:

- PBKDF2-HMAC-SHA256 for passphrase-derived keys
- AES-256-GCM for authenticated encryption
- SHA-256 for payload and vault fingerprints
- constant-time comparison for stored fingerprints

This is not custom cryptography. The feature is a local export workflow built on
standard primitives.

## Threat model

This protects exported session artifacts at rest and in transit between trusted
machines when the passphrase is kept secret.

It helps with:

- private archival
- portable backup
- tamper detection
- offline sharing where the recipient already has the passphrase

It does not protect against:

- a compromised host at export time
- malicious browser extensions reading the passphrase
- weak user passphrases
- legal notarization requirements
- multi-party signatures or identity proofs
- full-disk compromise while the plaintext session is open in Odysseus

## Non-goals

This feature does not:

- upload vaults to any server
- add telemetry
- replace the database/session system
- log secrets or passphrases
- require cloud services
- introduce a UI rewrite

## Testing

Relevant tests live in:

```text
tests/test_session_export_vault.py
```

They cover:

- valid vault round-trip
- verification without plaintext reveal
- wrong passphrase failure
- ciphertext tamper failure
- authenticated metadata tamper failure
- malformed vault rejection
