"""Ed25519 artifact signing and verification.

The APU signs the artifact before export; the OAE verifies before analysis. The
signature covers the canonical JSON (sorted keys, no whitespace) of the payload
without the "signature" and "signed_by" fields.

Keys are raw 32-byte files (~/.nssa/probe.key / .pub). OAE verification also
accepts ASCII-armored public keys from ``nssa-probe --get-pubkey``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    # nacl types used only in annotations
    from nacl.signing import SigningKey, VerifyKey


# ── Optional dependency guard ──

try:
    import nacl.signing  # noqa: F401
    import nacl.exceptions  # noqa: F401
    _NACL_AVAILABLE = True
except ImportError:
    _NACL_AVAILABLE = False


def _require_nacl() -> None:
    if not _NACL_AVAILABLE:
        raise RuntimeError(
            "pynacl is required for artifact signing. "
            "Install it with: pip install pynacl"
        )


# ── Public exception ──

class IntegrityError(Exception):
    """Raised when signature verification fails or keys are unusable."""


# ── Key management ──

def generate_key_pair(private_key_path: str | Path) -> Path:
    """Generate an Ed25519 key pair; the public key goes alongside with a ``.pub`` suffix.

    The private key is chmod-ed to 0o600. Returns the public key path.
    """
    _require_nacl()
    from nacl.signing import SigningKey

    signing_key = SigningKey.generate()
    priv = Path(private_key_path)
    priv.parent.mkdir(parents=True, exist_ok=True)
    priv.write_bytes(signing_key.encode())
    priv.chmod(0o600)

    pub = priv.with_suffix(priv.suffix + ".pub")
    pub.write_bytes(signing_key.verify_key.encode())
    return pub


def load_signing_key(private_key_path: str | Path) -> "SigningKey":
    """Load an Ed25519 signing (private) key from a raw binary file."""
    _require_nacl()
    from nacl.signing import SigningKey
    raw = Path(private_key_path).read_bytes()
    return SigningKey(raw)


def _decode_armored_verify_key(raw: bytes) -> bytes:
    """Decode base64/armored verify keys (base64, NSSA BEGIN/END block, or PEM-like); else return raw bytes."""
    if len(raw) == 32:
        return raw

    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        return raw

    if not text:
        return raw

    if "-----BEGIN NSSA PUBLIC KEY-----" in text:
        lines = [
            line.strip()
            for line in text.splitlines()
            if line.strip()
            and line.strip() not in {
                "-----BEGIN NSSA PUBLIC KEY-----",
                "-----END NSSA PUBLIC KEY-----",
            }
        ]
        text = "".join(lines)
    elif "-----BEGIN" in text and "-----END" in text:
        lines = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("-----")
        ]
        text = "".join(lines)

    if not text:
        return raw

    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return raw


def load_verify_key(public_key_path: str | Path) -> "VerifyKey":
    """Load an Ed25519 verify (public) key from raw 32 bytes or an armored/base64 file."""
    _require_nacl()
    from nacl.signing import VerifyKey
    raw = Path(public_key_path).read_bytes()
    decoded = _decode_armored_verify_key(raw)
    try:
        return VerifyKey(decoded)
    except ValueError as exc:
        raise ValueError(f"Invalid Ed25519 public key in '{public_key_path}': {exc}") from exc


# ── Policy hash ──

def compute_policy_hash(policy_bytes: bytes) -> str:
    """Return the SHA-256 hex digest of raw SPM policy bytes.

    Lets the OAE confirm which policy version was executed. Pass the exact
    parsed bytes (see parse_spm_bytes); a path would yield an empty hash for
    one-shot streams such as /dev/stdin.
    """
    return hashlib.sha256(policy_bytes).hexdigest()


# ── Deployment hash ──

def compute_deployment_hash(deployment_bytes: bytes) -> str:
    """Return the SHA-256 hex digest of raw deployment.json bytes.

    Like compute_policy_hash(), pass the exact parsed bytes (see
    parse_deployment_bytes).
    """
    return hashlib.sha256(deployment_bytes).hexdigest()


# ── Canonical serialisation ──

def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    """Deterministic UTF-8 JSON, sorted keys, no extra whitespace.

    Public: also used by audit_config_parser to hash AuditConfiguration sections.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# Backward-compatible internal alias.
_canonical_bytes = canonical_json_bytes


# ── Signing (APU side) ──

def sign_artifact(
    payload: dict[str, Any],
    signing_key: "SigningKey",
    probe_id: str,
) -> dict[str, Any]:
    """Return a copy of *payload* with "signed_by" and "signature" appended.

    The signature covers the canonical JSON of *payload* before those fields
    are added. probe_id is stored with the signature.
    """
    _require_nacl()
    canonical = _canonical_bytes(payload)
    signed = signing_key.sign(canonical)
    sig_b64 = base64.b64encode(signed.signature).decode("ascii")
    return {**payload, "signed_by": probe_id, "signature": sig_b64}


# ── Verification (OAE side) ──

def verify_artifact(
    raw: dict[str, Any],
    verify_key: "VerifyKey",
) -> None:
    """Verify the Ed25519 signature of an APU artifact; return if authentic.

    Called by the OAE before any analysis. verify_key is the probe's public key
    from the trust store. Raises IntegrityError if the signature is missing,
    malformed, or invalid.
    """
    _require_nacl()
    from nacl.exceptions import BadSignatureError

    sig_b64 = raw.get("signature")
    if not sig_b64:
        raise IntegrityError(
            "Artifact is unsigned — 'signature' field is absent. "
            "Was the probe run without --sign-with?"
        )

    try:
        signature = base64.b64decode(sig_b64)
    except Exception as exc:
        raise IntegrityError(f"Malformed base64 signature: {exc}") from exc

    # Reconstruct the signed bytes: payload minus signature fields.
    unsigned_payload = {
        k: v for k, v in raw.items() if k not in ("signature", "signed_by")
    }
    canonical = _canonical_bytes(unsigned_payload)

    try:
        verify_key.verify(canonical, signature)
    except BadSignatureError as exc:
        raise IntegrityError(
            "Artifact signature verification FAILED — "
            "artifact may have been tampered with after signing."
        ) from exc
