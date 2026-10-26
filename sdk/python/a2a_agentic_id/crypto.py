# SPDX-License-Identifier: Apache-2.0
import base64
import hashlib
import json
import secrets
from typing import Any, Dict, Tuple
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def base64url_encode(data: bytes) -> str:
    """
    Encode bytes to URL-safe base64 string without trailing padding '='.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_decode(s: str) -> bytes:
    """
    Decode URL-safe base64 string, adding padding '=' as needed.
    """
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def compute_sha256_base64url(data: bytes | str) -> str:
    """
    Compute SHA-256 digest of input and return as base64url string without padding.
    Used for SD-JWT _sd hashes and KB-JWT sd_hash.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    digest = hashlib.sha256(data).digest()
    return base64url_encode(digest)


TLS_EXPORTER_LABEL = b"EXPORTER-Channel-Binding"
TLS_EXPORTER_LENGTH = 32


def encode_tls_exporter(exporter: bytes) -> str:
    """
    Encodes an RFC 9266 `tls-exporter` channel binding value for the KB-JWT `channel_binding`
    claim (spec 9.5, 12.8): base64url without padding.

    The transport computes `exporter` from the TLS 1.3 connection as the exporter output with
    label TLS_EXPORTER_LABEL, an empty context and TLS_EXPORTER_LENGTH bytes. The SDK has no
    TLS context of its own, so the value is always supplied by the caller.
    """
    if not isinstance(exporter, (bytes, bytearray)) or len(exporter) != TLS_EXPORTER_LENGTH:
        raise ValueError(f"tls-exporter value must be {TLS_EXPORTER_LENGTH} bytes")
    return base64url_encode(bytes(exporter))


def generate_nonce(num_bytes: int = 16) -> str:
    """
    Generate a cryptographically random ASCII URL-safe nonce string.
    """
    return secrets.token_urlsafe(num_bytes)


def generate_salt(num_bytes: int = 16) -> str:
    """
    Generate a cryptographically random salt (at least 128 bits) for SD-JWT disclosures.
    """
    return secrets.token_urlsafe(num_bytes)


def generate_ec_p256_keypair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """
    Generate a fresh EC P-256 (SECP256R1) private and public key pair.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def export_jwk_from_public_key(pub_key: ec.EllipticCurvePublicKey) -> Dict[str, str]:
    """
    Export an EC P-256 public key as a JWK dict per RFC 7517.
    """
    numbers = pub_key.public_numbers()
    x_bytes = numbers.x.to_bytes(32, byteorder="big")
    y_bytes = numbers.y.to_bytes(32, byteorder="big")
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": base64url_encode(x_bytes),
        "y": base64url_encode(y_bytes),
    }


def export_jwk_from_private_key(priv_key: ec.EllipticCurvePrivateKey) -> Dict[str, str]:
    """
    Export an EC P-256 private key as a JWK dict per RFC 7517 (includes 'd').
    """
    jwk = export_jwk_from_public_key(priv_key.public_key())
    d_bytes = priv_key.private_numbers().private_value.to_bytes(32, byteorder="big")
    jwk["d"] = base64url_encode(d_bytes)
    return jwk


def import_public_key_from_jwk(jwk: Dict[str, Any]) -> ec.EllipticCurvePublicKey:
    """
    Import an EC P-256 public key from a JWK dict.
    """
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("Unsupported key type or curve in JWK; expected EC P-256")
    x = int.from_bytes(base64url_decode(jwk["x"]), byteorder="big")
    y = int.from_bytes(base64url_decode(jwk["y"]), byteorder="big")
    numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    return numbers.public_key()


def import_private_key_from_jwk(jwk: Dict[str, Any]) -> ec.EllipticCurvePrivateKey:
    """
    Import an EC P-256 private key from a JWK dict containing 'd'.
    """
    pub_key = import_public_key_from_jwk(jwk)
    d = int.from_bytes(base64url_decode(jwk["d"]), byteorder="big")
    priv_numbers = ec.EllipticCurvePrivateNumbers(d, pub_key.public_numbers())
    return priv_numbers.private_key()
