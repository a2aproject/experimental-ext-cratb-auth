# SPDX-License-Identifier: Apache-2.0
"""
Issuer key discovery and trust (spec 5.4, 7.3.4 step 3, 9.3; SD-JWT VC draft-19 Section 5).

The Verifier MUST establish the issuer's verification key through a mechanism permitted for that
issuer: JWT VC Issuer Metadata, or an X.509 certificate chain (`x5c`) validated against configured
trust anchors. This module implements both. It is opt-in: an `SDJWTVerifier` built without an
`issuer_key_discovery` keeps using its `jwks_resolver` callback (configured trust), unchanged.

Policy is configured per issuer and never chosen by the token:
  * an issuer listed in `x5c_trust_anchors` MUST present a valid `x5c` chain, and there is no
    fallback to metadata when it does not;
  * every other issuer is resolved through JWT VC Issuer Metadata, and an `x5c` header on its
    token is ignored, so a token cannot swap in a weaker mechanism by adding one.

Network access goes through an injectable client (`http_client.get(url)` returning an object with
`status_code` and `content`). Without one, a short-lived `httpx` client is created that does not
follow redirects. Every failure maps to `VP_SIGNATURE_INVALID` (spec 7.3.4 step 3).
"""

import base64
import datetime as dt
import json
import threading
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from .crypto import export_jwk_from_public_key, import_public_key_from_jwk
from .models import ErrorCode
from .verifier import CredentialVerificationError

WELL_KNOWN_SEGMENT = "/.well-known/jwt-vc-issuer"


def _fail(message: str) -> CredentialVerificationError:
    return CredentialVerificationError(ErrorCode.VP_SIGNATURE_INVALID, message)


def _parse_issuer(iss: Any) -> Any:
    """Validates `iss` as the HTTPS issuer identifier this profile requires (spec 9.2)."""
    if not isinstance(iss, str) or not iss:
        raise _fail("Issuer identifier 'iss' must be a non-empty string")
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F or ch == "\\" for ch in iss):
        raise _fail("Issuer identifier contains whitespace, control or backslash characters")
    if "?" in iss or "#" in iss:
        raise _fail("Issuer identifier must not contain a query or fragment")
    try:
        parts = urlsplit(iss)
        host = parts.hostname
        parts.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError:
        raise _fail("Issuer identifier is not a valid URL")
    if parts.scheme != "https" or not host:
        raise _fail("Issuer identifier must be an https URL with a host")
    if parts.username is not None or parts.password is not None:
        raise _fail("Issuer identifier must not contain userinfo")
    return parts


class IssuerKeyDiscovery:
    """
    Resolves the key that verifies an Issuer-signed JWT, per the issuer's permitted mechanism.

    `resolve(iss, issuer_header)` returns a JWK, or a JWKS ({"keys": [...]}) from which
    `SDJWTVerifier` then selects by the token's `kid`.
    """

    def __init__(
        self,
        http_client: Optional[Any] = None,
        x5c_trust_anchors: Optional[Mapping[str, Sequence[x509.Certificate]]] = None,
        cache_ttl: float = 300.0,
        max_response_bytes: int = 64 * 1024,
        max_chain_length: int = 5,
        time_fn: Callable[[], float] = time.time,
    ) -> None:
        self.http_client = http_client
        # iss -> configured trust anchors for issuers that require an x5c chain.
        self.x5c_trust_anchors: Dict[str, List[x509.Certificate]] = {
            iss: list(anchors) for iss, anchors in (x5c_trust_anchors or {}).items()
        }
        for iss, anchors in self.x5c_trust_anchors.items():
            if not anchors:
                raise ValueError(f"x5c issuer {iss!r} is configured with no trust anchors")
        self.cache_ttl = cache_ttl
        self.max_response_bytes = max_response_bytes
        self.max_chain_length = max_chain_length
        self._time = time_fn
        self._default_client: Optional[Any] = None
        self._cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ public API

    @staticmethod
    def well_known_url(iss: str) -> str:
        """
        SD-JWT VC Section 5: insert `/.well-known/jwt-vc-issuer` between the host and the path of
        `iss`, after removing a terminating `/`.
          https://issuer.example.com          -> https://issuer.example.com/.well-known/jwt-vc-issuer
          https://issuer.example.com/tenant/1 -> https://issuer.example.com/.well-known/jwt-vc-issuer/tenant/1
        """
        parts = _parse_issuer(iss)
        return f"https://{parts.netloc}{WELL_KNOWN_SEGMENT}{parts.path.rstrip('/')}"

    def resolve(self, iss: str, issuer_header: Mapping[str, Any]) -> Dict[str, Any]:
        _parse_issuer(iss)
        if iss in self.x5c_trust_anchors:
            # The issuer is configured to prove its key with a certificate chain. A token that
            # omits the chain is refused, never answered from metadata.
            if "x5c" not in issuer_header:
                raise _fail(f"Issuer {iss!r} requires an 'x5c' certificate chain in the JOSE header")
            return self._key_from_x5c(iss, issuer_header["x5c"])
        # Metadata issuer: an `x5c` the token carries is not consulted.
        return self._jwks_from_metadata(iss)

    def invalidate(self, iss: Optional[str] = None) -> None:
        """Drops cached issuer metadata (all of it, or one issuer's)."""
        with self._lock:
            if iss is None:
                self._cache.clear()
            else:
                self._cache.pop(iss, None)

    # ------------------------------------------------------------------ JWT VC Issuer Metadata

    def _jwks_from_metadata(self, iss: str) -> Dict[str, Any]:
        now = self._time()
        with self._lock:
            hit = self._cache.get(iss)
            if hit is not None and hit[0] > now:
                return hit[1]

        document = self._fetch_json(self.well_known_url(iss))
        if not isinstance(document, dict):
            raise _fail("Issuer metadata is not a JSON object")
        if document.get("issuer") != iss:
            raise _fail("Issuer metadata 'issuer' does not match the token 'iss' exactly")
        has_jwks, has_uri = "jwks" in document, "jwks_uri" in document
        if has_jwks == has_uri:
            raise _fail("Issuer metadata must contain exactly one of 'jwks' or 'jwks_uri'")
        if has_jwks:
            jwks = document["jwks"]
        else:
            jwks_uri = document["jwks_uri"]
            if not isinstance(jwks_uri, str):
                raise _fail("Issuer metadata 'jwks_uri' must be a string")
            try:
                uri_parts = urlsplit(jwks_uri)
                ok = uri_parts.scheme == "https" and bool(uri_parts.hostname) and uri_parts.username is None
            except ValueError:
                ok = False
            if not ok or any(ch.isspace() for ch in jwks_uri):
                raise _fail("Issuer metadata 'jwks_uri' must be an https URL")
            jwks = self._fetch_json(jwks_uri)

        validated = {"keys": self._valid_signing_keys(jwks)}
        with self._lock:
            self._cache[iss] = (now + self.cache_ttl, validated)
        return validated

    @staticmethod
    def _valid_signing_keys(jwks: Any) -> List[Dict[str, Any]]:
        """
        Keeps only keys this profile can use to verify ES256 issuer signatures: public EC P-256
        keys that are not restricted away from signing. A key carrying private material is never
        used. At least one usable key is required.
        """
        if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
            raise _fail("Issuer JWKS must be an object with a 'keys' array")
        usable: List[Dict[str, Any]] = []
        for key in jwks["keys"]:
            if not isinstance(key, dict) or "d" in key:
                continue
            if key.get("kty") != "EC" or key.get("crv") != "P-256":
                continue
            if not isinstance(key.get("x"), str) or not isinstance(key.get("y"), str):
                continue
            if key.get("use") not in (None, "sig"):
                continue
            if key.get("alg") not in (None, "ES256"):
                continue
            try:
                import_public_key_from_jwk(key)  # rejects points that are not on the curve
            except Exception:
                continue
            usable.append({k: v for k, v in key.items() if k in ("kty", "crv", "x", "y", "kid", "use", "alg")})
        if not usable:
            raise _fail("Issuer JWKS contains no usable EC P-256 signing key")
        return usable

    def _fetch_json(self, url: str) -> Any:
        client = self.http_client
        if client is None:
            if self._default_client is None:
                try:
                    import httpx
                except ImportError:
                    raise _fail("httpx is required for issuer metadata retrieval but is not installed")
                # No redirects: a changed target is a new, unauthenticated origin.
                self._default_client = httpx.Client(timeout=10.0, follow_redirects=False)
            client = self._default_client
        try:
            response = client.get(url)
        except Exception as exc:
            raise _fail(f"Failed to fetch issuer key material: {type(exc).__name__}")
        if response.status_code != 200:
            raise _fail(f"Issuer key material request returned status {response.status_code}")
        body = response.content
        if isinstance(body, str):
            body = body.encode("utf-8")
        if not isinstance(body, (bytes, bytearray)) or len(body) > self.max_response_bytes:
            raise _fail("Issuer key material response is missing or exceeds the size limit")
        try:
            return json.loads(bytes(body).decode("utf-8"))
        except Exception:
            raise _fail("Issuer key material response is not valid JSON")

    # ------------------------------------------------------------------ X.509 chain (x5c)

    def _key_from_x5c(self, iss: str, x5c: Any) -> Dict[str, Any]:
        if not isinstance(x5c, list) or not x5c or len(x5c) > self.max_chain_length:
            raise _fail(f"'x5c' must be a non-empty array of at most {self.max_chain_length} certificates")
        certs: List[x509.Certificate] = []
        for item in x5c:
            try:
                if not isinstance(item, str):
                    raise ValueError("not a string")
                certs.append(x509.load_der_x509_certificate(base64.b64decode(item, validate=True)))
            except Exception:
                raise _fail("'x5c' contains a certificate that is not valid base64 DER")
        leaf, intermediates = certs[0], certs[1:]

        # Complete chain validation against the configured anchors for this issuer, at the
        # verifier's clock. Extracting the leaf key without this is prohibited (spec 9.3).
        when = dt.datetime.fromtimestamp(self._time(), dt.timezone.utc)
        try:
            verifier = (
                PolicyBuilder()
                .store(Store(self.x5c_trust_anchors[iss]))
                .time(when)
                .max_chain_depth(self.max_chain_length)
                .build_client_verifier()
            )
            verifier.verify(leaf, intermediates)
        except VerificationError as exc:
            raise _fail(f"x5c certificate chain validation failed: {str(exc)[:120]}")
        except Exception as exc:
            raise _fail(f"x5c certificate chain could not be validated: {type(exc).__name__}")

        self._require_authorizes_issuer(leaf, iss)

        public_key = leaf.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
            raise _fail("x5c end-entity certificate key must be an EC P-256 key")
        return export_jwk_from_public_key(public_key)

    @staticmethod
    def _require_authorizes_issuer(leaf: x509.Certificate, iss: str) -> None:
        """
        The end-entity certificate must authorize `iss` (spec 9.3). A URI SAN must equal `iss`
        exactly. A dNSName SAN equal to the issuer host is accepted only for a host-only issuer,
        since a hostname does not authorize one tenant path on that host.
        """
        try:
            usage = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
            if not usage.digital_signature:
                raise _fail("x5c end-entity certificate does not permit digital signatures")
        except x509.ExtensionNotFound:
            pass
        try:
            san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            raise _fail("x5c end-entity certificate has no subjectAltName naming the issuer")
        parts = urlsplit(iss)
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
        dns_names = [d.lower() for d in san.get_values_for_type(x509.DNSName)]
        host_only = parts.path in ("", "/")
        if iss in uris or (host_only and (parts.hostname or "").lower() in dns_names):
            return
        raise _fail("x5c end-entity certificate does not authorize the issuer identifier")
