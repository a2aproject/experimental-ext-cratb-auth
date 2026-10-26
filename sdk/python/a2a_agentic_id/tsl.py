# SPDX-License-Identifier: Apache-2.0
import time
import zlib
from typing import Any, Callable, Dict, List, Optional
import jwt

from .crypto import (
    base64url_decode,
    base64url_encode,
    import_private_key_from_jwk,
    import_public_key_from_jwk,
)
from .models import StatusListReference

MAX_DECOMPRESSED_SIZE = 1024 * 1024  # 1 MB boundary protecting against decompression bombs


class TokenStatusListClient:
    """
    Client for verifying Token Status List (TSL) revocation bit-arrays per IETF draft-ietf-oauth-status-list.
    Enforces strict signature verification, JOSE headers, sub-binding, bounded zlib decompression,
    and HTTP caching with TTL.
    """
    def __init__(
        self,
        jwks_resolver: Optional[Callable[[str], Dict[str, Any]]] = None,
        default_public_key_jwk: Optional[Dict[str, Any]] = None,
        require_signature: bool = True,
        allow_unverified_for_testing: bool = False,
        max_tsl_age: int = 86400,
        allowed_future_skew: int = 60,
        http_client: Optional[Any] = None,
    ) -> None:
        self.jwks_resolver = jwks_resolver
        self.default_public_key_jwk = default_public_key_jwk
        self.require_signature = require_signature
        # Explicit unsafe escape hatch: accept status lists without verifying the signature.
        self.allow_unverified_for_testing = allow_unverified_for_testing
        self.max_tsl_age = max_tsl_age
        self.allowed_future_skew = allowed_future_skew
        self.http_client = http_client

        self.cached_status_lists: Dict[str, bytes] = {}
        self.cached_status_bits: Dict[str, int] = {}
        self.cached_metadata: Dict[str, Dict[str, Any]] = {}
        self.cache_timestamps: Dict[str, float] = {}

    def fetch_and_register_status_list_jwt(
        self,
        uri: str,
        issuer_public_key_jwk: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Fetches a Token Status List JWT over HTTP/HTTPS and registers it in the cache.
        """
        client = self.http_client
        if client is None:
            try:
                import httpx
                client = httpx.Client(timeout=10.0, follow_redirects=True)
            except ImportError:
                raise RuntimeError("httpx is required for HTTP status list retrieval but not installed")

        try:
            resp = client.get(uri)
            if resp.status_code != 200:
                raise ValueError(f"HTTP fetch failed for status list '{uri}': status code {resp.status_code}")
            jwt_str = resp.text.strip()
        except Exception as e:
            raise ValueError(f"Failed to fetch status list from '{uri}': {str(e)}")

        self.register_status_list_jwt(
            uri=uri,
            jwt_str=jwt_str,
            issuer_public_key_jwk=issuer_public_key_jwk,
        )

    def register_status_list_jwt(
        self,
        uri: str,
        jwt_str: str,
        issuer_public_key_jwk: Optional[Dict[str, Any]] = None,
        require_signature: Optional[bool] = None,
    ) -> None:
        """
        Registers and parses a Token Status List JWT, validating headers, signature, claims,
        and caching the uncompressed bit-array bytes.
        """
        # 1. Unverified header inspection
        try:
            header = jwt.get_unverified_header(jwt_str)
        except Exception as e:
            raise ValueError(f"Failed to decode status list JWT header: {e}")

        alg = header.get("alg")
        if not alg or alg.lower() == "none":
            raise ValueError(f"Invalid status list JWT algorithm '{alg}': unsigned TSL JWTs are not permitted")

        typ = header.get("typ")
        typ_lower = (typ or "").lower()

        # 2. Resolve public key for signature verification
        pub_jwk = issuer_public_key_jwk or self.default_public_key_jwk
        if not pub_jwk and self.jwks_resolver:
            try:
                unverified_payload = jwt.decode(jwt_str, options={"verify_signature": False})
                iss = unverified_payload.get("iss")
                if iss:
                    pub_jwk = self.jwks_resolver(iss)
            except Exception:
                pass

        # Signature verification is mandatory unless the client was explicitly constructed
        # with allow_unverified_for_testing=True. A per-call require_signature=False is
        # honored only under that same flag.
        if self.allow_unverified_for_testing:
            should_verify = bool(pub_jwk) if require_signature is None else require_signature
        else:
            should_verify = True

        if should_verify:
            if not typ or typ_lower not in ("statuslist+jwt", "application/statuslist+jwt"):
                raise ValueError(
                    f"Invalid status list JWT header 'typ': expected 'statuslist+jwt', got '{typ}'"
                )
            if alg not in ("ES256", "ES384", "ES512", "RS256"):
                raise ValueError(f"Unsupported status list JWT algorithm '{alg}'")
        elif typ and typ_lower not in ("statuslist+jwt", "application/statuslist+jwt", "jwt"):
            raise ValueError(
                f"Invalid status list JWT header 'typ': expected 'statuslist+jwt', got '{typ}'"
            )

        if pub_jwk:
            try:
                pub_key = import_public_key_from_jwk(pub_jwk)
                from cryptography.hazmat.primitives import serialization
                pem_pub_key = pub_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                payload = jwt.decode(
                    jwt_str,
                    key=pem_pub_key,
                    algorithms=["ES256", "ES384", "ES512", "RS256"],
                    options={"verify_aud": False},
                )
            except Exception as e:
                raise ValueError(f"Token Status List signature verification failed: {e}")
        elif should_verify:
            raise ValueError(
                "Signature verification required for Token Status List JWT, but no public key or jwks_resolver was provided"
            )
        else:
            payload = jwt.decode(jwt_str, options={"verify_signature": False})

        # 3. Payload Claims Validation
        now = int(time.time())
        iss = payload.get("iss")
        if not iss or not isinstance(iss, str):
            raise ValueError("Status list JWT missing or invalid 'iss' claim")

        # Validate 'sub' binding to URI per draft-ietf-oauth-status-list
        sub = payload.get("sub")
        if sub is not None or should_verify:
            if not isinstance(sub, str) or not sub:
                raise ValueError("Status list JWT missing or invalid 'sub' claim")
            if sub != uri:
                raise ValueError(
                    f"Status list JWT 'sub' claim '{sub}' does not match registered URI '{uri}'"
                )

        # Validate temporal claims (iat and exp)
        iat = payload.get("iat")
        if iat is not None:
            if not isinstance(iat, (int, float)):
                raise ValueError("Status list JWT 'iat' claim must be numeric")
            if iat > (now + self.allowed_future_skew):
                raise ValueError(f"Status list JWT 'iat' ({iat}) is in the future")
            if self.max_tsl_age and (now - iat) > self.max_tsl_age:
                raise ValueError(f"Status list JWT 'iat' ({iat}) exceeds maximum allowed age ({self.max_tsl_age}s)")
        elif should_verify:
            raise ValueError("Status list JWT missing or invalid 'iat' claim")

        exp = payload.get("exp")
        if exp is not None:
            if not isinstance(exp, (int, float)):
                raise ValueError("Status list JWT 'exp' claim must be numeric")
            if (now - self.allowed_future_skew) > exp:
                raise ValueError(f"Status list JWT has expired (exp: {exp}, now: {now})")

        # 4. Status list bit-array extraction & bounded decompression
        status_list_obj = payload.get("status_list")
        if not isinstance(status_list_obj, dict):
            raise ValueError("Status list JWT missing 'status_list' object")

        lst_b64 = status_list_obj.get("lst", "")
        if not lst_b64 or not isinstance(lst_b64, str):
            raise ValueError("Status list JWT missing 'status_list.lst' base64url payload")

        bits = status_list_obj.get("bits", 1)
        if not isinstance(bits, int) or bits not in (1, 2, 4, 8):
            raise ValueError(f"Unsupported status_list 'bits' value: {bits}. Must be 1, 2, 4, or 8.")

        raw_bytes = base64url_decode(lst_b64)
        # Enforce strict bounded zlib decompression (reject raw bytes fallback)
        try:
            d_obj = zlib.decompressobj()
            decompressed = d_obj.decompress(raw_bytes, MAX_DECOMPRESSED_SIZE)
            if d_obj.unconsumed_tail:
                raise ValueError(f"Decompressed status list exceeds maximum allowable limit ({MAX_DECOMPRESSED_SIZE} bytes)")
            if not decompressed:
                raise ValueError("Decompressed status list is empty")
        except Exception as e:
            raise ValueError(f"Invalid Token Status List: zlib decompression failed: {e}")

        self.cached_status_lists[uri] = decompressed
        self.cached_status_bits[uri] = bits
        self.cached_metadata[uri] = {
            "iss": payload.get("iss"),
            "sub": sub,
            "iat": iat,
            "exp": exp,
            "bits": bits,
            "cached_at": now,
        }
        self.cache_timestamps[uri] = now

    def _is_stale(self, uri: str) -> bool:
        """True if the cached list's own exp has passed or it was cached longer than max_tsl_age ago."""
        meta = self.cached_metadata.get(uri) or {}
        now = int(time.time())
        exp = meta.get("exp")
        if exp is not None and (now - self.allowed_future_skew) > exp:
            return True
        cached_at = self.cache_timestamps.get(uri)
        if self.max_tsl_age and cached_at is not None and (now - cached_at) > self.max_tsl_age:
            return True
        return False

    def _evict(self, uri: str) -> None:
        self.cached_status_lists.pop(uri, None)
        self.cached_status_bits.pop(uri, None)
        self.cached_metadata.pop(uri, None)
        self.cache_timestamps.pop(uri, None)

    def is_revoked(self, ref: StatusListReference) -> bool:
        """
        Checks if the status entry at index 'ref.idx' indicates revocation or suspension.
        Conforms to IETF draft-ietf-oauth-status-list §4: LSB-first bit ordering.
        For bits=1: 0=valid, 1=revoked.
        For bits=2: 0=valid, 1=revoked, 2=suspended.
        Returns False if valid (0), True if revoked or suspended (1, 2).
        """
        if not ref.uri or not isinstance(ref.uri, str):
            raise ValueError("Invalid StatusListReference: uri must be a non-empty string")
        if ref.idx is None or not isinstance(ref.idx, int) or ref.idx < 0:
            raise ValueError("Invalid StatusListReference: idx must be a non-negative integer")

        bit_array = self.cached_status_lists.get(ref.uri)
        if bit_array is not None and self._is_stale(ref.uri):
            # Fail closed: stale or expired evidence is dropped, never reused.
            self._evict(ref.uri)
            bit_array = None
        if bit_array is None:
            # If HTTP client or automatic fetching is enabled and URI starts with http/https
            if ref.uri.startswith(("http://", "https://")):
                try:
                    self.fetch_and_register_status_list_jwt(ref.uri)
                    bit_array = self.cached_status_lists.get(ref.uri)
                except Exception as e:
                    raise KeyError(f"Status list URI '{ref.uri}' could not be retrieved: {e}")

        if bit_array is None:
            raise KeyError(f"Status list URI '{ref.uri}' not registered in TSL cache")

        bits = self.cached_status_bits.get(ref.uri, 1)
        bit_pos = ref.idx * bits
        byte_idx = bit_pos // 8
        bit_offset = bit_pos % 8  # LSB-first: bit 0 of entry is at LSB of byte
        if byte_idx >= len(bit_array):
            raise IndexError(f"Status list index {ref.idx} out of range")

        byte_val = bit_array[byte_idx]
        mask = (1 << bits) - 1
        status_val = (byte_val >> bit_offset) & mask
        return status_val in (1, 2)

    @staticmethod
    def create_status_list_jwt(
        issuer_private_key_jwk: Dict[str, Any],
        iss: str,
        revoked_indices: List[int],
        total_bits: int = 1024,
        bits: int = 1,
        use_zlib: bool = True,
        sub: Optional[str] = None,
        ttl_seconds: int = 86400,
    ) -> str:
        """
        Helper method to create an ES256 Token Status List JWT with specified revoked indices.
        Uses LSB-first bit ordering per IETF draft-ietf-oauth-status-list §4.
        Sets typ='statuslist+jwt', sub, iat, exp, and compressed lst bit-array.
        """
        if not use_zlib:
            raise ValueError("Uncompressed status list is not supported; draft-ietf-oauth-status-list mandates zlib compression")

        total_bit_count = total_bits * bits
        num_bytes = (total_bit_count + 7) // 8
        bit_array = bytearray(num_bytes)
        for idx in revoked_indices:
            if idx >= total_bits:
                continue
            bit_pos = idx * bits
            byte_idx = bit_pos // 8
            bit_offset = bit_pos % 8
            bit_array[byte_idx] |= (1 << bit_offset)

        compressed = zlib.compress(bytes(bit_array))
        lst_b64 = base64url_encode(compressed)

        now = int(time.time())
        exp = now + ttl_seconds
        target_sub = sub or f"{iss}/status-list.jwt"

        payload = {
            "iss": iss,
            "sub": target_sub,
            "iat": now,
            "exp": exp,
            "status_list": {
                "bits": bits,
                "lst": lst_b64,
            },
        }

        priv_key = import_private_key_from_jwk(issuer_private_key_jwk)
        from cryptography.hazmat.primitives import serialization
        pem_key = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return jwt.encode(
            payload=payload,
            key=pem_key,
            algorithm="ES256",
            headers={"typ": "statuslist+jwt"},
        )
