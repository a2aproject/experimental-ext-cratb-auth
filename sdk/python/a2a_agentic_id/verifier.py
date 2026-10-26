# SPDX-License-Identifier: Apache-2.0
import hmac
import json
import time
from typing import Any, Callable, Dict, List, Optional
import jwt
from pydantic import BaseModel, Field

from .crypto import (
    base64url_decode,
    compute_sha256_base64url,
    import_public_key_from_jwk,
)
from .models import CHANNEL_BINDING_TYPES, DCQLCredentialQuery, DCQLQuery, ErrorCode


class CredentialVerificationError(Exception):
    """
    Raised when presentation verification fails, containing the appropriate ErrorCode.
    """
    def __init__(self, error_code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message


class VerificationResult(BaseModel):
    """
    Result of a successful SD-JWT presentation verification.
    """
    is_valid: bool = True
    issuer: str
    credential_type: str
    id_claim: str
    disclosed_claims: Dict[str, Any]
    raw_issuer_jwt_payload: Dict[str, Any]
    kb_jwt_payload: Dict[str, Any]
    query_id: Optional[str] = None
    results: Dict[str, Any] = Field(default_factory=dict)

    def get_credential_result(self, query_id: str) -> Optional["VerificationResult"]:
        """Returns the individual VerificationResult for a specific DCQL query ID."""
        return self.results.get(query_id)


def _empty_jwks_resolver(_iss: str) -> Dict[str, Any]:
    return {}


class SDJWTVerifier:
    """
    Verifies SD-JWT presentations per Section 7.3.4 of the A2A Agentic Identity extension spec.
    """
    def __init__(
        self,
        client_id: str,
        jwks_resolver: Optional[Callable[[str], Dict[str, Any]]] = None,
        tsl_client: Optional[Any] = None,
        allow_unverified_status: bool = False,
        supported_algorithms: Optional[List[str]] = None,
        max_kb_age: int = 300,
        allowed_future_skew: int = 60,
        issuer_key_discovery: Optional[Any] = None,
        channel_binding: Optional[List[str]] = None,
    ) -> None:
        # Optional `IssuerKeyDiscovery` (spec 7.3.4 step 3): JWT VC Issuer Metadata or an x5c
        # chain validated against configured trust anchors. Unset (the default), issuer keys come
        # from `jwks_resolver` / `issuer_public_key_jwk` exactly as before.
        self.issuer_key_discovery = issuer_key_discovery
        # Spec 4.1 / 12.8: the Agent Card `channel_binding` value. When set, every KB-JWT must
        # carry `channel_binding` equal to the tls-exporter value of the connection it arrived on.
        if channel_binding is not None:
            unknown = [t for t in channel_binding if t not in CHANNEL_BINDING_TYPES]
            if not channel_binding or unknown:
                raise ValueError(
                    f"channel_binding must be a non-empty list of {sorted(CHANNEL_BINDING_TYPES)}, got {channel_binding}"
                )
        self.channel_binding = channel_binding
        self.client_id = client_id
        self.jwks_resolver = jwks_resolver or _empty_jwks_resolver
        self.tsl_client = tsl_client
        self.allow_unverified_status = allow_unverified_status
        self.supported_algorithms = supported_algorithms or ["ES256"]
        self.max_kb_age = max_kb_age
        self.allowed_future_skew = allowed_future_skew

    @staticmethod
    def resolve_credential_type(payload: Dict[str, Any]) -> str:
        """
        Returns the credential type: the top-level `vct` claim, which spec 7.3.4 step 5 requires
        to be a string. The legacy `dct` claim is not part of the profile and is never consulted.
        Raises CredentialVerificationError(VP_DCQL_UNSATISFIED) when `vct` is missing or not a
        non-empty string.
        """
        vct = payload.get("vct")
        if not isinstance(vct, str) or not vct:
            raise CredentialVerificationError(
                ErrorCode.VP_DCQL_UNSATISFIED,
                "Credential is missing the required 'vct' claim (a non-empty string)",
            )
        return vct

    @staticmethod
    def _select_jwk(resolved: Dict[str, Any], kid: Optional[str], iss: str) -> Dict[str, Any]:
        """
        Selects the issuer verification key from a resolver result.

        A bare JWK is returned unchanged (a `kid` in the token header is then informational).
        For a JWKS, the token's `kid` must match exactly one key. A JWKS with a single key and
        no token `kid` is accepted; with several keys a missing or unknown `kid` is rejected
        rather than trying keys in turn.
        """
        keys = resolved.get("keys") if isinstance(resolved, dict) else None
        if keys is None:
            return resolved
        if not isinstance(keys, list) or not keys:
            raise CredentialVerificationError(
                ErrorCode.VP_SIGNATURE_INVALID, f"JWKS for issuer {iss} contains no keys"
            )
        if kid is None:
            if len(keys) == 1:
                return keys[0]
            raise CredentialVerificationError(
                ErrorCode.VP_SIGNATURE_INVALID,
                f"Issuer JWKS for {iss} has {len(keys)} keys but the token header has no 'kid'",
            )
        matches = [k for k in keys if isinstance(k, dict) and k.get("kid") == kid]
        if len(matches) != 1:
            raise CredentialVerificationError(
                ErrorCode.VP_SIGNATURE_INVALID,
                f"No unique key with kid '{kid}' in issuer JWKS for {iss} ({len(matches)} matches)",
            )
        return matches[0]

    @staticmethod
    def _process_disclosures(
        payload: Dict[str, Any], disclosures_raw: List[str]
    ) -> Dict[str, Any]:
        """Returns the top-level disclosed claims; see `_process_disclosures_full`."""
        return SDJWTVerifier._process_disclosures_full(payload, disclosures_raw)[1]

    @staticmethod
    def _process_disclosures_full(
        payload: Dict[str, Any], disclosures_raw: List[str]
    ) -> "tuple[Dict[str, Any], Dict[str, Any]]":
        """
        Recursively validates supplied Disclosures against the issuer payload (RFC 9901 §7.1).
        Returns (processed payload, top-level disclosed claims). The processed payload is the
        issuer payload with every supplied Disclosure applied at any depth, so DCQL claim paths
        can be resolved against it. Rejects duplicate disclosures/digest references,
        claim-name collisions, unreferenced disclosures, and non-sha-256 digest algorithms.
        """
        def fail(code: ErrorCode, msg: str) -> CredentialVerificationError:
            return CredentialVerificationError(code, msg)

        if payload.get("_sd_alg") != "sha-256":
            raise fail(
                ErrorCode.VP_SIGNATURE_INVALID,
                f"Unsupported or missing '_sd_alg' {payload.get('_sd_alg')!r}; expected 'sha-256'",
            )

        # digest -> ("object", name, value) | ("array", None, value)
        by_digest: Dict[str, Any] = {}
        for disc_b64 in disclosures_raw:
            if not disc_b64:
                continue
            try:
                digest = compute_sha256_base64url(disc_b64)
                disc_json = json.loads(base64url_decode(disc_b64).decode("utf-8"))
            except Exception as e:
                raise fail(ErrorCode.VP_MALFORMED, f"Malformed disclosure: {e}")
            if digest in by_digest:
                raise fail(ErrorCode.VP_SIGNATURE_INVALID, "Duplicate disclosure in presentation")
            if not isinstance(disc_json, list) or not isinstance(disc_json[0] if disc_json else None, str):
                raise fail(ErrorCode.VP_MALFORMED, "Disclosure must be an array starting with a string salt")
            if len(disc_json) == 3:
                name = disc_json[1]
                if not isinstance(name, str) or name in ("_sd", "...", "_sd_alg"):
                    raise fail(ErrorCode.VP_MALFORMED, f"Invalid disclosed claim name {name!r}")
                by_digest[digest] = ("object", name, disc_json[2])
            elif len(disc_json) == 2:
                by_digest[digest] = ("array", None, disc_json[1])
            else:
                raise fail(ErrorCode.VP_MALFORMED, "Disclosure must have 2 or 3 elements")

        referenced: set = set()

        def claim_ref(digest: Any, kind: str) -> Any:
            if not isinstance(digest, str):
                raise fail(ErrorCode.VP_MALFORMED, "Digest reference must be a string")
            if digest in referenced:
                raise fail(ErrorCode.VP_SIGNATURE_INVALID, "Duplicate digest reference in credential")
            referenced.add(digest)
            entry = by_digest.get(digest)
            if entry is not None and entry[0] != kind:
                raise fail(ErrorCode.VP_MALFORMED, f"Disclosure type mismatch for {kind} digest")
            return entry

        top_level: Dict[str, Any] = {}

        def process(node: Any, depth: int) -> Any:
            if isinstance(node, dict):
                if depth > 0 and "_sd_alg" in node:
                    raise fail(ErrorCode.VP_MALFORMED, "Nested '_sd_alg' is not permitted")
                result: Dict[str, Any] = {}
                for k, v in node.items():
                    if k in ("_sd", "_sd_alg"):
                        continue
                    result[k] = process(v, depth + 1)
                sd = node.get("_sd")
                if sd is not None:
                    if not isinstance(sd, list):
                        raise fail(ErrorCode.VP_MALFORMED, "'_sd' must be an array of digests")
                    for digest in sd:
                        entry = claim_ref(digest, "object")
                        if entry is None:
                            continue
                        _, name, value = entry
                        if name in result:
                            raise fail(
                                ErrorCode.VP_SIGNATURE_INVALID,
                                f"Disclosed claim '{name}' collides with an existing claim",
                            )
                        result[name] = process(value, depth + 1)
                        if depth == 0:
                            top_level[name] = result[name]
                return result
            if isinstance(node, list):
                out: List[Any] = []
                for el in node:
                    if isinstance(el, dict) and set(el.keys()) == {"..."}:
                        entry = claim_ref(el["..."], "array")
                        if entry is not None:
                            out.append(process(entry[2], depth + 1))
                    else:
                        out.append(process(el, depth + 1))
                return out
            return node

        processed = process(payload, 0)

        unreferenced = set(by_digest) - referenced
        if unreferenced:
            raise fail(
                ErrorCode.VP_SIGNATURE_INVALID,
                "Disclosed claim hash not found in issuer '_sd' array",
            )
        return processed, top_level

    @staticmethod
    def _resolve_claim_path(processed: Dict[str, Any], path: List[str]) -> Any:
        """
        Resolves a DCQL claim path of object keys against the processed payload (OID4VP 7.1,
        object-key subset). Returns None if any segment is absent or descends into a non-object.
        """
        node: Any = processed
        for segment in path:
            if not isinstance(node, dict) or segment not in node:
                return None
            node = node[segment]
        return node

    def verify_presentation(
        self,
        presentation_str: str,
        nonce: str,
        expected_context_id: Optional[str] = None,
        dcql_query: Optional[DCQLQuery] = None,
        single_cred_query: Optional[DCQLCredentialQuery] = None,
        issuer_public_key_jwk: Optional[Dict[str, Any]] = None,
        tls_exporter: Optional[str] = None,
    ) -> VerificationResult:
        """
        Executes the ordered verification algorithm of spec 7.3.4 for an SD-JWT presentation string.

        `tls_exporter` is the encoded tls-exporter value (see `crypto.encode_tls_exporter`) of the
        TLS connection the presentation arrived on, supplied by the transport. It is required
        when the verifier was configured with `channel_binding` (spec 12.8).
        """
        parts = presentation_str.split("~")
        if len(parts) < 2:
            raise CredentialVerificationError(
                ErrorCode.VP_MALFORMED,
                "Malformed SD-JWT presentation string; expected tilde-separated segments",
            )

        issuer_jwt_str = parts[0]
        # In `<issuer-jwt>~<disc1>~...~<kb-jwt>`, the last element is the KB-JWT
        kb_jwt_str = parts[-1]
        disclosures_raw = parts[1:-1] if len(parts) > 2 else []

        if not kb_jwt_str:
            raise CredentialVerificationError(
                ErrorCode.VP_KEY_BINDING_MISSING,
                "Key Binding JWT (KB-JWT) is missing from presentation",
            )

        # Step 2: Decode unverified issuer header/payload to validate alg and get iss
        try:
            issuer_header = jwt.get_unverified_header(issuer_jwt_str)
        except Exception as e:
            raise CredentialVerificationError(
                ErrorCode.VP_MALFORMED,
                f"Failed to decode Issuer-signed JWT header: {str(e)}",
            )

        issuer_alg = issuer_header.get("alg")
        if not issuer_alg or issuer_alg == "none" or issuer_alg not in self.supported_algorithms:
            raise CredentialVerificationError(
                ErrorCode.VP_FORMAT_UNSUPPORTED,
                f"Unsupported Issuer-signed JWT algorithm '{issuer_alg}'; verifier requires one of {self.supported_algorithms}",
            )

        # Spec 7.3.4 step 2: the Issuer-signed JWT header `typ` MUST be `dc+sd-jwt`.
        issuer_typ = issuer_header.get("typ")
        if issuer_typ != "dc+sd-jwt":
            raise CredentialVerificationError(
                ErrorCode.VP_FORMAT_UNSUPPORTED,
                f"Issuer-signed JWT header 'typ' must be 'dc+sd-jwt', got '{issuer_typ}'",
            )

        # Spec 7.3.4 step 2: the KB-JWT header (typ, alg) is checked before any signature work.
        try:
            kb_header = jwt.get_unverified_header(kb_jwt_str)
        except Exception as e:
            raise CredentialVerificationError(
                ErrorCode.VP_MALFORMED,
                f"Failed to decode KB-JWT header: {str(e)}",
            )

        kb_typ = kb_header.get("typ")
        if kb_typ != "kb+jwt":
            raise CredentialVerificationError(
                ErrorCode.VP_FORMAT_UNSUPPORTED,
                f"KB-JWT header 'typ' must be 'kb+jwt', got '{kb_typ}'",
            )

        kb_alg = kb_header.get("alg")
        if not kb_alg or kb_alg == "none" or kb_alg not in self.supported_algorithms:
            raise CredentialVerificationError(
                ErrorCode.VP_FORMAT_UNSUPPORTED,
                f"Unsupported KB-JWT algorithm '{kb_alg}'; verifier requires one of {self.supported_algorithms}",
            )

        try:
            unverified_payload = jwt.decode(
                issuer_jwt_str, options={"verify_signature": False}
            )
        except Exception as e:
            raise CredentialVerificationError(
                ErrorCode.VP_MALFORMED,
                f"Failed to decode Issuer-signed JWT: {str(e)}",
            )

        iss = unverified_payload.get("iss")
        if not iss:
            raise CredentialVerificationError(
                ErrorCode.VP_FORMAT_UNSUPPORTED,
                "Issuer-signed JWT missing 'iss' claim",
            )

        # Resolve Issuer Public Key JWK. An explicitly supplied key is configured trust and wins.
        # Otherwise, with discovery configured, the issuer's permitted mechanism decides; without
        # it the `jwks_resolver` callback is used, as before.
        if issuer_public_key_jwk:
            pub_jwk = issuer_public_key_jwk
        elif self.issuer_key_discovery is not None:
            pub_jwk = self.issuer_key_discovery.resolve(iss, issuer_header)
        else:
            pub_jwk = self.jwks_resolver(iss)
        if not pub_jwk:
            raise CredentialVerificationError(
                ErrorCode.VP_SIGNATURE_INVALID,
                f"Unable to resolve public key for issuer: {iss}",
            )
        # The resolver may return a single JWK or a JWKS ({"keys": [...]}); pick by header kid.
        pub_jwk = self._select_jwk(pub_jwk, issuer_header.get("kid"), iss)

        # Verify Issuer-signed JWT signature first, then enforce exp/iat
        try:
            pub_key = import_public_key_from_jwk(pub_jwk)
            from cryptography.hazmat.primitives import serialization
            pem_pub_key = pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            verified_issuer_payload = jwt.decode(
                issuer_jwt_str,
                key=pem_pub_key,
                algorithms=self.supported_algorithms,
                options={
                    "verify_aud": False,
                    "require": ["exp", "iat"],
                    "verify_exp": True,
                    "verify_iat": True,
                },
            )
        except jwt.ExpiredSignatureError as e:
            raise CredentialVerificationError(
                ErrorCode.VP_CREDENTIAL_EXPIRED,
                f"Issuer-signed JWT has expired: {str(e)}",
            )
        except jwt.MissingRequiredClaimError as e:
            raise CredentialVerificationError(
                ErrorCode.VP_FORMAT_UNSUPPORTED,
                f"Issuer-signed JWT missing required temporal claim: {str(e)}",
            )
        except Exception as e:
            raise CredentialVerificationError(
                ErrorCode.VP_SIGNATURE_INVALID,
                f"Issuer-signed JWT signature verification failed: {str(e)}",
            )

        # Step 5: credential profile and required plaintext claims (Spec 7.3.4 step 5).
        # Read from the signature-verified payload only, so a disclosed `id` or `_sd_alg` cannot count.
        if verified_issuer_payload.get("_sd_alg") != "sha-256":
            raise CredentialVerificationError(
                ErrorCode.VP_SIGNATURE_INVALID,
                f"Unsupported or missing '_sd_alg' {verified_issuer_payload.get('_sd_alg')!r}; expected 'sha-256'",
            )
        agent_id = verified_issuer_payload.get("id")
        if not isinstance(agent_id, str) or not agent_id:
            raise CredentialVerificationError(
                ErrorCode.VP_SIGNATURE_INVALID,
                "Issuer-signed JWT 'id' must be a non-empty plaintext string (not selectively disclosed)",
            )
        cnf = verified_issuer_payload.get("cnf", {})
        holder_jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
        if not holder_jwk:
            raise CredentialVerificationError(
                ErrorCode.VP_FORMAT_UNSUPPORTED,
                "Issuer-signed JWT missing holder binding 'cnf.jwk'",
            )

        # Step 6: validate disclosures recursively per RFC 9901 §7.1 (before the KB-JWT is verified)
        processed_payload, disclosed_claims = self._process_disclosures_full(
            verified_issuer_payload, disclosures_raw
        )

        # Spec 7.3.4 step 5 / 9.2: if `sub` is present it MUST equal `id`; any mismatch is
        # rejected. Checked on the processed payload so a selectively disclosed `sub` counts too.
        if "sub" in processed_payload and processed_payload["sub"] != agent_id:
            raise CredentialVerificationError(
                ErrorCode.VP_SIGNATURE_INVALID,
                "Issuer-signed JWT 'sub' does not equal 'id'; a present 'sub' must match the agent identifier",
            )
        if "vct" in disclosed_claims:
            raise CredentialVerificationError(
                ErrorCode.VP_DCQL_UNSATISFIED,
                "Credential 'vct' must be a plaintext claim and MUST NOT be selectively disclosed",
            )

        # Step 7: verify the KB-JWT signature, required claims and sd_hash
        try:
            holder_pub_key = import_public_key_from_jwk(holder_jwk)
            pem_holder_key = holder_pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            kb_payload = jwt.decode(
                kb_jwt_str,
                key=pem_holder_key,
                algorithms=self.supported_algorithms,
                options={
                    "verify_aud": False,
                    "verify_iat": False,
                },
            )
        except Exception as e:
            raise CredentialVerificationError(
                ErrorCode.VP_SIGNATURE_INVALID,
                f"KB-JWT signature verification failed: {str(e)}",
            )

        # Enforce required typed claims in KB-JWT payload
        if not isinstance(kb_payload.get("nonce"), str) or not kb_payload.get("nonce"):
            raise CredentialVerificationError(
                ErrorCode.VP_FORMAT_UNSUPPORTED,
                "KB-JWT missing or invalid 'nonce' claim (must be non-empty string)",
            )
        if not isinstance(kb_payload.get("aud"), str) or not kb_payload.get("aud"):
            raise CredentialVerificationError(
                ErrorCode.VP_FORMAT_UNSUPPORTED,
                "KB-JWT missing or invalid 'aud' claim (must be single string)",
            )
        if not isinstance(kb_payload.get("sd_hash"), str) or not kb_payload.get("sd_hash"):
            raise CredentialVerificationError(
                ErrorCode.VP_FORMAT_UNSUPPORTED,
                "KB-JWT missing or invalid 'sd_hash' claim (must be non-empty string)",
            )
        if "iat" not in kb_payload or not isinstance(kb_payload.get("iat"), (int, float)):
            raise CredentialVerificationError(
                ErrorCode.VP_FORMAT_UNSUPPORTED,
                "KB-JWT missing or invalid 'iat' claim (must be numeric timestamp)",
            )

        # Verify sd_hash in KB-JWT matches base64url SHA-256 of SD-JWT body
        sd_jwt_body = "~".join(parts[:-1]) + "~"
        expected_sd_hash = compute_sha256_base64url(sd_jwt_body)
        if kb_payload.get("sd_hash") != expected_sd_hash:
            raise CredentialVerificationError(
                ErrorCode.VP_SIGNATURE_INVALID,
                "KB-JWT 'sd_hash' does not match SD-JWT presentation body digest",
            )

        # Step 8: freshness, nonce, audience, conversation and domain binding
        # Freshness acceptance window check (spec 7.3.4 step 8: VP_SIGNATURE_INVALID). This is a
        # property of the presentation, not of the credential, so it is not VP_CREDENTIAL_EXPIRED.
        now = int(time.time())
        kb_iat = int(kb_payload["iat"])
        if kb_iat < (now - self.max_kb_age) or kb_iat > (now + self.allowed_future_skew):
            raise CredentialVerificationError(
                ErrorCode.VP_SIGNATURE_INVALID,
                f"KB-JWT 'iat' ({kb_iat}) is outside freshness acceptance window [now - {self.max_kb_age}, now + {self.allowed_future_skew}]",
            )

        # Verify nonce
        if kb_payload.get("nonce") != nonce:
            raise CredentialVerificationError(
                ErrorCode.VP_NONCE_MISMATCH,
                f"KB-JWT nonce mismatch; expected '{nonce}', got '{kb_payload.get('nonce')}'",
            )

        # Verify aud equals verifier client_id
        if kb_payload.get("aud") != self.client_id:
            raise CredentialVerificationError(
                ErrorCode.VP_AUDIENCE_MISMATCH,
                f"KB-JWT audience mismatch; expected '{self.client_id}', got '{kb_payload.get('aud')}'",
            )

        # Verify conversation_id if present in KB-JWT
        # A present conversation_id is never ignored
        if "conversation_id" in kb_payload:
            conv_id = kb_payload["conversation_id"]
            if not isinstance(conv_id, str) or not conv_id:
                raise CredentialVerificationError(
                    ErrorCode.VP_CONVERSATION_MISMATCH,
                    "KB-JWT 'conversation_id' must be a non-empty string",
                )
            if expected_context_id is None:
                raise CredentialVerificationError(
                    ErrorCode.VP_CONVERSATION_MISMATCH,
                    "KB-JWT carries 'conversation_id' but no trusted expected context is available",
                )
            if conv_id != expected_context_id:
                raise CredentialVerificationError(
                    ErrorCode.VP_CONVERSATION_MISMATCH,
                    f"KB-JWT conversation_id '{conv_id}' does not match task contextId '{expected_context_id}'",
                )

        # Verify domains if present in KB-JWT.
        # Absent => unrestricted; present must be list[str]; [] authorizes no verifier.
        if "domains" in kb_payload:
            domains = kb_payload["domains"]
            if not isinstance(domains, list) or not all(isinstance(d, str) for d in domains):
                raise CredentialVerificationError(
                    ErrorCode.VP_DOMAIN_NOT_ALLOWED,
                    "KB-JWT 'domains' must be an array of strings",
                )
            if self.client_id not in domains:
                raise CredentialVerificationError(
                    ErrorCode.VP_DOMAIN_NOT_ALLOWED,
                    f"Verifier client_id '{self.client_id}' not present in KB-JWT authorized domains: {domains}",
                )

        # Spec 7.3.4 step 8 / 12.8: channel binding, enforced only when the verifier declares it.
        # Undeclared, a present claim is ignored.
        if self.channel_binding:
            claimed = kb_payload.get("channel_binding")
            if not tls_exporter:
                raise CredentialVerificationError(
                    ErrorCode.VP_CHANNEL_BINDING_MISMATCH,
                    "Verifier requires channel binding but the tls-exporter value of the connection is unavailable",
                )
            if not isinstance(claimed, str) or not claimed:
                raise CredentialVerificationError(
                    ErrorCode.VP_CHANNEL_BINDING_MISMATCH,
                    "KB-JWT lacks the 'channel_binding' claim that this verifier requires",
                )
            if not hmac.compare_digest(claimed.encode("ascii", "replace"), tls_exporter.encode("ascii", "replace")):
                raise CredentialVerificationError(
                    ErrorCode.VP_CHANNEL_BINDING_MISMATCH,
                    "KB-JWT 'channel_binding' does not match the tls-exporter value of this connection",
                )

        # Step 9: Token Status List revocation check (Spec 7.3.4 step 9), after the KB-JWT is
        # verified so unauthenticated presentations cause no status-list lookups. Read from the signature-verified payload only.
        status_list_ref = (verified_issuer_payload.get("status") or {}).get("status_list")
        if status_list_ref:
            if self.tsl_client is None:
                if not self.allow_unverified_status:
                    raise CredentialVerificationError(
                        ErrorCode.VP_CREDENTIAL_REVOKED,
                        f"Credential contains status_list reference '{status_list_ref.get('uri')}' but verifier has no TSL client configured (fail-closed)",
                    )
            else:
                from .models import StatusListReference

                ref = StatusListReference(
                    idx=status_list_ref.get("idx", 0),
                    uri=status_list_ref.get("uri", ""),
                )
                try:
                    revoked = self.tsl_client.is_revoked(ref)
                except Exception as e:
                    # Fail closed: an unresolvable status list is not evidence of validity.
                    raise CredentialVerificationError(
                        ErrorCode.VP_CREDENTIAL_REVOKED,
                        f"Token Status List check could not be completed for {ref.uri} [idx {ref.idx}]: {e}",
                    )
                if revoked:
                    raise CredentialVerificationError(
                        ErrorCode.VP_CREDENTIAL_REVOKED,
                        f"Credential is revoked in Token Status List {ref.uri} [idx {ref.idx}]",
                    )

        # Spec 7.3.4 step 5: `vct` is required whether or not a query constrains it.
        cred_vct = self.resolve_credential_type(verified_issuer_payload)

        # Check DCQL Query requirements if provided
        # Can check single_cred_query directly, or iterate credentials in dcql_query
        target_queries: List[DCQLCredentialQuery] = []
        if single_cred_query:
            target_queries = [single_cred_query]
        elif dcql_query:
            target_queries = dcql_query.credentials

        for cred_query in target_queries:
            # 1. Enforce Credential Type against meta.vct_values
            expected_vcts = cred_query.meta.get("vct_values") if cred_query.meta else None
            if expected_vcts:
                # Exact, case-sensitive match against the requested vct_values. A short
                # name only matches when the query lists that short name itself.
                if cred_vct not in expected_vcts:
                    raise CredentialVerificationError(
                        ErrorCode.VP_DCQL_UNSATISFIED,
                        f"Credential type '{cred_vct}' does not satisfy requested vct_values: {expected_vcts}",
                    )

            # 2. Check that each requested claim is present in either plaintext payload or disclosed_claims
            for claim_query in cred_query.claims:
                req_name = ".".join(claim_query.path)
                val = self._resolve_claim_path(processed_payload, claim_query.path)
                if val is None:
                    raise CredentialVerificationError(
                        ErrorCode.VP_DCQL_UNSATISFIED,
                        f"Required claim '{req_name}' was not disclosed in presentation",
                    )
                if claim_query.values and val not in claim_query.values:
                    raise CredentialVerificationError(
                        ErrorCode.VP_DCQL_UNSATISFIED,
                        f"Claim '{req_name}' value '{val}' not in allowed values: {claim_query.values}",
                    )

        verified_type = cred_vct
        query_id = single_cred_query.id if single_cred_query else (target_queries[0].id if target_queries else None)

        res = VerificationResult(
            is_valid=True,
            issuer=iss,
            credential_type=verified_type,
            id_claim=verified_issuer_payload.get("id", ""),
            disclosed_claims=disclosed_claims,
            raw_issuer_jwt_payload=verified_issuer_payload,
            kb_jwt_payload=kb_payload,
            query_id=query_id,
        )
        if query_id:
            res.results[query_id] = res
        return res
