# SPDX-License-Identifier: Apache-2.0
import json
import time
from typing import Any, Dict, List, Optional, Tuple
import jwt
from pydantic import BaseModel

from .crypto import (
    base64url_decode,
    base64url_encode,
    compute_sha256_base64url,
    generate_salt,
    import_private_key_from_jwk,
    import_public_key_from_jwk,
    export_jwk_from_public_key,
)
from .models import (
    AI_AGENT_IDENTITY_VCT,
    DCQLCredentialQuery,
    DCQLQuery,
    IdentityResponse,
    is_collision_resistant_type,
)
from .verifier import CredentialVerificationError, SDJWTVerifier


RESERVED_ISSUER_CLAIMS = frozenset({
    "iss",
    "sub",
    "iat",
    "exp",
    "nbf",
    "cnf",
    "vct",
    "dct",
    "id",
    "_sd",
    "_sd_alg",
    "status",
})


class CredentialItem(BaseModel):
    """
    Stored credential in the wallet.
    """
    id: str
    format: str = "dc+sd-jwt"
    sd_jwt_string: str  # Format: "<issuer-jwt>~<disclosure_1>~...~"
    holder_private_key_jwk: Dict[str, Any]


class SDJWTWallet:
    """
    Manages SD-JWT credentials and generates Verifiable Presentations with Key Binding JWTs (KB-JWT).
    """
    def __init__(self) -> None:
        self.credentials: Dict[str, CredentialItem] = {}

    def add_credential(self, cred: CredentialItem) -> None:
        self.credentials[cred.id] = cred

    def get_credential(self, cred_id: str) -> Optional[CredentialItem]:
        return self.credentials.get(cred_id)

    def _find_matching_credential(
        self, cred_query: DCQLCredentialQuery
    ) -> Optional[CredentialItem]:
        """
        Selects a candidate credential matching the DCQL query constraints per Spec 9.6:
        1. Exact ID match (if held in wallet and satisfies format/type constraints).
        2. Candidate discovery by format match and meta.vct_values match (if meta.vct_values specified).
        3. Prioritizes candidates satisfying requested claims.
        """
        requested_paths = [c.path for c in cred_query.claims]
        expected_vcts = cred_query.meta.get("vct_values") if cred_query.meta else None

        # A stored credential whose id equals the query id is only a *preference*: it must
        # pass the same format, type and claim checks as any other candidate (Spec 9.6.1).
        exact_item = self.credentials.get(cred_query.id)
        if exact_item and exact_item.format != cred_query.format:
            raise ValueError(
                f"Credential '{cred_query.id}' has format '{exact_item.format}', "
                f"but the DCQL query requests '{cred_query.format}'"
            )

        if expected_vcts or requested_paths:
            candidates: List[Tuple[int, int, CredentialItem]] = []
            for cred_item in self.credentials.values():
                if cred_item.format != cred_query.format:
                    continue

                try:
                    parts = cred_item.sd_jwt_string.split("~")
                    issuer_jwt = parts[0]
                    disclosures_raw = parts[1:-1] if len(parts) > 1 else []
                    payload = jwt.decode(issuer_jwt, options={"verify_signature": False})
                except Exception:
                    continue

                if expected_vcts:
                    try:
                        item_vct = SDJWTVerifier.resolve_credential_type(payload)
                    except CredentialVerificationError:
                        continue
                    if item_vct not in expected_vcts:
                        continue

                # Check claims availability: resolve each full path against the payload with every
                # stored disclosure applied, so nested paths are evaluated, not just their first key.
                try:
                    processed, _ = SDJWTVerifier._process_disclosures_full(
                        {**payload, "_sd_alg": payload.get("_sd_alg", "sha-256")}, disclosures_raw
                    )
                except Exception:
                    continue
                available_claims = set(processed.keys())

                # Every requested path must resolve (and satisfy any value constraint); a
                # partial match is not a candidate.
                if not all(
                    SDJWTVerifier._resolve_claim_path(processed, cq.path) is not None
                    and (not cq.values or SDJWTVerifier._resolve_claim_path(processed, cq.path) in cq.values)
                    for cq in cred_query.claims
                ):
                    continue
                prefer_exact = 0 if cred_item is exact_item else 1
                candidates.append((prefer_exact, len(available_claims), cred_item))

            if candidates:
                candidates.sort(key=lambda x: (x[0], x[1]))
                return candidates[0][2]
            return None

        # No type or claim constraints in the query: the id match (if any) is all there is.
        return exact_item

    def create_vp_token(
        self,
        dcql_query: DCQLQuery,
        nonce: str,
        client_id: str,
        conversation_id: Optional[str] = None,
        domains: Optional[List[str]] = None,
        channel_binding: Optional[str] = None,
    ) -> IdentityResponse:
        """
        Creates an IdentityResponse containing vp_token mapped by DCQL credential ID.

        Matches credentials by format, meta.vct_values, and requested claims (Spec 9.6).
        Returned presentations are keyed by the query's cred_query.id.
        """
        vp_token: Dict[str, List[str]] = {}

        for cred_query in dcql_query.credentials:
            cred_item = self._find_matching_credential(cred_query)
            if not cred_item:
                raise ValueError(f"Credential satisfying DCQL query '{cred_query.id}' not found in wallet")

            requested_claims = [c.path[0] for c in cred_query.claims]

            vp_str = self.create_presentation(
                cred_item=cred_item,
                requested_claims=requested_claims,
                requested_paths=[c.path for c in cred_query.claims],
                nonce=nonce,
                client_id=client_id,
                conversation_id=conversation_id,
                domains=domains,
                channel_binding=channel_binding,
            )
            vp_token[cred_query.id] = [vp_str]

        return IdentityResponse(vp_token=vp_token)

    def create_presentation(
        self,
        cred_item: CredentialItem,
        requested_claims: List[str],
        nonce: str,
        client_id: str,
        conversation_id: Optional[str] = None,
        domains: Optional[List[str]] = None,
        requested_paths: Optional[List[List[str]]] = None,
        channel_binding: Optional[str] = None,
    ) -> str:
        """
        Constructs a single SD-JWT presentation string with a Key Binding JWT (KB-JWT).

        `requested_claims` names top-level claims. `requested_paths` (DCQL claim paths) also
        reveals the Disclosures along each nested path, so the path resolves at the Verifier.
        `channel_binding` is the encoded tls-exporter value of the connection that will carry the
        presentation (spec 12.8); pass it only to a Verifier that declares channel binding.
        """
        parts = cred_item.sd_jwt_string.split("~")
        issuer_jwt = parts[0]
        disclosures_raw = parts[1:-1] if len(parts) > 1 else []

        # digest -> (disclosure string, claim name, claim value), for object-property disclosures
        by_digest: Dict[str, Tuple[str, str, Any]] = {}
        for disc_b64 in disclosures_raw:
            if not disc_b64:
                continue
            disc_bytes = base64url_decode(disc_b64)
            disc_json = json.loads(disc_bytes.decode("utf-8"))
            # Form: [salt, claim_name, claim_value]
            if len(disc_json) >= 3:
                by_digest[compute_sha256_base64url(disc_b64)] = (disc_b64, disc_json[1], disc_json[2])

        selected: set = set()

        def reveal(node: Any, path: List[str]) -> None:
            """Selects the Disclosures needed to resolve `path` starting at `node`."""
            if not path or not isinstance(node, dict):
                return
            head, rest = path[0], path[1:]
            if head in node:  # plaintext key
                reveal(node[head], rest)
            for digest in node.get("_sd", []) if isinstance(node.get("_sd"), list) else []:
                entry = by_digest.get(digest)
                if entry and entry[1] == head:
                    selected.add(entry[0])
                    reveal(entry[2], rest)

        issuer_payload = jwt.decode(issuer_jwt, options={"verify_signature": False})
        for path in (requested_paths if requested_paths is not None else [[c] for c in requested_claims]):
            reveal(issuer_payload, list(path))
        # Preserve the original disclosure order; also keep any top-level claim named in
        # `requested_claims` even if it is not reachable from the payload's own `_sd`.
        selected_disclosures: List[str] = [
            d for d in disclosures_raw
            if d and (d in selected or (
                by_digest.get(compute_sha256_base64url(d)) is not None
                and by_digest[compute_sha256_base64url(d)][1] in requested_claims
            ))
        ]

        # Build SD-JWT body before KB-JWT: "<issuer-jwt>~<disc1>~<disc2>~"
        sd_jwt_body = issuer_jwt + "~" + "~".join(selected_disclosures) + "~"

        # Compute sd_hash per SD-JWT spec
        sd_hash = compute_sha256_base64url(sd_jwt_body)

        # Build KB-JWT payload
        now = int(time.time())
        kb_payload: Dict[str, Any] = {
            "nonce": nonce,
            "aud": client_id,
            "iat": now,
            "sd_hash": sd_hash,
        }
        if conversation_id:
            kb_payload["conversation_id"] = conversation_id
        if domains is not None:
            kb_payload["domains"] = domains
        if channel_binding:
            kb_payload["channel_binding"] = channel_binding

        # Sign KB-JWT with holder private key (ES256)
        priv_key = import_private_key_from_jwk(cred_item.holder_private_key_jwk)
        # pyjwt expects a PEM format or we can use cryptography serialization
        from cryptography.hazmat.primitives import serialization
        pem_key = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        kb_jwt = jwt.encode(
            payload=kb_payload,
            key=pem_key,
            algorithm="ES256",
            headers={"typ": "kb+jwt"},
        )

        return sd_jwt_body + kb_jwt

    @staticmethod
    def issue_sd_jwt(
        issuer_private_key_jwk: Dict[str, Any],
        iss: str,
        dct: Optional[str] = None,
        id_claim: str = "",
        plaintext_claims: Optional[Dict[str, Any]] = None,
        sd_claims: Optional[Dict[str, Any]] = None,
        holder_public_key_jwk: Optional[Dict[str, Any]] = None,
        expires_in_seconds: int = 86400,
        status_list_ref: Optional[Dict[str, Any]] = None,
        vct: Optional[str] = None,
        require_identity_profile: bool = False,
    ) -> str:
        """
        Helper method for Issuers to generate conformant SD-JWT credentials with cnf.jwk holder binding.
        Sets the plaintext `vct` claim (spec 9.2) and the JOSE header typ='dc+sd-jwt', and protects
        reserved claims.

        `vct` is the credential type. The `dct` parameter is a deprecated alias for the same
        value, kept so existing callers keep working; passing both with different values is an
        error. No `dct` claim is written to the credential (it is not part of the profile).
        """
        if vct is not None and dct is not None and vct != dct:
            raise ValueError(f"Conflicting credential type: vct={vct!r} but legacy dct={dct!r}")
        # Extract status_list_ref from plaintext_claims if provided via {"status": {"status_list": ...}}
        effective_status_list_ref = status_list_ref
        effective_plaintext_claims = dict(plaintext_claims) if plaintext_claims else {}

        if "status" in effective_plaintext_claims:
            status_val = effective_plaintext_claims.pop("status")
            if not isinstance(status_val, dict) or "status_list" not in status_val:
                raise ValueError("Cannot overwrite reserved claim 'status' via plaintext_claims")
            if effective_status_list_ref is None:
                effective_status_list_ref = status_val["status_list"]

        # Validate that plaintext_claims and sd_claims do not overwrite reserved claims
        for claim_name in effective_plaintext_claims:
            if claim_name in RESERVED_ISSUER_CLAIMS:
                raise ValueError(
                    f"Cannot overwrite reserved claim '{claim_name}' via plaintext_claims"
                )

        if sd_claims:
            for claim_name in sd_claims:
                if claim_name in RESERVED_ISSUER_CLAIMS:
                    raise ValueError(
                        f"Cannot selectively disclose reserved claim '{claim_name}' via sd_claims"
                    )

        # Collision detection between plaintext and selectively disclosed claims
        if effective_plaintext_claims and sd_claims:
            collisions = set(effective_plaintext_claims.keys()) & set(sd_claims.keys())
            if collisions:
                raise ValueError(
                    f"Claim collision: claims {sorted(collisions)} appear in both plaintext_claims and sd_claims"
                )

        # Validate status_list_ref if present
        if effective_status_list_ref is not None:
            uri = effective_status_list_ref.get("uri") if isinstance(effective_status_list_ref, dict) else None
            if not uri or not isinstance(uri, str):
                raise ValueError("status_list_ref missing or invalid 'uri' (must be non-empty string)")
            idx = effective_status_list_ref.get("idx") if isinstance(effective_status_list_ref, dict) else None
            if idx is None or not isinstance(idx, int) or idx < 0:
                raise ValueError("status_list_ref missing or invalid 'idx' (must be non-negative integer)")

        # Validate identity profile claims if required
        if require_identity_profile:
            all_claims = set(effective_plaintext_claims.keys()) | set((sd_claims or {}).keys())
            for req in ("name", "description", "owner"):
                if req not in all_claims:
                    raise ValueError(f"Identity profile credential missing required claim '{req}'")

        now = int(time.time())
        exp = now + expires_in_seconds

        effective_vct = vct or dct or AI_AGENT_IDENTITY_VCT
        # Spec 9.2: `vct` is a collision-resistant type identifier, so a bare label is refused.
        if not is_collision_resistant_type(effective_vct):
            raise ValueError(
                f"vct {effective_vct!r} is not a collision-resistant type identifier "
                f"(use an absolute https URI or a URN, e.g. {AI_AGENT_IDENTITY_VCT})"
            )

        disclosures: List[str] = []
        sd_hashes: List[str] = []

        for claim_name, claim_value in (sd_claims or {}).items():
            salt = generate_salt(16)
            disc_array = [salt, claim_name, claim_value]
            disc_str = json.dumps(disc_array, separators=(",", ":"))
            disc_b64 = base64url_encode(disc_str.encode("utf-8"))
            disclosures.append(disc_b64)
            sd_hashes.append(compute_sha256_base64url(disc_b64))

        payload: Dict[str, Any] = {
            "iss": iss,
            "iat": now,
            "exp": exp,
            "vct": effective_vct,
            "id": id_claim,
            "cnf": {"jwk": holder_public_key_jwk} if holder_public_key_jwk else {},
            "_sd": sd_hashes,
            "_sd_alg": "sha-256",
        }
        if effective_plaintext_claims:
            payload.update(effective_plaintext_claims)
        if effective_status_list_ref:
            payload["status"] = {"status_list": effective_status_list_ref}

        priv_key = import_private_key_from_jwk(issuer_private_key_jwk)
        from cryptography.hazmat.primitives import serialization
        pem_key = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        issuer_jwt = jwt.encode(
            payload=payload,
            key=pem_key,
            algorithm="ES256",
            headers={"typ": "dc+sd-jwt"},
        )

        # Format: "<issuer-jwt>~<disc1>~<disc2>~..."
        return issuer_jwt + "~" + "~".join(disclosures) + "~"
