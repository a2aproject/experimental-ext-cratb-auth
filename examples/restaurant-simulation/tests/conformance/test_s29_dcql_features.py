# SPDX-License-Identifier: Apache-2.0
"""
S29: DCQL schema and unsupported-feature handling (spec 9.6, 9.6.1, security considerations).

- "dcql_query MUST be validated against DCQL schema before processing"
- "Unsupported required DCQL semantics MUST NOT be silently ignored"
- "A Holder unable to satisfy all required queries MUST NOT return a partial success"
- "One accepted presentation MUST NOT substitute for other required query results"
- ids: non-empty [A-Za-z0-9_-], unique within one dcql_query
"""

import copy
import json
import unittest
from pathlib import Path
from typing import Any, Dict

from pydantic import ValidationError

from a2a_agentic_id import (
    CredentialItem,
    DCQLClaimQuery,
    DCQLCredentialQuery,
    DCQLQuery,
    IdentityChallenge,
    SDJWTWallet,
)
from a2a_agentic_id.crypto import (
    export_jwk_from_private_key,
    export_jwk_from_public_key,
    generate_ec_p256_keypair,
)

VCT = "https://example.com/credentials/Thing/v1"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def cred(**over: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {"id": "a", "format": "dc+sd-jwt", "meta": {"vct_values": [VCT]}}
    base.update(over)
    return base


def query(*creds: Dict[str, Any], **top: Any) -> Dict[str, Any]:
    return {"credentials": list(creds), **top}


class TestUnsupportedFeaturesRejected(unittest.TestCase):
    def assertRejected(self, raw: Dict[str, Any], msg: str = "") -> None:
        with self.assertRaises(ValidationError, msg=msg):
            DCQLQuery.model_validate(raw)

    def test_credential_sets_rejected(self) -> None:
        self.assertRejected(query(cred(), credential_sets=[{"options": [["a"]]}]))

    def test_claim_sets_rejected(self) -> None:
        self.assertRejected(query(cred(claims=[{"path": ["x"]}], claim_sets=[["x"]])))

    def test_claim_id_rejected(self) -> None:
        # claims[].id exists only so claim_sets can reference it.
        self.assertRejected(query(cred(claims=[{"id": "c1", "path": ["x"]}])))

    def test_multiple_true_rejected(self) -> None:
        self.assertRejected(query(cred(multiple=True)))

    def test_holder_binding_cannot_be_waived(self) -> None:
        self.assertRejected(query(cred(require_cryptographic_holder_binding=False)))

    def test_defaults_for_multiple_and_binding_accepted(self) -> None:
        q = DCQLQuery.model_validate(query(cred(multiple=False, require_cryptographic_holder_binding=True)))
        self.assertEqual(len(q.credentials), 1)

    def test_unknown_fields_rejected_at_every_level(self) -> None:
        self.assertRejected(query(cred(), surprise=1), "top level")
        self.assertRejected(query(cred(surprise=1)), "credential query")
        self.assertRejected(query(cred(claims=[{"path": ["x"], "surprise": 1}])), "claim query")

    def test_unknown_meta_field_rejected_for_dc_sd_jwt(self) -> None:
        self.assertRejected(query(cred(meta={"vct_values": [VCT], "doctype_value": "x"})))

    def test_empty_claims_array_rejected_but_absent_claims_fine(self) -> None:
        self.assertRejected(query(cred(claims=[])))
        self.assertEqual(DCQLQuery.model_validate(query(cred())).credentials[0].claims, [])

    def test_empty_credentials_rejected(self) -> None:
        self.assertRejected({"credentials": []})
        self.assertRejected({})


class TestCredentialQueryIds(unittest.TestCase):
    def test_duplicate_ids_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            DCQLQuery.model_validate(query(cred(id="a"), cred(id="a", meta={"vct_values": ["https://example.com/credentials/Other/v1"]})))

    def test_distinct_ids_accepted(self) -> None:
        q = DCQLQuery.model_validate(query(cred(id="a"), cred(id="b-2_x", meta={"vct_values": ["https://example.com/credentials/Other/v1"]})))
        self.assertEqual([c.id for c in q.credentials], ["a", "b-2_x"])

    def test_id_character_set_enforced(self) -> None:
        for bad in ("", "a b", "a.b", "a/b", "é", "a:b"):
            with self.assertRaises(ValidationError, msg=repr(bad)):
                DCQLCredentialQuery(id=bad, meta={"vct_values": [VCT]})


class TestTrustedAuthorities(unittest.TestCase):
    def test_well_formed_trusted_authorities_accepted(self) -> None:
        meta = {"vct_values": [VCT], "trusted_authorities": [{"type": "aki", "values": ["abc", "def"]}]}
        self.assertEqual(DCQLCredentialQuery(id="a", meta=meta).meta["trusted_authorities"][0]["type"], "aki")

    def test_malformed_trusted_authorities_rejected(self) -> None:
        for bad in (
            [], {}, "aki", [{"type": "aki"}], [{"values": ["x"]}], [{"type": "", "values": ["x"]}],
            [{"type": "aki", "values": []}], [{"type": "aki", "values": [1]}],
            [{"type": "aki", "values": ["x"], "extra": 1}], ["aki"],
        ):
            with self.assertRaises(ValidationError, msg=repr(bad)):
                DCQLCredentialQuery(id="a", meta={"vct_values": [VCT], "trusted_authorities": bad})


class TestWireCompatibility(unittest.TestCase):
    def test_default_query_serializes_without_profile_only_fields(self) -> None:
        dumped = DCQLQuery.default_agent_identity_query().model_dump()
        self.assertEqual(set(dumped["credentials"][0]), {"id", "format", "meta", "claims"})

    def test_dump_and_revalidate_roundtrip(self) -> None:
        q = DCQLQuery.default_agent_identity_query()
        again = DCQLQuery.model_validate(copy.deepcopy(q.model_dump()))
        self.assertEqual(again, q)

    def test_appendix_a_challenge_fixture_still_parses(self) -> None:
        task = json.loads((FIXTURES / "a3_auth_required.json").read_text(encoding="utf-8"))["result"]["task"]
        meta = task["status"]["message"]["metadata"]
        ext = next(iter(meta.values()))
        challenge = IdentityChallenge.model_validate(ext)
        self.assertTrue(challenge.dcql_query.credentials)

    def test_challenge_with_unsupported_feature_is_rejected_not_ignored(self) -> None:
        task = json.loads((FIXTURES / "a3_auth_required.json").read_text(encoding="utf-8"))["result"]["task"]
        ext = copy.deepcopy(next(iter(task["status"]["message"]["metadata"].values())))
        ext["dcql_query"]["credential_sets"] = [{"options": [["agent_identity"]]}]
        with self.assertRaises(ValidationError):
            IdentityChallenge.model_validate(ext)


class TestHolderNeverReturnsPartialSuccess(unittest.TestCase):
    def setUp(self) -> None:
        iss_priv, _ = generate_ec_p256_keypair()
        holder_priv, holder_pub = generate_ec_p256_keypair()
        token = SDJWTWallet.issue_sd_jwt(
            export_jwk_from_private_key(iss_priv), "https://issuer.example.com", vct=VCT, id_claim="a",
            sd_claims={"name": "n"}, holder_public_key_jwk=export_jwk_from_public_key(holder_pub),
        )
        self.wallet = SDJWTWallet()
        self.wallet.add_credential(
            CredentialItem(id="held", sd_jwt_string=token, holder_private_key_jwk=export_jwk_from_private_key(holder_priv))
        )

    def test_all_queries_satisfiable_returns_every_key(self) -> None:
        q = DCQLQuery(credentials=[DCQLCredentialQuery(id="one", meta={"vct_values": [VCT]})])
        vp = self.wallet.create_vp_token(q, nonce="n", client_id="https://v.example.com")
        self.assertEqual(set(vp.vp_token), {"one"})

    def test_one_unsatisfiable_query_means_no_vp_token_at_all(self) -> None:
        q = DCQLQuery(credentials=[
            DCQLCredentialQuery(id="one", meta={"vct_values": [VCT]}),
            DCQLCredentialQuery(id="two", meta={"vct_values": ["https://example.com/credentials/NotHeld/v1"]}),
        ])
        with self.assertRaises(ValueError):
            self.wallet.create_vp_token(q, nonce="n", client_id="https://v.example.com")

    def test_unsatisfiable_claim_constraint_also_blocks_the_whole_response(self) -> None:
        q = DCQLQuery(credentials=[
            DCQLCredentialQuery(id="one", meta={"vct_values": [VCT]}),
            DCQLCredentialQuery(
                id="two", meta={"vct_values": [VCT]}, claims=[DCQLClaimQuery(path=["name"], values=["other"])]
            ),
        ])
        with self.assertRaises(ValueError):
            self.wallet.create_vp_token(q, nonce="n", client_id="https://v.example.com")


if __name__ == "__main__":
    unittest.main()
