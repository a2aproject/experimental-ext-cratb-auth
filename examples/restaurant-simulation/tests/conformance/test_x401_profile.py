# SPDX-License-Identifier: Apache-2.0
import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../infrastructure")))

from a2a_agentic_id.models import ErrorCode
from a2a_agentic_id.verifier import CredentialVerificationError
from restaurant_domain.x401 import (
    RESULT_ARTIFACT_TOKEN_TYPE,
    TOKEN_EXCHANGE_GRANT_TYPE,
    build_result_artifact,
    decode_result_artifact,
    encode_result_artifact,
    extract_vp_token,
)
from kitchen_oauth_as.server import KitchenOAuthAS, TokenExchangeRequest


class TestX401ResultArtifact(unittest.TestCase):
    """Spec Appendix C.3: Result Artifact construction and encoding."""

    VP_TOKEN = {"emp_cred": ["issuer.jwt~disc1~disc2~kb.jwt"]}

    def test_artifact_shape_matches_appendix_c3(self) -> None:
        self.assertEqual(
            build_result_artifact(self.VP_TOKEN),
            {
                "credential_result": {
                    "protocol": "openid4vp",
                    "data": {"vp_token": {"emp_cred": ["issuer.jwt~disc1~disc2~kb.jwt"]}},
                }
            },
        )

    def test_dcql_ids_are_not_rekeyed(self) -> None:
        multi = {"agent_identity": ["a~b"], "emp_cred": ["c~d"], "sub_approval": ["e~f"]}
        data = build_result_artifact(multi)["credential_result"]["data"]["vp_token"]
        self.assertEqual(set(data.keys()), set(multi.keys()))
        self.assertEqual(data, multi)

    def test_encoding_is_unpadded_base64url(self) -> None:
        encoded = encode_result_artifact(build_result_artifact(self.VP_TOKEN))
        self.assertNotIn("=", encoded)
        self.assertNotIn("+", encoded)
        self.assertNotIn("/", encoded)
        decoded = json.loads(
            base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8")
        )
        self.assertEqual(decoded["credential_result"]["protocol"], "openid4vp")

    def test_round_trip_preserves_presentations_verbatim(self) -> None:
        artifact = build_result_artifact(self.VP_TOKEN)
        recovered = extract_vp_token(decode_result_artifact(encode_result_artifact(artifact)))
        self.assertEqual(recovered, self.VP_TOKEN)
        self.assertEqual(recovered["emp_cred"][0], "issuer.jwt~disc1~disc2~kb.jwt")

    def test_malformed_artifacts_are_rejected(self) -> None:
        for bad in (
            {},
            {"credential_result": {}},
            {"credential_result": {"protocol": "mdoc", "data": {"vp_token": {}}}},
            {"credential_result": {"protocol": "openid4vp", "data": {}}},
        ):
            with self.assertRaises(ValueError, msg=f"accepted {bad!r}"):
                extract_vp_token(bad)

    def test_token_type_and_grant_type_constants(self) -> None:
        self.assertEqual(
            RESULT_ARTIFACT_TOKEN_TYPE,
            "urn:x401:params:oauth:token-type:result_artifact",
        )
        self.assertEqual(
            TOKEN_EXCHANGE_GRANT_TYPE,
            "urn:ietf:params:oauth:grant-type:token-exchange",
        )

    def test_server_rejects_unsupported_token_type_and_grant_type(self) -> None:
        as_server = KitchenOAuthAS()
        valid_req = TokenExchangeRequest(
            subject_token=encode_result_artifact(build_result_artifact(self.VP_TOKEN)),
            scope="kitchen:appliances:use",
            nonce="test-nonce",
        )
        self.assertEqual(valid_req.subject_token_type, RESULT_ARTIFACT_TOKEN_TYPE)
        self.assertEqual(valid_req.grant_type, TOKEN_EXCHANGE_GRANT_TYPE)

        # Unsupported subject_token_type
        bad_type_req = TokenExchangeRequest(
            subject_token=encode_result_artifact(build_result_artifact(self.VP_TOKEN)),
            subject_token_type="urn:ietf:params:oauth:token-type:vp_token",
            scope="kitchen:appliances:use",
            nonce="test-nonce",
        )
        with self.assertRaises(ValueError):
            as_server.token_exchange(bad_type_req)

        # Unsupported grant_type
        bad_grant_req = TokenExchangeRequest(
            subject_token=encode_result_artifact(build_result_artifact(self.VP_TOKEN)),
            grant_type="client_credentials",
            scope="kitchen:appliances:use",
            nonce="test-nonce",
        )
        with self.assertRaises(ValueError):
            as_server.token_exchange(bad_grant_req)

    def test_server_rejects_malformed_subject_token_with_error_code(self) -> None:
        as_server = KitchenOAuthAS()

        # Non-base64 / non-json string
        bad_req = TokenExchangeRequest(
            subject_token="not-valid-base64url-json",
            scope="kitchen:appliances:use",
            nonce="test-nonce",
        )
        with self.assertRaises(CredentialVerificationError) as ctx:
            as_server.token_exchange(bad_req)
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_FORMAT_UNSUPPORTED)

        # Decodable JSON but missing required fields
        bad_artifact_req = TokenExchangeRequest(
            subject_token=encode_result_artifact({"some": "other-data"}),
            scope="kitchen:appliances:use",
            nonce="test-nonce",
        )
        with self.assertRaises(CredentialVerificationError) as ctx:
            as_server.token_exchange(bad_artifact_req)
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_FORMAT_UNSUPPORTED)


if __name__ == "__main__":
    unittest.main()
