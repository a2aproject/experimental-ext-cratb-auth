# SPDX-License-Identifier: Apache-2.0
"""TASK-5.2: spec Appendix A (A2A v1.0 JSON) fixtures parsed through the SDK models."""

import json
import unittest
from pathlib import Path
from typing import Any, Dict

from a2a_agentic_id import (
    A2ATaskMessage,
    A2ATaskStatusResponse,
    DCQLQuery,
    ExtensionSupportRequiredError,
    IdentityChallenge,
    IdentityResponse,
    ServerAuthRequiredInterceptor,
    SDJWTVerifier,
)
from a2a_agentic_id.interceptor import EXTENSION_URI

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def load(name: str) -> Dict[str, Any]:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


class TestAppendixAFixtures(unittest.TestCase):
    def test_a2_initial_request_has_no_ids_and_parses_as_message(self) -> None:
        msg = load("a2_initial_request")["params"]["message"]
        req = A2ATaskMessage(
            channel_id="test-channel",
            headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"},
            metadata=msg["metadata"],
            parts=msg["parts"],
        )
        self.assertIsNone(req.id)
        fmts = req.metadata[EXTENSION_URI]["vp_formats_supported"]["dc+sd-jwt"]
        self.assertEqual(fmts["kb-jwt_alg_values"], ["ES256"])

    def test_a3_challenge_parses_into_identity_challenge_and_task_response(self) -> None:
        task = load("a3_auth_required")["result"]["task"]
        resp = A2ATaskStatusResponse(**task)
        self.assertEqual(resp.status.wire_state, "TASK_STATE_AUTH_REQUIRED")
        self.assertEqual(resp.status.state, "TASK_STATE_AUTH_REQUIRED")
        challenge = IdentityChallenge.model_validate(resp.message["metadata"][EXTENSION_URI])
        self.assertTrue(challenge.client_id.startswith("a2a_agent_card:"))
        self.assertEqual(challenge.response_uri, "https://verifier.example.com/a2a")
        self.assertEqual(
            challenge.dcql_query.credentials[0].meta["vct_values"],
            ["https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"],
        )

    def test_a4_identity_response_parses(self) -> None:
        msg = load("a4_identity_response")["params"]["message"]
        resp = IdentityResponse.model_validate(msg["metadata"][EXTENSION_URI])
        self.assertEqual(list(resp.vp_token), ["agent_identity"])
        req = A2ATaskMessage(channel_id="test-channel", id=msg["taskId"], contextId=msg["contextId"], metadata=msg["metadata"])
        self.assertEqual(req.context_id, msg["contextId"])

    def test_a5_completed_is_terminal(self) -> None:
        task = load("a5_completed")["result"]["task"]
        resp = A2ATaskStatusResponse(**task)
        self.assertEqual(resp.status.wire_state, "TASK_STATE_COMPLETED")
        ic = ServerAuthRequiredInterceptor(SDJWTVerifier(client_id="c"))
        ic.authenticated_tasks.add(resp.id)
        ic._finalize(resp)
        self.assertNotIn(resp.id, ic.authenticated_tasks)

    def test_sdk_challenge_roundtrips_through_the_spec_a3_shape(self) -> None:
        """What the SDK emits must parse back into the same models the spec example does."""
        ic = ServerAuthRequiredInterceptor(SDJWTVerifier(client_id="https://verifier.example.com"))
        out = ic.process_incoming_request(
            A2ATaskMessage(channel_id="test-channel", headers={"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"}), lambda r, v: None
        )
        wire = out.to_wire()
        self.assertNotIn("kind", wire)
        msg = wire["status"]["message"]
        self.assertNotIn("kind", msg)
        self.assertEqual(msg["role"], "ROLE_AGENT")
        self.assertEqual(msg["parts"], [{"text": "Identity verification required."}])
        self.assertEqual(wire["status"]["state"], "TASK_STATE_AUTH_REQUIRED")
        meta = wire["status"]["message"]["metadata"][EXTENSION_URI]
        IdentityChallenge.model_validate(meta)
        self.assertTrue(DCQLQuery.model_validate(meta["dcql_query"]).credentials)


class TestExtensionSupportRequiredError(unittest.TestCase):
    """Spec 6.2: missing activation is a protocol error (-32008), not a failed Task."""

    def _ic(self, required: bool = True) -> ServerAuthRequiredInterceptor:
        return ServerAuthRequiredInterceptor(SDJWTVerifier(client_id="c"), required=required)

    def test_jsonrpc_error_matches_spec_example(self) -> None:
        with self.assertRaises(ExtensionSupportRequiredError) as ctx:
            self._ic().process_incoming_request(
                A2ATaskMessage(channel_id="ch", id="t", context_id="c", headers={"A2A-Version": "1.0"}), lambda r, v: None
            )
        err = ctx.exception.to_jsonrpc_error("request-1")
        self.assertEqual(err["jsonrpc"], "2.0")
        self.assertEqual(err["id"], "request-1")
        self.assertEqual(err["error"]["code"], -32008)
        info = err["error"]["data"][0]
        self.assertEqual(info["@type"], "type.googleapis.com/google.rpc.ErrorInfo")
        self.assertEqual(info["reason"], "EXTENSION_SUPPORT_REQUIRED")
        self.assertEqual(info["domain"], "a2a-protocol.org")
        self.assertEqual(info["metadata"], {"extensionUri": EXTENSION_URI})

    def test_other_binding_mappings(self) -> None:
        self.assertEqual(ExtensionSupportRequiredError.HTTP_STATUS, 400)
        self.assertEqual(ExtensionSupportRequiredError.GRPC_STATUS, "FAILED_PRECONDITION")

    def test_not_an_11_1_task_error_code(self) -> None:
        from a2a_agentic_id import ErrorCode
        self.assertNotIn("AUTH_EXTENSION_REQUIRED", [e.value for e in ErrorCode])

    def test_optional_extension_does_not_raise(self) -> None:
        res = self._ic(required=False).process_incoming_request(
            A2ATaskMessage(channel_id="ch", id="t", context_id="c", headers={"A2A-Version": "1.0"}), lambda r, v: None
        )
        self.assertEqual(res.state, "TASK_STATE_AUTH_REQUIRED")

    def test_no_state_is_created_before_the_error(self) -> None:
        ic = self._ic()
        with self.assertRaises(ExtensionSupportRequiredError):
            ic.process_incoming_request(A2ATaskMessage(channel_id="ch", id="t", context_id="c", headers={"A2A-Version": "1.0"}), lambda r, v: None)
        self.assertFalse(ic.buffered_requests)
        self.assertFalse(ic.active_nonces)


if __name__ == "__main__":
    unittest.main()
