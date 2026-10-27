# SPDX-License-Identifier: Apache-2.0
import unittest

from a2a_agentic_id.interceptor import (
    EXTENSION_URI,
    A2ATaskMessage,
    A2ATaskStatus,
    A2ATaskStatusResponse,
)


class TestA2AWireFormat(unittest.TestCase):
    """Spec 7.3.3 / 11.2: the task envelope nests state and message under `status`."""

    def test_error_envelope_matches_spec_11_2(self) -> None:
        resp = A2ATaskStatusResponse(
            id="task-01",
            context_id="ctx-01",
            state="TASK_STATE_FAILED",
            message={
                "role": "ROLE_AGENT",
                "parts": [{"text": "Verification failed."}],
                "metadata": {EXTENSION_URI: {"status": "failed", "error": "VP_NONCE_MISMATCH"}},
            },
        )
        dumped = resp.model_dump(by_alias=True)

        # A2A v1.0.0 Task: no `kind` discriminator.
        self.assertEqual(set(dumped.keys()), {"id", "contextId", "status"})
        self.assertEqual(dumped["contextId"], "ctx-01")
        self.assertNotIn("state", dumped)
        self.assertNotIn("message", dumped)
        self.assertNotIn("context_id", dumped)

        self.assertEqual(dumped["status"]["state"], "TASK_STATE_FAILED")
        self.assertEqual(
            dumped["status"]["message"]["metadata"][EXTENSION_URI]["error"],
            "VP_NONCE_MISMATCH",
        )

    def test_challenge_metadata_path_matches_spec_7_3_3(self) -> None:
        """Spec 7.3.3 documents the challenge at task.status.message.metadata[ext_uri]."""
        resp = A2ATaskStatusResponse(
            id="task-02",
            context_id="ctx-02",
            status=A2ATaskStatus(
                state="TASK_STATE_AUTH_REQUIRED",
                message={"metadata": {EXTENSION_URI: {"status": "identity_required"}}},
            ),
        )
        dumped = resp.model_dump(by_alias=True)
        self.assertEqual(
            dumped["status"]["message"]["metadata"][EXTENSION_URI]["status"],
            "identity_required",
        )

    def test_flat_accessors_remain_available(self) -> None:
        resp = A2ATaskStatusResponse(
            id="task-03", context_id="ctx-03", state="TASK_STATE_COMPLETED", message={"parts": [{"text": "done"}]}
        )
        self.assertEqual(resp.state, "TASK_STATE_COMPLETED")
        self.assertEqual(resp.message["parts"], [{"text": "done"}])
        # The status message is completed into a valid v1.0.0 Message.
        self.assertEqual(resp.message["taskId"], "task-03")
        self.assertEqual(resp.message["contextId"], "ctx-03")
        self.assertEqual(resp.message["role"], "ROLE_AGENT")
        self.assertTrue(resp.message["messageId"])
        self.assertEqual(resp.status.state, "TASK_STATE_COMPLETED")

    def test_inbound_nested_json_round_trips(self) -> None:
        payload = {
            "id": "task-04",
            "contextId": "ctx-04",
            "status": {"state": "TASK_STATE_WORKING", "message": {}},
        }
        resp = A2ATaskStatusResponse.model_validate(payload)
        self.assertEqual(resp.context_id, "ctx-04")
        self.assertEqual(resp.state, "TASK_STATE_WORKING")
        self.assertEqual(resp.model_dump(by_alias=True), payload)

    def test_task_message_uses_camel_case_context_id(self) -> None:
        msg = A2ATaskMessage(channel_id="test-channel", id="task-05", context_id="ctx-05")
        self.assertEqual(msg.model_dump(by_alias=True)["contextId"], "ctx-05")
        self.assertEqual(
            A2ATaskMessage.model_validate({"id": "task-05", "contextId": "ctx-05"}).context_id,
            "ctx-05",
        )


if __name__ == "__main__":
    unittest.main()
