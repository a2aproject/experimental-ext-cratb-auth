# SPDX-License-Identifier: Apache-2.0
"""
S27: this SDK speaks A2A v1.0.0 only (https://a2a-protocol.org/v1.0.0/specification/).

Checks the emitted wire shapes against the required fields of the v1.0.0 `a2a.proto`, the
server-generated task-id rule (Section 3.4.2), the `A2A-Version` requirement (Section 3.6), the
`SendMessageResponse` wrapper, and the error bodies for all three bindings.

This module is deliberately NOT given the autouse task-id patch from `conftest.py`, so the
interceptor's real behaviour for client-chosen task ids is what is tested here.
"""

import json
import re
import unittest
from pathlib import Path
from typing import Any, Dict, Optional

from a2a_agentic_id import (
    A2ATaskMessage,
    A2ATaskStatusResponse,
    ExtensionSupportRequiredError,
    SDJWTVerifier,
    ServerAuthRequiredInterceptor,
    TaskNotFoundError,
    VersionNotSupportedError,
    a2a_wire,
)
from a2a_agentic_id.interceptor import (
    EXTENSION_URI,
    TASK_STATE_AUTH_REQUIRED,
    TASK_STATE_FAILED,
    TASK_STATE_WORKING,
    validate_task_state,
)
from a2a_agentic_id.models import A2AProtocolError, ErrorCode

H = {"A2A-Extensions": EXTENSION_URI, "A2A-Version": "1.0"}
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

# Required fields from a2a.proto (field_behavior = REQUIRED), v1.0.0.
MESSAGE_REQUIRED = ("messageId", "role", "parts")
TASK_REQUIRED = ("id", "status")
STATUS_REQUIRED = ("state",)


def make_ic(**kw: Any) -> ServerAuthRequiredInterceptor:
    return ServerAuthRequiredInterceptor(SDJWTVerifier(client_id="https://v.example.com/a2a"), **kw)


def first_turn(ic: ServerAuthRequiredInterceptor, **kw: Any) -> A2ATaskStatusResponse:
    return ic.process_incoming_request(
        A2ATaskMessage(channel_id="ch", headers=H, parts=[{"text": "hi"}], **kw), lambda r, v: None
    )


class TestEmittedMessagesAreValidV1(unittest.TestCase):
    """Every server message carries the fields the A2A v1.0.0 proto requires."""

    def assertValidTask(self, wire: Dict[str, Any]) -> None:
        for f in TASK_REQUIRED:
            self.assertIn(f, wire)
        self.assertNotIn("kind", wire)
        for f in STATUS_REQUIRED:
            self.assertIn(f, wire["status"])
        msg = wire["status"].get("message")
        if msg:
            for f in MESSAGE_REQUIRED:
                self.assertIn(f, msg, f"server Message is missing required field {f}")
            self.assertTrue(msg["messageId"])
            self.assertIn(msg["role"], ("ROLE_USER", "ROLE_AGENT"))
            self.assertNotIn("kind", msg)
            # Server messages carry the context, and the task they belong to.
            self.assertEqual(msg["contextId"], wire["contextId"])
            self.assertEqual(msg["taskId"], wire["id"])
            for part in msg["parts"]:
                self.assertEqual(len([k for k in ("text", "raw", "url", "data") if k in part]), 1)
                self.assertNotIn("kind", part)

    def test_challenge_is_a_valid_task(self) -> None:
        wire = first_turn(make_ic()).to_wire()
        self.assertValidTask(wire)
        self.assertEqual(wire["status"]["state"], "TASK_STATE_AUTH_REQUIRED")
        self.assertEqual(wire["status"]["message"]["role"], "ROLE_AGENT")

    def test_error_task_is_a_valid_task(self) -> None:
        ic = make_ic()
        wire = ic._build_error_response("t", "c", ErrorCode.VP_MISSING, "no vp_token").to_wire()
        self.assertValidTask(wire)
        self.assertEqual(wire["status"]["state"], "TASK_STATE_FAILED")
        self.assertEqual(wire["status"]["message"]["metadata"][EXTENSION_URI]["error"], "VP_MISSING")

    def test_each_message_gets_its_own_message_id(self) -> None:
        ic = make_ic()
        ids = {first_turn(ic).to_wire()["status"]["message"]["messageId"] for _ in range(5)}
        self.assertEqual(len(ids), 5)

    def test_supplied_message_id_is_kept(self) -> None:
        r = A2ATaskStatusResponse(id="t", context_id="c", state=TASK_STATE_WORKING, message={"messageId": "m-1", "parts": [{"text": "x"}]})
        self.assertEqual(r.message["messageId"], "m-1")

    def test_message_ids_are_not_overwritten_when_present(self) -> None:
        r = A2ATaskStatusResponse(
            id="t", context_id="c", state=TASK_STATE_WORKING,
            message={"taskId": "other-task", "contextId": "other-ctx", "parts": [{"text": "x"}]},
        )
        self.assertEqual((r.message["taskId"], r.message["contextId"]), ("other-task", "other-ctx"))

    def test_empty_status_message_is_allowed(self) -> None:
        # `TaskStatus.message` is optional, so a status with none is fine.
        r = A2ATaskStatusResponse(id="t", context_id="c", state=TASK_STATE_WORKING)
        self.assertNotIn("messageId", r.to_wire()["status"].get("message", {}))

    def test_appendix_a_fixture_shape_matches_what_the_sdk_emits(self) -> None:
        fixture = json.loads((FIXTURES / "a3_auth_required.json").read_text(encoding="utf-8"))["result"]["task"]
        emitted = first_turn(make_ic()).to_wire()
        self.assertEqual(set(emitted), set(fixture) & {"id", "contextId", "status"} | {"id", "contextId", "status"})
        self.assertEqual(set(emitted["status"]["message"]), set(fixture["status"]["message"]))


class TestLegacyShapesAreRejected(unittest.TestCase):
    def test_legacy_states_rejected(self) -> None:
        for legacy in ("auth-required", "working", "completed", "failed", "input-required", "cancelled", "TASK_STATE_BOGUS", ""):
            with self.assertRaises(ValueError, msg=legacy):
                A2ATaskStatusResponse(id="t", context_id="c", state=legacy)
            with self.assertRaises(ValueError, msg=legacy):
                validate_task_state(legacy)

    def test_all_v1_states_accepted(self) -> None:
        for s in ("SUBMITTED", "WORKING", "INPUT_REQUIRED", "AUTH_REQUIRED", "COMPLETED", "FAILED", "CANCELED", "REJECTED"):
            self.assertEqual(A2ATaskStatusResponse(id="t", context_id="c", state=f"TASK_STATE_{s}").state, f"TASK_STATE_{s}")

    def test_unspecified_state_is_not_accepted(self) -> None:
        with self.assertRaises(ValueError):
            A2ATaskStatusResponse(id="t", context_id="c", state="TASK_STATE_UNSPECIFIED")

    def test_kind_discriminator_rejected_in_messages_and_parts(self) -> None:
        with self.assertRaises(ValueError):
            A2ATaskStatusResponse(id="t", context_id="c", state=TASK_STATE_WORKING, message={"kind": "message", "parts": [{"text": "x"}]})
        with self.assertRaises(ValueError):
            A2ATaskStatusResponse(id="t", context_id="c", state=TASK_STATE_WORKING, message={"parts": [{"kind": "text", "text": "x"}]})

    def test_legacy_roles_rejected(self) -> None:
        for role in ("agent", "user", "AGENT", ""):
            with self.assertRaises(ValueError, msg=role):
                A2ATaskStatusResponse(id="t", context_id="c", state=TASK_STATE_WORKING, message={"role": role, "parts": []})

    def test_a_part_must_contain_exactly_one_content_member(self) -> None:
        for bad in ({}, {"text": "a", "url": "https://x.example"}, {"metadata": {"k": 1}}):
            with self.assertRaises(ValueError, msg=str(bad)):
                A2ATaskStatusResponse(id="t", context_id="c", state=TASK_STATE_WORKING, message={"parts": [bad]})

    def test_all_four_part_kinds_are_valid(self) -> None:
        for part in ({"text": "a"}, {"raw": "AAEC"}, {"url": "https://x.example/f"}, {"data": {"k": 1}}):
            r = A2ATaskStatusResponse(id="t", context_id="c", state=TASK_STATE_WORKING, message={"parts": [part]})
            self.assertEqual(r.message["parts"], [part])


class TestServerGeneratedTaskIds(unittest.TestCase):
    """A2A v1.0.0 Section 3.4.2: task ids are server-generated; a client-chosen one is TaskNotFoundError."""

    def test_initial_request_gets_a_128_bit_server_allocated_id(self) -> None:
        r = first_turn(make_ic())
        self.assertRegex(r.id, r"^[0-9a-f]{32}$")

    def test_ids_are_unique_per_task(self) -> None:
        ic = make_ic()
        self.assertEqual(len({first_turn(ic).id for _ in range(20)}), 20)

    def test_client_chosen_task_id_is_task_not_found(self) -> None:
        ic = make_ic()
        with self.assertRaises(TaskNotFoundError) as ctx:
            ic.process_incoming_request(A2ATaskMessage(channel_id="ch", id="client-picked", headers=H), lambda r, v: None)
        self.assertEqual(ctx.exception.task_id, "client-picked")

    def test_nothing_is_stored_for_a_rejected_client_chosen_id(self) -> None:
        ic = make_ic()
        with self.assertRaises(TaskNotFoundError):
            ic.process_incoming_request(A2ATaskMessage(channel_id="ch", id="client-picked", headers=H), lambda r, v: None)
        for store in (ic.buffered_requests, ic.active_nonces, ic.task_contexts, ic.allocated_tasks, ic.authenticated_tasks):
            self.assertNotIn("client-picked", store)

    def test_a_followup_on_the_allocated_id_is_accepted(self) -> None:
        ic = make_ic()
        t = first_turn(ic)
        again = ic.process_incoming_request(A2ATaskMessage(channel_id="ch", id=t.id, context_id=t.context_id, headers=H), lambda r, v: None)
        # No vp_token on a pending task is VP_MISSING, a normal task error, not TaskNotFound.
        self.assertEqual(again.status.state, TASK_STATE_FAILED)
        self.assertEqual(again.message["metadata"][EXTENSION_URI]["error"], "VP_MISSING")

    def test_a_forgotten_task_id_is_task_not_found_again(self) -> None:
        ic = make_ic()
        t = first_turn(ic)
        ic.close_task_session(t.id)
        with self.assertRaises(TaskNotFoundError):
            ic.process_incoming_request(A2ATaskMessage(channel_id="ch", id=t.id, headers=H), lambda r, v: None)

    def test_a_guessed_id_cannot_reach_another_clients_task(self) -> None:
        # Spec 5.5: knowledge of a task_id alone grants nothing, and an unknown id is not even a task.
        ic = make_ic()
        first_turn(ic)
        for guess in ("0" * 32, "1" * 32, "task-1"):
            with self.assertRaises(TaskNotFoundError):
                ic.process_incoming_request(A2ATaskMessage(channel_id="ch", id=guess, headers=H), lambda r, v: None)

    def test_task_not_found_maps_to_the_documented_codes(self) -> None:
        e = TaskNotFoundError("x")
        self.assertEqual((e.JSON_RPC_CODE, e.GRPC_STATUS, e.HTTP_STATUS), (-32001, "NOT_FOUND", 404))
        self.assertEqual(e.error_info()["reason"], "TASK_NOT_FOUND")
        self.assertEqual(e.error_info()["metadata"], {"taskId": "x"})


class TestA2AVersionHeader(unittest.TestCase):
    """The request MUST state A2A-Version 1.0; an absent header means 0.3 (A2A Section 3.6)."""

    def send(self, version: Optional[str], **kw: Any) -> A2ATaskStatusResponse:
        headers = {"A2A-Extensions": EXTENSION_URI}
        if version is not None:
            headers["A2A-Version"] = version
        return make_ic(**kw).process_incoming_request(A2ATaskMessage(channel_id="ch", headers=headers), lambda r, v: None)

    def test_1_0_is_served(self) -> None:
        self.assertEqual(self.send("1.0").status.state, TASK_STATE_AUTH_REQUIRED)

    def test_patch_versions_of_1_0_are_served(self) -> None:
        # The version is compared at Major.Minor (A2A Section 3.6).
        self.assertEqual(self.send("1.0.3").status.state, TASK_STATE_AUTH_REQUIRED)

    def test_missing_header_is_rejected(self) -> None:
        with self.assertRaises(VersionNotSupportedError) as ctx:
            self.send(None)
        self.assertEqual(ctx.exception.requested_version, "0.3")

    def test_other_versions_are_rejected(self) -> None:
        for v in ("0.3", "0.5", "1.1", "2.0", "1", "", "v1.0", "one"):
            with self.assertRaises(VersionNotSupportedError, msg=repr(v)):
                self.send(v)

    def test_header_name_is_case_insensitive(self) -> None:
        r = make_ic().process_incoming_request(
            A2ATaskMessage(channel_id="ch", headers={"a2a-extensions": EXTENSION_URI, "a2a-version": "1.0"}), lambda r, v: None)
        self.assertEqual(r.status.state, TASK_STATE_AUTH_REQUIRED)

    def test_version_is_checked_before_any_state_is_created(self) -> None:
        ic = make_ic()
        with self.assertRaises(VersionNotSupportedError):
            ic.process_incoming_request(A2ATaskMessage(channel_id="ch", headers={"A2A-Extensions": EXTENSION_URI}), lambda r, v: None)
        self.assertFalse(ic.allocated_tasks or ic.buffered_requests or ic.active_nonces)

    def test_version_error_maps_to_the_documented_codes(self) -> None:
        e = VersionNotSupportedError("0.3")
        self.assertEqual((e.JSON_RPC_CODE, e.GRPC_STATUS, e.HTTP_STATUS), (-32009, "FAILED_PRECONDITION", 400))
        self.assertEqual(e.error_info()["reason"], "VERSION_NOT_SUPPORTED")
        self.assertEqual(e.error_info()["metadata"]["supportedVersions"], "1.0")


class TestSendMessageResponseWrapper(unittest.TestCase):
    def test_task_wrapper(self) -> None:
        r = first_turn(make_ic())
        resp = r.to_send_message_response()
        self.assertEqual(list(resp), ["task"])
        self.assertEqual(resp["task"], r.to_wire())

    def test_jsonrpc_envelope_echoes_the_request_id(self) -> None:
        r = first_turn(make_ic())
        for rid in (7, "req-1"):
            out = r.to_jsonrpc_response(rid)
            self.assertEqual((out["jsonrpc"], out["id"]), ("2.0", rid))
            self.assertEqual(list(out["result"]), ["task"])

    def test_exactly_one_of_task_or_message(self) -> None:
        with self.assertRaises(ValueError):
            a2a_wire.send_message_response()
        with self.assertRaises(ValueError):
            a2a_wire.send_message_response(task={"id": "t"}, message={"messageId": "m"})
        self.assertEqual(list(a2a_wire.send_message_response(message={"messageId": "m"})), ["message"])

    def test_envelope_matches_the_spec_appendix_a_shape(self) -> None:
        fixture = json.loads((FIXTURES / "a3_auth_required.json").read_text(encoding="utf-8"))
        out = first_turn(make_ic()).to_jsonrpc_response(fixture["id"])
        self.assertEqual(set(out), set(fixture))
        self.assertEqual(set(out["result"]), set(fixture["result"]))

    def test_send_message_request_builder(self) -> None:
        req = a2a_wire.jsonrpc_send_message_request({"parts": [{"text": "hi"}]}, request_id="r1")
        self.assertEqual((req["method"], req["id"]), ("SendMessage", "r1"))
        m = req["params"]["message"]
        self.assertEqual(m["role"], "ROLE_USER")
        self.assertTrue(m["messageId"])
        self.assertNotIn("taskId", m)


class TestBindingErrorBodies(unittest.TestCase):
    """A2A v1.0.0 9.5 / 10.6 / 11.6: an A2A-specific error carries a google.rpc.ErrorInfo."""

    ERRORS = (ExtensionSupportRequiredError(EXTENSION_URI), TaskNotFoundError("t-1"), VersionNotSupportedError("0.3"))

    def test_reason_is_upper_snake_case_without_the_error_suffix(self) -> None:
        self.assertEqual(a2a_wire.error_reason("TaskNotFoundError"), "TASK_NOT_FOUND")
        self.assertEqual(a2a_wire.error_reason("TaskNotCancelableError"), "TASK_NOT_CANCELABLE")
        self.assertEqual(a2a_wire.error_reason("ExtensionSupportRequiredError"), "EXTENSION_SUPPORT_REQUIRED")
        self.assertEqual(a2a_wire.error_reason("VersionNotSupportedError"), "VERSION_NOT_SUPPORTED")
        for e in self.ERRORS:
            self.assertEqual(e.error_info()["reason"], e.REASON)

    def check_info(self, info: Dict[str, Any]) -> None:
        self.assertEqual(info["@type"], "type.googleapis.com/google.rpc.ErrorInfo")
        self.assertEqual(info["domain"], "a2a-protocol.org")
        self.assertRegex(info["reason"], r"^[A-Z]+(_[A-Z]+)*$")

    def test_jsonrpc_body(self) -> None:
        for e in self.ERRORS:
            body = e.to_jsonrpc_error("req-9")
            self.assertEqual((body["jsonrpc"], body["id"]), ("2.0", "req-9"))
            self.assertEqual(body["error"]["code"], e.JSON_RPC_CODE)
            self.assertIsInstance(body["error"]["data"], list)
            self.check_info(body["error"]["data"][0])

    def test_http_json_body(self) -> None:
        for e in self.ERRORS:
            err = e.to_http_error()["error"]
            self.assertEqual((err["code"], err["status"]), (e.HTTP_STATUS, e.GRPC_STATUS))
            self.assertEqual(err["message"], e.message)
            self.assertIsInstance(err["details"], list)
            self.check_info(err["details"][0])
            self.assertNotIn("data", err)

    def test_grpc_status(self) -> None:
        for e in self.ERRORS:
            st = e.to_grpc_status()
            self.assertEqual(st["code"], e.GRPC_STATUS)
            self.assertIsInstance(st["details"], list)
            self.check_info(st["details"][0])

    def test_all_three_bindings_carry_the_same_error_info(self) -> None:
        for e in self.ERRORS:
            a = e.to_jsonrpc_error()["error"]["data"]
            b = e.to_http_error()["error"]["details"]
            c = e.to_grpc_status()["details"]
            self.assertEqual(a, b)
            self.assertEqual(b, c)

    def test_mappings_match_the_a2a_error_table(self) -> None:
        table = {
            TaskNotFoundError: (-32001, "NOT_FOUND", 404),
            ExtensionSupportRequiredError: (-32008, "FAILED_PRECONDITION", 400),
            VersionNotSupportedError: (-32009, "FAILED_PRECONDITION", 400),
        }
        for e in self.ERRORS:
            self.assertEqual((e.JSON_RPC_CODE, e.GRPC_STATUS, e.HTTP_STATUS), table[type(e)])
            self.assertEqual(a2a_wire.http_status(e.ERROR_TYPE), e.HTTP_STATUS)

    def test_extension_uri_metadata_convention_kept(self) -> None:
        info = ExtensionSupportRequiredError(EXTENSION_URI).error_info()
        self.assertEqual(info["metadata"], {"extensionUri": EXTENSION_URI})

    def test_protocol_errors_share_one_base_and_are_not_task_error_codes(self) -> None:
        for e in self.ERRORS:
            self.assertIsInstance(e, A2AProtocolError)
        self.assertEqual({c.value for c in ErrorCode} & {e.REASON for e in self.ERRORS}, set())

    def test_the_serialised_bodies_are_json_safe(self) -> None:
        for e in self.ERRORS:
            for body in (e.to_jsonrpc_error(1), e.to_http_error(), e.to_grpc_status()):
                json.dumps(body)


class TestNoLegacyLeftInTheEmittedWire(unittest.TestCase):
    def test_no_legacy_marker_anywhere_in_a_full_flow(self) -> None:
        wire = first_turn(make_ic()).to_jsonrpc_response(1)
        text = json.dumps(wire)
        for legacy in ('"kind"', '"auth-required"', '"working"', '"failed"', '"completed"', '"role": "agent"', '"role": "user"'):
            self.assertNotIn(legacy, text)
        self.assertTrue(re.search(r'"state": "TASK_STATE_AUTH_REQUIRED"', text))


if __name__ == "__main__":
    unittest.main()
