# SPDX-License-Identifier: Apache-2.0
import unittest

from a2a_agentic_id.relay import TunnelRelay, TunnelError, TunnelRelayError
from a2a_agentic_id.interceptor import A2ATaskMessage, EXTENSION_URI
from a2a_agentic_id.models import DCQLQuery, IdentityChallenge


def challenge(client_id="https://terminal.example.com/a2a"):
    return IdentityChallenge(
        nonce="n1", client_id=client_id,
        response_uri="https://terminal.example.com/a2a", response_mode="a2a_metadata",
        dcql_query=DCQLQuery.default_agent_identity_query(),
    )


def answer(origin, task_id="t1"):
    return A2ATaskMessage(
        id=task_id, context_id="c1",
        metadata={EXTENSION_URI: {"tunneled_response": {"origin_task_id": origin, "response": {"q": ["x~y"]}}}},
    )


class Clock:
    def __init__(self): self.t = 0.0
    def __call__(self): return self.t


class TestRelay(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.relay = TunnelRelay(max_lifetime=60, clock=self.clock)

    def test_open_returns_auth_required_with_unchanged_challenge(self):
        r = self.relay.open_tunnel("t2", challenge(), "t1", "c1")
        self.assertEqual(r.state, "TASK_STATE_AUTH_REQUIRED")
        meta = r.message["metadata"][EXTENSION_URI]
        self.assertEqual(meta["tunneled_challenge"]["origin_task_id"], "t2")
        self.assertEqual(meta["tunneled_challenge"]["challenge"]["nonce"], "n1")
        self.assertNotIn("status", meta)
        self.assertTrue(self.relay.is_open("t2"))

    def test_take_response_returns_it_unchanged_and_closes(self):
        self.relay.open_tunnel("t2", challenge(), "t1", "c1")
        resp = self.relay.take_response(answer("t2"))
        self.assertEqual(resp.response, {"q": ["x~y"]})
        self.assertFalse(self.relay.is_open("t2"))

    def test_second_answer_is_expired_not_replayed(self):
        self.relay.open_tunnel("t2", challenge(), "t1", "c1")
        self.relay.take_response(answer("t2"))
        with self.assertRaises(TunnelRelayError) as c:
            self.relay.take_response(answer("t2"))
        self.assertEqual(c.exception.tunnel_error, TunnelError.TUNNEL_EXPIRED)

    def test_unknown_origin(self):
        with self.assertRaises(TunnelRelayError) as c:
            self.relay.take_response(answer("nope"))
        self.assertEqual(c.exception.tunnel_error, TunnelError.TUNNEL_ORIGIN_UNKNOWN)

    def test_wrong_task_does_not_close_tunnel(self):
        self.relay.open_tunnel("t2", challenge(), "t1", "c1")
        with self.assertRaises(TunnelRelayError) as c:
            self.relay.take_response(answer("t2", task_id="other"))
        self.assertEqual(c.exception.tunnel_error, TunnelError.TUNNEL_ORIGIN_UNKNOWN)
        self.assertTrue(self.relay.is_open("t2"))

    def test_deadline_expires_tunnel(self):
        self.relay.open_tunnel("t2", challenge(), "t1", "c1")
        self.clock.t = 61
        with self.assertRaises(TunnelRelayError) as c:
            self.relay.take_response(answer("t2"))
        self.assertEqual(c.exception.tunnel_error, TunnelError.TUNNEL_EXPIRED)

    def test_terminal_task_closes_tunnel_either_side(self):
        self.relay.open_tunnel("t2", challenge(), "t1", "c1")
        self.assertEqual(self.relay.close_for_task("t1"), 1)
        self.relay.open_tunnel("t3", challenge(), "t1", "c1")
        self.assertEqual(self.relay.close_for_task("t3"), 1)
        self.assertEqual(self.relay.close_for_task("zzz"), 0)

    def test_no_tunneled_response_returns_none(self):
        self.assertIsNone(self.relay.take_response(A2ATaskMessage(id="t1", context_id="c1", metadata={})))

    def test_duplicate_open_rejected(self):
        self.relay.open_tunnel("t2", challenge(), "t1", "c1")
        with self.assertRaises(ValueError):
            self.relay.open_tunnel("t2", challenge(), "t1", "c1")

    def test_error_response_uses_tunnel_error_not_error(self):
        e = TunnelRelayError(TunnelError.TUNNEL_REFUSED, "refused")
        r = TunnelRelay.error_response("t1", "c1", e)
        meta = r.message["metadata"][EXTENSION_URI]
        self.assertEqual(meta["tunnel_error"], "TUNNEL_REFUSED")
        self.assertNotIn("error", meta)
        self.assertEqual(r.state, "TASK_STATE_AUTH_REQUIRED")

    def test_ended_records_are_bounded(self):
        relay = TunnelRelay(max_lifetime=60, clock=self.clock, max_ended_records=3)
        for i in range(10):
            relay.open_tunnel(f"o{i}", challenge(), "t1", "c1")
            relay.close_for_task(f"o{i}")
        self.assertEqual(len(relay._ended), 3)
        with self.assertRaises(TunnelRelayError) as c:   # oldest forgotten -> unknown, not a crash
            relay.take_response(answer("o0"))
        self.assertEqual(c.exception.tunnel_error, TunnelError.TUNNEL_ORIGIN_UNKNOWN)
        with self.assertRaises(TunnelRelayError) as c:   # newest still remembered
            relay.take_response(answer("o9"))
        self.assertEqual(c.exception.tunnel_error, TunnelError.TUNNEL_EXPIRED)

    def test_is_tunneled_response(self):
        self.assertTrue(TunnelRelay.is_tunneled_response(answer("t2")))
        self.assertFalse(TunnelRelay.is_tunneled_response(A2ATaskMessage(id="t1", context_id="c1", metadata={})))
        self.assertFalse(TunnelRelay.is_tunneled_response(
            A2ATaskMessage(id="t1", context_id="c1", metadata={EXTENSION_URI: {"vp_token": {"q": ["x"]}}})))

    def test_bad_lifetime(self):
        with self.assertRaises(ValueError):
            TunnelRelay(max_lifetime=0)
        with self.assertRaises(ValueError):
            TunnelRelay(max_ended_records=0)


if __name__ == "__main__":
    unittest.main()
