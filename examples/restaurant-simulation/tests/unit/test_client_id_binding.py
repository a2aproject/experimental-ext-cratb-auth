# SPDX-License-Identifier: Apache-2.0
import unittest

from a2a_agentic_id.client_interceptor import _canonical_https_url, _check_verifier_origin

CARD = "a2a_agent_card:https://v.example.com/.well-known/agent-card.json"
CONTACTED = "https://v.example.com/a2a"


class TestClientIdBinding(unittest.TestCase):
    """Spec 8.1.1: canonical URL suffix, same-origin binding, optional exact URL match."""

    def test_same_origin_accepted(self) -> None:
        _check_verifier_origin(CARD, CONTACTED)

    def test_canonical_form_lowercases_host_and_drops_default_port(self) -> None:
        self.assertEqual(_canonical_https_url("https://V.Example.com:443"), "https://v.example.com/")

    def test_ambiguous_urls_rejected(self) -> None:
        for url in [
            "https://v.example.com/a?x=1",
            "https://v.example.com/a#f",
            "https://user@v.example.com/",
            "https://v.example.com/%2e%2E/x",
            "https://v.example.com/a%2fb",
            "https://v.example.com/a%25b",
            "https://v.example.com/a%zz",
            "https://v.example.com/a\b",
            "https://v.example.com/a b",
            "https://127.0.0.1/",
            "https://v.example.com./",
            "https://v.example.com:0443/",
            "http://v.example.com/",
        ]:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    _canonical_https_url(url)

    def test_ambiguous_suffix_refused_in_check(self) -> None:
        with self.assertRaises(ValueError):
            _check_verifier_origin("a2a_agent_card:https://v.example.com/a?x=1", CONTACTED)

    def test_expected_url_must_match_exactly(self) -> None:
        _check_verifier_origin(CARD, CONTACTED, "https://V.example.com:443/.well-known/agent-card.json")
        with self.assertRaises(ValueError) as ctx:
            _check_verifier_origin(CARD, CONTACTED, "https://v.example.com/other-card.json")
        self.assertIn("expected Agent Card URL", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
