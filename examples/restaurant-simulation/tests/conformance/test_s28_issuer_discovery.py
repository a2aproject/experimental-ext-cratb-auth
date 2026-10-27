# SPDX-License-Identifier: Apache-2.0
"""
S28: issuer key discovery and trust (spec 5.4, 7.3.4 step 3, 9.3; SD-JWT VC draft-19 Section 5).

Everything here runs offline: a fake HTTP client serves issuer metadata and certificates are
generated in-process. The demos never use IssuerKeyDiscovery; these tests are its only caller.
"""

import base64
import datetime as dt
import json
import time
import unittest
from typing import Any, Dict, List, Optional

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from a2a_agentic_id import (
    CredentialItem,
    DCQLCredentialQuery,
    DCQLQuery,
    ErrorCode,
    IssuerKeyDiscovery,
    SDJWTVerifier,
    SDJWTWallet,
)
from a2a_agentic_id.crypto import (
    export_jwk_from_private_key,
    export_jwk_from_public_key,
    generate_ec_p256_keypair,
)
from a2a_agentic_id.verifier import CredentialVerificationError

VCT = "https://github.com/a2aproject/experimental-ext-cratb-auth/tree/main/v1"
CLIENT = "https://verifier.example.com"
ISS = "https://issuer.example.com"
ISS_TENANT = "https://issuer.example.com/tenant/1234"


# --------------------------------------------------------------------------- test doubles

class FakeResponse:
    def __init__(self, status_code: int = 200, body: Any = b"") -> None:
        self.status_code = status_code
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        self.content = body


class FakeHttp:
    """Serves canned responses by URL and records every request."""

    def __init__(self, routes: Optional[Dict[str, Any]] = None) -> None:
        self.routes = routes or {}
        self.requests: List[str] = []

    def get(self, url: str) -> FakeResponse:
        self.requests.append(url)
        if url not in self.routes:
            return FakeResponse(404)
        value = self.routes[url]
        if isinstance(value, Exception):
            raise value
        return value if isinstance(value, FakeResponse) else FakeResponse(200, value)


class Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


# --------------------------------------------------------------------------- PKI helpers

NOW = dt.datetime.now(dt.timezone.utc)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_cert(
    subject: str, subject_key: ec.EllipticCurvePrivateKey, issuer: str, issuer_key: ec.EllipticCurvePrivateKey,
    ca: bool, san: Optional[List[x509.GeneralName]] = None, eku: Optional[List[Any]] = None,
    not_before: Optional[dt.datetime] = None, not_after: Optional[dt.datetime] = None,
    path_length: Optional[int] = None, digital_signature: bool = True,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject)).issuer_name(_name(issuer)).public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or NOW - dt.timedelta(days=1))
        .not_valid_after(not_after or NOW + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        builder = builder.add_extension(
            x509.KeyUsage(digital_signature, False, False, False, False, False, False, False, False), critical=True)
    if san is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def der_b64(cert: x509.Certificate) -> str:
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def jwk_with(key: ec.EllipticCurvePrivateKey, **extra: Any) -> Dict[str, Any]:
    return {**export_jwk_from_public_key(key.public_key()), **extra}


# --------------------------------------------------------------------------- shared fixtures

class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.iss_key, _ = generate_ec_p256_keypair()
        holder_key, holder_pub = generate_ec_p256_keypair()
        self.holder_priv = export_jwk_from_private_key(holder_key)
        self.holder_pub = export_jwk_from_public_key(holder_pub)
        self.iss_pub = jwk_with(self.iss_key)
        self.query = DCQLQuery(credentials=[DCQLCredentialQuery(id="q", meta={"vct_values": [VCT]})])

    # -- credentials
    def token(self, iss: str = ISS, key: Optional[ec.EllipticCurvePrivateKey] = None, **header: Any) -> str:
        now = int(time.time())
        pem = (key or self.iss_key).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        issuer_jwt = jwt.encode(
            {"iss": iss, "iat": now, "exp": now + 3600, "vct": VCT, "id": "agent-1",
             "cnf": {"jwk": self.holder_pub}, "_sd": [], "_sd_alg": "sha-256"},
            pem, algorithm="ES256", headers={"typ": "dc+sd-jwt", **header},
        )
        return issuer_jwt + "~"

    def present(self, token: str) -> str:
        item = CredentialItem(id="q", sd_jwt_string=token, holder_private_key_jwk=self.holder_priv)
        return SDJWTWallet().create_presentation(item, [], nonce="n", client_id=CLIENT)

    def verify(self, verifier: SDJWTVerifier, token: str):
        return verifier.verify_presentation(self.present(token), nonce="n", dcql_query=self.query)

    def verifier_for(self, discovery: IssuerKeyDiscovery, **kw: Any) -> SDJWTVerifier:
        return SDJWTVerifier(client_id=CLIENT, issuer_key_discovery=discovery, allow_unverified_status=True, **kw)

    def assertSigInvalid(self, fn, msg: str = "") -> CredentialVerificationError:
        with self.assertRaises(CredentialVerificationError, msg=msg) as ctx:
            fn()
        self.assertEqual(ctx.exception.error_code, ErrorCode.VP_SIGNATURE_INVALID, msg or ctx.exception.message)
        return ctx.exception


def metadata(issuer: str = ISS, **over: Any) -> Dict[str, Any]:
    return {"issuer": issuer, **over}


def well_known(iss: str) -> str:
    return IssuerKeyDiscovery.well_known_url(iss)


# =========================================================================== metadata: URL

class TestWellKnownUrl(unittest.TestCase):
    def test_host_only_issuer(self) -> None:
        self.assertEqual(well_known("https://issuer.example.com"), "https://issuer.example.com/.well-known/jwt-vc-issuer")

    def test_trailing_slash_is_removed(self) -> None:
        self.assertEqual(well_known("https://issuer.example.com/"), "https://issuer.example.com/.well-known/jwt-vc-issuer")

    def test_path_issuer_inserts_well_known_between_host_and_path(self) -> None:
        self.assertEqual(
            well_known("https://issuer.example.com/tenant/1234"),
            "https://issuer.example.com/.well-known/jwt-vc-issuer/tenant/1234",
        )

    def test_path_issuer_with_trailing_slash(self) -> None:
        self.assertEqual(
            well_known("https://issuer.example.com/tenant/1234/"),
            "https://issuer.example.com/.well-known/jwt-vc-issuer/tenant/1234",
        )

    def test_port_is_preserved(self) -> None:
        self.assertEqual(well_known("https://issuer.example.com:8443/t"), "https://issuer.example.com:8443/.well-known/jwt-vc-issuer/t")

    def test_unsafe_issuer_identifiers_rejected(self) -> None:
        for bad in (
            "http://issuer.example.com", "issuer.example.com", "https://", "https:///x", "", None, 5,
            "https://user@issuer.example.com", "https://issuer.example.com?x=1", "https://issuer.example.com#f",
            "https://issuer.example.com/a b", "https://issuer.example.com\\evil", "https://issuer.example.com:notaport",
            "https://issuer.example.com/\n",
        ):
            with self.assertRaises(CredentialVerificationError, msg=repr(bad)):
                well_known(bad)  # type: ignore[arg-type]


# =========================================================================== metadata: resolution

class TestIssuerMetadata(_Base):
    def discovery(self, routes: Dict[str, Any], **kw: Any) -> IssuerKeyDiscovery:
        self.http = FakeHttp(routes)
        return IssuerKeyDiscovery(http_client=self.http, **kw)

    def test_inline_jwks_verifies_a_credential(self) -> None:
        d = self.discovery({well_known(ISS): metadata(jwks={"keys": [self.iss_pub]})})
        self.assertTrue(self.verify(self.verifier_for(d), self.token()).is_valid)
        self.assertEqual(self.http.requests, [well_known(ISS)])

    def test_jwks_uri_is_followed_to_the_key_set(self) -> None:
        d = self.discovery({
            well_known(ISS): metadata(jwks_uri="https://issuer.example.com/keys.json"),
            "https://issuer.example.com/keys.json": {"keys": [self.iss_pub]},
        })
        self.assertTrue(self.verify(self.verifier_for(d), self.token()).is_valid)
        self.assertEqual(self.http.requests, [well_known(ISS), "https://issuer.example.com/keys.json"])

    def test_path_issuer_uses_the_path_inserted_url(self) -> None:
        d = self.discovery({well_known(ISS_TENANT): metadata(ISS_TENANT, jwks={"keys": [self.iss_pub]})})
        self.assertTrue(self.verify(self.verifier_for(d), self.token(iss=ISS_TENANT)).is_valid)
        self.assertEqual(self.http.requests, ["https://issuer.example.com/.well-known/jwt-vc-issuer/tenant/1234"])

    def test_key_is_selected_by_kid(self) -> None:
        other, _ = generate_ec_p256_keypair()
        d = self.discovery({well_known(ISS): metadata(jwks={"keys": [
            jwk_with(other, kid="other"), jwk_with(self.iss_key, kid="signing")]})})
        self.assertTrue(self.verify(self.verifier_for(d), self.token(kid="signing")).is_valid)

    def test_wrong_kid_fails_signature(self) -> None:
        other, _ = generate_ec_p256_keypair()
        d = self.discovery({well_known(ISS): metadata(jwks={"keys": [
            jwk_with(other, kid="other"), jwk_with(self.iss_key, kid="signing")]})})
        self.assertSigInvalid(lambda: self.verify(self.verifier_for(d), self.token(kid="other")))

    def test_unknown_kid_rejected(self) -> None:
        d = self.discovery({well_known(ISS): metadata(jwks={"keys": [jwk_with(self.iss_key, kid="a"), jwk_with(generate_ec_p256_keypair()[0], kid="b")]})})
        with self.assertRaises(CredentialVerificationError):
            self.verify(self.verifier_for(d), self.token(kid="nope"))

    # ---- the metadata document must be what the spec says

    def test_issuer_property_must_match_iss_exactly(self) -> None:
        for claimed in ("https://issuer.example.com/", "https://ISSUER.example.com", "https://evil.example.com", "", None):
            d = self.discovery({well_known(ISS): {"issuer": claimed, "jwks": {"keys": [self.iss_pub]}}})
            self.assertSigInvalid(lambda: self.verify(self.verifier_for(d), self.token()), repr(claimed))

    def test_missing_issuer_property_rejected(self) -> None:
        d = self.discovery({well_known(ISS): {"jwks": {"keys": [self.iss_pub]}}})
        self.assertSigInvalid(lambda: self.verify(self.verifier_for(d), self.token()))

    def test_neither_jwks_nor_jwks_uri_rejected(self) -> None:
        d = self.discovery({well_known(ISS): metadata()})
        self.assertSigInvalid(lambda: self.verify(self.verifier_for(d), self.token()))

    def test_both_jwks_and_jwks_uri_rejected(self) -> None:
        d = self.discovery({well_known(ISS): metadata(jwks={"keys": [self.iss_pub]}, jwks_uri="https://issuer.example.com/k")})
        self.assertSigInvalid(lambda: self.verify(self.verifier_for(d), self.token()))
        self.assertEqual(self.http.requests, [well_known(ISS)], "must not fetch jwks_uri when both are present")

    def test_jwks_uri_must_be_https(self) -> None:
        for bad in ("http://issuer.example.com/k", "ftp://issuer.example.com/k", "/keys.json", "https://u@issuer.example.com/k", 5, "https://issuer.example.com/a b"):
            d = self.discovery({well_known(ISS): metadata(jwks_uri=bad)})
            self.assertSigInvalid(lambda: self.verify(self.verifier_for(d), self.token()), repr(bad))
            self.assertEqual(self.http.requests, [well_known(ISS)])

    def test_metadata_must_be_a_json_object(self) -> None:
        for body in (b"[]", b"null", b"not json", b'"str"', b"\xff\xfe"):
            d = self.discovery({well_known(ISS): body})
            self.assertSigInvalid(lambda: self.verify(self.verifier_for(d), self.token()), repr(body))

    # ---- key-set hygiene

    def test_private_key_material_in_jwks_is_never_used(self) -> None:
        priv = export_jwk_from_private_key(self.iss_key)
        d = self.discovery({well_known(ISS): metadata(jwks={"keys": [priv]})})
        self.assertSigInvalid(lambda: self.verify(self.verifier_for(d), self.token()))

    def test_unusable_keys_are_skipped_and_empty_sets_rejected(self) -> None:
        bad_keys = [
            {"kty": "RSA", "n": "x", "e": "AQAB"},
            {**self.iss_pub, "crv": "P-384"},
            {**self.iss_pub, "use": "enc"},
            {**self.iss_pub, "alg": "ES384"},
            {"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "AAAA"},   # not on the curve
            "not-a-key",
        ]
        d = self.discovery({well_known(ISS): metadata(jwks={"keys": bad_keys})})
        self.assertSigInvalid(lambda: self.verify(self.verifier_for(d), self.token()))

    def test_a_usable_key_still_works_next_to_unusable_ones(self) -> None:
        d = self.discovery({well_known(ISS): metadata(jwks={"keys": [{"kty": "RSA", "n": "x", "e": "AQAB"}, self.iss_pub]})})
        self.assertTrue(self.verify(self.verifier_for(d), self.token()).is_valid)

    def test_sig_use_and_es256_alg_are_accepted(self) -> None:
        d = self.discovery({well_known(ISS): metadata(jwks={"keys": [{**self.iss_pub, "use": "sig", "alg": "ES256"}]})})
        self.assertTrue(self.verify(self.verifier_for(d), self.token()).is_valid)

    def test_jwks_must_be_an_object_with_a_keys_array(self) -> None:
        for jwks in ({}, {"keys": "x"}, [], "x", None):
            d = self.discovery({well_known(ISS): {"issuer": ISS, "jwks": jwks}})
            self.assertSigInvalid(lambda: self.verify(self.verifier_for(d), self.token()), repr(jwks))

    # ---- transport failures

    def test_http_errors_fail_closed(self) -> None:
        for status in (301, 302, 403, 404, 500):
            d = self.discovery({well_known(ISS): FakeResponse(status, b"{}")})
            self.assertSigInvalid(lambda: self.verify(self.verifier_for(d), self.token()), str(status))

    def test_redirects_are_not_followed(self) -> None:
        d = self.discovery({
            well_known(ISS): FakeResponse(302, b""),
            "https://evil.example.com/jwt-vc-issuer": metadata(jwks={"keys": [self.iss_pub]}),
        })
        self.assertSigInvalid(lambda: self.verify(self.verifier_for(d), self.token()))
        self.assertEqual(self.http.requests, [well_known(ISS)])

    def test_network_errors_fail_closed_without_leaking_details(self) -> None:
        d = self.discovery({well_known(ISS): ConnectionError("dns exploded at 10.0.0.7")})
        err = self.assertSigInvalid(lambda: self.verify(self.verifier_for(d), self.token()))
        self.assertNotIn("10.0.0.7", err.message)

    def test_oversized_responses_rejected(self) -> None:
        d = self.discovery({well_known(ISS): b"{" + b" " * 70000 + b"}"})
        self.assertSigInvalid(lambda: self.verify(self.verifier_for(d), self.token()))

    def test_oversized_jwks_uri_response_rejected(self) -> None:
        d = self.discovery({
            well_known(ISS): metadata(jwks_uri="https://issuer.example.com/k"),
            "https://issuer.example.com/k": b'{"keys": [' + b" " * 70000 + b"]}",
        })
        self.assertSigInvalid(lambda: self.verify(self.verifier_for(d), self.token()))

    # ---- trust

    def test_a_signature_by_a_key_not_in_the_metadata_fails(self) -> None:
        impostor, _ = generate_ec_p256_keypair()
        d = self.discovery({well_known(ISS): metadata(jwks={"keys": [self.iss_pub]})})
        self.assertSigInvalid(lambda: self.verify(self.verifier_for(d), self.token(key=impostor)))

    def test_discovery_does_not_override_an_explicit_issuer_key(self) -> None:
        d = self.discovery({well_known(ISS): metadata(jwks={"keys": [jwk_with(generate_ec_p256_keypair()[0])]})})
        v = self.verifier_for(d)
        res = v.verify_presentation(self.present(self.token()), nonce="n", dcql_query=self.query, issuer_public_key_jwk=self.iss_pub)
        self.assertTrue(res.is_valid)
        self.assertEqual(self.http.requests, [], "configured trust must not trigger discovery")

    def test_non_https_iss_is_refused_before_any_request(self) -> None:
        d = self.discovery({})
        self.assertSigInvalid(lambda: self.verify(self.verifier_for(d), self.token(iss="http://issuer.example.com")))
        self.assertEqual(self.http.requests, [])

    # ---- caching

    def test_metadata_is_cached_until_the_ttl_expires(self) -> None:
        clock = Clock(1000.0)
        d = self.discovery({well_known(ISS): metadata(jwks={"keys": [self.iss_pub]})}, cache_ttl=60, time_fn=clock)
        v = self.verifier_for(d)
        self.verify(v, self.token())
        self.verify(v, self.token())
        self.assertEqual(len(self.http.requests), 1)
        clock.now += 61
        self.verify(v, self.token())
        self.assertEqual(len(self.http.requests), 2)

    def test_failures_are_not_cached(self) -> None:
        self.http = FakeHttp({well_known(ISS): FakeResponse(500)})
        d = IssuerKeyDiscovery(http_client=self.http)
        for _ in range(2):
            self.assertSigInvalid(lambda: self.verify(self.verifier_for(d), self.token()))
        self.assertEqual(len(self.http.requests), 2)
        self.http.routes[well_known(ISS)] = metadata(jwks={"keys": [self.iss_pub]})
        self.assertTrue(self.verify(self.verifier_for(d), self.token()).is_valid)

    def test_invalidate_drops_cached_metadata(self) -> None:
        d = self.discovery({well_known(ISS): metadata(jwks={"keys": [self.iss_pub]})})
        v = self.verifier_for(d)
        self.verify(v, self.token())
        d.invalidate(ISS)
        self.verify(v, self.token())
        self.assertEqual(len(self.http.requests), 2)

    def test_a_rotated_key_is_picked_up_after_invalidation(self) -> None:
        new_key, _ = generate_ec_p256_keypair()
        d = self.discovery({well_known(ISS): metadata(jwks={"keys": [self.iss_pub]})})
        v = self.verifier_for(d)
        self.assertTrue(self.verify(v, self.token()).is_valid)
        self.http.routes[well_known(ISS)] = metadata(jwks={"keys": [jwk_with(new_key)]})
        d.invalidate()
        self.assertTrue(self.verify(v, self.token(key=new_key)).is_valid)


# =========================================================================== x5c

class TestX5cChain(_Base):
    def setUp(self) -> None:
        super().setUp()
        self.root_key, self.inter_key = generate_ec_p256_keypair()[0], generate_ec_p256_keypair()[0]
        self.san_uri: List[x509.GeneralName] = [x509.UniformResourceIdentifier(ISS)]
        self.root = make_cert("root", self.root_key, "root", self.root_key, True, path_length=1)
        self.inter = make_cert("inter", self.inter_key, "root", self.root_key, True, path_length=0)
        self.leaf = make_cert("leaf", self.iss_key, "inter", self.inter_key, False, san=self.san_uri)
        self.chain = [der_b64(self.leaf), der_b64(self.inter)]

    def discovery(self, anchors: Optional[List[x509.Certificate]] = None, iss: str = ISS, **kw: Any) -> IssuerKeyDiscovery:
        self.http = FakeHttp({well_known(iss): metadata(iss, jwks={"keys": [self.iss_pub]})})
        return IssuerKeyDiscovery(
            http_client=self.http, x5c_trust_anchors={iss: anchors or [self.root]}, **kw)

    _DEFAULT = object()

    def accepted(self, d: IssuerKeyDiscovery, chain: Any = _DEFAULT, iss: str = ISS):
        return self.verify(self.verifier_for(d), self.token(iss=iss, x5c=self.chain if chain is self._DEFAULT else chain))

    def rejected(self, d: IssuerKeyDiscovery, chain: Any, msg: str = "", iss: str = ISS) -> CredentialVerificationError:
        return self.assertSigInvalid(lambda: self.accepted(d, chain, iss), msg)

    def test_valid_chain_to_a_configured_anchor_verifies(self) -> None:
        self.assertTrue(self.accepted(self.discovery()).is_valid)

    def test_chain_can_include_the_root_itself(self) -> None:
        self.assertTrue(self.accepted(self.discovery(), self.chain + [der_b64(self.root)]).is_valid)

    def test_x5c_issuer_never_touches_the_network(self) -> None:
        d = self.discovery()
        self.accepted(d)
        self.assertEqual(self.http.requests, [])

    def test_untrusted_root_rejected(self) -> None:
        other = generate_ec_p256_keypair()[0]
        self.rejected(self.discovery([make_cert("other", other, "other", other, True)]), self.chain)

    def test_missing_intermediate_rejected(self) -> None:
        self.rejected(self.discovery(), [der_b64(self.leaf)])

    def test_expired_leaf_rejected(self) -> None:
        old = make_cert("leaf", self.iss_key, "inter", self.inter_key, False, san=self.san_uri,
                        not_before=NOW - dt.timedelta(days=3), not_after=NOW - dt.timedelta(days=1))
        self.rejected(self.discovery(), [der_b64(old), der_b64(self.inter)])

    def test_not_yet_valid_leaf_rejected(self) -> None:
        future = make_cert("leaf", self.iss_key, "inter", self.inter_key, False, san=self.san_uri,
                           not_before=NOW + dt.timedelta(days=1), not_after=NOW + dt.timedelta(days=5))
        self.rejected(self.discovery(), [der_b64(future), der_b64(self.inter)])

    def test_validity_is_checked_at_the_verifiers_clock(self) -> None:
        clock = Clock(time.time() + 40 * 86400)  # after the 30-day certificates expire
        self.rejected(self.discovery(time_fn=clock), self.chain)

    def test_leaf_that_is_a_ca_rejected(self) -> None:
        ca_leaf = make_cert("leaf", self.iss_key, "inter", self.inter_key, True, san=self.san_uri, path_length=0)
        self.rejected(self.discovery(), [der_b64(ca_leaf), der_b64(self.inter)])

    def test_server_auth_only_leaf_rejected(self) -> None:
        srv = make_cert("leaf", self.iss_key, "inter", self.inter_key, False, san=self.san_uri,
                        eku=[ExtendedKeyUsageOID.SERVER_AUTH])
        self.rejected(self.discovery(), [der_b64(srv), der_b64(self.inter)])

    def test_leaf_without_digital_signature_usage_rejected(self) -> None:
        nosig = make_cert("leaf", self.iss_key, "inter", self.inter_key, False, san=self.san_uri, digital_signature=False)
        self.rejected(self.discovery(), [der_b64(nosig), der_b64(self.inter)])

    # ---- the leaf must authorize `iss`

    def test_leaf_without_san_rejected(self) -> None:
        nosan = make_cert("leaf", self.iss_key, "inter", self.inter_key, False)
        self.rejected(self.discovery(), [der_b64(nosan), der_b64(self.inter)])

    def test_leaf_san_naming_a_different_issuer_rejected(self) -> None:
        other = make_cert("leaf", self.iss_key, "inter", self.inter_key, False,
                          san=[x509.UniformResourceIdentifier("https://other.example.com")])
        self.rejected(self.discovery(), [der_b64(other), der_b64(self.inter)])

    def test_uri_san_must_equal_iss_exactly(self) -> None:
        near = make_cert("leaf", self.iss_key, "inter", self.inter_key, False,
                         san=[x509.UniformResourceIdentifier("https://issuer.example.com/")])
        self.rejected(self.discovery(), [der_b64(near), der_b64(self.inter)])

    def test_dns_san_authorizes_a_host_only_issuer(self) -> None:
        dns = make_cert("leaf", self.iss_key, "inter", self.inter_key, False, san=[x509.DNSName("issuer.example.com")])
        self.assertTrue(self.accepted(self.discovery(), [der_b64(dns), der_b64(self.inter)]).is_valid)

    def test_dns_san_does_not_authorize_a_path_issuer(self) -> None:
        dns = make_cert("leaf", self.iss_key, "inter", self.inter_key, False, san=[x509.DNSName("issuer.example.com")])
        d = self.discovery(iss=ISS_TENANT)
        self.rejected(d, [der_b64(dns), der_b64(self.inter)], iss=ISS_TENANT)

    def test_uri_san_authorizes_a_path_issuer(self) -> None:
        leaf = make_cert("leaf", self.iss_key, "inter", self.inter_key, False,
                         san=[x509.UniformResourceIdentifier(ISS_TENANT)])
        d = self.discovery(iss=ISS_TENANT)
        self.assertTrue(self.accepted(d, [der_b64(leaf), der_b64(self.inter)], iss=ISS_TENANT).is_valid)

    # ---- key and encoding checks

    def test_leaf_key_that_did_not_sign_the_token_fails(self) -> None:
        stranger = generate_ec_p256_keypair()[0]
        d = self.discovery()
        self.assertSigInvalid(lambda: self.verify(self.verifier_for(d), self.token(key=stranger, x5c=self.chain)))

    def test_non_p256_leaf_key_rejected(self) -> None:
        p384 = ec.generate_private_key(ec.SECP384R1())
        leaf = make_cert("leaf", p384, "inter", self.inter_key, False, san=self.san_uri)
        self.rejected(self.discovery(), [der_b64(leaf), der_b64(self.inter)])

    def test_malformed_x5c_values_rejected(self) -> None:
        for bad in ([], "x", None, 5, {}, [5], ["not base64!!"], [base64.b64encode(b"not a cert").decode()],
                    [der_b64(self.leaf)] * 6):
            self.rejected(self.discovery(), bad, repr(bad)[:40])

    def test_x5c_is_validated_not_just_parsed(self) -> None:
        # A self-signed certificate for the right key and SAN, but anchored nowhere trusted.
        selfie = make_cert("leaf", self.iss_key, "leaf", self.iss_key, False, san=self.san_uri)
        self.rejected(self.discovery(), [der_b64(selfie)])

    def test_each_issuer_has_its_own_trust_anchors(self) -> None:
        other_root_key = generate_ec_p256_keypair()[0]
        other_root = make_cert("root2", other_root_key, "root2", other_root_key, True)
        d = IssuerKeyDiscovery(http_client=FakeHttp(), x5c_trust_anchors={
            ISS: [other_root], "https://another.example.com": [self.root]})
        self.rejected(d, self.chain)

    def test_configuring_an_issuer_with_no_anchors_is_an_error(self) -> None:
        with self.assertRaises(ValueError):
            IssuerKeyDiscovery(x5c_trust_anchors={ISS: []})


# =========================================================================== mechanism downgrade

class TestNoMechanismDowngrade(_Base):
    """Spec 9.3: a token must not be able to pick a weaker validation mechanism."""

    def setUp(self) -> None:
        super().setUp()
        root_key = generate_ec_p256_keypair()[0]
        self.root = make_cert("root", root_key, "root", root_key, True)
        self.leaf = make_cert("leaf", self.iss_key, "root", root_key, False,
                              san=[x509.UniformResourceIdentifier(ISS)])
        self.http = FakeHttp({well_known(ISS): metadata(jwks={"keys": [self.iss_pub]})})
        self.d = IssuerKeyDiscovery(http_client=self.http, x5c_trust_anchors={ISS: [self.root]})

    def test_x5c_issuer_is_never_answered_from_metadata(self) -> None:
        # Metadata for this issuer is published and would verify the signature, but the issuer is
        # configured for x5c, so a token that omits the chain is refused.
        self.assertSigInvalid(lambda: self.verify(self.verifier_for(self.d), self.token()))
        self.assertEqual(self.http.requests, [])

    def test_metadata_issuer_ignores_an_attacker_supplied_x5c(self) -> None:
        # An issuer with no x5c policy is resolved through metadata. A forged chain on the token is
        # not consulted: the attacker's own root/leaf cannot make a bad signature verify.
        attacker_key = generate_ec_p256_keypair()[0]
        atk_root_key = generate_ec_p256_keypair()[0]
        atk_root = make_cert("atk", atk_root_key, "atk", atk_root_key, True)
        atk_leaf = make_cert("leaf", attacker_key, "atk", atk_root_key, False, san=[x509.UniformResourceIdentifier(ISS)])
        d = IssuerKeyDiscovery(http_client=self.http)  # no x5c anchors configured
        tok = self.token(key=attacker_key, x5c=[der_b64(atk_leaf), der_b64(atk_root)])
        self.assertSigInvalid(lambda: self.verify(self.verifier_for(d), tok))
        self.assertEqual(self.http.requests, [well_known(ISS)])

    def test_metadata_issuer_still_verifies_when_the_token_also_carries_x5c(self) -> None:
        d = IssuerKeyDiscovery(http_client=self.http)
        self.assertTrue(self.verify(self.verifier_for(d), self.token(x5c=[der_b64(self.leaf)])).is_valid)


# =========================================================================== opt-in / isolation

class TestOptInAndDemosUnaffected(_Base):
    def test_verifier_without_discovery_still_uses_jwks_resolver(self) -> None:
        v = SDJWTVerifier(client_id=CLIENT, jwks_resolver=lambda iss: self.iss_pub, allow_unverified_status=True)
        self.assertIsNone(v.issuer_key_discovery)
        self.assertTrue(self.verify(v, self.token()).is_valid)

    def test_verifier_without_discovery_ignores_x5c_headers(self) -> None:
        v = SDJWTVerifier(client_id=CLIENT, jwks_resolver=lambda iss: self.iss_pub, allow_unverified_status=True)
        self.assertTrue(self.verify(v, self.token(x5c=["AAAA"])).is_valid)

    def test_jwks_resolver_is_not_consulted_when_discovery_is_configured(self) -> None:
        calls: List[str] = []
        http = FakeHttp({well_known(ISS): metadata(jwks={"keys": [self.iss_pub]})})
        v = SDJWTVerifier(client_id=CLIENT, jwks_resolver=lambda iss: calls.append(iss) or {},
                          issuer_key_discovery=IssuerKeyDiscovery(http_client=http), allow_unverified_status=True)
        self.assertTrue(self.verify(v, self.token()).is_valid)
        self.assertEqual(calls, [])

    def test_no_demo_or_agent_module_imports_issuer_discovery(self) -> None:
        import pathlib

        root = pathlib.Path(__file__).resolve().parents[2]
        offenders = []
        for path in list(root.rglob("*.py")) + list((root.parent / "restaurant-adk").rglob("*.py")):
            if "tests" in path.parts or path.name == "test_s28_issuer_discovery.py":
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            if "IssuerKeyDiscovery" in text or "issuer_discovery" in text:
                offenders.append(str(path.relative_to(root.parent)))
        self.assertEqual(offenders, [], "demos must keep using jwks_resolver")


if __name__ == "__main__":
    unittest.main()
