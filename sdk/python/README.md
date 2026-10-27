# CRATB-Auth SDK ("cratbee")

Python implementation of the **CRATB-Auth: Claim Rich Agent Task Bound Authentication extension (`v0.1`, `dc+sd-jwt`)**.

The SDK (`a2a_agentic_id`) depends only on `pydantic`, `pyjwt`, `cryptography`, and `httpx`, and has no dependency on any agent framework - the demos in [`examples/`](../../examples/) show how to adapt it to a specific runtime. For the protocol it implements, see [`docs/protocol-overview.md`](../../docs/protocol-overview.md).

## Installation

Install in editable mode for local development:

```bash
pip install -e .
```

Or install with development dependencies:

```bash
pip install -e ".[dev]"
```

## Features

- **SD-JWT Issuance & Verification**: Generate and verify selective disclosure JWTs (`dc+sd-jwt`) with Key Binding JWTs (`KB-JWT`) using ECDSA P-256 (`ES256`).
- **Holder Binding**: Cryptographically bind credentials to agent holder keys (`cnf.jwk`).
- **A2A Handshake Interceptors**: Server middleware (`ServerAuthRequiredInterceptor`) and client challenge handlers (`ClientAuthHandler`) implementing Section 5 of the specification.
- **Digital Credential Query Language (DCQL)**: Parse, evaluate, and fulfill selective disclosure queries against wallet credentials.
- **Delegated Challenge Tunneling**: Detect and answer `tunneled_challenge` envelopes on the Holder side (Section 12.6.1).
- **Channel Binding**: Optional binding of each KB-JWT to the TLS 1.3 connection that carries it (RFC 9266 `tls-exporter`, Section 12.8), which stops a leaked presentation from being used over another connection.
- **Token Status List (TSL)**: Real-time bit-array revocation checking compliant with `draft-ietf-oauth-status-list`.
- **Dynamic On-Demand Issuance**: In-band issuance of step-up authorization credentials and non-repudiable consent tokens (`SubstitutionIssuer`, `OrderCommitmentSigner`).

## Components

```text
                ┌───────────── Holder side ─────────────┐   ┌──────────── Verifier side ─────────────┐
 A2A layer      │ ClientAuthHandler                     │   │ ServerAuthRequiredInterceptor          │
                │  (answers challenges, tunnels)        │   │  (gate, nonces, sessions, step-up)     │
                ├───────────────────────────────────────┤   ├────────────────────────────────────────┤
 Credential     │ SDJWTWallet                           │   │ SDJWTVerifier ──▶ TokenStatusListClient│
 layer          │  (issue, select claims, sign KB-JWT)  │   │  (§7.3.4 checks)    (revocation)       │
                └───────────────────────────────────────┘   └────────────────────────────────────────┘
 Shared         models (IdentityChallenge, IdentityResponse, DCQL, ErrorCode, …) · crypto (P-256, JWK)
```

| Module | Main classes and functions | Implements |
|---|---|---|
| `models.py` | `IdentityChallenge`, `IdentityResponse`, `TunneledChallenge`, `TunneledResponse`, `DCQLQuery`, `AgentCardExtensionParams`, `AIAgentIdentityCredential`, `OwnerClaim`, `KeyProtectionLevel`, `ErrorCode`, `ExtensionSupportRequiredError` | Data structures (§4.1, §5.2, §8, §9.2, §11.1, §12.6.1) |
| `crypto.py` | `generate_ec_p256_keypair`, JWK import/export, `generate_nonce`, `compute_sha256_base64url` | ES256 keys, nonces, `sd_hash` |
| `wallet.py` | `SDJWTWallet`, `CredentialItem` | Issuance (`issue_sd_jwt`), DCQL claim selection, presentation with KB-JWT (`create_vp_token`) (§9.3–§9.6). Each DCQL credential query must match a stored credential by exact ID and format; the wallet never substitutes another credential. |
| `verifier.py` | `SDJWTVerifier`, `VerificationResult`, `CredentialVerificationError` | Ordered verification (§7.3.4), including the optional channel-binding check (`SDJWTVerifier(channel_binding=["tls-exporter"])`, §12.8) |
| `a2a_wire.py` | `canonical_message`, `send_message_response`, `jsonrpc_*`, `error_info`, `http_error`, `grpc_status` | A2A v1.0.0 wire builders and binding error bodies (§6.2, §7.3.3, §11.2) |
| `interceptor.py` | `ServerAuthRequiredInterceptor`, `A2ATaskMessage`, `A2ATaskStatusResponse` | Verifier gate: activation check, challenges, (`task_id`, `nonce`) store, task sessions bound to the transport channel (`A2ATaskMessage.channel_id`, set by the transport adapter; `require_channel_binding=False` opts out), step-up (§5.5, §6, §7, §12.1) |
| `client_interceptor.py` | `ClientAuthHandler` | Holder side: detects `TASK_STATE_AUTH_REQUIRED`, builds the Identity Response, handles tunneled challenges (§7.3.4, §12.6.1) |
| `tsl.py` | `TokenStatusListClient` | Token Status List lookup and creation (§7.3.4, §9.3) |
| `issuer_discovery.py` | `IssuerKeyDiscovery` | Opt-in issuer key discovery: JWT VC Issuer Metadata and `x5c` chain validation against configured trust anchors (§5.4, §7.3.4 step 3, §9.3). Pass it as `SDJWTVerifier(issuer_key_discovery=...)`; without it the verifier uses `jwks_resolver`. |
| `relay.py` | `TunnelRelay`, `TunnelError`, `TunnelRelayError`, `PendingTunnel` | Intermediate Agent side of the tunneling profile: pending-tunnel store, `tunneled_response` matching, `tunnel_error` reporting, tunnel lifetime (§12.6.1 Rules 1, 3, 6-8). In-memory. Call `is_tunneled_response` before the interceptor. |

## Integration shape

On the Verifier side, the interceptor wraps the request handler, which runs only after verification succeeds:

```python
from a2a_agentic_id import SDJWTVerifier, ServerAuthRequiredInterceptor, DCQLQuery

verifier = SDJWTVerifier(client_id="https://verifier.example/a2a",
                         jwks_resolver=resolve_issuer_jwk)  # iss -> public JWK
gate = ServerAuthRequiredInterceptor(verifier=verifier,
                                     dcql_query=DCQLQuery.default_agent_identity_query())

response = gate.process_incoming_request(task_message, next_handler)
# -> a TASK_STATE_AUTH_REQUIRED Task with a challenge, a TASK_STATE_FAILED Task with an error code, or next_handler's result.
# The SDK speaks A2A v1.0.0 only: requests must carry `A2A-Version: 1.0` and no task id on the Initial Request
# (the Verifier allocates it). task.to_jsonrpc_response(request_id) wraps the result as `result.task`.
# Raises ExtensionSupportRequiredError (-32008 / 400 / FAILED_PRECONDITION) when the extension
# is required but the request does not activate it (§6.2). A binding adapter must catch it;
# err.to_jsonrpc_error(request_id) builds the JSON-RPC response.
```

On the Holder side, a `ClientAuthHandler` backed by a wallet answers the challenge:

```python
from a2a_agentic_id import SDJWTWallet, ClientAuthHandler

handler = ClientAuthHandler(wallet)                      # wallet holds credential + private key
if handler.is_auth_required(task_response):
    metadata = handler.handle_auth_challenge(
        task_response,
        contacted_url=agent_url,   # the https URL you connected to; client_id must share its origin
        expected_client_url=card_url,  # optional: exact Agent Card / interface URL obtained independently
        conversation_id=context_id,
    )
    # resend on the same task_id and context_id, with `metadata` in message.metadata
```

In an LLM-driven agent, both calls belong in deterministic code - a callback, middleware, or tool - never in the model's own output. The ADK demo's `IdentityGate` ([`identity_gate.py`](../../examples/restaurant-adk/common/identity_gate.py)) and `call_with_identity` ([`a2a_caller.py`](../../examples/restaurant-adk/common/a2a_caller.py)) are worked examples; the ADK demo also adds its own Intermediate Agent helpers (`tunnel_upstream`, `take_tunneled_response`), which the SDK now covers with `TunnelRelay` (`relay.py`).

<!-- TODO: Add a complete, runnable integration example, or link to API reference docs if they exist. `resolve_issuer_jwk`, `task_message`, and `next_handler` above are supplied by the integrator. -->

## A2A version

The SDK speaks **A2A v1.0.0 only**. It does not accept or emit the v0.3 wire shapes:

- Task states are the `TASK_STATE_*` strings (constants such as `TASK_STATE_AUTH_REQUIRED` live in `a2a_agentic_id.interceptor`) and roles are `ROLE_USER` / `ROLE_AGENT`. The v0.3 spellings (`"working"`, `"auth-required"`), `kind` discriminators and lowercase roles raise `ValueError`.
- Every server Message carries the proto's required `messageId` plus `taskId` and `contextId`. A Part has exactly one of `text` / `raw` / `url` / `data`.
- Task ids are server-generated (A2A §3.4.2). An Initial Request carries no task id and the Verifier allocates a 128-bit one; a client-chosen id raises `TaskNotFoundError`.
- Requests must state `A2A-Version: 1.0` (patch versions are fine). An absent header, which A2A defines as 0.3, or any other version raises `VersionNotSupportedError`.
- `ExtensionSupportRequiredError`, `TaskNotFoundError` and `VersionNotSupportedError` are `A2AProtocolError`s. Each has `to_jsonrpc_error()`, `to_http_error()` (send it with `HTTP_STATUS`) and `to_grpc_status()`, and each carries the `google.rpc.ErrorInfo` that A2A v1.0.0 makes mandatory.
- `A2ATaskStatusResponse.to_wire()` returns the Task, `to_send_message_response()` wraps it as `{"task": ...}`, and `to_jsonrpc_response(request_id)` adds the JSON-RPC envelope (`result.task`).

These rules are normative in [`spec/v0.1/extension.md`](../../spec/v0.1/extension.md) §5.5, §6.2, §6.3 and §7.3.2. Not provided yet: the HTTP / gRPC / JSON-RPC transport adapters that call the interceptor and write these responses, and streaming.

## Tests

The SDK is tested through the simulation suite (425 tests), which exercises every error code in §11.1, the A2A v1.0.0 wire shapes, issuer key discovery, DCQL handling and channel binding:

```bash
pytest ../../examples/restaurant-simulation/tests
```

See [`examples/restaurant-simulation/README.md`](../../examples/restaurant-simulation/README.md#4-comprehensive-test-suite--verification-matrix-425425-passed) for the test matrix.
