# Glossary

| Term | Meaning |
|---|---|
| **A2A** | Agent2Agent protocol, used by AI agents to exchange messages and tasks. |
| **ADK** | Google's Agent Development Kit, the framework used for the three agents in the full demo. |
| **Agent Card** | JSON document at `/.well-known/agent-card.json` describing an agent's capabilities, including the extensions it requires. |
| **Attesting Proxy** | A model in which an intermediate agent verifies a credential and vouches for the result to the next agent. The spec does not define it (§12.6.1). |
| **Authenticated Task Session** | The Verifier's record that a `task_id` has passed verification, so later messages on it need no new presentation. |
| **DCQL** | Digital Credentials Query Language, the part of OID4VP a verifier uses to specify required credentials and claims. |
| **Delegated Challenge Tunneling** | The spec's multi-hop profile (§12.6.1): an intermediate agent relays a challenge to the Holder in `tunneled_challenge` and forwards the `tunneled_response` unchanged. |
| **Holder Agent** | The agent that holds a credential and proves its identity with it (the A2A client). |
| **Intermediate Agent** | An agent between the Holder and the terminal Verifier that relays a tunneled challenge without answering or validating it. |
| **Issuer** | The trusted party that signs a credential and binds it to the holder's public key. |
| **KB-JWT** | Key Binding JWT, signed by the holder at presentation time to prove control of the key in `cnf.jwk` and bind the presentation to a nonce and audience. |
| **MCP** | Model Context Protocol, used here to expose kitchen tools to `chef_agent`. |
| **Nonce** | A single-use random value tying a presentation to one challenge, preventing replay. |
| **OID4VP** | OpenID for Verifiable Presentations; defines the structure of the challenge and response. |
| **SD-JWT** (`dc+sd-jwt`) | A signed JWT format supporting selective disclosure: the holder reveals some claims and withholds others. |
| **Single-hop / multi-hop** | In a single-hop exchange, the Verifier challenges its direct caller. In a multi-hop exchange, an intermediate agent tunnels the challenge to the Holder and forwards the answer unchanged (§12.6.1). |
| **Step-up challenge** | A mid-task challenge for an additional or different credential. |
| **Token Status List (TSL)** | IETF draft format for publishing credential revocation as a compressed bit array. |
| **Verifiable Credential (VC)** | A digitally signed set of claims about a subject. |
| **Verifiable Presentation (VP)** | A credential, or part of one, presented for a specific verifier and transaction. |
| **Verifier Agent** | The agent that checks a presentation before processing a request (the A2A server). |
| **x401** | Demo-only profile (not part of the extension spec or the SDK) for exchanging a presentation for an OAuth 2.0 access token to call an HTTP API. |
