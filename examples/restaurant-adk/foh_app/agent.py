# SPDX-License-Identifier: Apache-2.0
"""Front-of-House (FoH) agent module.

Validates customer voucher credentials and routes orders to chef_agent.

CONSENT_VERIFIER sets how this agent handles substitution consent:
- "chef": this agent is an Intermediate Agent (spec 12.6.1). It tunnels the
  chef's challenge to the customer and forwards the answer unchanged.
- "foh": this agent verifies the consent and tells chef_agent the result.
"""

from typing import Any, Dict

from google.adk.agents import Agent
from google.adk.tools.function_tool import FunctionTool
from google.adk.tools.tool_context import ToolContext

from a2a_agentic_id import DCQLClaimQuery, DCQLCredentialQuery, DCQLQuery, SDJWTVerifier

from common.a2a_caller import IdentityGateError, TunnelRequired, call_with_identity
from common.config import CHEF_AGENT_URL, CONSENT_VERIFIER, build_model
from common.consent import CONSENT_DCQL_QUERY
from common.exchange_log import SINGLE_HOP, log
from common.identity import (
    CHEF_AGENT,
    CUSTOMER_AGENT,
    FOH_AGENT,
    VOUCHER_CREDENTIAL_ID,
    VOUCHER_CREDENTIAL_TYPE,
    VOUCHER_ISSUER,
    build_employee_wallet,
    trusted_keys,
)
from common.identity_gate import (
    STATE_VERIFIED_IDENTITY,
    IdentityGate,
    emit_pending_extension_metadata,
    mark_pending_extension_metadata,
    take_tunneled_response,
    tunnel_upstream,
)
from common.verbose_log import on_after_model, on_after_tool, on_before_model, on_before_tool

_VOUCHER_DCQL_QUERY = DCQLQuery(
    credentials=[
        DCQLCredentialQuery(
            id=VOUCHER_CREDENTIAL_ID,
            format="dc+sd-jwt",
            meta={"vct_values": [VOUCHER_CREDENTIAL_TYPE]},
            claims=[
                DCQLClaimQuery(path=["entitlement"]),
                DCQLClaimQuery(path=["dietary"]),
            ],
        )
    ]
)

_CONSENT_TEXT_TO_CHEF = "The customer approved the substitution. Please complete the order."


# The voucher issuer is always trusted. The customer signs the consent, so
# the customer is trusted only if this agent verifies the consent.
_gate = IdentityGate(
    verifier=SDJWTVerifier(
        client_id=FOH_AGENT,
        jwks_resolver=trusted_keys(VOUCHER_ISSUER, *([CUSTOMER_AGENT] if CONSENT_VERIFIER == "foh" else [])),
    ),
    dcql_query=_VOUCHER_DCQL_QUERY,
)


async def relay_to_chef(tool_context: ToolContext) -> Dict[str, Any]:
    """Forward verified redemption request to chef_agent."""
    verified = tool_context.state.get(STATE_VERIFIED_IDENTITY)
    if not verified:
        return {"error": "Missing verified voucher."}

    disclosed = verified.get("disclosed_claims", {})
    entitlement = disclosed.get("entitlement")
    dietary = disclosed.get("dietary")
    transaction_id = tool_context.session.id

    try:
        result = await call_with_identity(
            CHEF_AGENT_URL,
            f"Prepare order: {entitlement} (dietary: {dietary})",
            context_id=transaction_id,
            wallet=build_employee_wallet(FOH_AGENT),
            caller=FOH_AGENT,
            callee=CHEF_AGENT,
        )
    except IdentityGateError as exc:
        return {"error": f"chef_agent rejected the order: {exc}"}

    substitution = result.ext_metadata.get("substitution_proposal")
    if substitution:
        mark_pending_extension_metadata(
            tool_context, {"substitution_proposal": substitution}, result.text
        )
    return {"chef_response": result.text, "substitution_proposal": substitution}


async def forward_consent(tool_context: ToolContext) -> Dict[str, Any]:
    """Move the customer's signed consent to chef_agent.

    CONSENT_VERIFIER selects the tunnel flow ("chef") or the single-hop flow ("foh").
    """
    verified = tool_context.state.get(STATE_VERIFIED_IDENTITY)
    if not verified:
        return {"error": "Unauthenticated task session."}

    if CONSENT_VERIFIER == "chef":
        return await _tunnel_consent(tool_context)
    return await _verify_and_forward_consent(tool_context)


async def _tunnel_consent(tool_context: ToolContext) -> Dict[str, Any]:
    """Relay consent between the customer and chef_agent (spec 12.6.1).

    Turn 1: call chef_agent. chef_agent asks for a credential that this agent
    does not hold, so this agent tunnels the challenge to the customer.
    Turn 2: the customer sends a tunneled_response. This agent forwards the
    vp_token to chef_agent unchanged. It does not validate the vp_token (Rule 4).
    """
    transaction_id = tool_context.session.id
    try:
        tunneled = take_tunneled_response(tool_context, relay=FOH_AGENT)
    except ValueError as exc:
        return {"error": str(exc)}

    if tunneled is not None:
        response, pending_call = tunneled
        try:
            result = await call_with_identity(
                pending_call["url"],
                pending_call["text"],
                context_id=transaction_id,
                wallet=build_employee_wallet(FOH_AGENT),
                caller=FOH_AGENT,
            callee=CHEF_AGENT,
                forward_vp_token=response.response,
            )
        except IdentityGateError as exc:
            return {"error": f"chef_agent rejected the consent: {exc}"}
        return {"chef_response": result.text}

    try:
        result = await call_with_identity(
            CHEF_AGENT_URL,
            _CONSENT_TEXT_TO_CHEF,
            context_id=transaction_id,
            wallet=build_employee_wallet(FOH_AGENT),
            caller=FOH_AGENT,
            callee=CHEF_AGENT,
            can_tunnel=True,
        )
    except TunnelRequired as required:
        tunnel_upstream(
            tool_context,
            required.tunneled,
            relay=FOH_AGENT,
            downstream_url=CHEF_AGENT_URL,
            downstream_text=_CONSENT_TEXT_TO_CHEF,
        )
        return {"status": "tunneling_consent_challenge"}
    except IdentityGateError as exc:
        return {"error": f"chef_agent rejected the order: {exc}"}

    # chef_agent did not ask for consent. This occurs only if chef_agent is
    # not set up as the consent verifier.
    return {"chef_response": result.text}


async def _verify_and_forward_consent(tool_context: ToolContext) -> Dict[str, Any]:
    """Verify the customer's consent here, then tell chef_agent the result."""
    result = _gate.step_up(
        tool_context,
        CONSENT_DCQL_QUERY,
        holder=CUSTOMER_AGENT,
        prompt="Please present your signed substitution consent.",
    )
    if isinstance(result, dict):
        return result

    log(
        FOH_AGENT,
        f"CONSENT_VERIFIER=foh: telling {CHEF_AGENT} in plain text that consent is verified. "
        f"{CHEF_AGENT} does not receive the customer's credential.",
        hop=SINGLE_HOP,
    )
    try:
        result = await call_with_identity(
            CHEF_AGENT_URL,
            "The customer's signed consent to the substitution has been verified. Please complete the order.",
            context_id=tool_context.session.id,
            wallet=build_employee_wallet(FOH_AGENT),
            caller=FOH_AGENT,
            callee=CHEF_AGENT,
        )
    except IdentityGateError as exc:
        return {"error": f"chef_agent rejected the consent: {exc}"}

    return {"chef_response": result.text}


root_agent = Agent(
    name="foh_agent",
    model=build_model("FOH_MODEL"),
    description=(
        "Front-of-House agent. Verifies the customer's voucher, coordinates "
        "order redemption with the chef agent, and relays any negotiation "
        "back to the customer. Never talks to the human customer directly."
    ),
    instruction=(
        "You handle order redemption between the customer agent and the "
        "chef agent. You never talk to a human directly -- every message you "
        "receive already comes from another agent, and every reply you send "
        "goes back to that agent.\n\n"
        "By the time you see a message, this agent's identity gate has "
        "already verified the customer's voucher presentation -- you don't "
        "need to check it yourself.\n\n"
        "When a redemption request arrives, call `relay_to_chef` to forward "
        "it to the chef agent. If the result includes a "
        "`substitution_proposal`, relay that proposal back verbatim so the "
        "customer agent can negotiate it with the human. If it includes a "
        "plain `chef_response` with no proposal, relay that as the order's "
        "outcome.\n\n"
        "When a message instead says the customer has approved a "
        "substitution and is presenting signed consent, call "
        "`forward_consent`. Also call `forward_consent` when a message "
        "resends the consent after a challenge. If it reports "
        "status='awaiting_consent_presentation' or "
        "status='tunneling_consent_challenge', just say verification is in "
        "progress -- the caller will resend automatically. Otherwise relay "
        "its `chef_response` as the final outcome.\n\n"
        "Always relay what the tools actually returned -- never fabricate "
        "an outcome or a substitution."
    ),
    tools=[
        FunctionTool(relay_to_chef),
        FunctionTool(forward_consent),
    ],
    before_agent_callback=_gate,
    after_agent_callback=emit_pending_extension_metadata,
    before_model_callback=on_before_model,
    after_model_callback=on_after_model,
    before_tool_callback=on_before_tool,
    after_tool_callback=on_after_tool,
)
