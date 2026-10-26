# SPDX-License-Identifier: Apache-2.0
"""Customer-facing agent module.

Handles voucher upload, redemption, substitution consent, and completion.
"""

from typing import Any, Dict

import jwt
from google.adk.agents import Agent
from google.adk.apps import App
from google.adk.plugins.save_files_as_artifacts_plugin import (
    SaveFilesAsArtifactsPlugin,
)
from google.adk.tools.function_tool import FunctionTool
from google.adk.tools.tool_context import ToolContext
from google.genai import types

from restaurant_domain import SubstitutionIssuer
from a2a_agentic_id.crypto import compute_sha256_base64url, generate_nonce

from common.a2a_caller import IdentityGateError, TunnelPolicy, call_with_identity
from common.config import FOH_AGENT_URL, build_model
from common.exchange_log import log
from common.identity import (
    CHEF_AGENT,
    CUSTOMER_AGENT,
    FOH_AGENT,
    SUBSTITUTION_APPROVAL_CREDENTIAL_ID,
    VOUCHER_CREDENTIAL_TYPE,
    VOUCHER_DIETARY_CLAIM,
    VOUCHER_ENTITLEMENT_CLAIM,
    VOUCHER_ISSUER,
    build_customer_wallet,
    extract_unverified_disclosures,
    holder_credential,
    load_private_jwk,
    load_public_jwk,
)

_STATE_TRANSACTION_ID = "customer.transaction_id"
_STATE_VOUCHER = "customer.voucher"
_STATE_ENTITLEMENT = "customer.entitlement"
_STATE_DIETARY = "customer.dietary"
_STATE_SUBSTITUTION = "customer.substitution_proposal"

# foh_agent can relay a challenge from chef_agent (spec 12.6.1). The customer
# answers a relayed challenge only from chef_agent, and only for the consent.
_CONSENT_TUNNEL_POLICY = TunnelPolicy(
    allowed_verifiers=frozenset({CHEF_AGENT}),
    allowed_credentials=frozenset({SUBSTITUTION_APPROVAL_CREDENTIAL_ID}),
)


def _artifact_text(artifact: types.Part) -> str:
    """Return the text of an uploaded file."""
    if artifact.inline_data and artifact.inline_data.data:
        return artifact.inline_data.data.decode("utf-8").strip()
    return (artifact.text or "").strip()


def _check_voucher(sd_jwt_string: str) -> str:
    """Check an uploaded voucher and return its issuer.

    The check fails if:
    - the issuer is not voucher_issuer, or the issuer signature is not valid,
    - the voucher is expired,
    - the credential type is not RestaurantVoucher,
    - the voucher is not bound to the key of customer_agent,
    - a disclosure is not in the '_sd' digest list.
    """
    issuer_jwt, *disclosures = sd_jwt_string.split("~")
    issuer = jwt.decode(issuer_jwt, options={"verify_signature": False}).get("iss")
    if issuer != VOUCHER_ISSUER:
        raise ValueError(f"issuer '{issuer}' is not trusted")
    payload = jwt.decode(
        issuer_jwt, key=jwt.PyJWK.from_dict(load_public_jwk(issuer)).key, algorithms=["ES256"]
    )
    if payload.get("vct") != VOUCHER_CREDENTIAL_TYPE:
        raise ValueError(f"credential type '{payload.get('vct')}' is not {VOUCHER_CREDENTIAL_TYPE}")
    holder_jwk = payload.get("cnf", {}).get("jwk", {})
    customer_jwk = load_public_jwk(CUSTOMER_AGENT)
    if (holder_jwk.get("x"), holder_jwk.get("y")) != (customer_jwk["x"], customer_jwk["y"]):
        raise ValueError("voucher is not bound to the key of customer_agent")
    digests = set(payload.get("_sd", []))
    if any(d and compute_sha256_base64url(d) not in digests for d in disclosures):
        raise ValueError("a disclosure is not in the '_sd' digest list")
    return issuer


async def load_voucher(filename: str, tool_context: ToolContext) -> Dict[str, Any]:
    """Load and verify an uploaded voucher artifact, then request user confirmation."""
    artifact = await tool_context.load_artifact(filename)
    if artifact is None:
        return {"error": f"No uploaded artifact named '{filename}' was found."}
    try:
        voucher = _artifact_text(artifact)
    except UnicodeDecodeError:
        return {"error": f"Uploaded file '{filename}' is not a text SD-JWT voucher."}

    log("customer_agent", f"verifying voucher '{filename}': checking issuer signature, holder key and disclosures")
    try:
        issuer = _check_voucher(voucher)
    except Exception as exc:
        log("customer_agent", f"voucher verification failed: {exc}")
        return {"error": f"Voucher verification failed: {exc}"}

    disclosures = extract_unverified_disclosures(voucher)
    entitlement = disclosures.get(VOUCHER_ENTITLEMENT_CLAIM)
    dietary = disclosures.get(VOUCHER_DIETARY_CLAIM)

    tool_context.state[_STATE_VOUCHER] = voucher
    tool_context.state[_STATE_ENTITLEMENT] = entitlement
    tool_context.state[_STATE_DIETARY] = dietary

    log(
        "customer_agent",
        f"voucher verified: issuer='{issuer}', entitlement='{entitlement}', dietary='{dietary}' -> asking user for confirmation",
    )
    return {
        "status": "verified",
        "issuer": issuer,
        "entitlement": entitlement,
        "dietary": dietary,
        "confirmation_prompt": f"Voucher verified for {entitlement} ({dietary}). Would you like to proceed with redeeming this voucher?",
    }


async def start_redemption(tool_context: ToolContext) -> Dict[str, Any]:
    """Initiate redemption with foh_agent using the voucher credential."""
    entitlement = tool_context.state.get(_STATE_ENTITLEMENT)
    voucher = tool_context.state.get(_STATE_VOUCHER)
    if not entitlement or not voucher:
        return {"error": "No voucher has been loaded yet. Upload and load one first."}

    transaction_id = f"txn-{generate_nonce(6)}"
    tool_context.state[_STATE_TRANSACTION_ID] = transaction_id

    try:
        result = await call_with_identity(
            FOH_AGENT_URL,
            f"Redeem voucher for: {entitlement} (dietary: {tool_context.state.get(_STATE_DIETARY)})",
            context_id=transaction_id,
            wallet=build_customer_wallet(voucher),
            caller=CUSTOMER_AGENT,
            callee=FOH_AGENT,
        )
    except IdentityGateError as exc:
        return {"error": f"foh_agent rejected the redemption: {exc}"}

    substitution = result.ext_metadata.get("substitution_proposal")
    if substitution:
        tool_context.state[_STATE_SUBSTITUTION] = substitution

    return {"transaction_id": transaction_id, "foh_response": result.text, "substitution_proposal": substitution}


async def approve_substitution(tool_context: ToolContext) -> Dict[str, Any]:
    """Capture explicit user confirmation and issue a signed consent credential."""
    if not tool_context.tool_confirmation:
        proposal = tool_context.state.get(_STATE_SUBSTITUTION)
        tool_context.request_confirmation(
            hint="The kitchen proposed a substitution. Approve or reject it.",
            payload=proposal,
        )
        return {"status": "awaiting_human_confirmation"}

    if not tool_context.tool_confirmation.confirmed:
        return {"status": "rejected"}

    proposal = tool_context.state.get(_STATE_SUBSTITUTION)
    transaction_id = tool_context.state.get(_STATE_TRANSACTION_ID)
    if not proposal or not transaction_id:
        return {"error": "No pending substitution proposal to approve."}

    consent_sd_jwt = SubstitutionIssuer.issue_approval_credential(
        customer_private_key_jwk=load_private_jwk(CUSTOMER_AGENT),
        customer_public_key_jwk=load_public_jwk(CUSTOMER_AGENT),
        customer_id=CUSTOMER_AGENT,
        order_id=transaction_id,
        original_ingredient=proposal["original"],
        substitute_ingredient=proposal["substitute"],
    )
    tool_context.state[SUBSTITUTION_APPROVAL_CREDENTIAL_ID] = consent_sd_jwt
    return {"status": "approved", "consent_issued": True}


async def submit_consent(tool_context: ToolContext) -> Dict[str, Any]:
    """Submit the signed consent presentation.

    foh_agent asks for the consent directly (CONSENT_VERIFIER="foh"), or it
    tunnels a challenge from chef_agent (CONSENT_VERIFIER="chef").
    This function answers both.
    """
    transaction_id = tool_context.state.get(_STATE_TRANSACTION_ID)
    consent_sd_jwt = tool_context.state.get(SUBSTITUTION_APPROVAL_CREDENTIAL_ID)
    if not transaction_id or not consent_sd_jwt:
        return {"error": "No approved substitution consent is available to submit."}

    wallet = build_customer_wallet(tool_context.state.get(_STATE_VOUCHER))
    wallet.add_credential(
        holder_credential(SUBSTITUTION_APPROVAL_CREDENTIAL_ID, consent_sd_jwt, CUSTOMER_AGENT)
    )

    try:
        result = await call_with_identity(
            FOH_AGENT_URL,
            "Here is my signed consent to the proposed substitution. Please complete the order.",
            context_id=transaction_id,
            wallet=wallet,
            caller=CUSTOMER_AGENT,
            callee=FOH_AGENT,
            tunnel_policy=_CONSENT_TUNNEL_POLICY,
        )
    except IdentityGateError as exc:
        return {"error": f"foh_agent rejected the consent: {exc}"}

    return {"foh_response": result.text}


root_agent = Agent(
    name="customer_agent",
    model=build_model("CUSTOMER_MODEL"),
    description=(
        "Customer-facing agent for the full voucher-redemption lifecycle: "
        "voucher upload, redemption, substitution negotiation, and signed "
        "consent."
    ),
    instruction=(
        "You are the customer-facing agent for a restaurant. You are the "
        "ONLY agent in this system allowed to talk to the human user -- "
        "every other step happens over agent-to-agent (A2A) calls the user "
        "does not participate in directly.\n\n"
        "Walk the human through this lifecycle, one stage at a time:\n\n"
        "STAGE 0 -- Voucher upload: When the human uploads a voucher file "
        "(a .jwt file), call `load_voucher` with that exact filename. Present "
        "the verified entitlement and dietary restriction to the human. Ask "
        "for their explicit confirmation before proceeding to redeem.\n\n"
        "STAGE 1 -- Initiation: Only after the human confirms redemption, "
        "call `start_redemption`. If it returns a `substitution_proposal`, "
        "move to Stage 3/4 below. If it returns a plain `foh_response` with "
        "no proposal, relay that response as the order's outcome.\n\n"
        "STAGE 3/4 -- Negotiation and consent: If a substitution was "
        "proposed (original ingredient unavailable, a substitute offered), "
        "explain the substitution to the human in plain language and ask "
        "them to explicitly approve or reject it. Only after they respond, "
        "call `approve_substitution` -- it will surface a native "
        "approve/reject confirmation for the human to answer directly; "
        "never decide on their behalf.\n\n"
        "STAGE 5 -- Completion: Once `approve_substitution` reports "
        "status='approved', call `submit_consent` to finalize the order "
        "and relay its `foh_response` to the human as the final outcome.\n\n"
        "Always relay what the tools actually returned -- never fabricate "
        "a confirmation, an entitlement, or a substitution."
    ),
    tools=[
        FunctionTool(load_voucher),
        FunctionTool(start_redemption),
        FunctionTool(approve_substitution, require_confirmation=True),
        FunctionTool(submit_consent),
    ],
)

app = App(
    name="customer_app",
    root_agent=root_agent,
    plugins=[SaveFilesAsArtifactsPlugin()],
)
