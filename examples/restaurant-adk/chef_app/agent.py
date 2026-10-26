# SPDX-License-Identifier: Apache-2.0
"""Chef agent module.

Validates FoH employee credentials, fulfills dishes using the Kitchen MCP
server, and manages ingredient substitutions.

If CONSENT_VERIFIER is "chef", this agent is the Terminal Verifier Agent for
the customer's signed consent (spec 12.6.1). foh_agent relays the challenge
and the presentation. It does not validate them.
"""

from typing import Any, Dict, List

from google.adk.agents import Agent
from google.adk.tools.function_tool import FunctionTool
from google.adk.tools.tool_context import ToolContext

from a2a_agentic_id import DCQLClaimQuery, DCQLCredentialQuery, DCQLQuery, SDJWTVerifier

from common.config import CONSENT_VERIFIER, build_model
from common.consent import CONSENT_DCQL_QUERY, consent_mismatch
from common.exchange_log import MULTI_HOP, SINGLE_HOP, log
from common.identity import (
    CHEF_AGENT,
    CUSTOMER_AGENT,
    FOH_AGENT,
    EMPLOYEE_CREDENTIAL_ID,
    EMPLOYEE_CREDENTIAL_TYPE,
    FOH_ROLE,
    RESTAURANT_ISSUER,
    trusted_keys,
)
from common.identity_gate import (
    STATE_VERIFIED_IDENTITY,
    IdentityGate,
    emit_pending_extension_metadata,
    mark_pending_extension_metadata,
)
from common import kitchen_client
from common.kitchen_api import KitchenError
from common.verbose_log import on_after_model, on_after_tool, on_before_model, on_before_tool

_STATE_DISH_NAME = "chef.dish_name"
_STATE_ORIGINAL_INGREDIENT = "chef.original_ingredient"
_STATE_SUBSTITUTE_INGREDIENT = "chef.substitute_ingredient"

_DISH_INGREDIENTS: Dict[str, List[str]] = {
    "Grilled Cheese": ["cheese", "gluten_free_bread", "butter"],
}
_SUBSTITUTE_INGREDIENT: Dict[str, str] = {
    "gluten_free_bread": "gluten_free_tortilla",
}

_EMPLOYEE_DCQL_QUERY = DCQLQuery(
    credentials=[
        DCQLCredentialQuery(
            id=EMPLOYEE_CREDENTIAL_ID,
            format="dc+sd-jwt",
            meta={"vct_values": [EMPLOYEE_CREDENTIAL_TYPE]},
            claims=[DCQLClaimQuery(path=["role"], values=[FOH_ROLE])],
        )
    ]
)

_gate = IdentityGate(
    verifier=SDJWTVerifier(client_id=CHEF_AGENT, jwks_resolver=trusted_keys(RESTAURANT_ISSUER)),
    dcql_query=_EMPLOYEE_DCQL_QUERY,
)

# The customer signs the consent credential. Only the consent step trusts this key.
_consent_verifier = SDJWTVerifier(client_id=CHEF_AGENT, jwks_resolver=trusted_keys(CUSTOMER_AGENT))


async def prepare_order(dish_name: str, tool_context: ToolContext) -> Dict[str, Any]:
    """Check ingredient inventory and prepare dish or propose substitution."""
    verified = tool_context.state.get(STATE_VERIFIED_IDENTITY)
    if not verified:
        return {"error": "Missing verified caller identity."}

    ingredients = _DISH_INGREDIENTS.get(dish_name)
    if ingredients is None:
        return {"error": f"Unknown dish '{dish_name}'."}
    tool_context.state[_STATE_DISH_NAME] = dish_name

    available = await kitchen_client.list_ingredients()
    depleted = next((name for name in ingredients if available.get(name, 0) <= 0), None)

    if depleted is not None:
        substitute = _SUBSTITUTE_INGREDIENT.get(depleted)
        if substitute is None:
            return {"error": f"'{depleted}' is depleted and has no substitute."}

        tool_context.state[_STATE_ORIGINAL_INGREDIENT] = depleted
        tool_context.state[_STATE_SUBSTITUTE_INGREDIENT] = substitute
        proposal = {
            "original": depleted,
            "substitute": substitute,
            "reason": f"'{depleted}' is out of stock",
        }
        mark_pending_extension_metadata(
            tool_context,
            {"substitution_proposal": proposal},
            f"'{depleted}' is unavailable for {dish_name}; proposing '{substitute}' instead.",
        )
        return {"status": "substitution_proposed", "substitution_proposal": proposal}

    try:
        dish = await kitchen_client.prepare_dish(dish_name, ingredients)
    except KitchenError as exc:
        return {"error": exc.message}
    return {"status": "completed", "dish": dish}


def _verify_customer_consent(
    tool_context: ToolContext, *, original: str, substitute: str
) -> Dict[str, Any] | None:
    """Request or verify the customer's signed consent.

    Returns None if the consent is valid. Otherwise returns the tool result.
    """
    # The challenge goes to foh_agent. foh_agent tunnels it to the customer.
    result = _gate.step_up(
        tool_context,
        CONSENT_DCQL_QUERY,
        holder=CUSTOMER_AGENT,
        relay=FOH_AGENT,
        verifier=_consent_verifier,
        prompt="Present the customer's signed substitution consent.",
    )
    if isinstance(result, dict):
        return result

    mismatch = consent_mismatch(
        result, order_id=tool_context.session.id, original=original, substitute=substitute
    )
    if mismatch:
        log(CHEF_AGENT, f"consent REJECTED: {mismatch}", hop=MULTI_HOP, step=5)
        return {"error": f"Consent does not agree with the pending substitution: {mismatch}"}
    log(
        CHEF_AGENT,
        f"consent agrees with the pending order (order_id, {original} -> {substitute}). "
        f"{CHEF_AGENT} verified it itself. It does not depend on {FOH_AGENT}'s word.",
        hop=MULTI_HOP,
        step=5,
    )
    return None


async def complete_substituted_order(tool_context: ToolContext) -> Dict[str, Any]:
    """Complete order preparation with agreed substitute ingredient."""
    dish_name = tool_context.state.get(_STATE_DISH_NAME)
    original = tool_context.state.get(_STATE_ORIGINAL_INGREDIENT)
    substitute = tool_context.state.get(_STATE_SUBSTITUTE_INGREDIENT)
    if not dish_name or not original or not substitute:
        return {"error": "No pending substitution found for this order."}

    if CONSENT_VERIFIER == "chef":
        error = _verify_customer_consent(tool_context, original=original, substitute=substitute)
        if error is not None:
            return error
    else:
        log(
            CHEF_AGENT,
            f"CONSENT_VERIFIER=foh: {CHEF_AGENT} accepts {FOH_AGENT}'s plain-text statement that "
            f"consent is verified. {CHEF_AGENT} does not see the customer's credential.",
            hop=SINGLE_HOP,
        )

    ingredients = [substitute if name == original else name for name in _DISH_INGREDIENTS[dish_name]]
    try:
        dish = await kitchen_client.prepare_dish(dish_name, ingredients)
    except KitchenError as exc:
        return {"error": exc.message}
    return {"status": "completed", "dish": dish}


root_agent = Agent(
    name="chef_agent",
    model=build_model("CHEF_MODEL"),
    description=(
        "Kitchen fulfillment agent. Verifies the Front-of-House agent's "
        "employee credential, prepares orders via the Kitchen API, and "
        "proposes ingredient substitutions when a resource is unavailable."
    ),
    instruction=(
        "You fulfill orders for the Front-of-House (FoH) agent. You never "
        "talk to a human or to the customer agent directly -- every message "
        "you receive comes from foh_agent, and every reply you send goes "
        "back to it.\n\n"
        "By the time you see a message, this agent's identity gate has "
        "already verified the caller's employee credential -- you don't "
        "need to check it yourself.\n\n"
        "When a message asks you to prepare an order (e.g. 'Prepare order: "
        "Grilled Cheese ...'), call `prepare_order` with that dish's name. "
        "If it reports status='substitution_proposed', relay the "
        "`substitution_proposal` back to foh_agent so it can negotiate with "
        "the customer -- never decide on a substitution yourself. If it "
        "reports status='completed', relay the finished dish as the order's "
        "outcome.\n\n"
        "When a message instead says the customer approved the "
        "substitution and asks you to complete the order, call "
        "`complete_substituted_order` (no arguments). If it reports "
        "status='awaiting_consent_presentation', just say that you need the "
        "customer's signed consent -- the caller will resend automatically. "
        "Otherwise relay its result as the final outcome.\n\n"
        "Always relay what the tools actually returned -- never fabricate a "
        "completed dish or a substitution."
    ),
    tools=[
        FunctionTool(prepare_order),
        FunctionTool(complete_substituted_order),
    ],
    before_agent_callback=_gate,
    after_agent_callback=emit_pending_extension_metadata,
    before_model_callback=on_before_model,
    after_model_callback=on_after_model,
    before_tool_callback=on_before_tool,
    after_tool_callback=on_after_tool,
)
