# SPDX-License-Identifier: Apache-2.0
"""Offline smoke test for the credential exchanges between the three agents.

Runs the real identity gate and A2A caller code. A fake transport replaces
HTTP, and no model is called. Prints the logs with timestamps, colors, and
random values removed, so that two runs can be compared.

Usage (from examples/restaurant-adk):
    python tests/smoke_hops.py chef
    python tests/smoke_hops.py foh
"""

import asyncio
import contextlib
import io
import os
import re
import sys
from pathlib import Path
from types import SimpleNamespace

MODE = sys.argv[1] if len(sys.argv) > 1 else "chef"
os.environ["CONSENT_VERIFIER"] = MODE
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import common  # noqa: E402,F401  (adds the SDK to sys.path)

from a2a.types import a2a_pb2  # noqa: E402
from google.protobuf.json_format import MessageToDict, ParseDict  # noqa: E402

from a2a_agentic_id import EXTENSION_URI  # noqa: E402
from restaurant_domain import SubstitutionIssuer  # noqa: E402

import chef_app.agent as chef  # noqa: E402
import common.a2a_caller as a2a_caller  # noqa: E402
import foh_app.agent as foh  # noqa: E402
from common.a2a_caller import TunnelPolicy, call_with_identity  # noqa: E402
from common.identity import (  # noqa: E402
    CHEF_AGENT,
    CUSTOMER_AGENT,
    FOH_AGENT,
    SUBSTITUTION_APPROVAL_CREDENTIAL_ID,
    VOUCHER_FILENAME,
    VOUCHERS_DIR,
    build_customer_wallet,
    build_employee_wallet,
    holder_credential,
    load_private_jwk,
    load_public_jwk,
)
from common.identity_gate import STATE_PENDING_EXTENSION_METADATA  # noqa: E402

TXN = "txn-smoke1"
CHEF_URL = "http://chef"
FOH_URL = "http://foh"


class FakeContext:
    """The parts of an ADK callback or tool context that the demo uses."""

    def __init__(self, agent_name: str) -> None:
        self.agent_name = agent_name
        self.state: dict = {}
        self.custom_metadata: dict = {}
        self.session = SimpleNamespace(id=TXN)

    def receive(self, request, context=None) -> None:
        """Copy the extension metadata of an A2A request into the context.

        Like an unmodified ADK server, this reads request-level metadata only.
        The client must also send the spec location (message.metadata) and the
        A2A-Extensions service parameter, which are asserted here.
        """
        meta = MessageToDict(request.metadata).get(EXTENSION_URI, {})
        assert MessageToDict(request.message.metadata).get(EXTENSION_URI, {}) == meta
        params = (context.service_parameters if context else None) or {}
        assert EXTENSION_URI in params.get("A2A-Extensions", "")
        self.custom_metadata = {"a2a_metadata": {EXTENSION_URI: meta}}


def reply(text: str, ext: dict | None = None):
    """Return a completed A2A task, like the ADK A2A server does."""
    task = a2a_pb2.Task(id=f"task-{TXN}", context_id=TXN)
    task.status.state = a2a_pb2.TaskState.TASK_STATE_COMPLETED
    message = task.status.message
    message.role = a2a_pb2.Role.ROLE_AGENT
    part = message.parts.add()
    part.text = text
    if ext:
        ParseDict({EXTENSION_URI: ext}, part.metadata)
    return SimpleNamespace(HasField=lambda field: field == "task", task=task)


def pending_reply(ctx: FakeContext, default_text: str):
    """Return the metadata that after_agent_callback emits, or a plain reply."""
    pending = ctx.state.pop(STATE_PENDING_EXTENSION_METADATA, None)
    if pending:
        return reply(pending["text"], pending["metadata"])
    return reply(default_text)


class FakeAgent:
    """Runs an agent's identity gate, then one of its tools."""

    def __init__(self, module, name: str, tool) -> None:
        self.module = module
        self.ctx = FakeContext(name)
        self.tool = tool

    async def send_message(self, request, context=None):
        self.ctx.receive(request, context)
        blocked = self.module._gate(self.ctx)
        if blocked is not None:
            part = blocked.parts[0]
            yield reply(part.text, part.part_metadata[EXTENSION_URI])
            return
        result = await self.tool(self.ctx)
        yield pending_reply(self.ctx, str(result))


async def chef_tool(ctx: FakeContext):
    ctx.state.update(
        {
            "chef.dish_name": "Grilled Cheese",
            "chef.original_ingredient": "gluten_free_bread",
            "chef.substitute_ingredient": "gluten_free_tortilla",
        }
    )
    if chef.CONSENT_VERIFIER == "chef":
        error = chef._verify_customer_consent(
            ctx, original="gluten_free_bread", substitute="gluten_free_tortilla"
        )
        return error or "Grilled Cheese prepared with gluten_free_tortilla"
    return "Grilled Cheese prepared with gluten_free_tortilla"


async def prepare_tool(ctx: FakeContext):
    return "Grilled Cheese needs a substitution"


async def foh_tool(ctx: FakeContext):
    return await foh.forward_consent(ctx)


AGENTS = {
    CHEF_URL: FakeAgent(chef, CHEF_AGENT, chef_tool),
    FOH_URL: FakeAgent(foh, FOH_AGENT, foh_tool),
}


async def fake_get_client(base_url: str, caller: str, callee: str):
    return AGENTS[base_url]


a2a_caller._get_client = fake_get_client
foh.CHEF_AGENT_URL = CHEF_URL


def customer_wallet():
    consent = SubstitutionIssuer.issue_approval_credential(
        customer_private_key_jwk=load_private_jwk(CUSTOMER_AGENT),
        customer_public_key_jwk=load_public_jwk(CUSTOMER_AGENT),
        customer_id=CUSTOMER_AGENT,
        order_id=TXN,
        original_ingredient="gluten_free_bread",
        substitute_ingredient="gluten_free_tortilla",
    )
    wallet = build_customer_wallet((VOUCHERS_DIR / VOUCHER_FILENAME).read_text(encoding="utf-8"))
    wallet.add_credential(holder_credential(SUBSTITUTION_APPROVAL_CREDENTIAL_ID, consent, CUSTOMER_AGENT))
    return wallet


async def scenario() -> list[str]:
    results = []

    print("### 1. foh_agent -> chef_agent: employee credential (direct)")
    AGENTS[CHEF_URL].tool = prepare_tool
    direct = await call_with_identity(
        CHEF_URL,
        "Prepare order: Grilled Cheese",
        context_id=TXN,
        wallet=build_employee_wallet(FOH_AGENT),
        caller=FOH_AGENT,
        callee=CHEF_AGENT,
    )
    results.append(direct.text)
    AGENTS[CHEF_URL].tool = chef_tool

    print(f"### 2. customer_agent -> foh_agent: consent (CONSENT_VERIFIER={MODE})")
    # foh_agent authenticated the customer's voucher in an earlier turn.
    AGENTS[FOH_URL].ctx.state["identity_gate.verified"] = {"credential_type": "https://example.com/credentials/RestaurantVoucher/v1"}
    foh._gate._interceptor.authenticated_tasks.add(TXN)
    consent = await call_with_identity(
        FOH_URL,
        "Here is my signed consent.",
        context_id=TXN,
        wallet=customer_wallet(),
        caller=CUSTOMER_AGENT,
        callee=FOH_AGENT,
        tunnel_policy=TunnelPolicy(frozenset({CHEF_AGENT}), frozenset({SUBSTITUTION_APPROVAL_CREDENTIAL_ID})),
    )
    results.append(consent.text)
    return results


_NORMALIZE = [
    (re.compile(r"\x1b\[[0-9;]*m"), ""),
    (re.compile(r"^\d\d:\d\d:\d\d\.\d{3} ", re.M), ""),
    (re.compile(r"(nonce=|task_id=)[\w\-.]+"), r"\1<id>"),
]


def main() -> None:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        results = asyncio.run(scenario())
    output = buffer.getvalue()
    for pattern, repl in _NORMALIZE:
        output = pattern.sub(repl, output)
    print(output, end="")
    print("### results")
    for text in results:
        print(text)


if __name__ == "__main__":
    main()
