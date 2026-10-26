# SPDX-License-Identifier: Apache-2.0
"""Tracing callbacks for intermediate agent model and tool interactions."""

from typing import Any, Dict, Optional

from google.adk.agents.callback_context import CallbackContext
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.tool_context import ToolContext

from common.exchange_log import log, truncate


def _request_text(llm_request: LlmRequest) -> str:
    """Return text content of the latest turn in the request."""
    if not llm_request.contents:
        return ""
    last = llm_request.contents[-1]
    return "".join(part.text or "" for part in (last.parts or []))


def _response_summary(llm_response: LlmResponse) -> str:
    """Return concise description of model response actions."""
    if llm_response.content is None or not llm_response.content.parts:
        return "(no content)"
    calls = [
        p.function_call.name or "?" for p in llm_response.content.parts if p.function_call
    ]
    if calls:
        return f"requesting tool call(s): {', '.join(calls)}"
    text = "".join(part.text or "" for part in llm_response.content.parts)
    return f'replying: "{truncate(text, 80)}"' if text else "(empty)"


def on_before_model(
    callback_context: CallbackContext, llm_request: LlmRequest
) -> Optional[LlmResponse]:
    """Log outgoing request text before model invocation."""
    agent_tag = callback_context.agent_name or "agent"
    text = _request_text(llm_request)
    details = f': "{truncate(text, 80)}"' if text else ""
    log(agent_tag, f"thinking -- sending turn to model{details}")
    return None


def on_after_model(
    callback_context: CallbackContext, llm_response: LlmResponse
) -> Optional[LlmResponse]:
    """Log summary of model response."""
    agent_tag = callback_context.agent_name or "agent"
    log(agent_tag, f"model responded -- {_response_summary(llm_response)}")
    return None


def on_before_tool(
    tool: BaseTool, args: Dict[str, Any], tool_context: ToolContext
) -> Optional[Dict[str, Any]]:
    """Log tool invocation arguments."""
    agent_tag = tool_context.agent_name or "agent"
    args_str = truncate(str(args), 80)
    log(agent_tag, f"calling tool '{tool.name}' with args={args_str}")
    return None


def on_after_tool(
    tool: BaseTool,
    args: Dict[str, Any],
    tool_context: ToolContext,
    tool_response: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Log response returned by tool execution."""
    _ = args
    agent_tag = tool_context.agent_name or "agent"
    resp_str = truncate(str(tool_response), 80)
    log(agent_tag, f"tool '{tool.name}' returned {resp_str}")
    return None

