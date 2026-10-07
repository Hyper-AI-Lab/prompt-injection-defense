"""Runtime adapters: brokered tool registry, OpenAI-style wrap, Claude hooks."""

from containment.adapters.claude_hook import (
    default_claude_plan,
    handle_pretool_use,
    map_claude_tool,
)
from containment.adapters.openai_tools import brokered_tool
from containment.adapters.registry import BrokeredRegistry

__all__ = [
    "BrokeredRegistry",
    "brokered_tool",
    "default_claude_plan",
    "handle_pretool_use",
    "map_claude_tool",
]
