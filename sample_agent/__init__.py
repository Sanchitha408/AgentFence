"""Deliberately vulnerable sample agent used as the target of AgentFence attacks.

Nothing in this package touches the real disk, the real network, or a real LLM.
Every tool is simulated and every secret is a fake canary token.
"""

from sample_agent.agent import DEFAULT_SYSTEM_PROMPT, AgentRun, VulnerableAgent
from sample_agent.mock_llm import FinalAnswer, MockLLM, ToolCall
from sample_agent.sandbox import canary_values, load_canaries
from sample_agent.tools import FakeTools, ToolResult

__all__ = [
    "DEFAULT_SYSTEM_PROMPT",
    "AgentRun",
    "FakeTools",
    "FinalAnswer",
    "MockLLM",
    "ToolCall",
    "ToolResult",
    "VulnerableAgent",
    "canary_values",
    "load_canaries",
]
