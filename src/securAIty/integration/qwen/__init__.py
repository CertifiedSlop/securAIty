"""
Qwen Integration Package

Integration bridge for Qwen subagent delegation and LLM-powered
security analysis capabilities.
"""

from .bridge import QwenBridge, QwenBridgeConfig, QwenSubAgent

__all__ = [
    "QwenBridge",
    "QwenBridgeConfig",
    "QwenSubAgent",
]
