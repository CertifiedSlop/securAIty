"""Integration Package

External system integrations for securAIty.
"""

from .qwen import QwenBridge, QwenBridgeConfig, QwenSubAgent

__all__ = [
    "QwenBridge",
    "QwenBridgeConfig",
    "QwenSubAgent",
]
