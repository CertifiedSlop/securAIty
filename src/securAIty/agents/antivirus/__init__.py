"""Antivirus Agent Package."""
from .agent import (
    AntivirusAgent,
    BehaviorReport,
    QuarantineResult,
    QuarantineStatus,
    ScanResult,
    ScanStatus,
    ThreatSeverity,
)

__all__ = [
    "AntivirusAgent",
    "ScanResult",
    "ScanStatus",
    "QuarantineResult",
    "QuarantineStatus",
    "BehaviorReport",
    "ThreatSeverity",
]
