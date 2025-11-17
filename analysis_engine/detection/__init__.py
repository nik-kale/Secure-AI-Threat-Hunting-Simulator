"""
Detection module for rule testing and validation.

Provides:
- Sigma rule testing against synthetic telemetry
- Rule effectiveness metrics
- Coverage analysis
- Sigma rule generation from scenarios
"""
from analysis_engine.detection.rule_tester import (
    DetectionRuleTester,
    RuleTestResult,
    RuleFormat,
    DetectionResult,
    SigmaRuleParser
)

__all__ = [
    "DetectionRuleTester",
    "RuleTestResult",
    "RuleFormat",
    "DetectionResult",
    "SigmaRuleParser"
]
