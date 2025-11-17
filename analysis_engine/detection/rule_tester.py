"""
Detection Rule Testing Framework

Tests security detection rules (Sigma, KQL, SPL) against synthetic telemetry
to validate effectiveness, identify false positives/negatives, and measure coverage.
"""
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import re
import logging
import yaml
from pathlib import Path

logger = logging.getLogger(__name__)


class RuleFormat(str, Enum):
    """Supported detection rule formats."""
    SIGMA = "sigma"
    KQL = "kql"  # Kusto Query Language (Azure Sentinel, Defender)
    SPL = "spl"  # Splunk Processing Language
    EQL = "eql"  # Event Query Language (Elastic)
    YARA_L = "yara-l"  # Chronicle YARA-L


class DetectionResult(str, Enum):
    """Detection test result."""
    TRUE_POSITIVE = "true_positive"  # Correctly detected attack
    FALSE_NEGATIVE = "false_negative"  # Missed attack
    FALSE_POSITIVE = "false_positive"  # Incorrectly flagged benign
    TRUE_NEGATIVE = "true_negative"  # Correctly ignored benign


@dataclass
class RuleTestResult:
    """Result of testing a detection rule."""
    rule_name: str
    rule_format: RuleFormat
    events_tested: int
    events_matched: int
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float  # TP / (TP + FP)
    recall: float  # TP / (TP + FN)
    f1_score: float  # 2 * (precision * recall) / (precision + recall)
    accuracy: float  # (TP + TN) / (TP + TN + FP + FN)
    matched_events: List[Dict[str, Any]]
    missed_events: List[Dict[str, Any]]
    false_alarms: List[Dict[str, Any]]
    test_duration_seconds: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "rule_name": self.rule_name,
            "rule_format": self.rule_format.value,
            "events_tested": self.events_tested,
            "events_matched": self.events_matched,
            "metrics": {
                "true_positives": self.true_positives,
                "false_positives": self.false_positives,
                "false_negatives": self.false_negatives,
                "true_negatives": self.true_negatives,
                "precision": round(self.precision, 4),
                "recall": round(self.recall, 4),
                "f1_score": round(self.f1_score, 4),
                "accuracy": round(self.accuracy, 4)
            },
            "matched_events": [e.get("event_id") or e.get("timestamp") for e in self.matched_events],
            "missed_events": [e.get("event_id") or e.get("timestamp") for e in self.missed_events],
            "false_alarms": [e.get("event_id") or e.get("timestamp") for e in self.false_alarms],
            "test_duration_seconds": round(self.test_duration_seconds, 3)
        }


class SigmaRuleParser:
    """
    Parser for Sigma detection rules.

    Sigma is a generic signature format for SIEM systems.
    https://github.com/SigmaHQ/sigma
    """

    @staticmethod
    def parse_sigma_rule(rule_content: str) -> Dict[str, Any]:
        """
        Parse a Sigma rule from YAML content.

        Args:
            rule_content: Sigma rule in YAML format

        Returns:
            Parsed rule dictionary
        """
        try:
            rule = yaml.safe_load(rule_content)
            return {
                "id": rule.get("id"),
                "title": rule.get("title"),
                "description": rule.get("description"),
                "status": rule.get("status"),
                "author": rule.get("author"),
                "date": rule.get("date"),
                "logsource": rule.get("logsource", {}),
                "detection": rule.get("detection", {}),
                "falsepositives": rule.get("falsepositives", []),
                "level": rule.get("level"),
                "tags": rule.get("tags", [])
            }
        except Exception as e:
            logger.error(f"Failed to parse Sigma rule: {e}")
            raise ValueError(f"Invalid Sigma rule: {e}")

    @staticmethod
    def match_event(event: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """
        Check if an event matches a Sigma rule.

        Args:
            event: Telemetry event
            rule: Parsed Sigma rule

        Returns:
            True if event matches rule
        """
        detection = rule.get("detection", {})
        if not detection:
            return False

        # Get condition
        condition = detection.get("condition")
        if not condition:
            return False

        # Evaluate each selection
        selections = {}
        for key, value in detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                selections[key] = SigmaRuleParser._match_selection(event, value)

        # Evaluate condition
        return SigmaRuleParser._evaluate_condition(condition, selections)

    @staticmethod
    def _match_selection(event: Dict[str, Any], selection: Dict[str, Any]) -> bool:
        """Check if event matches a selection."""
        for field, expected in selection.items():
            # Get value from event (support nested fields with dot notation)
            value = SigmaRuleParser._get_nested_value(event, field)

            if value is None:
                return False

            # Handle different match types
            if isinstance(expected, str):
                if not SigmaRuleParser._match_string(str(value), expected):
                    return False
            elif isinstance(expected, list):
                # Match any value in list
                if not any(SigmaRuleParser._match_string(str(value), exp) for exp in expected):
                    return False
            else:
                if value != expected:
                    return False

        return True

    @staticmethod
    def _match_string(value: str, pattern: str) -> bool:
        """Match string with wildcards and modifiers."""
        # Convert Sigma wildcards to regex
        # * = any characters
        # ? = single character
        # | = starts with
        # | (end) = ends with

        if pattern.startswith("|") and pattern.endswith("|"):
            # Exact match
            return value == pattern[1:-1]
        elif pattern.startswith("|"):
            # Starts with
            return value.startswith(pattern[1:])
        elif pattern.endswith("|"):
            # Ends with
            return value.endswith(pattern[:-1])
        elif "*" in pattern or "?" in pattern:
            # Wildcard match
            regex_pattern = pattern.replace("*", ".*").replace("?", ".")
            return bool(re.match(f"^{regex_pattern}$", value, re.IGNORECASE))
        else:
            # Case-insensitive exact match
            return value.lower() == pattern.lower()

    @staticmethod
    def _get_nested_value(event: Dict[str, Any], field: str) -> Any:
        """Get nested field value using dot notation."""
        parts = field.split(".")
        value = event
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        return value

    @staticmethod
    def _evaluate_condition(condition: str, selections: Dict[str, bool]) -> bool:
        """
        Evaluate Sigma condition.

        Supports: and, or, not, 1 of, all of, (parentheses)
        """
        # Simple evaluation for basic conditions
        # For production, would need full boolean expression parser

        # Replace selection names with their boolean values
        expr = condition
        for name, value in selections.items():
            expr = expr.replace(name, str(value))

        # Handle "1 of" pattern
        if "1 of" in expr:
            return any(selections.values())

        # Handle "all of" pattern
        if "all of" in expr:
            return all(selections.values())

        # Simple and/or/not evaluation
        expr = expr.replace("and", " and ").replace("or", " or ").replace("not", " not ")

        try:
            return eval(expr)
        except Exception:
            logger.warning(f"Could not evaluate condition: {condition}")
            return False


class DetectionRuleTester:
    """
    Test detection rules against synthetic telemetry.

    Validates rule effectiveness and identifies gaps.
    """

    def __init__(self):
        self.sigma_parser = SigmaRuleParser()

    def test_sigma_rule(
        self,
        rule_content: str,
        events: List[Dict[str, Any]],
        ground_truth: Optional[Set[str]] = None
    ) -> RuleTestResult:
        """
        Test a Sigma rule against events.

        Args:
            rule_content: Sigma rule in YAML format
            events: List of events to test
            ground_truth: Set of event IDs that should match (for validation)

        Returns:
            Test result with metrics
        """
        import time
        start_time = time.time()

        # Parse rule
        rule = self.sigma_parser.parse_sigma_rule(rule_content)
        rule_name = rule.get("title", "Unnamed Rule")

        # Test each event
        matched_events = []
        missed_events = []
        false_alarms = []

        for event in events:
            event_id = event.get("event_id") or event.get("timestamp")
            is_malicious = event.get("metadata", {}).get("suspicious") or \
                          event.get("metadata", {}).get("attack_stage")

            matches = self.sigma_parser.match_event(event, rule)

            if matches:
                matched_events.append(event)
                if not is_malicious:
                    false_alarms.append(event)
            else:
                if is_malicious:
                    missed_events.append(event)

        # Calculate metrics
        true_positives = len([e for e in matched_events if e.get("metadata", {}).get("suspicious")])
        false_positives = len(false_alarms)
        false_negatives = len(missed_events)
        true_negatives = len(events) - true_positives - false_positives - false_negatives

        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (true_positives + true_negatives) / len(events) if len(events) > 0 else 0

        duration = time.time() - start_time

        return RuleTestResult(
            rule_name=rule_name,
            rule_format=RuleFormat.SIGMA,
            events_tested=len(events),
            events_matched=len(matched_events),
            true_positives=true_positives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            true_negatives=true_negatives,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            accuracy=accuracy,
            matched_events=matched_events[:10],  # Limit for performance
            missed_events=missed_events[:10],
            false_alarms=false_alarms[:10],
            test_duration_seconds=duration
        )

    def test_multiple_rules(
        self,
        rules: List[str],
        events: List[Dict[str, Any]]
    ) -> List[RuleTestResult]:
        """
        Test multiple rules against the same event set.

        Args:
            rules: List of Sigma rules in YAML format
            events: List of events to test

        Returns:
            List of test results
        """
        results = []
        for rule_content in rules:
            try:
                result = self.test_sigma_rule(rule_content, events)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to test rule: {e}")

        return results

    def generate_coverage_report(
        self,
        results: List[RuleTestResult],
        scenario_name: str
    ) -> Dict[str, Any]:
        """
        Generate coverage report for multiple rules.

        Args:
            results: List of rule test results
            scenario_name: Name of scenario tested

        Returns:
            Coverage report
        """
        total_rules = len(results)
        effective_rules = len([r for r in results if r.f1_score > 0.7])
        avg_precision = sum(r.precision for r in results) / total_rules if total_rules > 0 else 0
        avg_recall = sum(r.recall for r in results) / total_rules if total_rules > 0 else 0
        avg_f1 = sum(r.f1_score for r in results) / total_rules if total_rules > 0 else 0

        return {
            "scenario": scenario_name,
            "total_rules_tested": total_rules,
            "effective_rules": effective_rules,
            "effectiveness_rate": effective_rules / total_rules if total_rules > 0 else 0,
            "average_metrics": {
                "precision": round(avg_precision, 4),
                "recall": round(avg_recall, 4),
                "f1_score": round(avg_f1, 4)
            },
            "rule_results": [r.to_dict() for r in results],
            "recommendations": self._generate_recommendations(results)
        }

    def _generate_recommendations(self, results: List[RuleTestResult]) -> List[str]:
        """Generate recommendations based on test results."""
        recommendations = []

        low_precision = [r for r in results if r.precision < 0.5]
        if low_precision:
            recommendations.append(
                f"{len(low_precision)} rules have low precision (<0.5) - high false positive rate. "
                "Consider adding more specific conditions."
            )

        low_recall = [r for r in results if r.recall < 0.5]
        if low_recall:
            recommendations.append(
                f"{len(low_recall)} rules have low recall (<0.5) - missing attacks. "
                "Consider broadening detection logic."
            )

        no_matches = [r for r in results if r.events_matched == 0]
        if no_matches:
            recommendations.append(
                f"{len(no_matches)} rules matched no events. "
                "Verify rule logic and field names match your log schema."
            )

        return recommendations

    def generate_sigma_rule_from_events(
        self,
        scenario_name: str,
        events: List[Dict[str, Any]]
    ) -> str:
        """
        Auto-generate a Sigma detection rule from telemetry events.

        Analyzes event patterns and creates a Sigma rule that would detect them.

        Args:
            scenario_name: Name of the scenario (used for rule title)
            events: List of telemetry events to analyze

        Returns:
            Sigma rule content as YAML string
        """
        import yaml
        import uuid
        from collections import Counter
        from datetime import datetime

        # Analyze events to extract common patterns
        event_types = Counter()
        actions = Counter()
        resources = set()
        statuses = Counter()
        mitre_techniques = set()

        for event in events:
            if "event_type" in event:
                event_types[event["event_type"]] += 1

            if "action" in event:
                actions[event["action"]] += 1

            if "resource" in event:
                resources.add(event["resource"])

            if "status" in event:
                statuses[event["status"]] += 1

            # Extract MITRE techniques from metadata
            metadata = event.get("metadata", {})
            if "mitre_techniques" in metadata:
                techniques = metadata["mitre_techniques"]
                if isinstance(techniques, list):
                    mitre_techniques.update(techniques)
                else:
                    mitre_techniques.add(techniques)

        # Determine most common patterns (top 5)
        top_event_types = [et for et, _ in event_types.most_common(5)]
        top_actions = [act for act, _ in actions.most_common(3)]
        top_status = statuses.most_common(1)[0][0] if statuses else "success"

        # Build Sigma rule
        rule = {
            "title": f"Auto-Generated: {scenario_name.replace('_', ' ').title()}",
            "id": str(uuid.uuid4()),
            "status": "experimental",
            "description": f"Auto-generated detection rule for {scenario_name} scenario based on {len(events)} telemetry events",
            "author": "AI Threat Hunting Simulator - Auto-Generator",
            "date": datetime.now().strftime("%Y/%m/%d"),
            "modified": datetime.now().strftime("%Y/%m/%d"),
            "tags": [],
            "logsource": {
                "product": "aws" if any("aws" in et.lower() for et in top_event_types) else "generic",
                "service": "cloudtrail" if any("iam" in et.lower() or "s3" in et.lower() for et in top_event_types) else "security"
            },
            "detection": {
                "selection": {},
                "condition": "selection"
            },
            "falsepositives": [
                "Legitimate administrative activities",
                "Automated processes",
                "CI/CD pipelines"
            ],
            "level": "high"
        }

        # Add MITRE tags
        for technique in sorted(mitre_techniques):
            technique_lower = technique.lower()
            rule["tags"].append(f"attack.{technique_lower.split('.')[0]}")
            rule["tags"].append(f"attack.{technique_lower}")

        # Build detection selection
        if top_event_types:
            if len(top_event_types) == 1:
                rule["detection"]["selection"]["event_type"] = top_event_types[0]
            else:
                rule["detection"]["selection"]["event_type|contains"] = top_event_types

        if top_actions:
            if len(top_actions) == 1:
                rule["detection"]["selection"]["action"] = top_actions[0]
            else:
                rule["detection"]["selection"]["action|contains"] = top_actions

        if top_status and top_status != "unknown":
            rule["detection"]["selection"]["status"] = top_status

        # Convert to YAML
        yaml_content = yaml.dump(
            rule,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True
        )

        return yaml_content
