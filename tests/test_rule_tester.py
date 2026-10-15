"""
Tests for Sigma rule evaluation in the detection rule tester.
"""
from pathlib import Path

import pytest

from analysis_engine.detection.rule_tester import DetectionRuleTester, SigmaRuleParser

evaluate = SigmaRuleParser._evaluate_condition

RULES_DIR = Path(__file__).resolve().parent.parent / "detection_rules" / "sigma"


class TestConditionEvaluation:
    @pytest.mark.parametrize("condition, expected", [
        ("selection", True),
        ("filter", False),
        ("selection and filter", False),
        ("selection or filter", True),
        ("selection and not filter", True),
        ("not (selection or filter)", False),
        ("(selection and filter) or other", True),
        ("1 of selection*", True),
        ("all of selection*", False),
        ("any of them", True),
        ("all of them", False),
        ("missing_name", False),
        ("all of nomatch_*", False),
    ])
    def test_boolean_logic(self, condition, expected):
        selections = {"selection": True, "selection_b": False, "filter": False, "other": True}

        assert evaluate(condition, selections) is expected

    def test_selection_name_that_prefixes_another(self):
        """Textual substitution of `selection` used to corrupt `selection_extra`."""
        selections = {"selection": False, "selection_extra": True}

        assert evaluate("selection_extra", selections) is True
        assert evaluate("selection or selection_extra", selections) is True

    # The payload avoids the substrings "and", "or" and "not", which the old
    # evaluator rewrote before handing the string to eval().
    PAYLOAD = "open('pwned', 'w') == 0"

    def test_condition_is_never_executed(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        result = evaluate(self.PAYLOAD, {"selection": True})

        assert result is False
        assert not (tmp_path / "pwned").exists()

    def test_rule_content_cannot_run_code_through_the_tester(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        rule = (
            "title: t\n"
            "detection:\n"
            "  selection:\n"
            "    action: GetUser\n"
            f"  condition: \"{self.PAYLOAD}\"\n"
        )

        DetectionRuleTester().test_sigma_rule(rule, [{"action": "GetUser"}])

        assert not (tmp_path / "pwned").exists()


class TestWildcardMatching:
    def test_wildcards_match(self):
        assert SigmaRuleParser._match_string("AttachUserPolicy", "Attach*Policy")
        assert SigmaRuleParser._match_string("GetUser", "Get?ser")

    def test_regex_metacharacters_are_literal(self):
        assert not SigmaRuleParser._match_string("aXb", "a.b*")
        assert SigmaRuleParser._match_string("a.b-suffix", "a.b*")


@pytest.mark.parametrize("rule_file", sorted(RULES_DIR.glob("*.yml")), ids=lambda p: p.stem)
def test_bundled_rule_conditions_parse(rule_file):
    rule = SigmaRuleParser.parse_sigma_rule(rule_file.read_text())
    condition = rule["detection"]["condition"]
    names = [k for k in rule["detection"] if k != "condition"]

    # Every bundled condition is satisfiable by setting all its selections true.
    assert evaluate(condition, {name: True for name in names}) is True
