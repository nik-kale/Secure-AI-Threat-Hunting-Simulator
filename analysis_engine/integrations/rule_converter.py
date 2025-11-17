"""Detection rule conversion for different SIEM platforms."""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
import re

class QueryLanguage(str, Enum):
    """Supported SIEM query languages."""
    SPL = "spl"  # Splunk
    KQL = "kql"  # Elastic/Sentinel
    YARAL = "yaral"  # Chronicle YARA-L
    AQL = "aql"  # QRadar
    SIGMA = "sigma"  # Universal Sigma format

@dataclass
class DetectionRule:
    """Universal detection rule format."""
    name: str
    description: str
    severity: str
    mitre_techniques: List[str]
    conditions: Dict[str, Any]
    fields: List[str]
    time_window: Optional[str] = None
    threshold: Optional[int] = None

class RuleConverter:
    """Convert detection rules between SIEM query languages."""

    def __init__(self):
        self.converters = {
            QueryLanguage.SPL: self._to_splunk_spl,
            QueryLanguage.KQL: self._to_kql,
            QueryLanguage.YARAL: self._to_yaral,
            QueryLanguage.AQL: self._to_qradar_aql
        }

    def convert_rule(self, rule: DetectionRule, target_language: QueryLanguage) -> str:
        """Convert detection rule to target query language.

        Args:
            rule: Universal detection rule
            target_language: Target SIEM query language

        Returns:
            Query string in target language
        """
        converter = self.converters.get(target_language)
        if not converter:
            raise ValueError(f"Unsupported query language: {target_language}")

        return converter(rule)

    def _to_splunk_spl(self, rule: DetectionRule) -> str:
        """Convert rule to Splunk SPL.

        Args:
            rule: Detection rule

        Returns:
            Splunk SPL query string
        """
        conditions = []

        # Build search conditions
        for field, value in rule.conditions.items():
            if isinstance(value, list):
                # Multiple values - OR condition
                or_conditions = [f'{field}="{v}"' for v in value]
                conditions.append(f"({' OR '.join(or_conditions)})")
            elif isinstance(value, dict):
                # Complex condition (range, regex, etc.)
                if "regex" in value:
                    conditions.append(f'{field}=~"{value["regex"]}"')
                elif "gt" in value:
                    conditions.append(f'{field}>{value["gt"]}')
                elif "lt" in value:
                    conditions.append(f'{field}<{value["lt"]}')
            else:
                # Simple equality
                conditions.append(f'{field}="{value}"')

        base_search = " AND ".join(conditions) if conditions else "*"

        # Add aggregation/stats if threshold specified
        if rule.threshold and rule.time_window:
            stats_fields = ", ".join(rule.fields[:5]) if rule.fields else "principal"
            query = f"""index=security {base_search}
| stats count by {stats_fields}
| where count > {rule.threshold}
| eval severity="{rule.severity}"
| eval mitre_techniques="{','.join(rule.mitre_techniques)}"
| eval detection_name="{rule.name}\""""
        else:
            fields_list = ", ".join(rule.fields[:10]) if rule.fields else "principal, resource, action"
            query = f"""index=security {base_search}
| table _time, {fields_list}
| eval severity="{rule.severity}"
| eval mitre_techniques="{','.join(rule.mitre_techniques)}"
| eval detection_name="{rule.name}\""""

        return query

    def _to_kql(self, rule: DetectionRule) -> str:
        """Convert rule to KQL (Kusto Query Language for Elastic/Sentinel).

        Args:
            rule: Detection rule

        Returns:
            KQL query string
        """
        conditions = []

        for field, value in rule.conditions.items():
            if isinstance(value, list):
                # Multiple values
                or_conditions = [f'{field} == "{v}"' for v in value]
                conditions.append(f"({' or '.join(or_conditions)})")
            elif isinstance(value, dict):
                if "regex" in value:
                    conditions.append(f'{field} matches regex "{value["regex"]}"')
                elif "gt" in value:
                    conditions.append(f'{field} > {value["gt"]}')
                elif "lt" in value:
                    conditions.append(f'{field} < {value["lt"]}')
                elif "contains" in value:
                    conditions.append(f'{field} contains "{value["contains"]}"')
            else:
                conditions.append(f'{field} == "{value}"')

        where_clause = " and ".join(conditions) if conditions else "true"

        if rule.threshold and rule.time_window:
            summarize_by = ", ".join(rule.fields[:5]) if rule.fields else "principal"
            query = f"""SecurityEvent
| where {where_clause}
| summarize EventCount = count() by {summarize_by}
| where EventCount > {rule.threshold}
| extend Severity = "{rule.severity}"
| extend MitreTechniques = "{','.join(rule.mitre_techniques)}"
| extend DetectionName = "{rule.name}\""""
        else:
            project_fields = ", ".join(rule.fields[:10]) if rule.fields else "TimeGenerated, principal, resource, action"
            query = f"""SecurityEvent
| where {where_clause}
| project {project_fields}
| extend Severity = "{rule.severity}"
| extend MitreTechniques = "{','.join(rule.mitre_techniques)}"
| extend DetectionName = "{rule.name}\""""

        return query

    def _to_yaral(self, rule: DetectionRule) -> str:
        """Convert rule to Chronicle YARA-L.

        Args:
            rule: Detection rule

        Returns:
            YARA-L rule string
        """
        rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', rule.name.lower())

        # Build events section
        conditions_list = []
        for field, value in rule.conditions.items():
            if isinstance(value, list):
                values_str = ", ".join(f'"{v}"' for v in value)
                conditions_list.append(f'        $e.{field} in [{values_str}]')
            elif isinstance(value, dict):
                if "regex" in value:
                    conditions_list.append(f'        re.regex($e.{field}, `{value["regex"]}`)')
                elif "contains" in value:
                    conditions_list.append(f'        strings.contains($e.{field}, "{value["contains"]}")')
            else:
                conditions_list.append(f'        $e.{field} = "{value}"')

        conditions_str = " and\n".join(conditions_list) if conditions_list else "        true"

        # Build match section
        if rule.threshold and rule.time_window:
            match_section = f"""    $principal = $e.principal.user.userid
    $count = count_distinct($e.metadata.id)
    $count > {rule.threshold}"""
        else:
            match_section = """    $principal = $e.principal.user.userid"""

        query = f"""rule {rule_name} {{
  meta:
    description = "{rule.description}"
    severity = "{rule.severity.upper()}"
    mitre_attack_tactic = "{rule.mitre_techniques[0] if rule.mitre_techniques else 'TA0001'}"

  events:
    $e.metadata.event_type = "USER_RESOURCE_ACCESS"
{conditions_str}

  match:
{match_section}

  outcome:
    $severity = "{rule.severity}"
    $detection_name = "{rule.name}"
    $mitre_techniques = "{','.join(rule.mitre_techniques)}"

  condition:
    $e
}}"""

        return query

    def _to_qradar_aql(self, rule: DetectionRule) -> str:
        """Convert rule to QRadar AQL.

        Args:
            rule: Detection rule

        Returns:
            QRadar AQL query string
        """
        conditions = []

        for field, value in rule.conditions.items():
            aql_field = self._map_field_to_qradar(field)

            if isinstance(value, list):
                values_str = ", ".join(f"'{v}'" for v in value)
                conditions.append(f"{aql_field} IN ({values_str})")
            elif isinstance(value, dict):
                if "regex" in value:
                    conditions.append(f"{aql_field} MATCHES '{value['regex']}'")
                elif "gt" in value:
                    conditions.append(f"{aql_field} > {value['gt']}")
                elif "lt" in value:
                    conditions.append(f"{aql_field} < {value['lt']}")
                elif "contains" in value:
                    conditions.append(f"{aql_field} ILIKE '%{value['contains']}%'")
            else:
                conditions.append(f"{aql_field} = '{value}'")

        where_clause = " AND ".join(conditions) if conditions else "TRUE"

        if rule.threshold and rule.time_window:
            group_by_fields = ", ".join(self._map_field_to_qradar(f) for f in rule.fields[:5]) if rule.fields else "username"
            query = f"""SELECT {group_by_fields}, COUNT(*) as event_count
FROM events
WHERE {where_clause}
GROUP BY {group_by_fields}
HAVING COUNT(*) > {rule.threshold}
LAST 1 HOURS"""
        else:
            select_fields = ", ".join(self._map_field_to_qradar(f) for f in rule.fields[:10]) if rule.fields else "DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm:ss'), username, sourceip"
            query = f"""SELECT {select_fields}
FROM events
WHERE {where_clause}
LAST 24 HOURS"""

        return query

    def _map_field_to_qradar(self, field: str) -> str:
        """Map universal field names to QRadar field names.

        Args:
            field: Universal field name

        Returns:
            QRadar field name
        """
        field_mapping = {
            "principal": "username",
            "source_ip": "sourceip",
            "resource": "resourcename",
            "action": "eventname",
            "status": "outcome",
            "timestamp": "starttime",
            "event_type": "category"
        }
        return field_mapping.get(field, field)

    def create_common_rules(self) -> List[DetectionRule]:
        """Create common detection rules for various attack techniques.

        Returns:
            List of common detection rules
        """
        return [
            DetectionRule(
                name="Privilege Escalation via Role Assumption",
                description="Detects attempts to assume privileged roles",
                severity="high",
                mitre_techniques=["T1078", "T1548"],
                conditions={
                    "event_type": ["iam.assume_role", "iam.get_role"],
                    "action": ["AssumeRole", "PassRole"],
                    "status": "success"
                },
                fields=["principal", "resource", "action", "timestamp"],
                threshold=5,
                time_window="5m"
            ),
            DetectionRule(
                name="Data Exfiltration from Cloud Storage",
                description="Detects bulk data downloads from cloud storage",
                severity="critical",
                mitre_techniques=["T1530", "T1537"],
                conditions={
                    "event_type": ["s3.get_object", "storage.objects.get"],
                    "status": "success"
                },
                fields=["principal", "resource", "source_ip", "timestamp"],
                threshold=100,
                time_window="10m"
            ),
            DetectionRule(
                name="Lateral Movement Cross-Account",
                description="Detects cross-account access attempts",
                severity="high",
                mitre_techniques=["T1078", "T1550"],
                conditions={
                    "event_type": "iam.assume_role",
                    "cross_account": "true",
                    "status": "success"
                },
                fields=["principal", "target_account", "resource", "timestamp"],
                threshold=3,
                time_window="15m"
            ),
            DetectionRule(
                name="Credential Access via Secret Enumeration",
                description="Detects enumeration of secrets and credentials",
                severity="high",
                mitre_techniques=["T1552", "T1555"],
                conditions={
                    "event_type": ["secretsmanager.get_secret", "ssm.get_parameter"],
                    "action": {"regex": ".*(Get|List|Describe).*"}
                },
                fields=["principal", "resource", "action", "timestamp"],
                threshold=10,
                time_window="5m"
            ),
            DetectionRule(
                name="Defense Evasion via CloudTrail Modification",
                description="Detects attempts to disable or modify logging",
                severity="critical",
                mitre_techniques=["T1562.008"],
                conditions={
                    "event_type": "cloudtrail.update_trail",
                    "action": ["StopLogging", "DeleteTrail", "UpdateTrail"]
                },
                fields=["principal", "resource", "action", "timestamp"]
            ),
            DetectionRule(
                name="Persistence via IAM User Creation",
                description="Detects creation of new IAM users for persistence",
                severity="medium",
                mitre_techniques=["T1136.003"],
                conditions={
                    "event_type": "iam.create_user",
                    "status": "success"
                },
                fields=["principal", "new_user", "timestamp"]
            ),
            DetectionRule(
                name="Execution via Lambda Function Invocation",
                description="Detects unusual Lambda function execution patterns",
                severity="medium",
                mitre_techniques=["T1059", "T1609"],
                conditions={
                    "event_type": "lambda.invoke",
                    "status": "success"
                },
                fields=["principal", "function_name", "source_ip", "timestamp"],
                threshold=20,
                time_window="5m"
            )
        ]
