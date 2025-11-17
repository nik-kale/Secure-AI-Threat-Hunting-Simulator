"""SIEM integration and event export."""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
import json
import logging

logger = logging.getLogger(__name__)

class SIEMType(str, Enum):
    """Supported SIEM platforms."""
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    CHRONICLE = "chronicle"
    SENTINEL = "sentinel"
    QRADAR = "qradar"

@dataclass
class SIEMConfig:
    """SIEM connection configuration."""
    siem_type: SIEMType
    host: str
    port: int
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    index: Optional[str] = None  # Splunk/Elastic index
    workspace_id: Optional[str] = None  # Sentinel workspace
    customer_id: Optional[str] = None  # Chronicle customer
    ssl_verify: bool = True
    batch_size: int = 1000

class SIEMExporter:
    """Export events and detections to SIEM platforms."""

    def __init__(self, config: SIEMConfig):
        self.config = config
        self.events_buffer: List[Dict[str, Any]] = []
        self._formatters = {
            SIEMType.SPLUNK: self._format_splunk,
            SIEMType.ELASTIC: self._format_elastic,
            SIEMType.CHRONICLE: self._format_chronicle,
            SIEMType.SENTINEL: self._format_sentinel,
            SIEMType.QRADAR: self._format_qradar
        }

    def export_events(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Export events to configured SIEM.

        Args:
            events: List of security events to export

        Returns:
            Export result with success status and metrics
        """
        formatter = self._formatters.get(self.config.siem_type)
        if not formatter:
            raise ValueError(f"Unsupported SIEM type: {self.config.siem_type}")

        formatted_events = [formatter(event) for event in events]

        # In production, this would send to actual SIEM via HTTP/HEC/API
        result = self._send_to_siem(formatted_events)

        return {
            "success": True,
            "siem_type": self.config.siem_type.value,
            "events_sent": len(formatted_events),
            "destination": f"{self.config.host}:{self.config.port}",
            "index": self.config.index,
            "details": result
        }

    def _send_to_siem(self, formatted_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Send formatted events to SIEM (production would use HTTP).

        Args:
            formatted_events: SIEM-formatted events

        Returns:
            Send result details
        """
        # Production implementation would use:
        # - Splunk HEC (HTTP Event Collector)
        # - Elasticsearch bulk API
        # - Chronicle ingestion API
        # - Azure Sentinel data collector API
        # - QRadar log source API

        logger.info(f"Would send {len(formatted_events)} events to {self.config.siem_type}")

        return {
            "batches_sent": (len(formatted_events) + self.config.batch_size - 1) // self.config.batch_size,
            "total_bytes": sum(len(json.dumps(e)) for e in formatted_events),
            "timestamp": "2024-01-15T10:00:00Z"
        }

    def _format_splunk(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Format event for Splunk HEC.

        Args:
            event: Raw security event

        Returns:
            Splunk HEC format event
        """
        return {
            "time": event.get("timestamp"),
            "host": event.get("source_ip", "unknown"),
            "source": "threat-hunting-simulator",
            "sourcetype": "security:event",
            "index": self.config.index or "security",
            "event": {
                "event_type": event.get("event_type"),
                "action": event.get("action"),
                "principal": event.get("principal"),
                "resource": event.get("resource"),
                "status": event.get("status"),
                "region": event.get("region"),
                "severity": event.get("severity", "medium"),
                "mitre_techniques": event.get("mitre_techniques", []),
                "metadata": event.get("metadata", {}),
                "raw_event": event
            }
        }

    def _format_elastic(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Format event for Elasticsearch/Elastic Security.

        Args:
            event: Raw security event

        Returns:
            ECS (Elastic Common Schema) format event
        """
        return {
            "@timestamp": event.get("timestamp"),
            "event": {
                "kind": "event",
                "category": ["authentication", "iam"],
                "type": ["access"],
                "action": event.get("action"),
                "outcome": event.get("status"),
                "severity": self._map_severity_ecs(event.get("severity", "medium"))
            },
            "user": {
                "name": event.get("principal"),
                "id": event.get("principal")
            },
            "cloud": {
                "provider": event.get("cloud_provider", "aws"),
                "region": event.get("region")
            },
            "threat": {
                "technique": {
                    "id": event.get("mitre_techniques", []),
                    "name": event.get("mitre_technique_names", [])
                }
            },
            "resource": {
                "name": event.get("resource"),
                "type": event.get("resource_type")
            },
            "source": {
                "ip": event.get("source_ip")
            },
            "raw": event
        }

    def _format_chronicle(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Format event for Google Chronicle.

        Args:
            event: Raw security event

        Returns:
            Chronicle UDM (Unified Data Model) format
        """
        return {
            "metadata": {
                "event_timestamp": event.get("timestamp"),
                "event_type": "USER_RESOURCE_ACCESS",
                "product_name": "Threat Hunting Simulator",
                "vendor_name": "Security Research"
            },
            "principal": {
                "user": {
                    "userid": event.get("principal")
                },
                "ip": [event.get("source_ip")] if event.get("source_ip") else []
            },
            "target": {
                "resource": {
                    "name": event.get("resource"),
                    "type": event.get("resource_type")
                },
                "location": {
                    "region": event.get("region")
                }
            },
            "security_result": [{
                "action": event.get("status", "UNKNOWN"),
                "severity": event.get("severity", "MEDIUM").upper()
            }],
            "extensions": {
                "auth": {
                    "type": event.get("event_type"),
                    "mechanism": event.get("auth_mechanism", "API")
                }
            },
            "additional": {
                "mitre_techniques": event.get("mitre_techniques", []),
                "metadata": event.get("metadata", {})
            }
        }

    def _format_sentinel(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Format event for Azure Sentinel.

        Args:
            event: Raw security event

        Returns:
            Azure Sentinel custom log format
        """
        return {
            "TimeGenerated": event.get("timestamp"),
            "EventType": event.get("event_type"),
            "Action": event.get("action"),
            "Principal": event.get("principal"),
            "Resource": event.get("resource"),
            "Status": event.get("status"),
            "Region": event.get("region"),
            "SourceIP": event.get("source_ip"),
            "Severity": event.get("severity", "Medium"),
            "MitreTechniques": ",".join(event.get("mitre_techniques", [])),
            "CloudProvider": event.get("cloud_provider", "AWS"),
            "ResourceType": event.get("resource_type"),
            "Metadata": json.dumps(event.get("metadata", {})),
            "WorkspaceId": self.config.workspace_id,
            "RawEvent": json.dumps(event)
        }

    def _format_qradar(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Format event for IBM QRadar.

        Args:
            event: Raw security event

        Returns:
            QRadar LEEF (Log Event Extended Format)
        """
        # QRadar uses LEEF format: LEEF:Version|Vendor|Product|Version|EventID|
        severity_map = {"low": 2, "medium": 5, "high": 8, "critical": 10}

        return {
            "leef_version": "2.0",
            "vendor": "SecurityResearch",
            "product": "ThreatHuntingSimulator",
            "version": "3.0",
            "event_id": event.get("event_type", "UNKNOWN"),
            "sev": severity_map.get(event.get("severity", "medium"), 5),
            "cat": "IAM/Authentication",
            "devTime": event.get("timestamp"),
            "src": event.get("source_ip"),
            "usrName": event.get("principal"),
            "identSrc": event.get("principal"),
            "resource": event.get("resource"),
            "action": event.get("action"),
            "outcome": event.get("status"),
            "proto": "HTTPS",
            "mitreAttack": ",".join(event.get("mitre_techniques", [])),
            "cloudProvider": event.get("cloud_provider", "AWS"),
            "region": event.get("region"),
            "custom_fields": json.dumps(event.get("metadata", {}))
        }

    def _map_severity_ecs(self, severity: str) -> int:
        """Map severity string to ECS numeric severity."""
        severity_map = {
            "low": 1,
            "medium": 5,
            "high": 7,
            "critical": 9
        }
        return severity_map.get(severity.lower(), 5)

    def buffer_event(self, event: Dict[str, Any]):
        """Add event to buffer for batch export.

        Args:
            event: Event to buffer
        """
        self.events_buffer.append(event)

        if len(self.events_buffer) >= self.config.batch_size:
            self.flush_buffer()

    def flush_buffer(self) -> Optional[Dict[str, Any]]:
        """Flush buffered events to SIEM.

        Returns:
            Export result if buffer was flushed, None if empty
        """
        if not self.events_buffer:
            return None

        result = self.export_events(self.events_buffer)
        self.events_buffer.clear()
        return result
