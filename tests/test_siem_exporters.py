"""
Tests for SIEM integration exporters.
"""
import json

import pytest

from analysis_engine.integrations.siem_exporter import SIEMConfig, SIEMExporter, SIEMType


def _exporter(siem_type, **kwargs):
    return SIEMExporter(SIEMConfig(siem_type=siem_type, host="siem.local", port=8088, **kwargs))


@pytest.fixture
def event():
    return {
        "timestamp": "2025-01-01T00:00:00Z",
        "event_type": "iam.attachuserpolicy",
        "action": "AttachUserPolicy",
        "principal": "arn:aws:iam::123456789012:user/attacker",
        "resource": "arn:aws:iam::aws:policy/AdministratorAccess",
        "status": "success",
        "region": "us-east-1",
        "source_ip": "203.0.113.10",
        "severity": "high",
        "mitre_techniques": ["T1098", "T1078.004"],
        "metadata": {"attack_stage": "privilege_escalation"},
    }


class TestSIEMExporter:
    def test_accepts_plain_string_type(self, event):
        result = _exporter("splunk").export_events([event])

        assert result["siem_type"] == "splunk"

    def test_rejects_unknown_type(self):
        with pytest.raises(ValueError):
            _exporter("not-a-siem")

    def test_export_result_summary(self, sample_mixed_events):
        result = _exporter(SIEMType.ELASTIC, index="sec", batch_size=4).export_events(sample_mixed_events)

        assert result["success"] is True
        assert result["events_sent"] == len(sample_mixed_events)
        assert result["destination"] == "siem.local:8088"
        assert result["index"] == "sec"
        assert result["details"]["batches_sent"] == -(-len(sample_mixed_events) // 4)

    def test_export_empty_events(self):
        result = _exporter(SIEMType.SPLUNK).export_events([])

        assert result["events_sent"] == 0
        assert result["details"]["batches_sent"] == 0

    def test_splunk_hec_format(self, event):
        formatted = _exporter(SIEMType.SPLUNK, index="security")._format_splunk(event)

        assert formatted["time"] == event["timestamp"]
        assert formatted["index"] == "security"
        assert formatted["event"]["principal"] == event["principal"]
        assert formatted["event"]["raw_event"] == event

    def test_elastic_ecs_format(self, event):
        formatted = _exporter(SIEMType.ELASTIC)._format_elastic(event)

        assert formatted["@timestamp"] == event["timestamp"]
        assert formatted["event"]["severity"] == 7
        assert formatted["source"]["ip"] == event["source_ip"]
        assert formatted["threat"]["technique"]["id"] == event["mitre_techniques"]

    def test_chronicle_udm_format(self, event):
        formatted = _exporter(SIEMType.CHRONICLE)._format_chronicle(event)

        assert formatted["principal"]["user"]["userid"] == event["principal"]
        assert formatted["principal"]["ip"] == [event["source_ip"]]
        assert formatted["security_result"][0]["severity"] == "HIGH"

    def test_sentinel_format(self, event):
        formatted = _exporter(SIEMType.SENTINEL, workspace_id="ws-1")._format_sentinel(event)

        assert formatted["MitreTechniques"] == "T1098,T1078.004"
        assert formatted["WorkspaceId"] == "ws-1"
        assert json.loads(formatted["RawEvent"]) == event

    def test_qradar_leef_format(self, event):
        formatted = _exporter(SIEMType.QRADAR)._format_qradar(event)

        assert formatted["sev"] == 8
        assert formatted["usrName"] == event["principal"]
        assert formatted["mitreAttack"] == "T1098,T1078.004"

    def test_buffer_flushes_at_batch_size(self, event):
        exporter = _exporter(SIEMType.SPLUNK, batch_size=3)

        for _ in range(3):
            exporter.buffer_event(event)

        assert exporter.events_buffer == []
        assert exporter.flush_buffer() is None

    def test_manual_flush_sends_remaining_events(self, event):
        exporter = _exporter(SIEMType.SPLUNK, batch_size=10)
        exporter.buffer_event(event)

        result = exporter.flush_buffer()

        assert result["events_sent"] == 1
        assert exporter.events_buffer == []
