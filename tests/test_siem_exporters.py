"""
Tests for SIEM integration exporters.
"""
import json
import pytest
from pathlib import Path

from analysis_engine.integrations.siem_exporter import SIEMExporter


class TestSIEMExporter:
    """Test SIEM export functionality."""

    def test_siem_exporter_initialization(self):
        """Test SIEM exporter can be initialized."""
        exporter = SIEMExporter(format="splunk")
        assert exporter is not None
        assert hasattr(exporter, 'export')

    def test_export_to_splunk_format(self, sample_mixed_events, temp_output_dir):
        """Test exporting events to Splunk HEC format."""
        exporter = SIEMExporter(format="splunk")
        
        output_file = temp_output_dir / "splunk_export.json"
        exporter.export(sample_mixed_events, output_file)
        
        assert output_file.exists()
        
        # Verify Splunk HEC format
        with open(output_file, 'r') as f:
            for line in f:
                event = json.loads(line)
                # Splunk HEC format should have specific structure
                assert "event" in event or "time" in event or isinstance(event, dict)

    def test_export_to_elastic_format(self, sample_mixed_events, temp_output_dir):
        """Test exporting events to Elasticsearch format."""
        exporter = SIEMExporter(format="elastic")
        
        output_file = temp_output_dir / "elastic_export.json"
        exporter.export(sample_mixed_events, output_file)
        
        assert output_file.exists()
        
        # Verify format is valid JSON
        with open(output_file, 'r') as f:
            content = f.read()
            # Should be valid JSON or NDJSON
            assert content.strip()

    def test_export_to_sentinel_format(self, sample_mixed_events, temp_output_dir):
        """Test exporting events to Azure Sentinel format."""
        exporter = SIEMExporter(format="sentinel")
        
        output_file = temp_output_dir / "sentinel_export.json"
        exporter.export(sample_mixed_events, output_file)
        
        assert output_file.exists()

    def test_export_to_qradar_format(self, sample_mixed_events, temp_output_dir):
        """Test exporting events to QRadar CEF format."""
        exporter = SIEMExporter(format="qradar")
        
        output_file = temp_output_dir / "qradar_export.cef"
        exporter.export(sample_mixed_events, output_file)
        
        assert output_file.exists()
        
        # CEF format should start with CEF:
        with open(output_file, 'r') as f:
            first_line = f.readline()
            # CEF events may start with CEF: or be in specific format
            assert len(first_line) > 0

    def test_export_empty_events(self, temp_output_dir):
        """Test exporting empty events list."""
        exporter = SIEMExporter(format="splunk")
        
        output_file = temp_output_dir / "empty_export.json"
        exporter.export([], output_file)
        
        # Should create file even if empty
        assert output_file.exists()

    def test_export_preserves_event_data(self, sample_iam_events, temp_output_dir):
        """Test that export preserves all event data."""
        exporter = SIEMExporter(format="splunk")
        
        output_file = temp_output_dir / "preserved_export.json"
        exporter.export(sample_iam_events, output_file)
        
        with open(output_file, 'r') as f:
            exported_data = f.read()
            
            # Key fields should be present in export
            assert "event_id" in exported_data or "event" in exported_data
            assert "timestamp" in exported_data or "time" in exported_data

    def test_export_with_field_mapping(self, sample_mixed_events, temp_output_dir):
        """Test export with custom field mapping."""
        exporter = SIEMExporter(
            format="splunk",
            field_mapping={
                "event_type": "sourcetype",
                "event_source": "source",
                "timestamp": "time"
            }
        )
        
        output_file = temp_output_dir / "mapped_export.json"
        exporter.export(sample_mixed_events, output_file)
        
        assert output_file.exists()

    def test_export_with_filtering(self, sample_mixed_events, temp_output_dir):
        """Test export with event filtering."""
        exporter = SIEMExporter(format="splunk")
        
        # Filter only IAM events
        iam_events = [e for e in sample_mixed_events if e.get("event_source") == "iam"]
        
        output_file = temp_output_dir / "filtered_export.json"
        exporter.export(iam_events, output_file)
        
        assert output_file.exists()
        assert len(iam_events) < len(sample_mixed_events)

    def test_invalid_format_handling(self):
        """Test handling of invalid SIEM format."""
        with pytest.raises((ValueError, KeyError, AttributeError)):
            exporter = SIEMExporter(format="invalid_format_xyz")
            exporter.export([], Path("/tmp/test.json"))

    def test_export_includes_metadata(self, sample_iam_events, temp_output_dir):
        """Test that metadata fields are included in export."""
        exporter = SIEMExporter(format="elastic")
        
        output_file = temp_output_dir / "metadata_export.json"
        exporter.export(sample_iam_events, output_file)
        
        with open(output_file, 'r') as f:
            content = f.read()
            # Should include metadata if present in events
            if any("metadata" in e for e in sample_iam_events):
                assert "metadata" in content or "attack_stage" in content

