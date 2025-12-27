"""
Integration tests for attack scenario generators.
"""
import json
import tempfile
from pathlib import Path
import pytest

from generator.attack_traces.lateral_movement.generator import generate_lateral_movement_scenario
from generator.attack_traces.data_exfiltration.generator import generate_data_exfiltration_scenario
from generator.attack_traces.supply_chain.generator import generate_supply_chain_scenario


class TestAttackScenarios:
    """Test all attack scenario generators."""

    def test_lateral_movement_scenario_generation(self):
        """Test lateral movement scenario generates valid telemetry."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            metadata = generate_lateral_movement_scenario(
                output_dir=output_dir,
                duration_hours=0.5,  # Short duration for testing
                add_noise=False  # No noise for easier validation
            )
            
            # Verify metadata
            assert metadata["scenario_name"] == "lateral_movement"
            assert metadata["num_events"] > 0
            assert "attacker_ip" in metadata
            assert len(metadata["attack_stages"]) > 0
            assert len(metadata["mitre_techniques"]) > 0
            
            # Verify output file exists and is valid JSON Lines
            output_file = output_dir / "telemetry.jsonl"
            assert output_file.exists()
            
            events = []
            with open(output_file, 'r') as f:
                for line in f:
                    event = json.loads(line)
                    events.append(event)
                    
                    # Verify required fields
                    assert "event_id" in event
                    assert "timestamp" in event
                    assert "event_type" in event
                    assert "event_source" in event
            
            assert len(events) == metadata["num_events"]
            
            # Verify STS events exist (key to lateral movement)
            sts_events = [e for e in events if e["event_source"] == "sts"]
            assert len(sts_events) > 0, "Should have STS AssumeRole events"

    def test_data_exfiltration_scenario_generation(self):
        """Test data exfiltration scenario generates valid telemetry."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            metadata = generate_data_exfiltration_scenario(
                output_dir=output_dir,
                duration_hours=0.5,
                add_noise=False
            )
            
            # Verify metadata
            assert metadata["scenario_name"] == "data_exfiltration"
            assert metadata["num_events"] > 0
            assert "exfiltration_target" in metadata
            assert "targeted_buckets" in metadata
            
            # Verify output file
            output_file = output_dir / "telemetry.jsonl"
            assert output_file.exists()
            
            events = []
            with open(output_file, 'r') as f:
                for line in f:
                    event = json.loads(line)
                    events.append(event)
            
            assert len(events) == metadata["num_events"]
            
            # Verify S3 copy events exist (key to exfiltration)
            copy_events = [e for e in events if e.get("action") == "CopyObject"]
            assert len(copy_events) > 0, "Should have S3 CopyObject events"
            
            # Verify CloudTrail events exist (anti-forensics)
            cloudtrail_events = [e for e in events if e["event_source"] == "cloudtrail"]
            assert len(cloudtrail_events) > 0, "Should have CloudTrail events"

    def test_supply_chain_scenario_generation(self):
        """Test supply chain attack scenario generates valid telemetry."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            metadata = generate_supply_chain_scenario(
                output_dir=output_dir,
                duration_hours=0.5,
                add_noise=False
            )
            
            # Verify metadata
            assert metadata["scenario_name"] == "supply_chain"
            assert metadata["num_events"] > 0
            assert "malicious_layer" in metadata
            assert "compromised_pipeline" in metadata
            
            # Verify output file
            output_file = output_dir / "telemetry.jsonl"
            assert output_file.exists()
            
            events = []
            with open(output_file, 'r') as f:
                for line in f:
                    event = json.loads(line)
                    events.append(event)
            
            assert len(events) == metadata["num_events"]
            
            # Verify CodePipeline events exist
            pipeline_events = [e for e in events if e["event_source"] == "codepipeline"]
            assert len(pipeline_events) > 0, "Should have CodePipeline events"
            
            # Verify Lambda events exist
            lambda_events = [e for e in events if e["event_source"] == "lambda"]
            assert len(lambda_events) > 0, "Should have Lambda events"

    def test_scenarios_with_noise(self):
        """Test scenarios generate realistic noise events."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            # Generate with noise
            metadata_with_noise = generate_lateral_movement_scenario(
                output_dir=output_dir,
                duration_hours=0.5,
                add_noise=True
            )
            
            # Generate without noise (new directory)
            output_dir2 = Path(tmpdir) / "no_noise"
            output_dir2.mkdir()
            metadata_without_noise = generate_lateral_movement_scenario(
                output_dir=output_dir2,
                duration_hours=0.5,
                add_noise=False
            )
            
            # With noise should have more events
            assert metadata_with_noise["num_events"] > metadata_without_noise["num_events"]

    def test_event_timestamps_sequential(self):
        """Test that events are generated in chronological order."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            generate_lateral_movement_scenario(
                output_dir=output_dir,
                duration_hours=0.5,
                add_noise=False
            )
            
            output_file = output_dir / "telemetry.jsonl"
            
            timestamps = []
            with open(output_file, 'r') as f:
                for line in f:
                    event = json.loads(line)
                    timestamps.append(event["timestamp"])
            
            # Verify timestamps are in order
            sorted_timestamps = sorted(timestamps)
            assert timestamps == sorted_timestamps, "Events should be chronologically ordered"

    def test_mitre_techniques_populated(self):
        """Test that MITRE ATT&CK techniques are properly mapped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scenarios = [
                generate_lateral_movement_scenario,
                generate_data_exfiltration_scenario,
                generate_supply_chain_scenario
            ]
            
            for scenario_func in scenarios:
                output_dir = Path(tmpdir) / scenario_func.__name__
                output_dir.mkdir(parents=True, exist_ok=True)
                
                metadata = scenario_func(
                    output_dir=output_dir,
                    duration_hours=0.5,
                    add_noise=False
                )
                
                # Each scenario should have MITRE techniques
                assert "mitre_techniques" in metadata
                assert len(metadata["mitre_techniques"]) > 0
                
                # Techniques should start with T followed by numbers
                for technique in metadata["mitre_techniques"]:
                    assert technique.startswith("T")

