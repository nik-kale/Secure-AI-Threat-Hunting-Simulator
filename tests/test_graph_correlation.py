"""
Tests for graph-based correlation engine.
"""
import pytest
from datetime import datetime, timedelta
from pathlib import Path
import tempfile

from analysis_engine.core import (
    EventParser,
    NormalizedEvent,
    GRAPH_CORRELATION_AVAILABLE,
)

# Skip all tests if networkx not available
pytestmark = pytest.mark.skipif(
    not GRAPH_CORRELATION_AVAILABLE,
    reason="NetworkX not installed"
)

if GRAPH_CORRELATION_AVAILABLE:
    from analysis_engine.core.graph_correlation import (
        GraphCorrelator,
        AttackCampaign,
        PivotPoint,
        AttackPath,
        LateralMovement,
    )


@pytest.fixture
def sample_events():
    """Create sample events for testing."""
    base_time = datetime(2024, 1, 15, 10, 0, 0)

    events = []
    for i in range(10):
        event = NormalizedEvent(
            event_id=f"evt-{i:03d}",
            timestamp=base_time + timedelta(minutes=i),
            event_type="iam.assume_role" if i % 3 == 0 else "s3.get_object",
            event_source="iam.amazonaws.com" if i % 3 == 0 else "s3.amazonaws.com",
            account_id="123456789012",
            region="us-east-1",
            principal=f"user{i % 3}@example.com",
            source_ip=f"10.0.{i % 2}.{i}",
            resource=f"arn:aws:s3:::bucket-{i % 4}/data.csv",
            status="success"
        )
        events.append(event)

    return events


@pytest.fixture
def correlator():
    """Create GraphCorrelator instance."""
    return GraphCorrelator(min_edge_weight=1)


class TestGraphCorrelator:
    """Tests for GraphCorrelator class."""

    def test_initialization(self, correlator):
        """Test correlator initialization."""
        assert correlator.min_edge_weight == 1
        assert correlator.graph.number_of_nodes() == 0
        assert correlator.graph.number_of_edges() == 0

    def test_build_attack_graph(self, correlator, sample_events):
        """Test building attack graph from events."""
        graph = correlator.build_attack_graph(sample_events)

        assert graph.number_of_nodes() > 0
        assert graph.number_of_edges() > 0

        # Check that nodes have correct attributes
        for node, data in graph.nodes(data=True):
            assert 'type' in data
            assert data['type'] in ['principal', 'ip', 'resource']
            assert 'first_seen' in data
            assert 'last_seen' in data
            assert 'event_count' in data

        # Check that edges have correct attributes
        for u, v, data in graph.edges(data=True):
            assert 'weight' in data
            assert data['weight'] >= 1
            assert 'timestamps' in data
            assert 'event_types' in data

    def test_extract_entities(self, correlator):
        """Test entity extraction from events."""
        event = NormalizedEvent(
            event_id="test-001",
            timestamp=datetime.now(),
            event_type="test",
            event_source="test",
            account_id="123",
            region="us-east-1",
            principal="user@example.com",
            source_ip="10.0.0.1",
            resource="resource-1",
            status="success"
        )

        entities = correlator._extract_entities(event)

        assert len(entities) == 3
        assert ("principal:user@example.com", "principal") in entities
        assert ("ip:10.0.0.1", "ip") in entities
        assert ("resource:resource-1", "resource") in entities

    def test_create_edges(self, correlator):
        """Test edge creation between entities."""
        entities = [
            ("principal:user@example.com", "principal"),
            ("ip:10.0.0.1", "ip"),
            ("resource:resource-1", "resource")
        ]

        event = NormalizedEvent(
            event_id="test-001",
            timestamp=datetime.now(),
            event_type="test",
            event_source="test",
            account_id="123",
            region="us-east-1",
            status="success"
        )

        edges = correlator._create_edges(entities, event)

        # Should create edges: principal->resource, ip->resource, ip->principal
        assert len(edges) == 3
        assert ("principal:user@example.com", "resource:resource-1") in edges
        assert ("ip:10.0.0.1", "resource:resource-1") in edges
        assert ("ip:10.0.0.1", "principal:user@example.com") in edges

    def test_generate_graph_summary(self, correlator, sample_events):
        """Test graph summary generation."""
        correlator.build_attack_graph(sample_events)
        summary = correlator.generate_graph_summary()

        assert 'nodes' in summary
        assert 'edges' in summary
        assert 'density' in summary
        assert 'node_types' in summary
        assert summary['nodes'] > 0
        assert summary['edges'] > 0

        # Check node types breakdown
        assert 'principal' in summary['node_types']
        assert 'ip' in summary['node_types']
        assert 'resource' in summary['node_types']

    def test_detect_attack_campaigns(self, correlator, sample_events):
        """Test attack campaign detection."""
        correlator.build_attack_graph(sample_events)
        campaigns = correlator.detect_attack_campaigns(min_campaign_size=2)

        # Should detect at least one campaign with connected nodes
        assert isinstance(campaigns, list)

        for campaign in campaigns:
            assert isinstance(campaign, AttackCampaign)
            assert len(campaign.nodes) >= 2
            assert len(campaign.events) > 0
            assert campaign.campaign_id.startswith('campaign-')
            assert 0.0 <= campaign.density <= 1.0

    def test_find_pivot_points(self, correlator, sample_events):
        """Test pivot point detection."""
        correlator.build_attack_graph(sample_events)
        pivots = correlator.find_pivot_points(top_n=5, min_degree=1)

        assert isinstance(pivots, list)

        for pivot in pivots:
            assert isinstance(pivot, PivotPoint)
            assert pivot.node_id
            assert pivot.node_type in ['principal', 'ip', 'resource']
            assert 0.0 <= pivot.betweenness_centrality <= 1.0
            assert 0.0 <= pivot.degree_centrality <= 1.0
            assert pivot.total_degree >= 1

        # Should be sorted by betweenness centrality
        if len(pivots) > 1:
            for i in range(len(pivots) - 1):
                assert pivots[i].betweenness_centrality >= pivots[i+1].betweenness_centrality

    def test_identify_lateral_movement(self, correlator, sample_events):
        """Test lateral movement detection."""
        correlator.build_attack_graph(sample_events)
        movements = correlator.identify_lateral_movement(min_hops=2, time_window_minutes=60)

        assert isinstance(movements, list)

        for movement in movements:
            assert isinstance(movement, LateralMovement)
            assert movement.num_hops >= 2
            assert len(movement.hops) >= 2
            assert len(movement.events) > 0
            assert movement.movement_id.startswith('movement-')

    def test_trace_attack_path(self, correlator, sample_events):
        """Test attack path tracing."""
        correlator.build_attack_graph(sample_events)

        # Get two nodes from the graph
        nodes = list(correlator.graph.nodes())
        if len(nodes) < 2:
            pytest.skip("Not enough nodes for path testing")

        # Find a principal and resource node
        principal_node = None
        resource_node = None

        for node in nodes:
            node_type = correlator.graph.nodes[node]['type']
            if node_type == 'principal' and not principal_node:
                principal_node = node
            elif node_type == 'resource' and not resource_node:
                resource_node = node

        if not principal_node or not resource_node:
            pytest.skip("Could not find suitable nodes for path testing")

        paths = correlator.trace_attack_path(principal_node, resource_node, k=3)

        assert isinstance(paths, list)

        for path in paths:
            assert isinstance(path, AttackPath)
            assert path.source_node == principal_node
            assert path.target_node == resource_node
            assert len(path.nodes) >= 2
            assert path.path_length >= 1

        # First path should be marked as shortest
        if paths:
            assert paths[0].is_shortest

    def test_export_to_graphml(self, correlator, sample_events):
        """Test GraphML export."""
        correlator.build_attack_graph(sample_events)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test_graph.graphml"
            correlator.export_to_graphml(output_path)

            assert output_path.exists()
            assert output_path.stat().st_size > 0

            # Verify it's valid XML
            with open(output_path) as f:
                content = f.read()
                assert '<?xml' in content
                assert '<graphml' in content
                assert '</graphml>' in content

    def test_min_edge_weight_filtering(self):
        """Test that min_edge_weight filters low-weight edges."""
        correlator = GraphCorrelator(min_edge_weight=3)

        # Create events that will create edges with different weights
        base_time = datetime(2024, 1, 15, 10, 0, 0)
        events = []

        # Create multiple events between same entities (high weight)
        for i in range(5):
            event = NormalizedEvent(
                event_id=f"evt-a-{i}",
                timestamp=base_time + timedelta(seconds=i),
                event_type="s3.get_object",
                event_source="s3.amazonaws.com",
                account_id="123",
                region="us-east-1",
                principal="user1@example.com",
                source_ip="10.0.0.1",
                resource="resource-1",
                status="success"
            )
            events.append(event)

        # Create single event between different entities (low weight)
        event = NormalizedEvent(
            event_id="evt-b-1",
            timestamp=base_time + timedelta(seconds=10),
            event_type="s3.get_object",
            event_source="s3.amazonaws.com",
            account_id="123",
            region="us-east-1",
            principal="user2@example.com",
            source_ip="10.0.0.2",
            resource="resource-2",
            status="success"
        )
        events.append(event)

        graph = correlator.build_attack_graph(events)

        # Check that only high-weight edges remain
        for u, v, data in graph.edges(data=True):
            assert data['weight'] >= 3

    def test_empty_events(self, correlator):
        """Test handling of empty event list."""
        graph = correlator.build_attack_graph([])

        assert graph.number_of_nodes() == 0
        assert graph.number_of_edges() == 0

        summary = correlator.generate_graph_summary()
        assert summary['nodes'] == 0
        assert summary['edges'] == 0

    def test_to_dict_methods(self, correlator, sample_events):
        """Test to_dict methods of data classes."""
        correlator.build_attack_graph(sample_events)

        # Test AttackCampaign.to_dict()
        campaigns = correlator.detect_attack_campaigns(min_campaign_size=2)
        if campaigns:
            campaign_dict = campaigns[0].to_dict()
            assert isinstance(campaign_dict, dict)
            assert 'campaign_id' in campaign_dict
            assert 'num_nodes' in campaign_dict
            assert 'num_edges' in campaign_dict

        # Test PivotPoint.to_dict()
        pivots = correlator.find_pivot_points(top_n=5, min_degree=1)
        if pivots:
            pivot_dict = pivots[0].to_dict()
            assert isinstance(pivot_dict, dict)
            assert 'node_id' in pivot_dict
            assert 'betweenness_centrality' in pivot_dict

        # Test LateralMovement.to_dict()
        movements = correlator.identify_lateral_movement(min_hops=2)
        if movements:
            movement_dict = movements[0].to_dict()
            assert isinstance(movement_dict, dict)
            assert 'movement_id' in movement_dict
            assert 'num_hops' in movement_dict


class TestIntegration:
    """Integration tests with pipeline."""

    def test_pipeline_integration(self, sample_events):
        """Test that graph correlation integrates with pipeline."""
        from analysis_engine.pipeline import ThreatHuntingPipeline

        pipeline = ThreatHuntingPipeline(
            enable_graph_analysis=True
        )

        # Check that graph correlator is initialized
        assert pipeline.enable_graph_analysis
        assert pipeline.graph_correlator is not None

    def test_pipeline_without_graph(self, sample_events):
        """Test pipeline works without graph analysis."""
        from analysis_engine.pipeline import ThreatHuntingPipeline

        pipeline = ThreatHuntingPipeline(
            enable_graph_analysis=False
        )

        assert not pipeline.enable_graph_analysis
        assert pipeline.graph_correlator is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
