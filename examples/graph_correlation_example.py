"""
Example: Using Graph-Based Correlation for Advanced Threat Detection

This example demonstrates how to use the GraphCorrelator for detecting
attack campaigns, pivot points, lateral movement, and attack paths.
"""
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis_engine.core import (
    EventParser,
    GraphCorrelator,
    GRAPH_CORRELATION_AVAILABLE,
)
from analysis_engine.pipeline import ThreatHuntingPipeline


def basic_graph_example():
    """Basic example of building and analyzing an attack graph."""

    if not GRAPH_CORRELATION_AVAILABLE:
        print("ERROR: NetworkX not installed. Install with:")
        print("  pip install networkx>=3.0 python-louvain")
        return

    print("=" * 80)
    print("Basic Graph Correlation Example")
    print("=" * 80)
    print()

    # Create sample events (normally loaded from telemetry)
    sample_events = [
        {
            "event_id": "evt-001",
            "timestamp": "2024-01-15T10:00:00Z",
            "event_type": "iam.assume_role",
            "event_source": "iam.amazonaws.com",
            "account_id": "123456789012",
            "region": "us-east-1",
            "principal": "attacker@evil.com",
            "source_ip": "203.0.113.10",
            "resource": "arn:aws:iam::123456789012:role/AdminRole",
            "status": "success"
        },
        {
            "event_id": "evt-002",
            "timestamp": "2024-01-15T10:05:00Z",
            "event_type": "s3.get_object",
            "event_source": "s3.amazonaws.com",
            "account_id": "123456789012",
            "region": "us-east-1",
            "principal": "attacker@evil.com",
            "source_ip": "203.0.113.10",
            "resource": "arn:aws:s3:::sensitive-bucket/data.csv",
            "status": "success"
        },
        {
            "event_id": "evt-003",
            "timestamp": "2024-01-15T10:10:00Z",
            "event_type": "lambda.invoke",
            "event_source": "lambda.amazonaws.com",
            "account_id": "123456789012",
            "region": "us-east-1",
            "principal": "attacker@evil.com",
            "source_ip": "203.0.113.10",
            "resource": "arn:aws:lambda:us-east-1:123456789012:function:exfiltrate",
            "status": "success"
        },
    ]

    # Parse events
    parser = EventParser()
    normalized_events = parser.parse_events(sample_events)
    print(f"Parsed {len(normalized_events)} events")
    print()

    # Initialize graph correlator
    correlator = GraphCorrelator(min_edge_weight=1)

    # Build attack graph
    print("Building attack graph...")
    graph = correlator.build_attack_graph(normalized_events)
    print(f"Created graph with {graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges")
    print()

    # Generate graph summary
    print("Graph Summary:")
    print("-" * 40)
    summary = correlator.generate_graph_summary()
    for key, value in summary.items():
        print(f"  {key}: {value}")
    print()

    # Detect attack campaigns
    print("Detecting Attack Campaigns:")
    print("-" * 40)
    campaigns = correlator.detect_attack_campaigns(min_campaign_size=2)
    for campaign in campaigns:
        print(f"  Campaign {campaign.campaign_id}:")
        print(f"    - Nodes: {len(campaign.nodes)}")
        print(f"    - Events: {len(campaign.events)}")
        print(f"    - Principals: {campaign.principals}")
        print(f"    - Resources: {list(campaign.resources)[:3]}")
    print()

    # Find pivot points
    print("Finding Pivot Points:")
    print("-" * 40)
    pivots = correlator.find_pivot_points(top_n=5, min_degree=1)
    for pivot in pivots:
        print(f"  {pivot.node_id}:")
        print(f"    - Type: {pivot.node_type}")
        print(f"    - Betweenness: {pivot.betweenness_centrality:.4f}")
        print(f"    - Degree: {pivot.total_degree}")
    print()

    # Identify lateral movement
    print("Identifying Lateral Movement:")
    print("-" * 40)
    movements = correlator.identify_lateral_movement(min_hops=2)
    for movement in movements:
        print(f"  {movement.movement_id}:")
        print(f"    - Hops: {movement.num_hops}")
        print(f"    - Events: {len(movement.events)}")
        print(f"    - Path: {' -> '.join([h[0].split(':')[1][:20] for h in movement.hops[:3]])}")
    print()


def pipeline_integration_example():
    """Example of using graph correlation with the full pipeline."""

    if not GRAPH_CORRELATION_AVAILABLE:
        print("ERROR: NetworkX not installed")
        return

    print("=" * 80)
    print("Pipeline Integration Example")
    print("=" * 80)
    print()

    # Initialize pipeline with graph analysis enabled
    pipeline = ThreatHuntingPipeline(
        time_window_minutes=60,
        min_events_for_session=3,
        risk_threshold=0.5,
        enable_graph_analysis=True  # Enable graph analysis
    )

    print(f"Graph analysis enabled: {pipeline.enable_graph_analysis}")
    print()

    # The pipeline will automatically perform graph analysis on each session
    # and include results in the analysis report
    print("Usage:")
    print("  results = pipeline.analyze_telemetry_file(")
    print("      Path('telemetry/sample.jsonl'),")
    print("      Path('output/')")
    print("  )")
    print()
    print("Graph analysis results will be available in:")
    print("  - results['sessions'][0]['graph_analysis']")
    print("  - output/attack_graph.graphml (for visualization)")
    print()


def advanced_path_tracing_example():
    """Example of tracing specific attack paths between entities."""

    if not GRAPH_CORRELATION_AVAILABLE:
        print("ERROR: NetworkX not installed")
        return

    print("=" * 80)
    print("Attack Path Tracing Example")
    print("=" * 80)
    print()

    # Create more complex event scenario
    events = [
        {
            "event_id": f"evt-{i:03d}",
            "timestamp": f"2024-01-15T10:{i:02d}:00Z",
            "event_type": "network.connection",
            "event_source": "vpc.amazonaws.com",
            "account_id": "123456789012",
            "region": "us-east-1",
            "principal": f"user{i % 3}@example.com",
            "source_ip": f"10.0.{i % 5}.{i}",
            "resource": f"arn:aws:ec2:::instance/i-{i:08x}",
            "status": "success"
        }
        for i in range(20)
    ]

    parser = EventParser()
    normalized_events = parser.parse_events(events)

    correlator = GraphCorrelator()
    correlator.build_attack_graph(normalized_events)

    # Trace path between specific entities
    source = "principal:user0@example.com"
    target = "resource:arn:aws:ec2:::instance/i-00000005"

    print(f"Tracing attack path from:")
    print(f"  Source: {source}")
    print(f"  Target: {target}")
    print()

    paths = correlator.trace_attack_path(source, target, k=3)

    if paths:
        for i, path in enumerate(paths, 1):
            print(f"Path {i} ({'shortest' if path.is_shortest else 'alternative'}):")
            print(f"  Length: {path.path_length} hops")
            print(f"  Nodes: {' -> '.join([n.split(':')[1][:20] for n in path.nodes])}")
            print()
    else:
        print("No path found")
    print()


def visualization_export_example():
    """Example of exporting graph for visualization."""

    if not GRAPH_CORRELATION_AVAILABLE:
        print("ERROR: NetworkX not installed")
        return

    print("=" * 80)
    print("Graph Visualization Export Example")
    print("=" * 80)
    print()

    # Create sample events
    events = [
        {
            "event_id": f"evt-{i}",
            "timestamp": f"2024-01-15T10:00:{i:02d}Z",
            "event_type": "api.call",
            "event_source": "api.amazonaws.com",
            "account_id": "123456789012",
            "region": "us-east-1",
            "principal": f"user{i % 3}@example.com",
            "source_ip": f"192.168.1.{i}",
            "resource": f"resource-{i % 5}",
            "status": "success"
        }
        for i in range(10)
    ]

    parser = EventParser()
    normalized_events = parser.parse_events(events)

    correlator = GraphCorrelator()
    correlator.build_attack_graph(normalized_events)

    # Export to GraphML
    output_path = Path("/tmp/attack_graph_example.graphml")
    correlator.export_to_graphml(output_path)

    print(f"Graph exported to: {output_path}")
    print()
    print("You can visualize this graph using tools like:")
    print("  - Gephi (https://gephi.org)")
    print("  - Cytoscape (https://cytoscape.org)")
    print("  - yEd (https://www.yworks.com/products/yed)")
    print("  - NetworkX/matplotlib in Python")
    print()


def performance_tips():
    """Tips for optimizing graph analysis on large datasets."""

    print("=" * 80)
    print("Performance Optimization Tips")
    print("=" * 80)
    print()

    print("For graphs with 1000+ nodes:")
    print()
    print("1. Use min_edge_weight to filter weak connections:")
    print("   correlator = GraphCorrelator(min_edge_weight=3)")
    print()
    print("2. Limit community detection resolution:")
    print("   campaigns = correlator.detect_attack_campaigns(resolution=0.5)")
    print()
    print("3. Reduce top_n for pivot point detection:")
    print("   pivots = correlator.find_pivot_points(top_n=10, min_degree=5)")
    print()
    print("4. Set cutoff for lateral movement search:")
    print("   # Already optimized with cutoff in implementation")
    print()
    print("5. Use streaming pipeline for large files:")
    print("   from analysis_engine.pipeline import StreamingPipeline")
    print("   pipeline = StreamingPipeline(chunk_size=1000)")
    print()


if __name__ == "__main__":
    # Run examples
    basic_graph_example()
    print("\n" + "=" * 80 + "\n")

    pipeline_integration_example()
    print("\n" + "=" * 80 + "\n")

    advanced_path_tracing_example()
    print("\n" + "=" * 80 + "\n")

    visualization_export_example()
    print("\n" + "=" * 80 + "\n")

    performance_tips()
