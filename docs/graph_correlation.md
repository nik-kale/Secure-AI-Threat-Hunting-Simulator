# Graph-Based Correlation

Advanced graph-based correlation engine for detecting attack campaigns, pivot points, lateral movement, and attack paths in security telemetry.

## Overview

The Graph-Based Correlation system uses NetworkX to build directed graphs from security events and apply graph algorithms to detect sophisticated attack patterns that may not be visible through traditional correlation methods.

## Features

### 1. Attack Graph Construction

Builds a directed graph where:
- **Nodes**: Principals (users/roles), IP addresses, and resources
- **Edges**: Events connecting entities with timestamps and metadata
- **Attributes**: Node and edge properties for analysis

### 2. Attack Campaign Detection

Uses community detection (Louvain method) to identify groups of densely connected entities that may represent coordinated attack campaigns.

**Key Metrics:**
- Community size (number of nodes)
- Community density (edge connectivity)
- Modularity score
- Time range and event count

### 3. Pivot Point Detection

Identifies critical nodes that act as bridges between different parts of the attack graph using centrality metrics:

- **Betweenness Centrality**: Nodes that lie on many shortest paths
- **Degree Centrality**: Nodes with many connections
- **Closeness Centrality**: Nodes close to all others

### 4. Attack Path Tracing

Finds shortest and alternative paths between entities to understand attack progression:

- k-shortest paths algorithm
- Weighted by event frequency
- Timeline reconstruction along paths

### 5. Lateral Movement Detection

Identifies multi-hop patterns indicating lateral movement:

- Detects sequences of resource access
- Filters by time window
- Highlights principal movements across resources

## Installation

Install required dependencies:

```bash
pip install networkx>=3.0 python-louvain>=0.16
```

Or install from requirements.txt:

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```python
from analysis_engine.core import GraphCorrelator, EventParser

# Parse events
parser = EventParser()
events = parser.parse_events(raw_events)

# Initialize correlator
correlator = GraphCorrelator(min_edge_weight=1)

# Build attack graph
graph = correlator.build_attack_graph(events)

# Get graph summary
summary = correlator.generate_graph_summary()
print(f"Graph has {summary['nodes']} nodes and {summary['edges']} edges")
```

### Detect Attack Campaigns

```python
# Detect communities (attack campaigns)
campaigns = correlator.detect_attack_campaigns(
    resolution=1.0,
    min_campaign_size=3
)

for campaign in campaigns:
    print(f"Campaign {campaign.campaign_id}:")
    print(f"  Nodes: {len(campaign.nodes)}")
    print(f"  Events: {len(campaign.events)}")
    print(f"  Principals: {campaign.principals}")
    print(f"  Density: {campaign.density:.4f}")
```

### Find Pivot Points

```python
# Find high-centrality nodes
pivots = correlator.find_pivot_points(
    top_n=10,
    min_degree=3
)

for pivot in pivots:
    print(f"Pivot: {pivot.node_id}")
    print(f"  Type: {pivot.node_type}")
    print(f"  Betweenness: {pivot.betweenness_centrality:.4f}")
    print(f"  Degree: {pivot.total_degree}")
```

### Trace Attack Paths

```python
# Find paths between entities
paths = correlator.trace_attack_path(
    source_entity="principal:attacker@evil.com",
    target_entity="resource:arn:aws:s3:::sensitive-bucket",
    k=3  # Find 3 shortest paths
)

for path in paths:
    print(f"Path ({path.path_length} hops):")
    print(f"  {' -> '.join(path.nodes)}")
    print(f"  Events: {len(path.events)}")
```

### Identify Lateral Movement

```python
# Detect multi-hop patterns
movements = correlator.identify_lateral_movement(
    min_hops=2,
    time_window_minutes=60
)

for movement in movements:
    print(f"Lateral Movement {movement.movement_id}:")
    print(f"  Hops: {movement.num_hops}")
    print(f"  Principals: {movement.principals}")
    print(f"  Resources: {movement.resources}")
```

### Export for Visualization

```python
from pathlib import Path

# Export to GraphML for visualization tools
correlator.export_to_graphml(Path("attack_graph.graphml"))
```

## Pipeline Integration

Graph correlation is automatically integrated with the threat hunting pipeline:

```python
from analysis_engine.pipeline import ThreatHuntingPipeline
from pathlib import Path

# Initialize with graph analysis enabled
pipeline = ThreatHuntingPipeline(
    time_window_minutes=60,
    min_events_for_session=3,
    enable_graph_analysis=True  # Enable graph correlation
)

# Analyze telemetry (graph analysis runs automatically)
results = pipeline.analyze_telemetry_file(
    telemetry_path=Path("telemetry/events.jsonl"),
    output_dir=Path("output/")
)

# Access graph analysis results
graph_data = results['sessions'][0]['graph_analysis']
print(f"Detected {len(graph_data['attack_campaigns'])} campaigns")
print(f"Found {len(graph_data['pivot_points'])} pivot points")
```

### Output Files

When using the pipeline with graph analysis enabled:

- `analysis_report.json` - Includes graph analysis section
- `analysis_report.md` - Formatted graph analysis section
- `attack_graph.graphml` - Graph file for visualization

## Visualization Tools

The exported GraphML files can be visualized using:

### Gephi (Recommended)

1. Download from https://gephi.org
2. Open the `.graphml` file
3. Apply layout algorithms:
   - ForceAtlas2 for attack campaign visualization
   - Fruchterman-Reingold for general structure
4. Color nodes by type (principal, ip, resource)
5. Size nodes by degree or betweenness centrality

### Cytoscape

1. Download from https://cytoscape.org
2. Import network from file
3. Apply visual styles to highlight pivot points
4. Use built-in network analysis tools

### Python/NetworkX

```python
import networkx as nx
import matplotlib.pyplot as plt

# Load graph
graph = nx.read_graphml("attack_graph.graphml")

# Visualize
plt.figure(figsize=(15, 10))
pos = nx.spring_layout(graph, k=0.5, iterations=50)

# Color by node type
colors = {
    'principal': 'red',
    'ip': 'blue',
    'resource': 'green'
}
node_colors = [colors.get(graph.nodes[n]['type'], 'gray') for n in graph.nodes()]

nx.draw(graph, pos,
        node_color=node_colors,
        node_size=500,
        with_labels=True,
        font_size=8,
        arrows=True)

plt.savefig("attack_graph.png", dpi=300, bbox_inches='tight')
plt.show()
```

## Performance Optimization

For graphs with 1000+ nodes:

### 1. Filter Weak Edges

```python
# Only include edges with 3+ events
correlator = GraphCorrelator(min_edge_weight=3)
```

### 2. Adjust Community Detection

```python
# Lower resolution = fewer, larger communities (faster)
campaigns = correlator.detect_attack_campaigns(
    resolution=0.5,
    min_campaign_size=5
)
```

### 3. Limit Pivot Point Search

```python
# Reduce top_n and increase min_degree
pivots = correlator.find_pivot_points(
    top_n=10,
    min_degree=5
)
```

### 4. Use Streaming Pipeline

```python
from analysis_engine.pipeline import StreamingPipeline

# For large telemetry files
pipeline = StreamingPipeline(
    chunk_size=1000,
    enable_graph_analysis=True
)
```

### 5. Disable Features Not Needed

```python
# Skip expensive operations if not needed
# Community detection is most expensive
# Path finding can be expensive on dense graphs
```

## Graph Metrics Reference

### Node Centrality Metrics

| Metric | Range | Interpretation |
|--------|-------|----------------|
| **Betweenness Centrality** | 0.0 - 1.0 | How often a node lies on shortest paths between other nodes. High values indicate critical pivot points. |
| **Degree Centrality** | 0.0 - 1.0 | Proportion of nodes connected to this node. High values indicate highly connected entities. |
| **Closeness Centrality** | 0.0 - 1.0 | How close a node is to all other nodes. High values indicate central positions in the graph. |

### Graph Metrics

| Metric | Range | Interpretation |
|--------|-------|----------------|
| **Density** | 0.0 - 1.0 | Proportion of possible edges that exist. Higher density indicates more interconnected activity. |
| **Modularity** | -0.5 - 1.0 | How well-separated communities are. Higher values indicate distinct attack campaigns. |
| **Diameter** | Integer | Longest shortest path in the graph. Indicates maximum separation between entities. |

## Algorithm Details

### Community Detection: Louvain Method

- **Algorithm**: Iterative modularity optimization
- **Complexity**: O(n log n) on sparse graphs
- **Parameters**:
  - `resolution`: Higher values = more smaller communities
  - `min_campaign_size`: Minimum nodes to consider as a campaign

### Centrality Calculation

- **Betweenness**: Uses Brandes' algorithm - O(nm) for unweighted, O(nm + n² log n) for weighted
- **Degree**: O(n + m) - count connections
- **Closeness**: O(nm) - requires shortest paths

### Path Finding

- **Algorithm**: Yen's k-shortest paths
- **Complexity**: O(kn(m + n log n))
- **Parameters**:
  - `k`: Number of paths to find
  - `weight`: Edge attribute to minimize (default: inverse of event count)

### Lateral Movement Detection

- **Algorithm**: Depth-limited simple path enumeration
- **Complexity**: Exponential in worst case, limited by cutoff
- **Parameters**:
  - `min_hops`: Minimum path length
  - `time_window_minutes`: Maximum time span for related events
  - `cutoff`: Maximum search depth (default: min_hops + 2)

## Use Cases

### 1. APT Detection

Detect Advanced Persistent Threats by finding:
- Long-duration attack campaigns (community detection)
- Compromised pivot accounts (high betweenness)
- Lateral movement patterns across resources

### 2. Insider Threat Detection

Identify unusual access patterns:
- Accounts accessing disconnected resource groups
- Unusual lateral movement outside normal workflows
- Sudden change in graph centrality

### 3. Incident Investigation

Reconstruct attack timeline:
- Find paths from initial compromise to data exfiltration
- Identify all affected resources in a campaign
- Discover overlooked pivot points

### 4. Attack Surface Analysis

Understand system connectivity:
- Identify critical resources (high betweenness)
- Find isolated security zones (disconnected components)
- Measure overall system interconnectedness (density)

## API Reference

See the [full API documentation](api_reference.md) for detailed class and method descriptions.

### Key Classes

- **GraphCorrelator**: Main correlation engine
- **AttackCampaign**: Detected attack campaign data
- **PivotPoint**: High-centrality node data
- **AttackPath**: Path between entities
- **LateralMovement**: Multi-hop movement pattern

## Troubleshooting

### ImportError: No module named 'networkx'

Install NetworkX:
```bash
pip install networkx>=3.0 python-louvain
```

### Graph analysis not running

Check that graph analysis is enabled:
```python
pipeline = ThreatHuntingPipeline(enable_graph_analysis=True)
print(pipeline.enable_graph_analysis)  # Should be True
```

### Poor performance on large graphs

1. Increase `min_edge_weight` to filter noise
2. Reduce `top_n` in pivot point detection
3. Use streaming pipeline for large files
4. Consider analyzing smaller time windows

### Empty results

Check that:
1. Events have required fields (principal, source_ip, or resource)
2. Events are related (same session/attack)
3. `min_campaign_size` and `min_degree` thresholds aren't too high

## Examples

See the [examples directory](../examples/) for complete working examples:

- `graph_correlation_example.py` - Comprehensive usage examples
- See also: `tests/test_graph_correlation.py` for more examples

## Contributing

When contributing to graph correlation:

1. Ensure tests pass: `pytest tests/test_graph_correlation.py`
2. Update documentation for new features
3. Consider performance impact on large graphs
4. Add examples for new functionality

## References

- NetworkX Documentation: https://networkx.org/documentation/
- Louvain Community Detection: https://en.wikipedia.org/wiki/Louvain_method
- Graph Centrality Metrics: https://en.wikipedia.org/wiki/Centrality
- GraphML Format: http://graphml.graphdrawing.org/
