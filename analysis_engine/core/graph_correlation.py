"""
Graph-based correlation engine for advanced attack pattern detection.

Uses NetworkX to build directed graphs of security events and detect
attack campaigns, pivot points, lateral movement, and attack paths.
"""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple, TYPE_CHECKING
from dataclasses import dataclass, field
import logging
from pathlib import Path

try:
    import networkx as nx
    from networkx.algorithms import community
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    nx = None

if TYPE_CHECKING:
    import networkx as nx

from .parser import NormalizedEvent
from .correlation import CorrelationSession

logger = logging.getLogger(__name__)


@dataclass
class AttackCampaign:
    """Represents a detected attack campaign (community)."""

    campaign_id: str
    nodes: Set[str] = field(default_factory=set)
    edges: List[Tuple[str, str]] = field(default_factory=list)
    events: List[NormalizedEvent] = field(default_factory=list)

    # Campaign characteristics
    principals: Set[str] = field(default_factory=set)
    source_ips: Set[str] = field(default_factory=set)
    resources: Set[str] = field(default_factory=set)

    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    # Graph metrics
    modularity: float = 0.0
    density: float = 0.0
    size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "campaign_id": self.campaign_id,
            "num_nodes": len(self.nodes),
            "num_edges": len(self.edges),
            "num_events": len(self.events),
            "principals": list(self.principals),
            "source_ips": list(self.source_ips),
            "resources": list(self.resources),
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else 0,
            "modularity": self.modularity,
            "density": self.density,
            "size": self.size,
        }


@dataclass
class PivotPoint:
    """Represents a high-centrality pivot node in the attack graph."""

    node_id: str
    node_type: str  # principal, ip, or resource

    # Centrality metrics
    betweenness_centrality: float = 0.0
    degree_centrality: float = 0.0
    closeness_centrality: float = 0.0

    # Node characteristics
    in_degree: int = 0
    out_degree: int = 0
    total_degree: int = 0

    # Related entities
    connected_nodes: Set[str] = field(default_factory=set)
    events: List[NormalizedEvent] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "betweenness_centrality": self.betweenness_centrality,
            "degree_centrality": self.degree_centrality,
            "closeness_centrality": self.closeness_centrality,
            "in_degree": self.in_degree,
            "out_degree": self.out_degree,
            "total_degree": self.total_degree,
            "connected_nodes": list(self.connected_nodes),
            "num_events": len(self.events),
        }


@dataclass
class AttackPath:
    """Represents a path through the attack graph."""

    path_id: str
    nodes: List[str] = field(default_factory=list)
    edges: List[Tuple[str, str]] = field(default_factory=list)
    events: List[NormalizedEvent] = field(default_factory=list)

    source_node: Optional[str] = None
    target_node: Optional[str] = None

    path_length: int = 0
    is_shortest: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "path_id": self.path_id,
            "nodes": self.nodes,
            "edges": [{"source": s, "target": t} for s, t in self.edges],
            "source_node": self.source_node,
            "target_node": self.target_node,
            "path_length": self.path_length,
            "is_shortest": self.is_shortest,
            "num_events": len(self.events),
        }


@dataclass
class LateralMovement:
    """Represents detected lateral movement patterns."""

    movement_id: str
    hops: List[Tuple[str, str]] = field(default_factory=list)
    principals: Set[str] = field(default_factory=set)
    source_ips: Set[str] = field(default_factory=set)
    resources: Set[str] = field(default_factory=set)

    num_hops: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    events: List[NormalizedEvent] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "movement_id": self.movement_id,
            "hops": [{"source": s, "target": t} for s, t in self.hops],
            "num_hops": self.num_hops,
            "principals": list(self.principals),
            "source_ips": list(self.source_ips),
            "resources": list(self.resources),
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "num_events": len(self.events),
        }


class GraphCorrelator:
    """
    Advanced graph-based correlation for threat hunting.

    Builds directed graphs from security events and detects:
    - Attack campaigns (community detection)
    - Pivot points (high centrality nodes)
    - Attack paths (shortest paths between entities)
    - Lateral movement (multi-hop patterns)
    """

    def __init__(self, min_edge_weight: int = 1):
        """
        Initialize graph correlator.

        Args:
            min_edge_weight: Minimum edge weight to include in graph
        """
        if not NETWORKX_AVAILABLE:
            raise ImportError(
                "NetworkX is required for graph correlation. "
                "Install with: pip install networkx>=3.0 python-louvain"
            )

        self.min_edge_weight = min_edge_weight
        self.graph = nx.DiGraph()
        self.events_by_edge: Dict[Tuple[str, str], List[NormalizedEvent]] = defaultdict(list)
        self.events_by_node: Dict[str, List[NormalizedEvent]] = defaultdict(list)

        logger.info("Initialized GraphCorrelator")

    def build_attack_graph(self, events: List[NormalizedEvent]) -> nx.DiGraph:
        """
        Build directed attack graph from events.

        Creates nodes for principals, IPs, and resources.
        Creates directed edges for events connecting them with timestamps.

        Args:
            events: List of normalized events

        Returns:
            NetworkX directed graph
        """
        logger.info(f"Building attack graph from {len(events)} events")

        # Reset graph
        self.graph = nx.DiGraph()
        self.events_by_edge.clear()
        self.events_by_node.clear()

        # Track edge weights (event counts)
        edge_weights: Dict[Tuple[str, str], int] = defaultdict(int)

        for event in events:
            # Extract entities from event
            entities = self._extract_entities(event)

            # Add nodes with attributes
            for entity_id, entity_type in entities:
                if not self.graph.has_node(entity_id):
                    self.graph.add_node(
                        entity_id,
                        type=entity_type,
                        first_seen=event.timestamp,
                        last_seen=event.timestamp,
                        event_count=0
                    )
                else:
                    # Update last seen time
                    self.graph.nodes[entity_id]['last_seen'] = max(
                        self.graph.nodes[entity_id]['last_seen'],
                        event.timestamp
                    )

                # Increment event count
                self.graph.nodes[entity_id]['event_count'] += 1
                self.events_by_node[entity_id].append(event)

            # Create edges between entities (directed)
            edges = self._create_edges(entities, event)

            for source, target in edges:
                edge_key = (source, target)
                edge_weights[edge_key] += 1
                self.events_by_edge[edge_key].append(event)

                # Add or update edge
                if self.graph.has_edge(source, target):
                    self.graph[source][target]['weight'] += 1
                    self.graph[source][target]['timestamps'].append(event.timestamp)
                    self.graph[source][target]['event_types'].add(event.event_type)
                else:
                    self.graph.add_edge(
                        source, target,
                        weight=1,
                        timestamps=[event.timestamp],
                        event_types={event.event_type},
                        first_event=event.timestamp
                    )

        # Filter edges by minimum weight
        if self.min_edge_weight > 1:
            edges_to_remove = [
                (u, v) for u, v, d in self.graph.edges(data=True)
                if d['weight'] < self.min_edge_weight
            ]
            self.graph.remove_edges_from(edges_to_remove)
            logger.info(f"Removed {len(edges_to_remove)} low-weight edges")

        logger.info(
            f"Built graph with {self.graph.number_of_nodes()} nodes "
            f"and {self.graph.number_of_edges()} edges"
        )

        return self.graph

    def _extract_entities(self, event: NormalizedEvent) -> List[Tuple[str, str]]:
        """
        Extract entities (nodes) from an event.

        Returns:
            List of (entity_id, entity_type) tuples
        """
        entities = []

        if event.principal:
            entities.append((f"principal:{event.principal}", "principal"))

        if event.source_ip:
            entities.append((f"ip:{event.source_ip}", "ip"))

        if event.resource:
            entities.append((f"resource:{event.resource}", "resource"))

        return entities

    def _create_edges(
        self,
        entities: List[Tuple[str, str]],
        event: NormalizedEvent
    ) -> List[Tuple[str, str]]:
        """
        Create directed edges between entities.

        Common patterns:
        - principal -> resource (access)
        - ip -> resource (network access)
        - principal -> ip (association)
        """
        edges = []

        # Create edges based on entity types
        entity_dict = {etype: eid for eid, etype in entities}

        # Principal to resource
        if 'principal' in entity_dict and 'resource' in entity_dict:
            edges.append((entity_dict['principal'], entity_dict['resource']))

        # IP to resource
        if 'ip' in entity_dict and 'resource' in entity_dict:
            edges.append((entity_dict['ip'], entity_dict['resource']))

        # IP to principal (if both exist, showing association)
        if 'ip' in entity_dict and 'principal' in entity_dict:
            edges.append((entity_dict['ip'], entity_dict['principal']))

        return edges

    def detect_attack_campaigns(
        self,
        resolution: float = 1.0,
        min_campaign_size: int = 3
    ) -> List[AttackCampaign]:
        """
        Detect attack campaigns using community detection.

        Uses Louvain method to find communities (groups of densely
        connected nodes that may represent coordinated attacks).

        Args:
            resolution: Resolution parameter for community detection
            min_campaign_size: Minimum nodes for a campaign

        Returns:
            List of detected attack campaigns
        """
        if self.graph.number_of_nodes() == 0:
            logger.warning("Cannot detect campaigns on empty graph")
            return []

        logger.info("Detecting attack campaigns using community detection")

        # Convert to undirected for community detection
        undirected = self.graph.to_undirected()

        # Apply Louvain community detection
        try:
            communities_dict = community.louvain_communities(
                undirected,
                resolution=resolution,
                seed=42
            )
        except Exception as e:
            logger.error(f"Community detection failed: {e}")
            return []

        campaigns = []

        for i, community_nodes in enumerate(communities_dict):
            if len(community_nodes) < min_campaign_size:
                continue

            # Create subgraph for this campaign
            subgraph = self.graph.subgraph(community_nodes)

            # Gather campaign information
            campaign = AttackCampaign(
                campaign_id=f"campaign-{i}",
                nodes=set(community_nodes),
                size=len(community_nodes)
            )

            # Extract edges within campaign
            campaign.edges = list(subgraph.edges())

            # Calculate density
            possible_edges = len(community_nodes) * (len(community_nodes) - 1)
            if possible_edges > 0:
                campaign.density = len(campaign.edges) / possible_edges

            # Gather events and metadata
            for node in community_nodes:
                if node in self.events_by_node:
                    campaign.events.extend(self.events_by_node[node])

            # Extract principals, IPs, resources
            for node in community_nodes:
                node_type = self.graph.nodes[node].get('type', '')
                if node_type == 'principal':
                    campaign.principals.add(node.replace('principal:', ''))
                elif node_type == 'ip':
                    campaign.source_ips.add(node.replace('ip:', ''))
                elif node_type == 'resource':
                    campaign.resources.add(node.replace('resource:', ''))

            # Time range
            if campaign.events:
                campaign.start_time = min(e.timestamp for e in campaign.events)
                campaign.end_time = max(e.timestamp for e in campaign.events)

            campaigns.append(campaign)

        logger.info(f"Detected {len(campaigns)} attack campaigns")
        return campaigns

    def find_pivot_points(
        self,
        top_n: int = 10,
        min_degree: int = 3
    ) -> List[PivotPoint]:
        """
        Find pivot points (high betweenness centrality nodes).

        Pivot points are nodes that act as bridges between different
        parts of the attack graph, often indicating compromised
        accounts or infrastructure used for lateral movement.

        Args:
            top_n: Number of top pivot points to return
            min_degree: Minimum degree for consideration

        Returns:
            List of pivot points ordered by betweenness centrality
        """
        if self.graph.number_of_nodes() == 0:
            logger.warning("Cannot find pivot points on empty graph")
            return []

        logger.info("Finding pivot points using centrality analysis")

        # Calculate centrality metrics
        betweenness = nx.betweenness_centrality(self.graph, weight='weight')
        degree_centrality = nx.degree_centrality(self.graph)

        # Calculate closeness (may fail on disconnected graphs)
        try:
            closeness = nx.closeness_centrality(self.graph)
        except:
            closeness = {node: 0.0 for node in self.graph.nodes()}

        pivot_points = []

        for node in self.graph.nodes():
            # Filter by minimum degree
            degree = self.graph.degree(node)
            if degree < min_degree:
                continue

            pivot = PivotPoint(
                node_id=node,
                node_type=self.graph.nodes[node].get('type', 'unknown'),
                betweenness_centrality=betweenness.get(node, 0.0),
                degree_centrality=degree_centrality.get(node, 0.0),
                closeness_centrality=closeness.get(node, 0.0),
                in_degree=self.graph.in_degree(node),
                out_degree=self.graph.out_degree(node),
                total_degree=degree,
                connected_nodes=set(self.graph.neighbors(node)),
                events=self.events_by_node.get(node, [])
            )

            pivot_points.append(pivot)

        # Sort by betweenness centrality (descending)
        pivot_points.sort(key=lambda p: p.betweenness_centrality, reverse=True)

        # Return top N
        result = pivot_points[:top_n]
        logger.info(f"Found {len(result)} pivot points")

        return result

    def trace_attack_path(
        self,
        source_entity: str,
        target_entity: str,
        k: int = 3
    ) -> List[AttackPath]:
        """
        Find attack paths between two entities.

        Args:
            source_entity: Source entity (e.g., "principal:user@example.com")
            target_entity: Target entity (e.g., "resource:s3://bucket")
            k: Number of shortest paths to find

        Returns:
            List of attack paths
        """
        if not self.graph.has_node(source_entity) or not self.graph.has_node(target_entity):
            logger.warning(f"Source or target entity not found in graph")
            return []

        logger.info(f"Tracing attack paths from {source_entity} to {target_entity}")

        paths = []

        try:
            # Find k shortest paths
            simple_paths = list(nx.shortest_simple_paths(
                self.graph,
                source_entity,
                target_entity,
                weight='weight'
            ))

            for i, path_nodes in enumerate(simple_paths[:k]):
                # Create edges from nodes
                path_edges = [(path_nodes[j], path_nodes[j+1])
                             for j in range(len(path_nodes) - 1)]

                # Gather events along path
                path_events = []
                for edge in path_edges:
                    if edge in self.events_by_edge:
                        path_events.extend(self.events_by_edge[edge])

                attack_path = AttackPath(
                    path_id=f"path-{i}",
                    nodes=path_nodes,
                    edges=path_edges,
                    events=path_events,
                    source_node=source_entity,
                    target_node=target_entity,
                    path_length=len(path_nodes) - 1,
                    is_shortest=(i == 0)
                )

                paths.append(attack_path)

        except nx.NetworkXNoPath:
            logger.info(f"No path found from {source_entity} to {target_entity}")
            return []
        except Exception as e:
            logger.error(f"Error finding paths: {e}")
            return []

        logger.info(f"Found {len(paths)} attack paths")
        return paths

    def identify_lateral_movement(
        self,
        min_hops: int = 2,
        time_window_minutes: int = 60
    ) -> List[LateralMovement]:
        """
        Identify lateral movement patterns.

        Detects multi-hop patterns where principals access multiple
        resources in sequence, potentially indicating lateral movement.

        Args:
            min_hops: Minimum number of hops to consider
            time_window_minutes: Time window for related events

        Returns:
            List of detected lateral movement patterns
        """
        if self.graph.number_of_nodes() == 0:
            logger.warning("Cannot identify lateral movement on empty graph")
            return []

        logger.info("Identifying lateral movement patterns")

        movements = []
        movement_id = 0

        # Find all principal nodes
        principal_nodes = [
            n for n, d in self.graph.nodes(data=True)
            if d.get('type') == 'principal'
        ]

        for principal in principal_nodes:
            # Get all paths from this principal with length >= min_hops
            for target in self.graph.nodes():
                if target == principal:
                    continue

                try:
                    # Find simple paths
                    for path in nx.all_simple_paths(
                        self.graph,
                        principal,
                        target,
                        cutoff=min_hops + 2  # Limit search depth
                    ):
                        if len(path) - 1 < min_hops:
                            continue

                        # Create hops
                        hops = [(path[i], path[i+1]) for i in range(len(path) - 1)]

                        # Gather events for this movement
                        movement_events = []
                        for hop in hops:
                            if hop in self.events_by_edge:
                                movement_events.extend(self.events_by_edge[hop])

                        # Check if events are within time window
                        if not movement_events:
                            continue

                        movement_events.sort(key=lambda e: e.timestamp)
                        time_span = (movement_events[-1].timestamp -
                                   movement_events[0].timestamp).total_seconds() / 60

                        if time_span > time_window_minutes:
                            continue

                        # Create lateral movement
                        movement = LateralMovement(
                            movement_id=f"movement-{movement_id}",
                            hops=hops,
                            num_hops=len(hops),
                            events=movement_events,
                            start_time=movement_events[0].timestamp,
                            end_time=movement_events[-1].timestamp
                        )

                        # Extract entities
                        for node in path:
                            node_type = self.graph.nodes[node].get('type', '')
                            if node_type == 'principal':
                                movement.principals.add(node.replace('principal:', ''))
                            elif node_type == 'ip':
                                movement.source_ips.add(node.replace('ip:', ''))
                            elif node_type == 'resource':
                                movement.resources.add(node.replace('resource:', ''))

                        movements.append(movement)
                        movement_id += 1

                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue

        logger.info(f"Identified {len(movements)} lateral movement patterns")
        return movements

    def export_to_graphml(self, output_path: Path) -> None:
        """
        Export graph to GraphML format for visualization tools.

        Args:
            output_path: Path to output GraphML file
        """
        if self.graph.number_of_nodes() == 0:
            logger.warning("Cannot export empty graph")
            return

        logger.info(f"Exporting graph to GraphML: {output_path}")

        # Convert timestamps to strings for GraphML compatibility
        graph_copy = self.graph.copy()

        for node in graph_copy.nodes():
            for attr in ['first_seen', 'last_seen']:
                if attr in graph_copy.nodes[node]:
                    graph_copy.nodes[node][attr] = str(graph_copy.nodes[node][attr])

        for u, v in graph_copy.edges():
            if 'timestamps' in graph_copy[u][v]:
                graph_copy[u][v]['timestamps'] = ','.join(
                    str(ts) for ts in graph_copy[u][v]['timestamps']
                )
            if 'event_types' in graph_copy[u][v]:
                graph_copy[u][v]['event_types'] = ','.join(
                    graph_copy[u][v]['event_types']
                )
            if 'first_event' in graph_copy[u][v]:
                graph_copy[u][v]['first_event'] = str(graph_copy[u][v]['first_event'])

        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write GraphML
        nx.write_graphml(graph_copy, str(output_path))

        logger.info(f"Graph exported to {output_path}")

    def generate_graph_summary(self) -> Dict[str, Any]:
        """
        Generate summary statistics about the attack graph.

        Returns:
            Dictionary with graph statistics and metrics
        """
        if self.graph.number_of_nodes() == 0:
            return {
                "nodes": 0,
                "edges": 0,
                "error": "Empty graph"
            }

        # Basic stats
        summary = {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "density": nx.density(self.graph),
        }

        # Node type breakdown
        node_types = defaultdict(int)
        for node, data in self.graph.nodes(data=True):
            node_types[data.get('type', 'unknown')] += 1
        summary["node_types"] = dict(node_types)

        # Connectivity
        if nx.is_weakly_connected(self.graph):
            summary["is_connected"] = True
            summary["diameter"] = nx.diameter(self.graph.to_undirected())
        else:
            summary["is_connected"] = False
            summary["num_components"] = nx.number_weakly_connected_components(self.graph)

        # Degree statistics
        degrees = [d for n, d in self.graph.degree()]
        if degrees:
            summary["avg_degree"] = sum(degrees) / len(degrees)
            summary["max_degree"] = max(degrees)
            summary["min_degree"] = min(degrees)

        # Top nodes by degree
        top_nodes = sorted(
            self.graph.degree(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        summary["top_nodes_by_degree"] = [
            {"node": n, "degree": d} for n, d in top_nodes
        ]

        return summary
