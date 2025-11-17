"""Advanced attack path analysis and blast radius calculation."""
from typing import List, Dict, Any, Set
from dataclasses import dataclass

@dataclass
class AttackPath:
    """Attack path between entities."""
    start: str
    end: str
    path: List[str]
    risk_score: float
    hops: int

@dataclass
class BlastRadius:
    """Blast radius from compromised entity."""
    origin: str
    affected_entities: Set[str]
    affected_resources: Set[str]
    radius_score: float
    impact: str

class AttackPathAnalyzer:
    """Analyzes attack paths through entity graph."""

    def __init__(self):
        self.graph = {}

    def build_from_events(self, events: List[Dict[str, Any]]):
        """Build graph from events."""
        for event in events:
            src = event.get('principal', '')
            dst = event.get('resource', '')
            if src and dst:
                if src not in self.graph:
                    self.graph[src] = set()
                self.graph[src].add(dst)

    def find_paths(self, start: str, end: str, max_hops: int = 10) -> List[AttackPath]:
        """Find attack paths."""
        paths = []
        visited = set()

        def dfs(current, target, path, hops):
            if hops > max_hops or current in visited:
                return
            if current == target:
                paths.append(AttackPath(
                    start=start, end=end, path=path[:],
                    risk_score=0.5, hops=len(path)-1
                ))
                return
            visited.add(current)
            for neighbor in self.graph.get(current, []):
                path.append(neighbor)
                dfs(neighbor, target, path, hops+1)
                path.pop()
            visited.remove(current)

        dfs(start, end, [start], 0)
        return paths[:50]

    def calculate_blast_radius(self, entity: str, max_radius: int = 5) -> BlastRadius:
        """Calculate blast radius."""
        affected = set([entity])
        resources = set()

        from collections import deque
        queue = deque([(entity, 0)])
        visited = set()

        while queue:
            current, dist = queue.popleft()
            if dist >= max_radius or current in visited:
                continue
            visited.add(current)
            for neighbor in self.graph.get(current, []):
                affected.add(neighbor)
                resources.add(neighbor)
                queue.append((neighbor, dist+1))

        return BlastRadius(
            origin=entity,
            affected_entities=affected,
            affected_resources=resources,
            radius_score=len(affected)/100.0,
            impact='high' if len(affected) > 20 else 'medium'
        )
