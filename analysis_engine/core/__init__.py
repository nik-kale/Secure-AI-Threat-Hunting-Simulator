"""Analysis engine core modules."""
from .loader import TelemetryLoader
from .parser import EventParser, NormalizedEvent
from .correlation import EventCorrelator, CorrelationSession
from .kill_chain import KillChainMapper, KillChainStage
from .mitre_mapper import MitreMapper, MitreTechnique
from .streaming import (
    StreamingTelemetryLoader,
    StreamingProgress,
    merge_sessions,
)

# Graph correlation (optional, requires networkx)
try:
    from .graph_correlation import (
        GraphCorrelator,
        AttackCampaign,
        PivotPoint,
        AttackPath,
        LateralMovement,
    )
    GRAPH_CORRELATION_AVAILABLE = True
except ImportError:
    GraphCorrelator = None
    AttackCampaign = None
    PivotPoint = None
    AttackPath = None
    LateralMovement = None
    GRAPH_CORRELATION_AVAILABLE = False

__all__ = [
    "TelemetryLoader",
    "EventParser",
    "NormalizedEvent",
    "EventCorrelator",
    "CorrelationSession",
    "KillChainMapper",
    "KillChainStage",
    "MitreMapper",
    "MitreTechnique",
    "StreamingTelemetryLoader",
    "StreamingProgress",
    "merge_sessions",
    "GraphCorrelator",
    "AttackCampaign",
    "PivotPoint",
    "AttackPath",
    "LateralMovement",
    "GRAPH_CORRELATION_AVAILABLE",
]
