"""
WebSocket support for real-time telemetry streaming.

Provides:
- Real-time scenario generation streaming
- Live analysis progress updates
- Event stream broadcasting
- Connection management
"""
from fastapi import WebSocket, WebSocketDisconnect
from typing import List, Dict, Any, Set
import asyncio
import json
import logging
import time
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class MessageType(str, Enum):
    """WebSocket message types."""
    SCENARIO_START = "scenario_start"
    EVENT_GENERATED = "event_generated"
    EVENT_BATCH = "event_batch"
    ANALYSIS_START = "analysis_start"
    ANALYSIS_PROGRESS = "analysis_progress"
    ANALYSIS_COMPLETE = "analysis_complete"
    SESSION_DETECTED = "session_detected"
    ERROR = "error"
    HEARTBEAT = "heartbeat"


class ConnectionManager:
    """
    Manages WebSocket connections for real-time streaming.

    Supports:
    - Multiple concurrent connections
    - Topic-based subscriptions
    - Broadcast and targeted messaging
    - Connection health monitoring
    """

    def __init__(self):
        """Initialize connection manager."""
        self.active_connections: List[WebSocket] = []
        self.subscriptions: Dict[str, Set[WebSocket]] = {}
        self.connection_metadata: Dict[WebSocket, Dict[str, Any]] = {}

    async def connect(self, websocket: WebSocket, client_id: str = None):
        """
        Accept and register a new WebSocket connection.

        Args:
            websocket: WebSocket connection
            client_id: Optional client identifier
        """
        await websocket.accept()
        self.active_connections.append(websocket)

        # Store connection metadata
        self.connection_metadata[websocket] = {
            "client_id": client_id or f"client_{len(self.active_connections)}",
            "connected_at": datetime.now().isoformat(),
            "subscriptions": set()
        }

        logger.info(
            f"WebSocket connected: {self.connection_metadata[websocket]['client_id']} "
            f"(total: {len(self.active_connections)})"
        )

    def disconnect(self, websocket: WebSocket):
        """
        Remove a WebSocket connection.

        Args:
            websocket: WebSocket to disconnect
        """
        # Remove from active connections
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

        # Remove from all subscriptions
        for topic in list(self.subscriptions.keys()):
            if websocket in self.subscriptions[topic]:
                self.subscriptions[topic].remove(websocket)
                if not self.subscriptions[topic]:
                    del self.subscriptions[topic]

        # Remove metadata
        client_id = self.connection_metadata.get(websocket, {}).get("client_id", "unknown")
        if websocket in self.connection_metadata:
            del self.connection_metadata[websocket]

        logger.info(
            f"WebSocket disconnected: {client_id} "
            f"(remaining: {len(self.active_connections)})"
        )

    async def subscribe(self, websocket: WebSocket, topic: str):
        """
        Subscribe a connection to a topic.

        Args:
            websocket: WebSocket connection
            topic: Topic to subscribe to
        """
        if topic not in self.subscriptions:
            self.subscriptions[topic] = set()

        self.subscriptions[topic].add(websocket)

        if websocket in self.connection_metadata:
            self.connection_metadata[websocket]["subscriptions"].add(topic)

        logger.debug(f"Client subscribed to topic: {topic}")

    async def unsubscribe(self, websocket: WebSocket, topic: str):
        """
        Unsubscribe a connection from a topic.

        Args:
            websocket: WebSocket connection
            topic: Topic to unsubscribe from
        """
        if topic in self.subscriptions and websocket in self.subscriptions[topic]:
            self.subscriptions[topic].remove(websocket)

            if not self.subscriptions[topic]:
                del self.subscriptions[topic]

        if websocket in self.connection_metadata:
            self.connection_metadata[websocket]["subscriptions"].discard(topic)

        logger.debug(f"Client unsubscribed from topic: {topic}")

    async def send_personal_message(self, message: Dict[str, Any], websocket: WebSocket):
        """
        Send message to a specific connection.

        Args:
            message: Message to send
            websocket: Target WebSocket
        """
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            self.disconnect(websocket)

    async def broadcast(self, message: Dict[str, Any], topic: str = None):
        """
        Broadcast message to all connections or topic subscribers.

        Args:
            message: Message to broadcast
            topic: Optional topic for targeted broadcast
        """
        # Determine recipients
        recipients = (
            self.subscriptions.get(topic, set())
            if topic
            else self.active_connections
        )

        # Send to all recipients
        disconnected = []
        for connection in recipients:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Failed to broadcast to connection: {e}")
                disconnected.append(connection)

        # Clean up disconnected
        for connection in disconnected:
            self.disconnect(connection)

    async def send_heartbeat(self):
        """Send heartbeat to all connections."""
        message = {
            "type": MessageType.HEARTBEAT,
            "timestamp": datetime.now().isoformat(),
            "active_connections": len(self.active_connections)
        }
        await self.broadcast(message)

    def get_stats(self) -> Dict[str, Any]:
        """
        Get connection statistics.

        Returns:
            Statistics dictionary
        """
        return {
            "total_connections": len(self.active_connections),
            "total_topics": len(self.subscriptions),
            "topics": {
                topic: len(subscribers)
                for topic, subscribers in self.subscriptions.items()
            }
        }


# Global connection manager instance
manager = ConnectionManager()


class StreamingScenarioGenerator:
    """
    Generator that streams scenario events via WebSocket.

    Wraps existing scenario generators to provide real-time streaming.
    """

    def __init__(self, websocket: WebSocket, scenario_name: str):
        """
        Initialize streaming generator.

        Args:
            websocket: WebSocket connection for streaming
            scenario_name: Name of scenario to generate
        """
        self.websocket = websocket
        self.scenario_name = scenario_name
        self.event_count = 0
        self.batch_size = 10  # Send events in batches

    async def stream_scenario(self) -> Dict[str, Any]:
        """
        Generate and stream scenario events.

        Returns:
            Summary of generated scenario
        """
        try:
            # Send start message
            await manager.send_personal_message({
                "type": MessageType.SCENARIO_START,
                "scenario_name": self.scenario_name,
                "timestamp": datetime.now().isoformat()
            }, self.websocket)

            # Import and run scenario generator
            # This is a simplified example - in production, integrate with actual generators
            from pathlib import Path
            import importlib.util

            scenario_module_path = (
                Path("generator/attack_traces") /
                self.scenario_name /
                "generator.py"
            )

            if not scenario_module_path.exists():
                raise ValueError(f"Scenario '{self.scenario_name}' not found")

            # Load scenario module dynamically
            spec = importlib.util.spec_from_file_location(
                f"{self.scenario_name}_generator",
                scenario_module_path
            )
            scenario_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(scenario_module)

            # Get generator class
            generator_class = getattr(scenario_module, "ScenarioGenerator", None)
            if not generator_class:
                raise ValueError(f"No ScenarioGenerator found in {self.scenario_name}")

            # Initialize generator
            generator = generator_class()

            # Generate events and stream
            events_batch = []

            # This is a simplified streaming approach
            # In production, modify generators to yield events one by one
            events = generator.generate()

            for event in events:
                events_batch.append(event)
                self.event_count += 1

                # Send batch when full
                if len(events_batch) >= self.batch_size:
                    await manager.send_personal_message({
                        "type": MessageType.EVENT_BATCH,
                        "events": events_batch,
                        "total_count": self.event_count
                    }, self.websocket)
                    events_batch = []

                    # Small delay for rate limiting
                    await asyncio.sleep(0.1)

            # Send remaining events
            if events_batch:
                await manager.send_personal_message({
                    "type": MessageType.EVENT_BATCH,
                    "events": events_batch,
                    "total_count": self.event_count
                }, self.websocket)

            # Send completion message
            summary = {
                "type": MessageType.SCENARIO_START,
                "scenario_name": self.scenario_name,
                "total_events": self.event_count,
                "timestamp": datetime.now().isoformat()
            }

            await manager.send_personal_message(summary, self.websocket)

            return summary

        except Exception as e:
            logger.error(f"Scenario streaming failed: {e}", exc_info=True)

            # Send error message
            await manager.send_personal_message({
                "type": MessageType.ERROR,
                "error": str(e),
                "scenario_name": self.scenario_name
            }, self.websocket)

            raise


class StreamingAnalyzer:
    """
    Analyzer that streams analysis progress via WebSocket.

    Wraps the analysis pipeline to provide real-time updates.
    """

    def __init__(self, websocket: WebSocket, pipeline):
        """
        Initialize streaming analyzer.

        Args:
            websocket: WebSocket connection for streaming
            pipeline: Analysis pipeline instance
        """
        self.websocket = websocket
        self.pipeline = pipeline

    async def stream_analysis(self, telemetry_path: str) -> Dict[str, Any]:
        """
        Analyze telemetry and stream progress.

        Args:
            telemetry_path: Path to telemetry file

        Returns:
            Analysis results
        """
        try:
            # Send start message
            await manager.send_personal_message({
                "type": MessageType.ANALYSIS_START,
                "telemetry_path": telemetry_path,
                "timestamp": datetime.now().isoformat()
            }, self.websocket)

            # Run analysis (this is blocking - in production, make it async)
            # For now, we'll run it and send periodic updates
            start_time = time.time()

            # Simulate progress updates during analysis
            async def send_progress_updates():
                """Send periodic progress updates."""
                for progress in range(0, 101, 20):
                    await manager.send_personal_message({
                        "type": MessageType.ANALYSIS_PROGRESS,
                        "progress_percent": progress,
                        "elapsed_seconds": round(time.time() - start_time, 2)
                    }, self.websocket)
                    await asyncio.sleep(1)

            # Run progress updates in background
            progress_task = asyncio.create_task(send_progress_updates())

            # Run actual analysis in executor to avoid blocking
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(
                None,
                self.pipeline.analyze_telemetry_file,
                telemetry_path
            )

            # Cancel progress updates
            progress_task.cancel()

            # Stream detected sessions
            for session in results.get("sessions", []):
                await manager.send_personal_message({
                    "type": MessageType.SESSION_DETECTED,
                    "session": session
                }, self.websocket)

            # Send completion message
            await manager.send_personal_message({
                "type": MessageType.ANALYSIS_COMPLETE,
                "results": results,
                "duration_seconds": round(time.time() - start_time, 2)
            }, self.websocket)

            return results

        except Exception as e:
            logger.error(f"Analysis streaming failed: {e}", exc_info=True)

            # Send error message
            await manager.send_personal_message({
                "type": MessageType.ERROR,
                "error": str(e)
            }, self.websocket)

            raise


async def heartbeat_task():
    """Background task to send periodic heartbeats."""
    while True:
        try:
            await manager.send_heartbeat()
            await asyncio.sleep(30)  # Every 30 seconds
        except Exception as e:
            logger.error(f"Heartbeat failed: {e}")
            await asyncio.sleep(30)
