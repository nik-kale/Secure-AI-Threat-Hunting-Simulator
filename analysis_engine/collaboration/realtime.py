"""Real-time collaboration features for team exercises."""
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json

class MessageType(str, Enum):
    """Types of real-time messages."""
    CHAT = "chat"
    SYSTEM = "system"
    ALERT = "alert"
    ANNOTATION = "annotation"
    STATUS_UPDATE = "status_update"
    DETECTION = "detection"

class MessagePriority(str, Enum):
    """Message priority levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"

@dataclass
class Message:
    """Real-time message."""
    message_id: str
    workspace_id: str
    sender_id: str
    message_type: MessageType
    content: str
    timestamp: datetime
    priority: MessagePriority = MessagePriority.NORMAL
    thread_id: Optional[str] = None  # For threaded conversations
    mentions: List[str] = field(default_factory=list)
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class UserPresence:
    """User presence status."""
    user_id: str
    status: str  # online, away, busy, offline
    last_seen: datetime
    current_workspace: Optional[str] = None
    current_activity: Optional[str] = None

@dataclass
class LiveUpdate:
    """Live workspace update."""
    update_id: str
    workspace_id: str
    update_type: str  # event_detected, user_joined, objective_completed, etc.
    data: Dict[str, Any]
    timestamp: datetime

class RealtimeCollaboration:
    """Real-time collaboration system for team exercises."""

    def __init__(self):
        self.messages: Dict[str, List[Message]] = {}  # workspace_id -> messages
        self.presence: Dict[str, UserPresence] = {}  # user_id -> presence
        self.subscriptions: Dict[str, List[Callable]] = {}  # workspace_id -> callbacks
        self.typing_indicators: Dict[str, Dict[str, datetime]] = {}  # workspace_id -> {user_id: timestamp}

    def send_message(
        self,
        workspace_id: str,
        sender_id: str,
        content: str,
        message_type: MessageType = MessageType.CHAT,
        priority: MessagePriority = MessagePriority.NORMAL,
        thread_id: Optional[str] = None,
        mentions: Optional[List[str]] = None,
        attachments: Optional[List[Dict[str, Any]]] = None
    ) -> Message:
        """Send a message to workspace.

        Args:
            workspace_id: Target workspace
            sender_id: User sending message
            content: Message content
            message_type: Type of message
            priority: Message priority
            thread_id: Optional thread for replies
            mentions: Users mentioned in message
            attachments: File attachments

        Returns:
            Created message
        """
        if workspace_id not in self.messages:
            self.messages[workspace_id] = []

        message_id = f"msg-{workspace_id}-{len(self.messages[workspace_id]):06d}"

        message = Message(
            message_id=message_id,
            workspace_id=workspace_id,
            sender_id=sender_id,
            message_type=message_type,
            content=content,
            timestamp=datetime.now(),
            priority=priority,
            thread_id=thread_id,
            mentions=mentions or [],
            attachments=attachments or []
        )

        self.messages[workspace_id].append(message)

        # Notify subscribers
        self._notify_subscribers(workspace_id, "message", message)

        return message

    def get_messages(
        self,
        workspace_id: str,
        limit: int = 50,
        since: Optional[datetime] = None,
        message_type: Optional[MessageType] = None
    ) -> List[Message]:
        """Get messages from workspace.

        Args:
            workspace_id: Workspace ID
            limit: Maximum messages to return
            since: Only messages after this time
            message_type: Filter by message type

        Returns:
            List of messages
        """
        messages = self.messages.get(workspace_id, [])

        # Filter by timestamp
        if since:
            messages = [m for m in messages if m.timestamp > since]

        # Filter by type
        if message_type:
            messages = [m for m in messages if m.message_type == message_type]

        # Return most recent messages
        return sorted(messages, key=lambda m: m.timestamp, reverse=True)[:limit]

    def update_presence(
        self,
        user_id: str,
        status: str,
        workspace_id: Optional[str] = None,
        activity: Optional[str] = None
    ):
        """Update user presence status.

        Args:
            user_id: User ID
            status: Presence status
            workspace_id: Current workspace
            activity: Current activity
        """
        self.presence[user_id] = UserPresence(
            user_id=user_id,
            status=status,
            last_seen=datetime.now(),
            current_workspace=workspace_id,
            current_activity=activity
        )

        # Notify workspace of presence change
        if workspace_id:
            self._notify_subscribers(
                workspace_id,
                "presence_update",
                {"user_id": user_id, "status": status, "activity": activity}
            )

    def get_workspace_users(self, workspace_id: str) -> List[UserPresence]:
        """Get all users currently in workspace.

        Args:
            workspace_id: Workspace ID

        Returns:
            List of user presence info
        """
        return [
            presence for presence in self.presence.values()
            if presence.current_workspace == workspace_id
        ]

    def set_typing_indicator(self, workspace_id: str, user_id: str, is_typing: bool):
        """Set typing indicator for user.

        Args:
            workspace_id: Workspace ID
            user_id: User ID
            is_typing: Whether user is typing
        """
        if workspace_id not in self.typing_indicators:
            self.typing_indicators[workspace_id] = {}

        if is_typing:
            self.typing_indicators[workspace_id][user_id] = datetime.now()
        else:
            self.typing_indicators[workspace_id].pop(user_id, None)

        # Notify subscribers
        self._notify_subscribers(
            workspace_id,
            "typing",
            {"user_id": user_id, "is_typing": is_typing}
        )

    def get_typing_users(self, workspace_id: str) -> List[str]:
        """Get users currently typing in workspace.

        Args:
            workspace_id: Workspace ID

        Returns:
            List of user IDs currently typing
        """
        if workspace_id not in self.typing_indicators:
            return []

        # Remove stale typing indicators (>10 seconds old)
        now = datetime.now()
        stale_users = [
            user_id for user_id, timestamp in self.typing_indicators[workspace_id].items()
            if (now - timestamp).total_seconds() > 10
        ]
        for user_id in stale_users:
            del self.typing_indicators[workspace_id][user_id]

        return list(self.typing_indicators[workspace_id].keys())

    def send_system_alert(
        self,
        workspace_id: str,
        alert_type: str,
        message: str,
        priority: MessagePriority = MessagePriority.HIGH,
        data: Optional[Dict[str, Any]] = None
    ) -> Message:
        """Send system alert to workspace.

        Args:
            workspace_id: Target workspace
            alert_type: Type of alert
            message: Alert message
            priority: Alert priority
            data: Additional alert data

        Returns:
            Created alert message
        """
        alert_msg = self.send_message(
            workspace_id=workspace_id,
            sender_id="system",
            content=message,
            message_type=MessageType.ALERT,
            priority=priority
        )

        alert_msg.metadata = {
            "alert_type": alert_type,
            "data": data or {}
        }

        return alert_msg

    def annotate_event(
        self,
        workspace_id: str,
        user_id: str,
        event_id: str,
        annotation: str,
        tags: Optional[List[str]] = None
    ) -> Message:
        """Add annotation to an event.

        Args:
            workspace_id: Workspace ID
            user_id: User adding annotation
            event_id: Event being annotated
            annotation: Annotation text
            tags: Optional tags

        Returns:
            Annotation message
        """
        return self.send_message(
            workspace_id=workspace_id,
            sender_id=user_id,
            content=annotation,
            message_type=MessageType.ANNOTATION,
            attachments=[{
                "type": "event_reference",
                "event_id": event_id,
                "tags": tags or []
            }]
        )

    def subscribe(self, workspace_id: str, callback: Callable[[str, Any], None]):
        """Subscribe to workspace updates.

        Args:
            workspace_id: Workspace to subscribe to
            callback: Function called on updates, receives (event_type, data)
        """
        if workspace_id not in self.subscriptions:
            self.subscriptions[workspace_id] = []

        self.subscriptions[workspace_id].append(callback)

    def unsubscribe(self, workspace_id: str, callback: Callable):
        """Unsubscribe from workspace updates.

        Args:
            workspace_id: Workspace ID
            callback: Callback to remove
        """
        if workspace_id in self.subscriptions:
            self.subscriptions[workspace_id].remove(callback)

    def _notify_subscribers(self, workspace_id: str, event_type: str, data: Any):
        """Notify subscribers of workspace event.

        Args:
            workspace_id: Workspace ID
            event_type: Type of event
            data: Event data
        """
        if workspace_id not in self.subscriptions:
            return

        for callback in self.subscriptions[workspace_id]:
            try:
                callback(event_type, data)
            except Exception as e:
                # Log error but don't fail
                print(f"Error in subscriber callback: {e}")

    def broadcast_detection(
        self,
        workspace_id: str,
        detection_name: str,
        severity: str,
        event_count: int,
        mitre_techniques: List[str],
        summary: str
    ) -> Message:
        """Broadcast detection to workspace.

        Args:
            workspace_id: Target workspace
            detection_name: Detection rule name
            severity: Severity level
            event_count: Number of events
            mitre_techniques: MITRE techniques detected
            summary: Detection summary

        Returns:
            Detection message
        """
        priority_map = {
            "low": MessagePriority.LOW,
            "medium": MessagePriority.NORMAL,
            "high": MessagePriority.HIGH,
            "critical": MessagePriority.URGENT
        }

        message = self.send_message(
            workspace_id=workspace_id,
            sender_id="detection_engine",
            content=f"**{detection_name}**\n{summary}",
            message_type=MessageType.DETECTION,
            priority=priority_map.get(severity.lower(), MessagePriority.NORMAL)
        )

        message.metadata = {
            "detection_name": detection_name,
            "severity": severity,
            "event_count": event_count,
            "mitre_techniques": mitre_techniques,
            "timestamp": datetime.now().isoformat()
        }

        return message

    def create_thread(
        self,
        workspace_id: str,
        parent_message_id: str,
        user_id: str,
        content: str
    ) -> Message:
        """Create threaded reply to message.

        Args:
            workspace_id: Workspace ID
            parent_message_id: Message being replied to
            user_id: User replying
            content: Reply content

        Returns:
            Reply message
        """
        return self.send_message(
            workspace_id=workspace_id,
            sender_id=user_id,
            content=content,
            thread_id=parent_message_id
        )

    def get_thread(self, workspace_id: str, thread_id: str) -> List[Message]:
        """Get all messages in a thread.

        Args:
            workspace_id: Workspace ID
            thread_id: Thread ID (parent message ID)

        Returns:
            List of messages in thread
        """
        messages = self.messages.get(workspace_id, [])
        thread_messages = [
            m for m in messages
            if m.message_id == thread_id or m.thread_id == thread_id
        ]
        return sorted(thread_messages, key=lambda m: m.timestamp)

    def search_messages(
        self,
        workspace_id: str,
        query: str,
        limit: int = 20
    ) -> List[Message]:
        """Search messages in workspace.

        Args:
            workspace_id: Workspace to search
            query: Search query
            limit: Maximum results

        Returns:
            Matching messages
        """
        messages = self.messages.get(workspace_id, [])
        query_lower = query.lower()

        matches = [
            m for m in messages
            if query_lower in m.content.lower() or query_lower in m.sender_id.lower()
        ]

        return sorted(matches, key=lambda m: m.timestamp, reverse=True)[:limit]

    def get_mentions(self, workspace_id: str, user_id: str) -> List[Message]:
        """Get messages mentioning a user.

        Args:
            workspace_id: Workspace ID
            user_id: User to find mentions of

        Returns:
            Messages mentioning the user
        """
        messages = self.messages.get(workspace_id, [])
        return [m for m in messages if user_id in m.mentions]

    def mark_as_read(self, message_ids: List[str], user_id: str):
        """Mark messages as read by user.

        Args:
            message_ids: Messages to mark as read
            user_id: User marking as read
        """
        # In production, this would update a read receipts table
        # For now, we just track in metadata
        for workspace_messages in self.messages.values():
            for message in workspace_messages:
                if message.message_id in message_ids:
                    if "read_by" not in message.metadata:
                        message.metadata["read_by"] = []
                    if user_id not in message.metadata["read_by"]:
                        message.metadata["read_by"].append(user_id)
