"""
Behavioral baseline learning for user and entity behavior analytics (UEBA).

Learns normal behavior patterns and detects deviations that may indicate
compromised accounts or insider threats.
"""
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import statistics
import logging

logger = logging.getLogger(__name__)


@dataclass
class BaselineProfile:
    """Behavioral baseline profile for an entity (user, service, resource)."""
    entity_id: str
    entity_type: str  # 'user', 'service_account', 'resource'

    # Activity patterns
    typical_hours: Set[int] = field(default_factory=set)
    typical_days: Set[int] = field(default_factory=set)
    avg_events_per_hour: float = 0.0
    max_events_per_hour: float = 0.0

    # Behavior patterns
    typical_actions: Counter = field(default_factory=Counter)
    typical_resources: Set[str] = field(default_factory=set)
    typical_event_types: Counter = field(default_factory=Counter)
    typical_source_ips: Set[str] = field(default_factory=set)

    # Geo patterns
    typical_locations: Set[str] = field(default_factory=set)

    # Success/failure ratios
    success_rate: float = 1.0
    typical_failure_rate: float = 0.0

    # Training metadata
    training_period_days: int = 0
    total_events_analyzed: int = 0
    last_updated: Optional[datetime] = None
    confidence_score: float = 0.0  # 0.0 to 1.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert profile to dictionary."""
        return {
            'entity_id': self.entity_id,
            'entity_type': self.entity_type,
            'typical_hours': list(self.typical_hours),
            'typical_days': list(self.typical_days),
            'avg_events_per_hour': self.avg_events_per_hour,
            'max_events_per_hour': self.max_events_per_hour,
            'typical_actions': dict(self.typical_actions),
            'typical_resources': list(self.typical_resources),
            'typical_event_types': dict(self.typical_event_types),
            'typical_source_ips': list(self.typical_source_ips),
            'typical_locations': list(self.typical_locations),
            'success_rate': self.success_rate,
            'typical_failure_rate': self.typical_failure_rate,
            'training_period_days': self.training_period_days,
            'total_events_analyzed': self.total_events_analyzed,
            'last_updated': self.last_updated.isoformat() if self.last_updated else None,
            'confidence_score': self.confidence_score
        }


class BehavioralBaseline:
    """
    Learns and maintains behavioral baselines for entities.

    Uses statistical analysis and pattern recognition to establish
    normal behavior profiles.
    """

    def __init__(
        self,
        min_training_events: int = 100,
        training_period_days: int = 7,
        confidence_threshold: float = 0.7
    ):
        """
        Initialize behavioral baseline learning system.

        Args:
            min_training_events: Minimum events needed for reliable baseline
            training_period_days: Days of data to use for training
            confidence_threshold: Minimum confidence for profile usage
        """
        self.min_training_events = min_training_events
        self.training_period_days = training_period_days
        self.confidence_threshold = confidence_threshold

        self.profiles: Dict[str, BaselineProfile] = {}

    def build_baseline(
        self,
        events: List[Dict[str, Any]],
        entity_key: str = 'principal'
    ) -> Dict[str, BaselineProfile]:
        """
        Build behavioral baselines from training events.

        Args:
            events: Training events
            entity_key: Key to use for entity identification

        Returns:
            Dictionary mapping entity IDs to baseline profiles
        """
        logger.info(f"Building behavioral baselines from {len(events)} events")

        # Group events by entity
        entity_events = defaultdict(list)
        for event in events:
            entity_id = event.get(entity_key, 'unknown')
            entity_events[entity_id].append(event)

        # Build profile for each entity
        for entity_id, entity_event_list in entity_events.items():
            if len(entity_event_list) < self.min_training_events:
                logger.debug(f"Skipping {entity_id}: only {len(entity_event_list)} events (need {self.min_training_events})")
                continue

            profile = self._build_entity_profile(entity_id, entity_event_list)
            self.profiles[entity_id] = profile

        logger.info(f"Built baselines for {len(self.profiles)} entities")
        return self.profiles

    def _build_entity_profile(
        self,
        entity_id: str,
        events: List[Dict[str, Any]]
    ) -> BaselineProfile:
        """Build baseline profile for a single entity."""
        profile = BaselineProfile(
            entity_id=entity_id,
            entity_type=self._infer_entity_type(entity_id, events),
            total_events_analyzed=len(events),
            last_updated=datetime.now()
        )

        # Extract temporal patterns
        hours_counter = Counter()
        days_counter = Counter()
        hourly_event_counts = defaultdict(int)

        for event in events:
            if 'timestamp' in event:
                try:
                    ts = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                    hours_counter[ts.hour] += 1
                    days_counter[ts.weekday()] += 1
                    hour_key = f"{ts.date()}_{ts.hour}"
                    hourly_event_counts[hour_key] += 1
                except:
                    pass

        # Typical hours (hours with activity in at least 25% of days)
        total_days = len(set(events[0].get('timestamp', '').split('T')[0] for events in [events]))
        profile.typical_hours = {
            hour for hour, count in hours_counter.items()
            if count / max(total_days, 1) >= 0.25
        }

        # Typical days
        profile.typical_days = {
            day for day, count in days_counter.most_common(5)
        }

        # Calculate average and max events per hour
        hourly_counts = list(hourly_event_counts.values())
        if hourly_counts:
            profile.avg_events_per_hour = statistics.mean(hourly_counts)
            profile.max_events_per_hour = max(hourly_counts)

        # Extract behavior patterns
        for event in events:
            # Actions
            action = event.get('action', '')
            if action:
                profile.typical_actions[action] += 1

            # Resources
            resource = event.get('resource', '')
            if resource:
                profile.typical_resources.add(resource)

            # Event types
            event_type = event.get('event_type', '')
            if event_type:
                profile.typical_event_types[event_type] += 1

            # Source IPs
            source_ip = event.get('source_ip', '')
            if source_ip:
                profile.typical_source_ips.add(source_ip)

            # Locations (if available)
            location = event.get('location', '')
            if location:
                profile.typical_locations.add(location)

        # Calculate success/failure ratios
        statuses = [event.get('status', '') for event in events]
        success_count = statuses.count('success')
        failed_count = statuses.count('failed')
        total_status_events = success_count + failed_count

        if total_status_events > 0:
            profile.success_rate = success_count / total_status_events
            profile.typical_failure_rate = failed_count / total_status_events

        # Calculate confidence score
        profile.confidence_score = self._calculate_confidence(profile)

        # Training period
        if events:
            try:
                first_ts = datetime.fromisoformat(events[0]['timestamp'].replace('Z', '+00:00'))
                last_ts = datetime.fromisoformat(events[-1]['timestamp'].replace('Z', '+00:00'))
                profile.training_period_days = (last_ts - first_ts).days or 1
            except:
                profile.training_period_days = 1

        return profile

    def _infer_entity_type(self, entity_id: str, events: List[Dict[str, Any]]) -> str:
        """Infer entity type from ID pattern and behavior."""
        entity_lower = entity_id.lower()

        if any(pattern in entity_lower for pattern in ['service', 'lambda', 'role', 'automation']):
            return 'service_account'
        elif any(pattern in entity_lower for pattern in ['user', 'admin', 'developer']):
            return 'user'
        else:
            # Check event patterns
            event_types = [e.get('event_type', '') for e in events]
            automated_events = sum(1 for et in event_types if 'automated' in et.lower() or 'scheduled' in et.lower())

            if automated_events / len(events) > 0.5:
                return 'service_account'
            else:
                return 'user'

    def _calculate_confidence(self, profile: BaselineProfile) -> float:
        """
        Calculate confidence score for a baseline profile.

        Based on:
        - Number of events analyzed
        - Training period length
        - Pattern diversity
        """
        confidence = 0.0

        # Event count factor (0.0 to 0.4)
        events_factor = min(profile.total_events_analyzed / (self.min_training_events * 5), 1.0) * 0.4

        # Training period factor (0.0 to 0.3)
        period_factor = min(profile.training_period_days / self.training_period_days, 1.0) * 0.3

        # Pattern diversity factor (0.0 to 0.3)
        diversity_score = 0.0
        if profile.typical_hours:
            diversity_score += 0.1
        if len(profile.typical_actions) >= 3:
            diversity_score += 0.1
        if len(profile.typical_event_types) >= 3:
            diversity_score += 0.1

        confidence = events_factor + period_factor + diversity_score

        return min(confidence, 1.0)

    def detect_deviations(
        self,
        events: List[Dict[str, Any]],
        entity_key: str = 'principal'
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Detect deviations from established baselines.

        Args:
            events: Events to analyze
            entity_key: Key to use for entity identification

        Returns:
            Dictionary mapping entity IDs to lists of deviation details
        """
        deviations = defaultdict(list)

        for event in events:
            entity_id = event.get(entity_key, 'unknown')

            if entity_id not in self.profiles:
                # No baseline - treat as potential anomaly
                deviations[entity_id].append({
                    'event': event,
                    'deviation_type': 'no_baseline',
                    'severity': 'low',
                    'description': f"No baseline profile exists for {entity_id}"
                })
                continue

            profile = self.profiles[entity_id]

            # Skip low-confidence profiles
            if profile.confidence_score < self.confidence_threshold:
                continue

            # Check for deviations
            event_deviations = self._check_event_deviations(event, profile)
            if event_deviations:
                deviations[entity_id].extend(event_deviations)

        return dict(deviations)

    def _check_event_deviations(
        self,
        event: Dict[str, Any],
        profile: BaselineProfile
    ) -> List[Dict[str, Any]]:
        """Check a single event for deviations from profile."""
        deviations = []

        # Temporal deviations
        if 'timestamp' in event:
            try:
                ts = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))

                # Unusual hour
                if ts.hour not in profile.typical_hours and len(profile.typical_hours) > 0:
                    deviations.append({
                        'event': event,
                        'deviation_type': 'unusual_time',
                        'severity': 'medium',
                        'description': f"Activity at hour {ts.hour} outside typical hours {sorted(profile.typical_hours)}",
                        'confidence': profile.confidence_score
                    })

                # Unusual day
                if ts.weekday() not in profile.typical_days and len(profile.typical_days) > 0:
                    deviations.append({
                        'event': event,
                        'deviation_type': 'unusual_day',
                        'severity': 'low',
                        'description': f"Activity on {ts.strftime('%A')} outside typical days",
                        'confidence': profile.confidence_score
                    })
            except:
                pass

        # Behavioral deviations
        action = event.get('action', '')
        if action and action not in profile.typical_actions:
            deviations.append({
                'event': event,
                'deviation_type': 'new_action',
                'severity': 'medium',
                'description': f"New action '{action}' not seen in baseline",
                'confidence': profile.confidence_score
            })

        # Resource access deviations
        resource = event.get('resource', '')
        if resource and resource not in profile.typical_resources and len(profile.typical_resources) > 0:
            deviations.append({
                'event': event,
                'deviation_type': 'new_resource',
                'severity': 'medium',
                'description': f"Access to new resource '{resource}'",
                'confidence': profile.confidence_score
            })

        # Event type deviations
        event_type = event.get('event_type', '')
        if event_type and event_type not in profile.typical_event_types:
            deviations.append({
                'event': event,
                'deviation_type': 'new_event_type',
                'severity': 'low',
                'description': f"New event type '{event_type}'",
                'confidence': profile.confidence_score
            })

        # Source IP deviations
        source_ip = event.get('source_ip', '')
        if source_ip and source_ip not in profile.typical_source_ips and len(profile.typical_source_ips) > 0:
            deviations.append({
                'event': event,
                'deviation_type': 'new_source_ip',
                'severity': 'high',
                'description': f"Activity from new IP address '{source_ip}'",
                'confidence': profile.confidence_score
            })

        # Failure rate deviations
        if event.get('status') == 'failed':
            # High failure rate might indicate brute force
            if profile.typical_failure_rate < 0.1:  # Normally low failures
                deviations.append({
                    'event': event,
                    'deviation_type': 'unusual_failure',
                    'severity': 'high',
                    'description': "Failed event from entity with normally high success rate",
                    'confidence': profile.confidence_score
                })

        return deviations

    def get_profile(self, entity_id: str) -> Optional[BaselineProfile]:
        """Get baseline profile for an entity."""
        return self.profiles.get(entity_id)

    def update_baseline(
        self,
        entity_id: str,
        new_events: List[Dict[str, Any]]
    ) -> BaselineProfile:
        """
        Update existing baseline with new events (incremental learning).

        Args:
            entity_id: Entity ID to update
            new_events: New events to incorporate

        Returns:
            Updated baseline profile
        """
        if entity_id in self.profiles:
            # Merge with existing profile
            existing_events_count = self.profiles[entity_id].total_events_analyzed

            # Simple approach: rebuild with all events (could be optimized for incremental updates)
            all_events_count = existing_events_count + len(new_events)

            if all_events_count >= self.min_training_events:
                # Rebuild profile (in production, this would be incremental)
                new_profile = self._build_entity_profile(entity_id, new_events)
                self.profiles[entity_id] = new_profile
                return new_profile
        else:
            # Build new profile
            if len(new_events) >= self.min_training_events:
                new_profile = self._build_entity_profile(entity_id, new_events)
                self.profiles[entity_id] = new_profile
                return new_profile

        return self.profiles.get(entity_id)

    def export_profiles(self) -> List[Dict[str, Any]]:
        """Export all profiles to serializable format."""
        return [profile.to_dict() for profile in self.profiles.values()]

    def import_profiles(self, profiles_data: List[Dict[str, Any]]):
        """Import profiles from serialized format."""
        for data in profiles_data:
            profile = BaselineProfile(
                entity_id=data['entity_id'],
                entity_type=data['entity_type'],
                typical_hours=set(data.get('typical_hours', [])),
                typical_days=set(data.get('typical_days', [])),
                avg_events_per_hour=data.get('avg_events_per_hour', 0.0),
                max_events_per_hour=data.get('max_events_per_hour', 0.0),
                typical_actions=Counter(data.get('typical_actions', {})),
                typical_resources=set(data.get('typical_resources', [])),
                typical_event_types=Counter(data.get('typical_event_types', {})),
                typical_source_ips=set(data.get('typical_source_ips', [])),
                typical_locations=set(data.get('typical_locations', [])),
                success_rate=data.get('success_rate', 1.0),
                typical_failure_rate=data.get('typical_failure_rate', 0.0),
                training_period_days=data.get('training_period_days', 0),
                total_events_analyzed=data.get('total_events_analyzed', 0),
                confidence_score=data.get('confidence_score', 0.0)
            )

            if data.get('last_updated'):
                profile.last_updated = datetime.fromisoformat(data['last_updated'])

            self.profiles[profile.entity_id] = profile

        logger.info(f"Imported {len(profiles_data)} behavioral profiles")
