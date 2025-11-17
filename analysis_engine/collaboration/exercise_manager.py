"""Exercise management and scheduling for team training."""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

class ExerciseType(str, Enum):
    """Types of security exercises."""
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    PURPLE_TEAM = "purple_team"
    CTF = "ctf"
    TABLETOP = "tabletop"
    INCIDENT_RESPONSE_DRILL = "incident_response_drill"

class ExerciseStatus(str, Enum):
    """Exercise lifecycle status."""
    SCHEDULED = "scheduled"
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"

@dataclass
class Participant:
    """Exercise participant."""
    user_id: str
    role: str
    team: str  # red, blue, purple, observer
    joined_at: Optional[datetime] = None
    score: float = 0.0

@dataclass
class ExerciseObjective:
    """Exercise learning objective."""
    objective_id: str
    description: str
    mitre_techniques: List[str]
    success_criteria: str
    achieved: bool = False

@dataclass
class ExerciseEvent:
    """Event that occurred during exercise."""
    event_id: str
    timestamp: datetime
    event_type: str
    actor: str  # user_id
    action: str
    target: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Exercise:
    """Security training exercise."""
    exercise_id: str
    title: str
    description: str
    exercise_type: ExerciseType
    status: ExerciseStatus
    created_by: str
    created_at: datetime
    scheduled_start: datetime
    scheduled_end: datetime
    actual_start: Optional[datetime] = None
    actual_end: Optional[datetime] = None
    participants: List[Participant] = field(default_factory=list)
    objectives: List[ExerciseObjective] = field(default_factory=list)
    events: List[ExerciseEvent] = field(default_factory=list)
    scenario_config: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ExerciseTemplate:
    """Reusable exercise template."""
    template_id: str
    name: str
    description: str
    exercise_type: ExerciseType
    default_duration_hours: int
    objectives: List[ExerciseObjective]
    scenario_config: Dict[str, Any]
    recommended_team_size: int

class ExerciseManager:
    """Manage security training exercises."""

    def __init__(self):
        self.exercises: Dict[str, Exercise] = {}
        self.templates: Dict[str, ExerciseTemplate] = {}
        self._load_default_templates()

    def _load_default_templates(self):
        """Load pre-built exercise templates."""
        templates = [
            ExerciseTemplate(
                template_id="tmpl-001-ransomware-response",
                name="Ransomware Incident Response",
                description="Simulate and respond to a ransomware attack",
                exercise_type=ExerciseType.INCIDENT_RESPONSE_DRILL,
                default_duration_hours=4,
                objectives=[
                    ExerciseObjective(
                        objective_id="obj-001",
                        description="Detect ransomware execution within 15 minutes",
                        mitre_techniques=["T1486"],
                        success_criteria="Identify malicious process and affected systems"
                    ),
                    ExerciseObjective(
                        objective_id="obj-002",
                        description="Contain the attack by isolating affected systems",
                        mitre_techniques=["T1486"],
                        success_criteria="Network isolation completed within 30 minutes"
                    ),
                    ExerciseObjective(
                        objective_id="obj-003",
                        description="Identify C2 communication and block IOCs",
                        mitre_techniques=["T1071"],
                        success_criteria="C2 domains/IPs blocked at firewall"
                    )
                ],
                scenario_config={
                    "attack_vector": "phishing_email",
                    "ransomware_family": "lockbit",
                    "encryption_speed_files_per_minute": 100,
                    "initial_compromise": "workstation-ws-042"
                },
                recommended_team_size=6
            ),

            ExerciseTemplate(
                template_id="tmpl-002-apt-detection",
                name="APT Detection and Hunting",
                description="Hunt for and detect advanced persistent threat activity",
                exercise_type=ExerciseType.PURPLE_TEAM,
                default_duration_hours=6,
                objectives=[
                    ExerciseObjective(
                        objective_id="obj-004",
                        description="Identify initial access technique",
                        mitre_techniques=["T1078", "T1566"],
                        success_criteria="Detect spear-phishing or credential abuse"
                    ),
                    ExerciseObjective(
                        objective_id="obj-005",
                        description="Track lateral movement across environment",
                        mitre_techniques=["T1021.002", "T1550"],
                        success_criteria="Map attacker's path through network"
                    ),
                    ExerciseObjective(
                        objective_id="obj-006",
                        description="Discover data exfiltration attempts",
                        mitre_techniques=["T1530", "T1048"],
                        success_criteria="Identify exfiltration channels and volume"
                    )
                ],
                scenario_config={
                    "apt_group": "APT29",
                    "duration_days": 14,
                    "compromised_systems": 8,
                    "data_exfiltrated_gb": 250
                },
                recommended_team_size=10
            ),

            ExerciseTemplate(
                template_id="tmpl-003-cloud-breach",
                name="Cloud Environment Breach Response",
                description="Respond to a cloud infrastructure compromise",
                exercise_type=ExerciseType.BLUE_TEAM,
                default_duration_hours=3,
                objectives=[
                    ExerciseObjective(
                        objective_id="obj-007",
                        description="Identify compromised cloud credentials",
                        mitre_techniques=["T1552.001"],
                        success_criteria="Locate leaked or stolen access keys"
                    ),
                    ExerciseObjective(
                        objective_id="obj-008",
                        description="Revoke compromised credentials and rotate keys",
                        mitre_techniques=["T1098"],
                        success_criteria="All compromised credentials deactivated"
                    ),
                    ExerciseObjective(
                        objective_id="obj-009",
                        description="Assess blast radius of the breach",
                        mitre_techniques=["T1069"],
                        success_criteria="Identify all accessed resources and data"
                    )
                ],
                scenario_config={
                    "cloud_provider": "aws",
                    "compromised_role": "admin",
                    "breach_duration_hours": 12,
                    "unauthorized_actions": 247
                },
                recommended_team_size=4
            ),

            ExerciseTemplate(
                template_id="tmpl-004-insider-threat",
                name="Insider Threat Investigation",
                description="Investigate suspicious insider activity",
                exercise_type=ExerciseType.TABLETOP,
                default_duration_hours=2,
                objectives=[
                    ExerciseObjective(
                        objective_id="obj-010",
                        description="Identify behavioral anomalies in user activity",
                        mitre_techniques=["T1213"],
                        success_criteria="Detect unusual data access patterns"
                    ),
                    ExerciseObjective(
                        objective_id="obj-011",
                        description="Determine scope of unauthorized access",
                        mitre_techniques=["T1213", "T1005"],
                        success_criteria="List all accessed sensitive resources"
                    ),
                    ExerciseObjective(
                        objective_id="obj-012",
                        description="Preserve evidence for investigation",
                        mitre_techniques=[],
                        success_criteria="Collect logs and artifacts without alerting insider"
                    )
                ],
                scenario_config={
                    "insider_type": "malicious",
                    "motivation": "financial",
                    "access_level": "developer",
                    "data_targeted": "source_code_and_customer_data"
                },
                recommended_team_size=5
            )
        ]

        for template in templates:
            self.templates[template.template_id] = template

    def create_exercise(
        self,
        title: str,
        exercise_type: ExerciseType,
        created_by: str,
        scheduled_start: datetime,
        duration_hours: int,
        template_id: Optional[str] = None,
        description: Optional[str] = None
    ) -> Exercise:
        """Create a new exercise.

        Args:
            title: Exercise title
            exercise_type: Type of exercise
            created_by: User creating the exercise
            scheduled_start: When exercise starts
            duration_hours: Exercise duration
            template_id: Optional template to use
            description: Exercise description

        Returns:
            Created exercise
        """
        exercise_id = f"ex-{len(self.exercises):04d}"
        scheduled_end = scheduled_start + timedelta(hours=duration_hours)

        # Load from template if provided
        objectives = []
        scenario_config = {}
        if template_id and template_id in self.templates:
            template = self.templates[template_id]
            objectives = template.objectives.copy()
            scenario_config = template.scenario_config.copy()
            if not description:
                description = template.description

        exercise = Exercise(
            exercise_id=exercise_id,
            title=title,
            description=description or "",
            exercise_type=exercise_type,
            status=ExerciseStatus.SCHEDULED,
            created_by=created_by,
            created_at=datetime.now(),
            scheduled_start=scheduled_start,
            scheduled_end=scheduled_end,
            objectives=objectives,
            scenario_config=scenario_config
        )

        self.exercises[exercise_id] = exercise
        return exercise

    def add_participant(
        self,
        exercise_id: str,
        user_id: str,
        role: str,
        team: str
    ) -> Participant:
        """Add participant to exercise.

        Args:
            exercise_id: Exercise ID
            user_id: User to add
            role: User's role in exercise
            team: Team assignment

        Returns:
            Created participant
        """
        exercise = self.exercises.get(exercise_id)
        if not exercise:
            raise ValueError(f"Exercise not found: {exercise_id}")

        participant = Participant(
            user_id=user_id,
            role=role,
            team=team,
            joined_at=datetime.now()
        )

        exercise.participants.append(participant)
        return participant

    def start_exercise(self, exercise_id: str) -> Exercise:
        """Start an exercise.

        Args:
            exercise_id: Exercise to start

        Returns:
            Updated exercise
        """
        exercise = self.exercises.get(exercise_id)
        if not exercise:
            raise ValueError(f"Exercise not found: {exercise_id}")

        if exercise.status != ExerciseStatus.SCHEDULED:
            raise ValueError(f"Exercise cannot be started in {exercise.status} state")

        exercise.status = ExerciseStatus.IN_PROGRESS
        exercise.actual_start = datetime.now()

        return exercise

    def complete_exercise(self, exercise_id: str) -> Exercise:
        """Complete an exercise.

        Args:
            exercise_id: Exercise to complete

        Returns:
            Updated exercise with final metrics
        """
        exercise = self.exercises.get(exercise_id)
        if not exercise:
            raise ValueError(f"Exercise not found: {exercise_id}")

        exercise.status = ExerciseStatus.COMPLETED
        exercise.actual_end = datetime.now()

        # Calculate final metrics
        exercise.metrics = self._calculate_metrics(exercise)

        return exercise

    def _calculate_metrics(self, exercise: Exercise) -> Dict[str, Any]:
        """Calculate exercise metrics.

        Args:
            exercise: Exercise to analyze

        Returns:
            Metrics dictionary
        """
        if not exercise.actual_start or not exercise.actual_end:
            return {}

        actual_duration = exercise.actual_end - exercise.actual_start
        objectives_achieved = sum(1 for obj in exercise.objectives if obj.achieved)
        objectives_total = len(exercise.objectives)

        participant_scores = {
            p.user_id: p.score for p in exercise.participants
        }

        return {
            "actual_duration_minutes": int(actual_duration.total_seconds() / 60),
            "objectives_achieved": objectives_achieved,
            "objectives_total": objectives_total,
            "success_rate": objectives_achieved / objectives_total if objectives_total > 0 else 0,
            "participant_count": len(exercise.participants),
            "participant_scores": participant_scores,
            "average_score": sum(participant_scores.values()) / len(participant_scores) if participant_scores else 0,
            "event_count": len(exercise.events)
        }

    def record_event(
        self,
        exercise_id: str,
        event_type: str,
        actor: str,
        action: str,
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ExerciseEvent:
        """Record an event during exercise.

        Args:
            exercise_id: Exercise ID
            event_type: Type of event
            actor: User performing action
            action: Action taken
            target: Target of action
            metadata: Additional event data

        Returns:
            Created event
        """
        exercise = self.exercises.get(exercise_id)
        if not exercise:
            raise ValueError(f"Exercise not found: {exercise_id}")

        event = ExerciseEvent(
            event_id=f"evt-{len(exercise.events):06d}",
            timestamp=datetime.now(),
            event_type=event_type,
            actor=actor,
            action=action,
            target=target,
            metadata=metadata or {}
        )

        exercise.events.append(event)
        return event

    def update_objective_status(
        self,
        exercise_id: str,
        objective_id: str,
        achieved: bool
    ) -> ExerciseObjective:
        """Update objective completion status.

        Args:
            exercise_id: Exercise ID
            objective_id: Objective to update
            achieved: Whether objective was achieved

        Returns:
            Updated objective
        """
        exercise = self.exercises.get(exercise_id)
        if not exercise:
            raise ValueError(f"Exercise not found: {exercise_id}")

        for obj in exercise.objectives:
            if obj.objective_id == objective_id:
                obj.achieved = achieved
                return obj

        raise ValueError(f"Objective not found: {objective_id}")

    def get_upcoming_exercises(self, limit: int = 10) -> List[Exercise]:
        """Get upcoming scheduled exercises.

        Args:
            limit: Maximum number to return

        Returns:
            List of upcoming exercises
        """
        upcoming = [
            ex for ex in self.exercises.values()
            if ex.status == ExerciseStatus.SCHEDULED and ex.scheduled_start > datetime.now()
        ]

        return sorted(upcoming, key=lambda x: x.scheduled_start)[:limit]

    def get_exercise_report(self, exercise_id: str) -> Dict[str, Any]:
        """Generate exercise report.

        Args:
            exercise_id: Exercise to report on

        Returns:
            Comprehensive exercise report
        """
        exercise = self.exercises.get(exercise_id)
        if not exercise:
            raise ValueError(f"Exercise not found: {exercise_id}")

        return {
            "exercise_id": exercise.exercise_id,
            "title": exercise.title,
            "type": exercise.exercise_type.value,
            "status": exercise.status.value,
            "duration": exercise.metrics.get("actual_duration_minutes", 0),
            "participants": len(exercise.participants),
            "objectives": {
                "achieved": exercise.metrics.get("objectives_achieved", 0),
                "total": exercise.metrics.get("objectives_total", 0),
                "success_rate": exercise.metrics.get("success_rate", 0)
            },
            "scores": exercise.metrics.get("participant_scores", {}),
            "average_score": exercise.metrics.get("average_score", 0),
            "events_recorded": len(exercise.events),
            "started_at": exercise.actual_start.isoformat() if exercise.actual_start else None,
            "completed_at": exercise.actual_end.isoformat() if exercise.actual_end else None
        }
