"""Purple team exercise management."""
from typing import Dict, Any
from dataclasses import dataclass

@dataclass
class ExerciseScore:
    """Purple team exercise scoring."""
    red_team_score: float
    blue_team_score: float
    detection_rate: float
    response_time_seconds: float
    overall_grade: str

class PurpleTeamExercise:
    """Purple team exercise orchestration."""
    
    def __init__(self, exercise_id: str):
        self.exercise_id = exercise_id
        self.red_actions = []
        self.blue_detections = []
    
    def record_red_action(self, action: Dict[str, Any]):
        """Record red team action."""
        self.red_actions.append(action)
    
    def record_blue_detection(self, detection: Dict[str, Any]):
        """Record blue team detection."""
        self.blue_detections.append(detection)
    
    def calculate_score(self) -> ExerciseScore:
        """Calculate exercise score."""
        detection_rate = len(self.blue_detections) / max(len(self.red_actions), 1)
        
        return ExerciseScore(
            red_team_score=1.0 - detection_rate,
            blue_team_score=detection_rate,
            detection_rate=detection_rate,
            response_time_seconds=0.0,
            overall_grade="A" if detection_rate > 0.9 else "B" if detection_rate > 0.7 else "C"
        )
