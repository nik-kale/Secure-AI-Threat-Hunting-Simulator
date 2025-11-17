"""CTF (Capture The Flag) mode for security training."""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import random

class CTFDifficulty(str, Enum):
    """CTF challenge difficulty levels."""
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"

class CTFCategory(str, Enum):
    """CTF challenge categories."""
    ANOMALY_DETECTION = "anomaly_detection"
    THREAT_HUNTING = "threat_hunting"
    INCIDENT_RESPONSE = "incident_response"
    FORENSICS = "forensics"
    MITRE_MAPPING = "mitre_mapping"
    LOG_ANALYSIS = "log_analysis"

@dataclass
class CTFFlag:
    """CTF flag/answer."""
    flag_id: str
    value: str
    points: int
    hint: Optional[str] = None

@dataclass
class CTFChallenge:
    """CTF challenge definition."""
    challenge_id: str
    title: str
    description: str
    category: CTFCategory
    difficulty: CTFDifficulty
    points: int
    flags: List[CTFFlag]
    event_dataset: List[Dict[str, Any]]
    hints: List[str] = field(default_factory=list)
    time_limit_minutes: Optional[int] = None
    prerequisites: List[str] = field(default_factory=list)  # Other challenge IDs

@dataclass
class CTFSubmission:
    """User's flag submission."""
    submission_id: str
    user_id: str
    challenge_id: str
    flag_id: str
    submitted_value: str
    is_correct: bool
    timestamp: datetime
    points_awarded: int

@dataclass
class CTFScore:
    """User's CTF score."""
    user_id: str
    total_points: int
    challenges_completed: int
    rank: int
    submissions: List[CTFSubmission]
    time_to_complete: Optional[timedelta] = None

class CTFMode:
    """CTF mode for security training exercises."""

    def __init__(self):
        self.challenges: Dict[str, CTFChallenge] = {}
        self.scores: Dict[str, CTFScore] = {}
        self.submissions: List[CTFSubmission] = []
        self._load_default_challenges()

    def _load_default_challenges(self):
        """Load pre-built CTF challenges."""
        challenges = self._create_default_challenges()
        for challenge in challenges:
            self.challenges[challenge.challenge_id] = challenge

    def _create_default_challenges(self) -> List[CTFChallenge]:
        """Create default CTF challenges."""
        return [
            # Beginner: Find the compromised user
            CTFChallenge(
                challenge_id="ctf-001-compromised-user",
                title="Find the Compromised User",
                description="An attacker has gained access to your AWS environment. Analyze the logs to identify which IAM user was compromised. Flag format: FLAG{username}",
                category=CTFCategory.ANOMALY_DETECTION,
                difficulty=CTFDifficulty.BEGINNER,
                points=100,
                flags=[
                    CTFFlag(
                        flag_id="flag-001",
                        value="FLAG{admin-user-12345}",
                        points=100,
                        hint="Look for unusual login times or locations"
                    )
                ],
                event_dataset=[
                    {
                        "timestamp": "2024-01-15T02:30:00Z",
                        "event_type": "iam.login",
                        "principal": "admin-user-12345",
                        "source_ip": "203.0.113.45",  # Suspicious foreign IP
                        "status": "success",
                        "metadata": {"login_location": "Russia", "unusual_time": True}
                    }
                ],
                hints=[
                    "Check for logins from unusual IP addresses",
                    "Look for login events at odd hours",
                    "Consider geographic anomalies"
                ],
                time_limit_minutes=30
            ),

            # Intermediate: Reconstruct the attack path
            CTFChallenge(
                challenge_id="ctf-002-attack-path",
                title="Reconstruct the Attack Path",
                description="An attacker performed privilege escalation. Identify the sequence of actions. Flag format: FLAG{action1->action2->action3}",
                category=CTFCategory.THREAT_HUNTING,
                difficulty=CTFDifficulty.INTERMEDIATE,
                points=250,
                flags=[
                    CTFFlag(
                        flag_id="flag-002",
                        value="FLAG{AssumeRole->PassRole->GetSecretValue}",
                        points=250,
                        hint="Look at the temporal sequence of IAM actions"
                    )
                ],
                event_dataset=[
                    {
                        "timestamp": "2024-01-15T10:00:00Z",
                        "event_type": "iam.assume_role",
                        "action": "AssumeRole",
                        "principal": "attacker",
                        "resource": "arn:aws:iam::123456789012:role/AdminRole"
                    },
                    {
                        "timestamp": "2024-01-15T10:05:00Z",
                        "event_type": "iam.pass_role",
                        "action": "PassRole",
                        "principal": "attacker",
                        "resource": "arn:aws:iam::123456789012:role/LambdaExecutionRole"
                    },
                    {
                        "timestamp": "2024-01-15T10:10:00Z",
                        "event_type": "secretsmanager.get_secret_value",
                        "action": "GetSecretValue",
                        "principal": "attacker",
                        "resource": "production-database-credentials"
                    }
                ],
                hints=[
                    "Trace the actions chronologically",
                    "Each action enables the next one",
                    "Focus on privilege escalation techniques"
                ],
                time_limit_minutes=45
            ),

            # Advanced: Identify the MITRE technique
            CTFChallenge(
                challenge_id="ctf-003-mitre-technique",
                title="Identify MITRE ATT&CK Technique",
                description="Analyze the attack pattern and identify the primary MITRE ATT&CK technique ID. Flag format: FLAG{T####.###}",
                category=CTFCategory.MITRE_MAPPING,
                difficulty=CTFDifficulty.ADVANCED,
                points=400,
                flags=[
                    CTFFlag(
                        flag_id="flag-003",
                        value="FLAG{T1530}",  # Data from Cloud Storage Object
                        points=400,
                        hint="This technique involves accessing cloud storage"
                    )
                ],
                event_dataset=[
                    {
                        "timestamp": "2024-01-15T14:00:00Z",
                        "event_type": "s3.list_buckets",
                        "action": "ListBuckets",
                        "principal": "attacker"
                    },
                    {
                        "timestamp": "2024-01-15T14:05:00Z",
                        "event_type": "s3.get_object",
                        "action": "GetObject",
                        "principal": "attacker",
                        "resource": "s3://sensitive-data/customer-records.csv",
                        "metadata": {"download_count": 150}
                    }
                ],
                hints=[
                    "Check the MITRE ATT&CK framework for cloud tactics",
                    "The attack involves data exfiltration",
                    "Look under the Collection tactic"
                ],
                time_limit_minutes=60
            ),

            # Expert: Full incident reconstruction
            CTFChallenge(
                challenge_id="ctf-004-full-incident",
                title="Full Incident Reconstruction",
                description="A sophisticated APT attacked your environment. Identify: (1) Initial access method, (2) Number of compromised users, (3) Total data exfiltrated (GB), (4) C2 IP address. Flag format: FLAG{method:users:gb:ip}",
                category=CTFCategory.INCIDENT_RESPONSE,
                difficulty=CTFDifficulty.EXPERT,
                points=1000,
                flags=[
                    CTFFlag(
                        flag_id="flag-004",
                        value="FLAG{phishing:3:450:203.0.113.89}",
                        points=1000,
                        hint="Correlate events across multiple users and services"
                    )
                ],
                event_dataset=self._generate_complex_apt_scenario(),
                hints=[
                    "Start with authentication anomalies",
                    "Track lateral movement between users",
                    "Calculate data transfer volumes from S3 events",
                    "Identify repeated connections to external IPs"
                ],
                time_limit_minutes=120
            ),

            # Forensics: Timeline reconstruction
            CTFChallenge(
                challenge_id="ctf-005-timeline",
                title="Timeline Reconstruction",
                description="Reconstruct the attack timeline. What was the time gap between initial access and data exfiltration? Flag format: FLAG{HH:MM}",
                category=CTFCategory.FORENSICS,
                difficulty=CTFDifficulty.INTERMEDIATE,
                points=300,
                flags=[
                    CTFFlag(
                        flag_id="flag-005",
                        value="FLAG{03:45}",
                        points=300,
                        hint="Compare timestamps of first suspicious event and data transfer"
                    )
                ],
                event_dataset=[
                    {
                        "timestamp": "2024-01-15T10:00:00Z",
                        "event_type": "iam.login",
                        "principal": "compromised-user",
                        "metadata": {"first_malicious_event": True}
                    },
                    {
                        "timestamp": "2024-01-15T13:45:00Z",
                        "event_type": "s3.get_object",
                        "principal": "compromised-user",
                        "metadata": {"data_exfiltration": True}
                    }
                ],
                hints=[
                    "Find the first and last relevant events",
                    "Calculate time difference in hours and minutes",
                    "Ignore unrelated events in between"
                ],
                time_limit_minutes=30
            )
        ]

    def _generate_complex_apt_scenario(self) -> List[Dict[str, Any]]:
        """Generate complex APT scenario for expert challenge."""
        events = []
        c2_ip = "203.0.113.89"
        compromised_users = ["user-alpha", "user-beta", "user-gamma"]

        # Phishing initial access
        events.append({
            "timestamp": "2024-01-15T08:00:00Z",
            "event_type": "email.phishing_link_clicked",
            "principal": compromised_users[0],
            "source_ip": c2_ip,
            "metadata": {"initial_access": "phishing"}
        })

        # Lateral movement to other users
        for i, user in enumerate(compromised_users):
            events.append({
                "timestamp": f"2024-01-15T{8+i}:30:00Z",
                "event_type": "iam.assume_role",
                "principal": user,
                "source_ip": c2_ip
            })

        # Data exfiltration (450 GB total)
        for i in range(30):
            events.append({
                "timestamp": f"2024-01-15T{10+i//2}:{i%2*30:02d}:00Z",
                "event_type": "s3.get_object",
                "principal": random.choice(compromised_users),
                "source_ip": c2_ip,
                "metadata": {"data_size_gb": 15}
            })

        return events

    def submit_flag(self, user_id: str, challenge_id: str, flag_value: str) -> CTFSubmission:
        """Submit a flag answer.

        Args:
            user_id: User submitting the flag
            challenge_id: Challenge ID
            flag_value: Submitted flag value

        Returns:
            Submission result with correctness and points
        """
        challenge = self.challenges.get(challenge_id)
        if not challenge:
            raise ValueError(f"Challenge not found: {challenge_id}")

        # Check if flag is correct
        correct_flag = None
        for flag in challenge.flags:
            if flag.value == flag_value:
                correct_flag = flag
                break

        is_correct = correct_flag is not None
        points_awarded = correct_flag.points if is_correct else 0

        submission = CTFSubmission(
            submission_id=f"sub-{len(self.submissions)}",
            user_id=user_id,
            challenge_id=challenge_id,
            flag_id=correct_flag.flag_id if correct_flag else "unknown",
            submitted_value=flag_value,
            is_correct=is_correct,
            timestamp=datetime.now(),
            points_awarded=points_awarded
        )

        self.submissions.append(submission)
        self._update_score(user_id, submission)

        return submission

    def _update_score(self, user_id: str, submission: CTFSubmission):
        """Update user's score after submission.

        Args:
            user_id: User ID
            submission: Flag submission
        """
        if user_id not in self.scores:
            self.scores[user_id] = CTFScore(
                user_id=user_id,
                total_points=0,
                challenges_completed=0,
                rank=0,
                submissions=[]
            )

        score = self.scores[user_id]
        score.submissions.append(submission)

        if submission.is_correct:
            score.total_points += submission.points_awarded

            # Check if challenge is fully completed
            challenge = self.challenges[submission.challenge_id]
            user_correct_flags = {
                sub.flag_id for sub in score.submissions
                if sub.challenge_id == submission.challenge_id and sub.is_correct
            }
            challenge_flag_ids = {flag.flag_id for flag in challenge.flags}

            if user_correct_flags == challenge_flag_ids:
                score.challenges_completed += 1

        # Recalculate ranks
        self._recalculate_ranks()

    def _recalculate_ranks(self):
        """Recalculate user ranks based on scores."""
        sorted_users = sorted(
            self.scores.values(),
            key=lambda s: (s.total_points, -len(s.submissions)),
            reverse=True
        )

        for rank, score in enumerate(sorted_users, start=1):
            score.rank = rank

    def get_leaderboard(self, limit: int = 10) -> List[CTFScore]:
        """Get CTF leaderboard.

        Args:
            limit: Number of top users to return

        Returns:
            Top users by score
        """
        sorted_scores = sorted(
            self.scores.values(),
            key=lambda s: (s.total_points, -len(s.submissions)),
            reverse=True
        )
        return sorted_scores[:limit]

    def get_challenge(self, challenge_id: str) -> Optional[CTFChallenge]:
        """Get challenge by ID.

        Args:
            challenge_id: Challenge ID

        Returns:
            Challenge if found, None otherwise
        """
        return self.challenges.get(challenge_id)

    def get_user_progress(self, user_id: str) -> Dict[str, Any]:
        """Get user's CTF progress.

        Args:
            user_id: User ID

        Returns:
            Progress summary
        """
        score = self.scores.get(user_id)
        if not score:
            return {
                "total_points": 0,
                "challenges_completed": 0,
                "rank": 0,
                "completion_rate": 0.0
            }

        total_challenges = len(self.challenges)
        completion_rate = score.challenges_completed / total_challenges if total_challenges > 0 else 0.0

        return {
            "total_points": score.total_points,
            "challenges_completed": score.challenges_completed,
            "total_challenges": total_challenges,
            "completion_rate": completion_rate,
            "rank": score.rank,
            "recent_submissions": score.submissions[-5:]
        }

    def get_hint(self, challenge_id: str, hint_index: int, user_id: str) -> Optional[str]:
        """Get a hint for a challenge (costs points).

        Args:
            challenge_id: Challenge ID
            hint_index: Index of hint to retrieve
            user_id: User requesting hint

        Returns:
            Hint text if available
        """
        challenge = self.challenges.get(challenge_id)
        if not challenge or hint_index >= len(challenge.hints):
            return None

        # Deduct points for hint (20% of challenge value)
        penalty = int(challenge.points * 0.2)
        if user_id in self.scores:
            self.scores[user_id].total_points = max(0, self.scores[user_id].total_points - penalty)

        return challenge.hints[hint_index]
