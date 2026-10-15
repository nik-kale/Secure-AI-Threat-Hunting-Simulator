"""
Tests for ML behavioral baseline module.
"""

from datetime import datetime, timedelta

from analysis_engine.ml.behavioral_baseline import BaselineProfile, BehavioralBaseline

EMPLOYEE = "arn:aws:iam::123456789012:user/employee"


def _event(
    when,
    action="GetUser",
    status="success",
    source_ip="203.0.113.10",
    resource="arn:aws:s3:::reports",
    principal=EMPLOYEE,
):
    return {
        "timestamp": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type": f"iam.{action.lower()}",
        "action": action,
        "status": status,
        "principal": principal,
        "resource": resource,
        "source_ip": source_ip,
    }


def _office_hours(days=14, hours=(9, 12, 15), start=datetime(2025, 1, 6)):
    """Three actions a day at fixed hours across `days` days."""
    events = []
    for day in range(days):
        for hour in hours:
            for action in ("GetUser", "ListRoles", "GetObject"):
                events.append(
                    _event(start + timedelta(days=day, hours=hour), action=action)
                )
    return events


class TestBuildBaseline:
    def test_skips_entities_below_minimum_events(self):
        baseline = BehavioralBaseline(min_training_events=10)

        profiles = baseline.build_baseline(_office_hours(days=1, hours=(9,)))

        assert profiles == {}

    def test_learns_actions_ips_and_resources(self):
        baseline = BehavioralBaseline(min_training_events=10)

        profile = baseline.build_baseline(_office_hours())[EMPLOYEE]

        assert isinstance(profile, BaselineProfile)
        assert set(profile.typical_actions) == {"GetUser", "ListRoles", "GetObject"}
        assert profile.typical_source_ips == {"203.0.113.10"}
        assert profile.typical_resources == {"arn:aws:s3:::reports"}
        assert profile.total_events_analyzed == 14 * 3 * 3

    def test_typical_hours_require_activity_on_a_quarter_of_days(self):
        """One stray 03:00 event across 14 days is not a typical hour."""
        events = _office_hours() + [_event(datetime(2025, 1, 8, 3, 0))]
        baseline = BehavioralBaseline(min_training_events=10)

        profile = baseline.build_baseline(events)[EMPLOYEE]

        assert profile.typical_hours == {9, 12, 15}

    def test_training_period_ignores_event_order(self):
        events = list(reversed(_office_hours()))
        baseline = BehavioralBaseline(min_training_events=10)

        profile = baseline.build_baseline(events)[EMPLOYEE]

        assert profile.training_period_days == 13

    def test_confidence_includes_training_period(self):
        baseline = BehavioralBaseline(min_training_events=10, training_period_days=7)

        profile = baseline.build_baseline(_office_hours())[EMPLOYEE]

        # 0.4 (events) + 0.3 (14 days >= 7) + 0.3 (diversity)
        assert profile.confidence_score == 1.0

    def test_failure_rate_uses_schema_status_values(self):
        events = _office_hours()
        for event in events[:9]:
            event["status"] = "failure"
        baseline = BehavioralBaseline(min_training_events=10)

        profile = baseline.build_baseline(events)[EMPLOYEE]

        assert profile.typical_failure_rate == 9 / len(events)


class TestDetectDeviations:
    def _trained(self):
        baseline = BehavioralBaseline(min_training_events=10)
        baseline.build_baseline(_office_hours())
        return baseline

    def test_unknown_entity_has_no_baseline(self):
        deviations = self._trained().detect_deviations(
            [
                _event(
                    datetime(2025, 2, 1, 9),
                    principal="arn:aws:iam::123456789012:user/new",
                )
            ]
        )

        [entry] = deviations["arn:aws:iam::123456789012:user/new"]
        assert entry["deviation_type"] == "no_baseline"

    def test_normal_event_has_no_deviation(self):
        deviations = self._trained().detect_deviations(
            [_event(datetime(2025, 1, 13, 9))]
        )

        assert deviations == {}

    def test_flags_new_action_ip_resource_and_hour(self):
        event = _event(
            datetime(2025, 1, 13, 3),
            action="AttachUserPolicy",
            source_ip="198.51.100.50",
            resource="arn:aws:iam::aws:policy/AdministratorAccess",
        )

        deviations = self._trained().detect_deviations([event])

        types = {d["deviation_type"] for d in deviations[EMPLOYEE]}
        assert {"new_action", "new_source_ip", "new_resource", "unusual_time"} <= types

    def test_flags_schema_failure_status(self):
        deviations = self._trained().detect_deviations(
            [_event(datetime(2025, 1, 13, 9), status="denied")]
        )

        types = {d["deviation_type"] for d in deviations[EMPLOYEE]}
        assert "unusual_failure" in types


class TestProfileSerialisation:
    def test_export_import_round_trip(self):
        baseline = BehavioralBaseline(min_training_events=10)
        baseline.build_baseline(_office_hours())

        restored = BehavioralBaseline()
        restored.import_profiles(baseline.export_profiles())

        original = baseline.get_profile(EMPLOYEE)
        copy = restored.get_profile(EMPLOYEE)
        assert copy.typical_hours == original.typical_hours
        assert copy.typical_actions == original.typical_actions
        assert copy.confidence_score == original.confidence_score
