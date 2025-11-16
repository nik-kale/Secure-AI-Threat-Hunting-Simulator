"""
Data exfiltration attack scenario.
S3 enumeration to external bucket with CloudTrail deletion.
"""
from .generator import generate_data_exfiltration_scenario

__all__ = ['generate_data_exfiltration_scenario']
