"""
Alert parsers for normalizing heterogeneous security telemetry
(Sysmon, AWS CloudTrail, and Zeek).
"""

from .sysmon_parser import SysmonParser
from .cloudtrail_parser import CloudTrailParser
from .zeek_parser import ZeekParser

__all__ = ["SysmonParser", "CloudTrailParser", "ZeekParser"]
