"""
Unit tests for Sysmon, CloudTrail, and Zeek telemetry parsers.
"""

from analyst_core.parsers.cloudtrail_parser import CloudTrailParser
from analyst_core.parsers.sysmon_parser import SysmonParser
from analyst_core.parsers.zeek_parser import ZeekParser
from analyst_core.state import AlertSource, ObservableType


def test_sysmon_process_creation_parser():
    parser = SysmonParser()
    raw = {
        "EventID": 1,
        "UtcTime": "2026-10-14 02:14:10.120",
        "ProcessId": 4120,
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "ParentProcessId": 1844,
        "ParentImage": "C:\\Windows\\explorer.exe",
        "User": "CORP\\alice",
        "Computer": "FIN-WS-01",
        "Hashes": "SHA256=BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD,MD5=8B3F5C3E2D1A4F5E6B7C8D9E0F1A2B3C",
    }

    alert = parser.parse(raw)
    assert alert.source == AlertSource.SYSMON
    assert alert.host == "FIN-WS-01"
    assert alert.user == "CORP\\alice"
    assert alert.process_name == "C:\\Windows\\System32\\cmd.exe"
    assert alert.pid == 4120
    assert alert.ppid == 1844
    assert alert.command_line == "cmd.exe /c whoami"

    # Verify extracted observables
    obs_types = {obs.obs_type: obs.value for obs in alert.observables}
    assert ObservableType.HOST in obs_types
    assert ObservableType.USER in obs_types
    assert ObservableType.PROCESS_NAME in obs_types
    assert ObservableType.HASH_SHA256 in obs_types
    assert ObservableType.HASH_MD5 in obs_types
    assert obs_types[ObservableType.HASH_SHA256] == "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"


def test_sysmon_network_connection_parser():
    parser = SysmonParser()
    raw = {
        "EventID": 3,
        "ProcessId": 4120,
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "SourceIp": "192.168.1.50",
        "SourcePort": 52140,
        "DestinationIp": "45.33.32.156",
        "DestinationPort": 443,
        "Computer": "FIN-WS-04",
    }

    alert = parser.parse(raw)
    assert alert.dest_ip == "45.33.32.156"
    assert alert.dest_port == 443
    assert alert.src_ip == "192.168.1.50"
    ip_values = [obs.value for obs in alert.observables if obs.obs_type == ObservableType.IP]
    assert "45.33.32.156" in ip_values
    assert "192.168.1.50" in ip_values


def test_cloudtrail_parser():
    parser = CloudTrailParser()
    raw = {
        "eventTime": "2026-10-14T03:22:11Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateUser",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "185.220.101.5",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "devops-ci",
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "arn": "arn:aws:iam::123456789012:user/devops-ci",
        },
        "requestParameters": {"userName": "backdoor_admin"},
    }

    alert = parser.parse(raw)
    assert alert.source == AlertSource.CLOUDTRAIL
    assert alert.user == "devops-ci"
    assert alert.src_ip == "185.220.101.5"
    assert alert.api_call == "iam.amazonaws.com:CreateUser"

    obs_values = {obs.obs_type: obs.value for obs in alert.observables}
    assert ObservableType.ACCESS_KEY_ID in obs_values
    assert obs_values[ObservableType.ACCESS_KEY_ID] == "AKIAIOSFODNN7EXAMPLE"
    assert ObservableType.IP in obs_values
    assert obs_values[ObservableType.IP] == "185.220.101.5"


def test_zeek_parser():
    parser = ZeekParser()
    raw = {
        "ts": 1710403250.0,
        "id.orig_h": "10.0.4.15",
        "id.orig_p": 49812,
        "id.resp_h": "45.33.32.156",
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl",
        "server_name": "c2.threat-actor-infra.xyz",
        "conn_state": "SF",
    }

    alert = parser.parse(raw)
    assert alert.source == AlertSource.ZEEK
    assert alert.src_ip == "10.0.4.15"
    assert alert.dest_ip == "45.33.32.156"
    assert alert.dest_port == 443
    assert alert.query == "c2.threat-actor-infra.xyz"

    domain_obs = [obs.value for obs in alert.observables if obs.obs_type == ObservableType.DOMAIN]
    assert "c2.threat-actor-infra.xyz" in domain_obs
