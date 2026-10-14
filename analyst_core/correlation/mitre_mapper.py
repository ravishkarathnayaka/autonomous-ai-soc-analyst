"""
Maps correlated telemetry, observables, and attack graph behaviors
to the MITRE ATT&CK Enterprise Matrix.
"""

import re
from typing import List
from ..state import MitreTechnique, NormalizedAlert


class MitreMapper:
    """Maps security events to MITRE ATT&CK tactics and techniques."""

    RULE_CATALOG = [
        {
            "id": "T1059.001",
            "name": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution",
            "description": "Adversaries may abuse PowerShell commands and scripts to execute malicious payloads.",
            "patterns": [
                r"powershell(\.exe)?",
                r"-enc(odedcommand)?",
                r"downloadstring",
                r"invoke-expression|iex",
                r"bypass\s+-nop",
            ],
        },
        {
            "id": "T1003.001",
            "name": "OS Credential Dumping: LSASS Memory",
            "tactic": "Credential Access",
            "description": "Adversaries may attempt to access credential material stored in the process memory of LSASS.",
            "patterns": [
                r"lsass\.exe",
                r"mimikatz",
                r"procdump.*lsass",
                r"sekurlsa",
                r"comsvcs\.dll.*minidump",
            ],
        },
        {
            "id": "T1071.001",
            "name": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control",
            "description": "Adversaries may communicate using application layer protocols (HTTP/HTTPS) to avoid detection.",
            "patterns": [
                r":443",
                r":80\b",
                r"zeek.*(conn|http|ssl)",
                r"cobalt_strike",
            ],
        },
        {
            "id": "T1486",
            "name": "Data Encrypted for Impact",
            "tactic": "Impact",
            "description": "Adversaries may encrypt data on target systems or secondary storage to disrupt system availability.",
            "patterns": [
                r"\.locked$",
                r"\.blackcat$",
                r"\.encrypt",
                r"readme_for_decrypt",
                r"ransomware",
            ],
        },
        {
            "id": "T1078.004",
            "name": "Valid Accounts: Cloud Accounts",
            "tactic": "Defense Evasion",
            "description": "Adversaries may obtain and abuse credentials of existing cloud accounts.",
            "patterns": [
                r"aws::.*::iam",
                r"AKIA[0-9A-Z]{16}",
                r"tor_exit_node",
            ],
        },
        {
            "id": "T1098",
            "name": "Account Manipulation",
            "tactic": "Persistence",
            "description": "Adversaries may manipulate accounts to maintain access to victim systems (e.g. creating rogue IAM users).",
            "patterns": [
                r"CreateUser",
                r"AttachUserPolicy",
                r"AddUserToGroup",
                r"CreateAccessKey",
            ],
        },
        {
            "id": "T1562.001",
            "name": "Impair Defenses: Disable or Modify Tools",
            "tactic": "Defense Evasion",
            "description": "Adversaries may disable or modify security tools (e.g., CloudTrail logging, antivirus).",
            "patterns": [
                r"StopLogging",
                r"DeleteTrail",
                r"DisableRule",
                r"Set-MpPreference.*-DisableRealtimeMonitoring",
            ],
        },
        {
            "id": "T1053.005",
            "name": "Scheduled Task/Job: Scheduled Task",
            "tactic": "Execution",
            "description": "Adversaries may abuse the Windows Task Scheduler to perform task scheduling.",
            "patterns": [
                r"schtasks(\.exe)?",
                r"Register-ScheduledTask",
            ],
        },
    ]

    def map_alerts(self, alerts: List[NormalizedAlert]) -> List[MitreTechnique]:
        """Evaluates alerts and returns unique mapped MITRE techniques."""
        matched: dict[str, MitreTechnique] = {}

        for alert in alerts:
            # Combine alert text fields into search corpus
            corpus_parts = [
                alert.process_name or "",
                alert.parent_process_name or "",
                alert.command_line or "",
                alert.file_path or "",
                alert.api_call or "",
                str(alert.request_parameters or {}),
                f":{alert.dest_port}" if alert.dest_port else "",
            ]
            for obs in alert.observables:
                corpus_parts.append(obs.value)
                corpus_parts.extend(obs.tags)

            corpus = " ".join(corpus_parts)

            for rule in self.RULE_CATALOG:
                evidence = []
                for pattern in rule["patterns"]:
                    matches = re.findall(pattern, corpus, re.IGNORECASE)
                    if matches:
                        evidence.append(pattern)

                if evidence:
                    tid = rule["id"]
                    if tid not in matched:
                        matched[tid] = MitreTechnique(
                            technique_id=tid,
                            technique_name=rule["name"],
                            tactic=rule["tactic"],
                            description=rule["description"],
                            observed_indicators=evidence,
                        )
                    else:
                        existing = matched[tid].observed_indicators
                        for e in evidence:
                            if e not in existing:
                                existing.append(e)

        return list(matched.values())
