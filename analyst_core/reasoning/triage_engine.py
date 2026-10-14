"""
Reasoning and Triage Engine with pluggable providers:
- OllamaReasoningProvider: Local LLM inference (Llama-3.2, Mistral, DeepSeek)
- MockReasoningProvider: Deterministic, rule-guided LLM simulation for CI/CD and offline use
"""

from abc import ABC, abstractmethod
import json
import os
import re
from typing import Any, Dict, List, Optional
import httpx

from ..state import (
    ContainmentAction,
    InvestigationHypothesis,
    InvestigationState,
    Severity,
    TriageVerdict,
)
from .prompt_templates import PromptTemplates


class LLMReasoningProvider(ABC):
    """Abstract base class for LLM reasoning engines."""

    @abstractmethod
    def evaluate(self, system_prompt: str, user_prompt: str, state: InvestigationState) -> Dict[str, Any]:
        """Evaluates investigation context and returns structured triage dictionary."""
        pass


class OllamaReasoningProvider(LLMReasoningProvider):
    """Connects to a local Ollama daemon for local $0 inference."""

    def __init__(self, host: Optional[str] = None, model: Optional[str] = None, timeout: float = 60.0):
        self.host = host or os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3.2")
        self.timeout = timeout

    def evaluate(self, system_prompt: str, user_prompt: str, state: InvestigationState) -> Dict[str, Any]:
        url = f"{self.host.rstrip('/')}/api/generate"
        payload = {
            "model": self.model,
            "system": system_prompt,
            "prompt": user_prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1, "top_p": 0.9},
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                raw_text = data.get("response", "{}")

                # Parse JSON, handling potential markdown code blocks
                clean_json = re.sub(r"^```(?:json)?\s*", "", raw_text.strip(), flags=re.MULTILINE)
                clean_json = re.sub(r"\s*```$", "", clean_json.strip(), flags=re.MULTILINE)
                return json.loads(clean_json)
        except Exception as e:
            # Fall back to deterministic provider if Ollama is unavailable
            mock = MockReasoningProvider()
            result = mock.evaluate(system_prompt, user_prompt, state)
            result["executive_summary"] = (
                f"[FALLBACK: Ollama connection failed ({e})] " + result.get("executive_summary", "")
            )
            return result


class MockReasoningProvider(LLMReasoningProvider):
    """Deterministic, rule-guided reasoning provider for offline execution and CI."""

    def evaluate(self, system_prompt: str, user_prompt: str, state: InvestigationState) -> Dict[str, Any]:
        # Inspect state to determine scenario
        has_malicious_cti = any(ind.malicious for ind in state.enriched_cti.values())
        max_threat_score = max([ind.threat_score for ind in state.enriched_cti.values()] or [0])

        has_encoded_ps = any(
            "-enc" in (a.command_line or "").lower() or "mimikatz" in (a.command_line or "").lower()
            for a in state.alerts
        )
        has_lsass = any(
            "lsass" in (a.command_line or "").lower()
            or "lsass" in (a.process_name or "").lower()
            or any("lsass" in obs.value.lower() for obs in a.observables)
            for a in state.alerts
        )
        has_ransomware_files = any(
            ".locked" in (a.file_path or "").lower() or ".blackcat" in (a.file_path or "").lower()
            for a in state.alerts
        )
        has_cloud_abuse = any(
            a.api_call and ("CreateUser" in a.api_call or "StopLogging" in a.api_call or "AttachUserPolicy" in a.api_call)
            for a in state.alerts
        )
        is_backup_or_maintenance = any(
            "backup" in (a.command_line or "").lower() or "defrag" in (a.command_line or "").lower()
            for a in state.alerts
        ) and not has_malicious_cti and not has_lsass

        # SCENARIO 1: False Positive - Administrative / Backup Maintenance
        if is_backup_or_maintenance:
            return {
                "root_cause_analysis": (
                    "Routine execution of scheduled administrative maintenance script "
                    "(e.g., Weekly_Disk_Defrag_Backup.ps1). Script was triggered by an authorized "
                    "service account (svc-backup) during designated maintenance hours with no anomalous network egress."
                ),
                "hypotheses": [
                    {
                        "hypothesis": "Authorized Administrative Maintenance",
                        "likelihood": "HIGH",
                        "supporting_evidence": [
                            "Execution path matches approved administrative directory",
                            "Initiating identity is a designated service account with scheduled batch privileges",
                            "Zero malicious CTI indicators or anomalous outbound connections observed",
                        ],
                        "contradicting_evidence": [
                            "Execution triggered generic script execution heuristic rule",
                        ],
                    },
                    {
                        "hypothesis": "Compromised Service Account Credentials",
                        "likelihood": "LOW",
                        "supporting_evidence": ["Elevated service account invoked scripting interpreter"],
                        "contradicting_evidence": [
                            "Activity strictly confined to standard backup routines",
                            "No secondary credential dumping or lateral reconnaissance observed",
                        ],
                    },
                ],
                "verdict": TriageVerdict.FALSE_POSITIVE.value,
                "confidence_score": 94,
                "severity": Severity.LOW.value,
                "executive_summary": (
                    "The alert represents benign administrative activity. Service account 'svc-backup' executed "
                    "a scheduled disk maintenance and backup script. No credential dumping, malicious C2 communication, "
                    "or unauthorized modifications were detected. Recommend closing alert as False Positive."
                ),
                "containment_playbook": [
                    {
                        "action_type": "TUNE_DETECTION_RULE",
                        "target": "Detection Rule: Script Execution by Service Account",
                        "description": "Add exclusion filter for authorized backup service account executing in standard maintenance directory.",
                        "urgency": "LOW",
                        "automation_ready": True,
                        "cli_command": "# Tuning recommendation: add exclusion for svc-backup and known script path",
                    }
                ],
            }

        # SCENARIO 2: True Positive - Cloud Credential Abuse / Privilege Escalation
        if has_cloud_abuse and has_malicious_cti:
            target_user = "unknown-user"
            access_key = "UNKNOWN-KEY"
            for a in state.alerts:
                if a.user:
                    target_user = a.user
                if a.request_parameters and "userName" in a.request_parameters:
                    target_user = a.request_parameters["userName"]
                for obs in a.observables:
                    if obs.obs_type.value == "access_key_id":
                        access_key = obs.value

            return {
                "root_cause_analysis": (
                    f"Compromised AWS IAM Access Key ({access_key}) accessed from a known Tor exit node / anonymizer IP. "
                    "Adversary authenticated outside standard working parameters, executed unauthorized user creation (CreateUser), "
                    "attached administrative policies (AttachUserPolicy), and attempted defense evasion by disabling logging (StopLogging)."
                ),
                "hypotheses": [
                    {
                        "hypothesis": "Active Cloud Identity Hijack & Privilege Escalation",
                        "likelihood": "HIGH",
                        "supporting_evidence": [
                            "Source IP enriched with high-confidence Tor exit node reputation",
                            "Unauthorized IAM user creation coupled with AdministratorAccess policy attachment",
                            "Defense evasion attempt via StopLogging API invocation",
                        ],
                        "contradicting_evidence": [],
                    },
                    {
                        "hypothesis": "Authorized Cloud Engineer using VPN/Tor",
                        "likelihood": "LOW",
                        "supporting_evidence": ["Valid access key credentials were used"],
                        "contradicting_evidence": [
                            "Corporate security policy strictly prohibits Tor exit relays for infrastructure access",
                            "Actions attempt to blind telemetry by disabling cloud auditing",
                        ],
                    },
                ],
                "verdict": TriageVerdict.TRUE_POSITIVE.value,
                "confidence_score": 96,
                "severity": Severity.CRITICAL.value,
                "executive_summary": (
                    f"CRITICAL INCIDENT: AWS account compromise detected. An unauthorized actor operating from an anonymized "
                    f"IP used IAM credentials ({access_key}) to establish persistent administrative access and deactivate audit logging. "
                    "Immediate containment is required to deactivate compromised keys and revoke rogue IAM entities."
                ),
                "containment_playbook": [
                    {
                        "action_type": "REVOKE_IAM_CREDENTIALS",
                        "target": access_key,
                        "description": "Deactivate and delete the compromised IAM Access Key immediately.",
                        "urgency": "CRITICAL",
                        "automation_ready": True,
                        "cli_command": f"aws iam update-access-key --access-key-id {access_key} --status Inactive",
                    },
                    {
                        "action_type": "REVOKE_ACTIVE_SESSIONS",
                        "target": target_user,
                        "description": "Attach explicit deny policy to invalidate all active STS sessions for the affected principal.",
                        "urgency": "CRITICAL",
                        "automation_ready": True,
                        "cli_command": f"aws iam put-user-policy --user-name {target_user} --policy-name RevokeOldSessions --policy-document '{{\"Version\":\"2012-10-17\",\"Statement\":[{{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\"}}]}}'",
                    },
                    {
                        "action_type": "BLOCK_PERIMETER_IP",
                        "target": "185.220.101.5",
                        "description": "Block source IP across AWS WAF and perimeter security groups.",
                        "urgency": "HIGH",
                        "automation_ready": True,
                        "cli_command": "aws wafv2 update-ip-set --name BlockedThreatActors --scope REGIONAL --addresses 185.220.101.5/32",
                    },
                ],
            }

        # SCENARIO 3: True Positive - Multi-Stage Ransomware (PowerShell -> C2 -> LSASS -> Encryption)
        if has_encoded_ps or has_lsass or has_ransomware_files or (has_malicious_cti and max_threat_score >= 80):
            target_host = state.alerts[0].host if state.alerts else "FIN-WS-04"
            dest_c2 = next((a.dest_ip for a in state.alerts if a.dest_ip), "45.33.32.156")

            return {
                "root_cause_analysis": (
                    f"Multi-stage intrusion observed on host '{target_host}'. Initial execution originated via an obfuscated "
                    "base64-encoded PowerShell process. The process established outbound Command & Control (C2) beaconing to "
                    f"known malicious infrastructure ({dest_c2}), dumped memory from LSASS.exe for credential harvesting, "
                    "and commenced high-velocity encryption of user documents with a ransomware extension."
                ),
                "hypotheses": [
                    {
                        "hypothesis": "Coordinated Ransomware / Cyber Extortion Campaign",
                        "likelihood": "HIGH",
                        "supporting_evidence": [
                            "Base64-encoded PowerShell execution bypassing execution policies",
                            f"Outbound C2 beaconing to high-reputation malicious IP ({dest_c2})",
                            "Direct process memory access targeting LSASS.exe",
                            "Mass creation of encrypted files with ransomware markers",
                        ],
                        "contradicting_evidence": [],
                    },
                    {
                        "hypothesis": "Authorized Red Team or Penetration Test",
                        "likelihood": "LOW",
                        "supporting_evidence": ["Standard adversary emulation techniques were observed"],
                        "contradicting_evidence": [
                            "No active authorized red team exercise registered for this workstation",
                            "Target system is an active finance endpoint with actual data encryption in progress",
                        ],
                    },
                ],
                "verdict": TriageVerdict.TRUE_POSITIVE.value,
                "confidence_score": 98,
                "severity": Severity.CRITICAL.value,
                "executive_summary": (
                    f"CRITICAL THREAT: Active ransomware infection confirmed on endpoint '{target_host}'. The adversary "
                    f"has achieved remote execution, established C2 channel to {dest_c2}, harvested local credentials from LSASS, "
                    "and initiated file encryption. Immediate host isolation and enterprise credential rotation are mandatory."
                ),
                "containment_playbook": [
                    {
                        "action_type": "ISOLATE_HOST",
                        "target": target_host,
                        "description": "Sever network connectivity of the compromised endpoint via EDR network containment.",
                        "urgency": "CRITICAL",
                        "automation_ready": True,
                        "cli_command": f"Invoke-EDRContainment -ComputerName '{target_host}' -Action Isolate",
                    },
                    {
                        "action_type": "TERMINATE_PROCESS",
                        "target": "PowerShell / Ransomware PID",
                        "description": "Kill active adversary processes and memory dumpers.",
                        "urgency": "CRITICAL",
                        "automation_ready": True,
                        "cli_command": "Stop-Process -Name 'powershell','procdump','mimikatz' -Force",
                    },
                    {
                        "action_type": "BLOCK_IP",
                        "target": dest_c2,
                        "description": "Block C2 destination IP at perimeter firewall, edge proxies, and DNS sinkhole.",
                        "urgency": "HIGH",
                        "automation_ready": True,
                        "cli_command": f"New-NetFirewallRule -DisplayName 'Block C2 {dest_c2}' -Direction Outbound -RemoteAddress {dest_c2} -Action Block",
                    },
                    {
                        "action_type": "RESET_PASSWORD",
                        "target": "Compromised Endpoint Users & Kerberos TGT",
                        "description": "Enforce immediate password reset and invalidate Kerberos tickets for users logged into this host.",
                        "urgency": "HIGH",
                        "automation_ready": True,
                        "cli_command": "Revoke-ADUserTokens -Identity '*' -HostScope target_host",
                    },
                ],
            }

        # Default fallback: Suspicious / Inconclusive
        return {
            "root_cause_analysis": "Anomalous telemetry requiring secondary Tier-2 manual verification.",
            "hypotheses": [
                {
                    "hypothesis": "Low-Risk Behavioral Anomaly",
                    "likelihood": "MEDIUM",
                    "supporting_evidence": ["Unusual command line execution pattern"],
                    "contradicting_evidence": ["No confirmed CTI hits"],
                }
            ],
            "verdict": TriageVerdict.SUSPICIOUS_BENIGN.value,
            "confidence_score": 60,
            "severity": Severity.MEDIUM.value,
            "executive_summary": "Telemetry shows anomalous execution characteristics, but lacks definitive indicators of compromise.",
            "containment_playbook": [
                {
                    "action_type": "COLLECT_FORENSIC_TRIAGE",
                    "target": state.alerts[0].host if state.alerts else "target-system",
                    "description": "Collect full memory capture and process tree for deep forensic analysis.",
                    "urgency": "MEDIUM",
                    "automation_ready": True,
                    "cli_command": "Start-ForensicCapture -Scope Quick",
                }
            ],
        }


class TriageEngine:
    """Coordinates structured reasoning prompts and populates investigation findings."""

    def __init__(self, provider: Optional[LLMReasoningProvider] = None):
        self.provider = provider or MockReasoningProvider()

    def run_triage(self, state: InvestigationState) -> InvestigationState:
        """Executes LLM reasoning across investigation state and updates verdict & playbook."""
        system_prompt = PromptTemplates.SYSTEM_PROMPT
        graph_dict = state.graph_summary.model_dump() if state.graph_summary else {}

        user_prompt = PromptTemplates.build_investigation_prompt(
            alerts=state.alerts,
            cti_data=state.enriched_cti,
            assets=state.internal_assets,
            users=state.internal_users,
            graph_summary=graph_dict,
            mitre_techniques=state.mitre_techniques,
        )

        reasoning_result = self.provider.evaluate(system_prompt, user_prompt, state)

        # Update state fields
        state.raw_reasoning_output = json.dumps(reasoning_result)
        state.root_cause_analysis = reasoning_result.get("root_cause_analysis")

        # Hypotheses
        raw_hypotheses = reasoning_result.get("hypotheses", [])
        state.hypotheses = [
            InvestigationHypothesis(
                hypothesis=h.get("hypothesis", ""),
                likelihood=h.get("likelihood", "MEDIUM"),
                supporting_evidence=h.get("supporting_evidence", []),
                contradicting_evidence=h.get("contradicting_evidence", []),
            )
            for h in raw_hypotheses
        ]

        # Verdict
        verdict_str = reasoning_result.get("verdict", TriageVerdict.INCONCLUSIVE.value)
        try:
            state.verdict = TriageVerdict(verdict_str)
        except ValueError:
            state.verdict = TriageVerdict.INCONCLUSIVE

        # Confidence
        conf = reasoning_result.get("confidence_score", 50)
        state.confidence_score = max(0, min(100, int(conf)))

        # Severity
        sev_str = reasoning_result.get("severity", Severity.MEDIUM.value)
        try:
            state.severity = Severity(sev_str)
        except ValueError:
            state.severity = Severity.MEDIUM

        # Executive summary
        state.executive_summary = reasoning_result.get("executive_summary")

        # Containment playbook
        raw_playbook = reasoning_result.get("containment_playbook", [])
        state.containment_playbook = [
            ContainmentAction(
                action_type=item.get("action_type", "CONTAINMENT"),
                target=item.get("target", "System"),
                description=item.get("description", ""),
                urgency=Severity(item.get("urgency", Severity.HIGH.value)) if item.get("urgency") in Severity._value2member_map_ else Severity.HIGH,
                automation_ready=item.get("automation_ready", True),
                cli_command=item.get("cli_command"),
            )
            for item in raw_playbook
        ]

        return state
