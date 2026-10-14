"""
Structured investigation prompt templates enforcing Chain-of-Thought (CoT)
cyber defense analysis and JSON-formatted structured outputs.
"""

import json
from typing import Any, Dict, List
from ..state import CTIIndicator, MitreTechnique, NormalizedAlert, AssetContext, UserContext


class PromptTemplates:
    """Formats raw telemetry and enriched graph context into structured LLM prompts."""

    SYSTEM_PROMPT = """You are an Autonomous Tier-1 / Senior Lead Security Operations Center (SOC) Analyst and Incident Response Specialist.
Your objective is to autonomously investigate security alerts, assess the attack chain, distinguish between legitimate administrative tasks and malicious activity, determine a triage verdict, and prescribe concrete containment actions.

You must think methodically using Chain-of-Thought (CoT):
1. Root Cause & Inception: What process, network connection, or identity call originated this activity?
2. Contextual Validation: Is this routine system administration, legitimate DevOps, or unauthorized activity? Consider asset criticality and user privileges.
3. Threat Intelligence & Reputation: Do observed IPs, hashes, or domains match known adversary infrastructure or anonymizers?
4. Causal Linkage: How do the individual events interconnect in the attack graph?
5. MITRE ATT&CK Attribution: Which tactics and techniques are confirmed by observed evidence?
6. Containment & Remediation: What immediate, high-priority actions must be taken to mitigate the blast radius?

You MUST respond strictly with a valid JSON object matching this schema:
{
  "root_cause_analysis": "Detailed explanation of the causal root cause...",
  "hypotheses": [
    {
      "hypothesis": "Hypothesis title...",
      "likelihood": "HIGH | MEDIUM | LOW",
      "supporting_evidence": ["evidence 1", "evidence 2"],
      "contradicting_evidence": ["evidence 1"]
    }
  ],
  "verdict": "TRUE_POSITIVE | FALSE_POSITIVE | SUSPICIOUS_BENIGN | INCONCLUSIVE",
  "confidence_score": 85,
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL",
  "executive_summary": "High-level incident summary for CISO / SOC leadership...",
  "containment_playbook": [
    {
      "action_type": "ISOLATE_HOST | REVOKE_CREDENTIALS | BLOCK_IP | TERMINATE_PROCESS | RESET_PASSWORD",
      "target": "Hostname, IP, User, or PID",
      "description": "Specific containment step explanation",
      "urgency": "CRITICAL | HIGH | MEDIUM | LOW",
      "automation_ready": true,
      "cli_command": "Command line snippet or API call"
    }
  ]
}
"""

    @classmethod
    def build_investigation_prompt(
        cls,
        alerts: List[NormalizedAlert],
        cti_data: Dict[str, CTIIndicator],
        assets: Dict[str, AssetContext],
        users: Dict[str, UserContext],
        graph_summary: Dict[str, Any],
        mitre_techniques: List[MitreTechnique],
    ) -> str:
        """Constructs the user investigation prompt with all correlated telemetry and context."""

        # Format alerts
        formatted_alerts = []
        for idx, a in enumerate(alerts, 1):
            formatted_alerts.append({
                "index": idx,
                "alert_id": a.alert_id,
                "timestamp": str(a.timestamp),
                "source": a.source.value,
                "host": a.host,
                "user": a.user,
                "process": a.process_name,
                "pid": a.pid,
                "parent_process": a.parent_process_name,
                "ppid": a.ppid,
                "command_line": a.command_line,
                "network": f"{a.src_ip}:{a.src_port} -> {a.dest_ip}:{a.dest_port}" if a.dest_ip else None,
                "api_call": a.api_call,
                "file_path": a.file_path,
            })

        # Format CTI
        formatted_cti = {}
        for k, v in cti_data.items():
            formatted_cti[k] = {
                "malicious": v.malicious,
                "threat_score": v.threat_score,
                "tags": v.tags,
                "description": v.description,
            }

        # Format Assets & Users
        formatted_assets = {k: v.model_dump() for k, v in assets.items()}
        formatted_users = {k: v.model_dump() for k, v in users.items()}

        # Format MITRE
        formatted_mitre = [
            {
                "id": m.technique_id,
                "name": m.technique_name,
                "tactic": m.tactic,
                "observed_indicators": m.observed_indicators,
            }
            for m in mitre_techniques
        ]

        payload = {
            "telemetry_stream": formatted_alerts,
            "threat_intelligence_enrichment": formatted_cti,
            "internal_asset_context": formatted_assets,
            "user_identity_context": formatted_users,
            "attack_graph_correlation": graph_summary,
            "mitre_attack_mappings": formatted_mitre,
        }

        return f"""Perform an autonomous SOC Tier-1 triage investigation on the following incident telemetry:

```json
{json.dumps(payload, indent=2)}
```

Analyze the telemetry according to your instructions and provide your structured JSON triage receipt.
"""
