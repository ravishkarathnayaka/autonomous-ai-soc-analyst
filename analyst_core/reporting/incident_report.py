"""
Generates enterprise-grade Markdown incident reports and structured
SOAR-compatible JSON containment playbooks.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict
from ..state import InvestigationState, Severity, TriageVerdict


class IncidentReportGenerator:
    """Produces executive Markdown reports and machine-actionable containment playbooks."""

    @staticmethod
    def generate_markdown(state: InvestigationState) -> str:
        """Renders a comprehensive, GitHub-flavored Markdown incident investigation report."""
        created_str = state.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")

        # Verdict Badge Styling
        verdict_badge = {
            TriageVerdict.TRUE_POSITIVE: "🚨 **TRUE POSITIVE (CONFIRMED ATTACK)**",
            TriageVerdict.FALSE_POSITIVE: "✅ **FALSE POSITIVE (BENIGN ACTIVITY)**",
            TriageVerdict.SUSPICIOUS_BENIGN: "⚠️ **SUSPICIOUS (MANUAL AUDIT RECOMMENDED)**",
            TriageVerdict.INCONCLUSIVE: "❓ **INCONCLUSIVE TELEMETRY**",
        }.get(state.verdict, str(state.verdict.value))

        severity_badge = {
            Severity.CRITICAL: "🔴 `CRITICAL`",
            Severity.HIGH: "🟠 `HIGH`",
            Severity.MEDIUM: "🟡 `MEDIUM`",
            Severity.LOW: "🔵 `LOW`",
            Severity.INFORMATIONAL: "⚪ `INFORMATIONAL`",
        }.get(state.severity, str(state.severity.value))

        lines = [
            f"# Incident Triage & Investigation Report: `{state.investigation_id}`",
            "",
            f"> **Autonomous AI SOC Analyst - Investigation Receipt**  ",
            f"> Generated: `{created_str}` | Engine: `Autonomous Tier-1 Pipeline v1.0`",
            "",
            "## 1. Executive Summary & Verdict",
            "",
            "| Metric | Assessment |",
            "| :--- | :--- |",
            f"| **Verdict** | {verdict_badge} |",
            f"| **Calculated Severity** | {severity_badge} |",
            f"| **Confidence Score** | `{state.confidence_score}%` |",
            f"| **Telemetry Events Correlated** | `{len(state.alerts)} records` |",
            f"| **Observables Extracted** | `{len(state.observables)} indicators` |",
            "",
            f"**Executive Summary:**  ",
            f"{state.executive_summary or 'No executive summary generated.'}",
            "",
            "## 2. Root Cause Analysis",
            "",
            f"{state.root_cause_analysis or 'Root cause undetermined.'}",
            "",
            "## 3. MITRE ATT&CK Matrix Alignment",
            "",
        ]

        if state.mitre_techniques:
            lines.extend([
                "| Tactic | Technique ID | Technique Name | Observed Indicators |",
                "| :--- | :--- | :--- | :--- |",
            ])
            for m in state.mitre_techniques:
                indicators = ", ".join(f"`{i}`" for i in m.observed_indicators) or "Behavioral pattern"
                lines.append(f"| **{m.tactic}** | `{m.technique_id}` | {m.technique_name} | {indicators} |")
        else:
            lines.append("_No MITRE ATT&CK techniques matched._")

        lines.extend([
            "",
            "## 4. Attack Chain Graph Correlation",
            "",
        ])

        if state.graph_summary:
            gs = state.graph_summary
            lines.extend([
                f"- **Total Correlated Entities:** `{gs.total_nodes} nodes`",
                f"- **Total Causal Interconnections:** `{gs.total_edges} edges`",
                f"- **Root Execution Nodes:** {', '.join(f'`{r}`' for r in gs.root_nodes) if gs.root_nodes else 'None'}",
                f"- **Terminal / Target Nodes:** {', '.join(f'`{l}`' for l in gs.leaf_nodes) if gs.leaf_nodes else 'None'}",
                "",
                "### Causal Paths & Anomalous Lineages:",
            ])
            if gs.suspicious_chains:
                for chain in gs.suspicious_chains:
                    lines.append(f"- ⚡ {chain}")
            else:
                lines.append("- _No anomalous execution chains detected._")
        else:
            lines.append("_Attack graph summary unavailable._")

        lines.extend([
            "",
            "## 5. Threat Intelligence & Indicator Enrichment",
            "",
        ])

        if state.enriched_cti:
            lines.extend([
                "| Indicator | Type | Malicious | Score | Reputation / Sources | Description |",
                "| :--- | :--- | :---: | :---: | :--- | :--- |",
            ])
            for ind, cti in state.enriched_cti.items():
                mal_badge = "🔴 **YES**" if cti.malicious else "🟢 NO"
                tags_str = ", ".join(cti.tags[:3]) if cti.tags else "clean"
                desc = (cti.description or "").replace("\n", " ")[:80]
                lines.append(
                    f"| `{ind}` | `{cti.ioc_type.value}` | {mal_badge} | `{cti.threat_score}/100` | `{tags_str}` | {desc} |"
                )
        else:
            lines.append("_No external threat intelligence hits._")

        lines.extend([
            "",
            "## 6. Internal Environmental Context",
            "",
        ])

        if state.internal_assets or state.internal_users:
            if state.internal_assets:
                lines.append("### Affected Assets:")
                for k, a in state.internal_assets.items():
                    crit_badge = "🚨 **Tier-0 (CRITICAL)**" if a.is_critical else f"`{a.asset_tier}`"
                    lines.append(f"- Asset `{a.identifier}` | Tier: {crit_badge} | Owner: `{a.owner}` | Env: `{a.environment}`")
            if state.internal_users:
                lines.append("\n### Involved Identities:")
                for k, u in state.internal_users.items():
                    priv_badge = "🔑 **Privileged**" if u.is_privileged else "Standard"
                    lines.append(f"- Identity `{u.username}` | Role: `{u.role}` | Privileges: {priv_badge} | Dept: `{u.department}`")
        else:
            lines.append("_No internal context matched._")

        lines.extend([
            "",
            "## 7. Competing Hypotheses & Probability",
            "",
        ])

        if state.hypotheses:
            for h in state.hypotheses:
                lines.extend([
                    f"### Hypothesis: {h.hypothesis} (Likelihood: `{h.likelihood}`)",
                    "**Supporting Evidence:**",
                ])
                for se in h.supporting_evidence:
                    lines.append(f"- {se}")
                if h.contradicting_evidence:
                    lines.append("**Contradicting Evidence:**")
                    for ce in h.contradicting_evidence:
                        lines.append(f"- {ce}")
                lines.append("")
        else:
            lines.append("_No competing hypotheses formulated._")

        lines.extend([
            "## 8. Actionable Containment Playbook (SOAR Ready)",
            "",
        ])

        if state.containment_playbook:
            lines.extend([
                "| Step | Action Type | Target | Urgency | Description |",
                "| :---: | :--- | :--- | :---: | :--- |",
            ])
            for idx, act in enumerate(state.containment_playbook, 1):
                urg_badge = f"`{act.urgency.value}`"
                lines.append(
                    f"| {idx} | **{act.action_type}** | `{act.target}` | {urg_badge} | {act.description} |"
                )

            lines.extend([
                "",
                "### Remediation Automation Commands:",
                "```bash",
            ])
            for act in state.containment_playbook:
                if act.cli_command:
                    lines.append(f"# [{act.action_type}] on target: {act.target}")
                    lines.append(f"{act.cli_command}\n")
            lines.append("```")
        else:
            lines.append("_No immediate containment actions required for this event._")

        lines.extend([
            "",
            "---",
            "*Report autonomously compiled by Autonomous Tier-1 AI SOC Analyst.*",
        ])

        return "\n".join(lines)

    @staticmethod
    def generate_json_playbook(state: InvestigationState) -> Dict[str, Any]:
        """Produces a machine-readable JSON dictionary for SOAR orchestration ingestion."""
        return {
            "investigation_id": state.investigation_id,
            "timestamp": state.created_at.isoformat(),
            "verdict": state.verdict.value,
            "severity": state.severity.value,
            "confidence_score": state.confidence_score,
            "root_cause": state.root_cause_analysis,
            "mitre_techniques": [
                {"id": m.technique_id, "name": m.technique_name, "tactic": m.tactic}
                for m in state.mitre_techniques
            ],
            "containment_actions": [
                {
                    "action_type": a.action_type,
                    "target": a.target,
                    "urgency": a.urgency.value,
                    "automation_ready": a.automation_ready,
                    "cli_command": a.cli_command,
                    "description": a.description,
                }
                for a in state.containment_playbook
            ],
            "indicators_of_compromise": [
                {
                    "indicator": ind,
                    "type": cti.ioc_type.value,
                    "malicious": cti.malicious,
                    "threat_score": cti.threat_score,
                }
                for ind, cti in state.enriched_cti.items()
                if cti.malicious
            ],
        }
