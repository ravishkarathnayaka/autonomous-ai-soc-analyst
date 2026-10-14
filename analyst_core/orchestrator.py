"""
Autonomous SOC Analyst Investigation Orchestrator.
Coordinates alert ingestion, parsing, enrichment, attack graph correlation,
LLM reasoning, and report generation.
"""

import argparse
from datetime import datetime, timezone
import json
import os
import sys
from typing import Any, Dict, List, Optional, Union
import uuid

from .correlation.attack_graph import AttackGraphBuilder
from .correlation.mitre_mapper import MitreMapper
from .enrichment.cti_client import CTIClient
from .enrichment.internal_context import InternalContextDB
from .parsers.cloudtrail_parser import CloudTrailParser
from .parsers.sysmon_parser import SysmonParser
from .parsers.zeek_parser import ZeekParser
from .reasoning.triage_engine import (
    MockReasoningProvider,
    OllamaReasoningProvider,
    TriageEngine,
)
from .reporting.incident_report import IncidentReportGenerator
from .state import (
    AlertSource,
    InvestigationState,
    NormalizedAlert,
    Observable,
    ObservableType,
)


class AnalystOrchestrator:
    """Master controller orchestrating autonomous end-to-end alert triage."""

    def __init__(
        self,
        reasoning_provider: Optional[str] = "mock",
        ollama_model: Optional[str] = None,
        ollama_host: Optional[str] = None,
    ):
        self.sysmon_parser = SysmonParser()
        self.cloudtrail_parser = CloudTrailParser()
        self.zeek_parser = ZeekParser()
        self.cti_client = CTIClient()
        self.context_db = InternalContextDB()
        self.mitre_mapper = MitreMapper()

        if reasoning_provider == "ollama":
            provider = OllamaReasoningProvider(host=ollama_host, model=ollama_model)
        else:
            provider = MockReasoningProvider()

        self.triage_engine = TriageEngine(provider=provider)

    def detect_source(self, raw_record: Dict[str, Any]) -> AlertSource:
        """Determines the alert source from structure and signature fields."""
        if "eventName" in raw_record or "eventSource" in raw_record or "userIdentity" in raw_record:
            return AlertSource.CLOUDTRAIL
        if "EventID" in raw_record or "EventData" in raw_record or "UtcTime" in raw_record:
            return AlertSource.SYSMON
        if "id.orig_h" in raw_record or "orig_h" in raw_record or "conn_state" in raw_record or "qtype_name" in raw_record:
            return AlertSource.ZEEK
        return AlertSource.GENERIC

    def normalize_single(self, raw_record: Dict[str, Any]) -> NormalizedAlert:
        """Parses a single raw event into a NormalizedAlert."""
        source = self.detect_source(raw_record)
        if source == AlertSource.CLOUDTRAIL:
            return self.cloudtrail_parser.parse(raw_record)
        elif source == AlertSource.ZEEK:
            return self.zeek_parser.parse(raw_record)
        else:
            return self.sysmon_parser.parse(raw_record)

    def ingest(self, raw_data: Union[Dict[str, Any], List[Dict[str, Any]]]) -> List[NormalizedAlert]:
        """Ingests raw alert data (single event, alert envelope, or batch list)."""
        alerts: List[NormalizedAlert] = []

        if isinstance(raw_data, list):
            for item in raw_data:
                alerts.append(self.normalize_single(item))
        elif isinstance(raw_data, dict):
            # Check if dict contains a list of events under common keys
            if "events" in raw_data and isinstance(raw_data["events"], list):
                for item in raw_data["events"]:
                    alerts.append(self.normalize_single(item))
            elif "records" in raw_data and isinstance(raw_data["records"], list):
                for item in raw_data["records"]:
                    alerts.append(self.normalize_single(item))
            elif "alerts" in raw_data and isinstance(raw_data["alerts"], list):
                for item in raw_data["alerts"]:
                    alerts.append(self.normalize_single(item))
            else:
                alerts.append(self.normalize_single(raw_data))

        return alerts

    def investigate(
        self,
        raw_telemetry: Union[Dict[str, Any], List[Dict[str, Any]]],
        investigation_id: Optional[str] = None,
    ) -> InvestigationState:
        """Runs the complete autonomous investigation pipeline."""
        inv_id = investigation_id or f"inv-{uuid.uuid4().hex[:10]}"
        now = datetime.now(timezone.utc)

        # 1. Ingestion & Normalization
        normalized_alerts = self.ingest(raw_telemetry)

        # 2. Extract Observables
        all_observables: List[Observable] = []
        seen_obs = set()
        for alert in normalized_alerts:
            for obs in alert.observables:
                key = (obs.obs_type, obs.value)
                if key not in seen_obs:
                    seen_obs.add(key)
                    all_observables.append(obs)

        # 3. Threat Intelligence Enrichment
        cti_data = self.cti_client.enrich_batch(all_observables)

        # 4. Internal Environmental Context
        assets = {}
        users = {}
        for alert in normalized_alerts:
            if alert.host and alert.host not in assets:
                assets[alert.host] = self.context_db.resolve_asset(alert.host)
            if alert.user and alert.user not in users:
                users[alert.user] = self.context_db.resolve_user(alert.user)

        # 5. Attack Graph Modeling
        graph_builder = AttackGraphBuilder()
        graph_builder.build_from_alerts(normalized_alerts)
        graph_summary = graph_builder.summarize()

        # 6. MITRE ATT&CK Mapping
        mitre_techniques = self.mitre_mapper.map_alerts(normalized_alerts)

        # Initialize State
        state = InvestigationState(
            investigation_id=inv_id,
            created_at=now,
            updated_at=now,
            alerts=normalized_alerts,
            observables=all_observables,
            enriched_cti=cti_data,
            internal_assets=assets,
            internal_users=users,
            graph_summary=graph_summary,
            mitre_techniques=mitre_techniques,
        )

        # 7. LLM Reasoning & Triage Verdict
        state = self.triage_engine.run_triage(state)

        return state


def run_cli():
    """Command-line interface for the autonomous SOC analyst orchestrator."""
    parser = argparse.ArgumentParser(
        description="Autonomous Tier-1 AI SOC Analyst & Threat Investigation Agent"
    )
    parser.add_argument(
        "--alert",
        "-a",
        required=True,
        help="Path to raw alert JSON file or telemetry fixture",
    )
    parser.add_argument(
        "--provider",
        choices=["mock", "ollama"],
        default="mock",
        help="Reasoning provider (default: mock for deterministic offline execution)",
    )
    parser.add_argument(
        "--model",
        default="llama3.2",
        help="Ollama model name if provider=ollama (default: llama3.2)",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Optional path to write generated Markdown report",
    )
    parser.add_argument(
        "--json-playbook",
        help="Optional path to write SOAR containment JSON playbook",
    )

    args = parser.parse_args()

    if not os.path.exists(args.alert):
        print(f"Error: Alert file '{args.alert}' not found.", file=sys.stderr)
        sys.exit(1)

    with open(args.alert, "r", encoding="utf-8") as f:
        try:
            raw_data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error: Failed to parse JSON from '{args.alert}': {e}", file=sys.stderr)
            sys.exit(1)

    # Ensure UTF-8 console output on Windows
    if sys.platform == "win32":
        try:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            if hasattr(sys.stderr, "reconfigure"):
                sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    print("=" * 70)
    print("[*] AUTONOMOUS TIER-1 AI SOC ANALYST - THREAT INVESTIGATION PIPELINE")
    print("=" * 70)
    print(f"[*] Ingesting telemetry: {args.alert}")
    print(f"[*] Reasoning engine: {args.provider.upper()} (Model: {args.model})")

    orchestrator = AnalystOrchestrator(
        reasoning_provider=args.provider,
        ollama_model=args.model,
    )

    state = orchestrator.investigate(raw_data)

    print(f"\n[+] Investigation Completed: {state.investigation_id}")
    print(f"    Verdict:           {state.verdict.value}")
    print(f"    Confidence:        {state.confidence_score}%")
    print(f"    Severity:          {state.severity.value}")
    print(f"    Events Correlated: {len(state.alerts)}")
    print(f"    MITRE Techniques:  {len(state.mitre_techniques)}")
    print(f"    Containment Steps: {len(state.containment_playbook)}")

    print("\n" + "-" * 70)
    print("EXECUTIVE SUMMARY:")
    print(f"{state.executive_summary}")
    print("-" * 70)

    # Render Markdown report
    report_md = IncidentReportGenerator.generate_markdown(state)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report_md)
        print(f"\n[+] Markdown Incident Report saved to: {args.output}")

    if args.json_playbook:
        playbook_dict = IncidentReportGenerator.generate_json_playbook(state)
        with open(args.json_playbook, "w", encoding="utf-8") as f:
            json.dump(playbook_dict, f, indent=2)
        print(f"[+] SOAR Containment Playbook saved to: {args.json_playbook}")

    print("\n[+] Autonomous Triage Complete.\n")


if __name__ == "__main__":
    run_cli()
