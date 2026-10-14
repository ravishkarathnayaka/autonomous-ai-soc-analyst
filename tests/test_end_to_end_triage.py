"""
End-to-end integration tests executing the complete autonomous triage pipeline
across all sample telemetry fixtures and FastAPI endpoints.
"""

import json
from pathlib import Path
from fastapi.testclient import TestClient

from analyst_core.orchestrator import AnalystOrchestrator
from analyst_core.reporting.incident_report import IncidentReportGenerator
from analyst_core.state import Severity, TriageVerdict
from api.app import app


client = TestClient(app)
FIXTURES_DIR = Path(__file__).parent.parent / "telemetry_fixtures"


def test_e2e_true_positive_ransomware():
    fixture_path = FIXTURES_DIR / "true_positive_ransomware.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        telemetry = json.load(f)

    orchestrator = AnalystOrchestrator(reasoning_provider="mock")
    state = orchestrator.investigate(telemetry, investigation_id="e2e-ransomware-001")

    # Verify pipeline state
    assert state.investigation_id == "e2e-ransomware-001"
    assert state.verdict == TriageVerdict.TRUE_POSITIVE
    assert state.confidence_score >= 90
    assert state.severity in (Severity.CRITICAL, Severity.HIGH)
    assert len(state.alerts) == 4
    assert len(state.observables) >= 5
    assert len(state.mitre_techniques) >= 2

    # Verify report generation
    report = IncidentReportGenerator.generate_markdown(state)
    assert "Incident Triage & Investigation Report" in report
    assert "TRUE POSITIVE" in report
    assert "Containment Playbook" in report

    # Verify SOAR JSON playbook
    playbook = IncidentReportGenerator.generate_json_playbook(state)
    assert playbook["verdict"] == "TRUE_POSITIVE"
    assert len(playbook["containment_actions"]) >= 2


def test_e2e_false_positive_admin():
    fixture_path = FIXTURES_DIR / "false_positive_admin.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        telemetry = json.load(f)

    orchestrator = AnalystOrchestrator(reasoning_provider="mock")
    state = orchestrator.investigate(telemetry, investigation_id="e2e-admin-fp-002")

    assert state.verdict == TriageVerdict.FALSE_POSITIVE
    assert state.confidence_score >= 85
    assert state.severity == Severity.LOW
    assert "FALSE POSITIVE" in IncidentReportGenerator.generate_markdown(state)


def test_e2e_cloud_credential_abuse():
    fixture_path = FIXTURES_DIR / "cloud_credential_abuse.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        telemetry = json.load(f)

    orchestrator = AnalystOrchestrator(reasoning_provider="mock")
    state = orchestrator.investigate(telemetry, investigation_id="e2e-cloud-tp-003")

    assert state.verdict == TriageVerdict.TRUE_POSITIVE
    assert state.severity == Severity.CRITICAL
    assert any("AKIAIOSFODNN7EXAMPLE" in a.target for a in state.containment_playbook)


def test_fastapi_e2e_endpoints():
    # 1. Healthcheck
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "HEALTHY"

    # 2. Ingest alert via API
    fixture_path = FIXTURES_DIR / "cloud_credential_abuse.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        telemetry = json.load(f)

    triage_res = client.post(
        "/api/v1/triage",
        json={"telemetry": telemetry, "investigation_id": "api-test-001", "reasoning_provider": "mock"},
    )
    assert triage_res.status_code == 201
    summary = triage_res.json()
    assert summary["investigation_id"] == "api-test-001"
    assert summary["verdict"] == "TRUE_POSITIVE"

    # 3. Fetch detailed investigation
    detail_res = client.get("/api/v1/investigations/api-test-001")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["verdict"] == "TRUE_POSITIVE"
    assert len(detail["containment_playbook"]) > 0

    # 4. Fetch Cytoscape graph
    graph_res = client.get("/api/v1/investigations/api-test-001/graph")
    assert graph_res.status_code == 200
    assert "nodes" in graph_res.json()

    # 5. Ad-hoc CTI enrichment
    enrich_res = client.post("/api/v1/enrich", json={"indicator": "185.220.101.5", "ioc_type": "ip"})
    assert enrich_res.status_code == 200
    assert enrich_res.json()["malicious"] is True
    assert "tor_exit_node" in enrich_res.json()["tags"]
