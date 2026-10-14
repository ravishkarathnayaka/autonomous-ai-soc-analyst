"""
Unit tests for LLM reasoning and triage verdict evaluation.
"""

from analyst_core.parsers.sysmon_parser import SysmonParser
from analyst_core.reasoning.triage_engine import MockReasoningProvider, TriageEngine
from analyst_core.state import (
    CTIIndicator,
    InvestigationState,
    ObservableType,
    Severity,
    TriageVerdict,
)


def test_triage_verdict_ransomware():
    parser = SysmonParser()
    alert = parser.parse({
        "EventID": 1,
        "Image": "powershell.exe",
        "CommandLine": "powershell.exe -enc aWV4IChOZXctT2JqZWN0...",
        "Computer": "FIN-WS-04",
        "DestinationIp": "45.33.32.156",
    })

    state = InvestigationState(
        investigation_id="inv-test-tp",
        alerts=[alert],
        enriched_cti={
            "45.33.32.156": CTIIndicator(
                indicator="45.33.32.156",
                ioc_type=ObservableType.IP,
                malicious=True,
                threat_score=95,
                tags=["c2_server"],
            )
        },
    )

    engine = TriageEngine(provider=MockReasoningProvider())
    updated_state = engine.run_triage(state)

    assert updated_state.verdict == TriageVerdict.TRUE_POSITIVE
    assert updated_state.confidence_score >= 90
    assert updated_state.severity in (Severity.CRITICAL, Severity.HIGH)
    assert len(updated_state.containment_playbook) > 0
    assert any("ISOLATE" in a.action_type for a in updated_state.containment_playbook)


def test_triage_verdict_false_positive_admin():
    parser = SysmonParser()
    alert = parser.parse({
        "EventID": 1,
        "Image": "powershell.exe",
        "CommandLine": "powershell.exe -File C:\\AdminScripts\\Weekly_Disk_Defrag_Backup.ps1",
        "Computer": "SRV-BACKUP-01",
        "User": "CORP\\svc-backup",
    })

    state = InvestigationState(
        investigation_id="inv-test-fp",
        alerts=[alert],
        enriched_cti={},
    )

    engine = TriageEngine(provider=MockReasoningProvider())
    updated_state = engine.run_triage(state)

    assert updated_state.verdict == TriageVerdict.FALSE_POSITIVE
    assert updated_state.confidence_score >= 85
    assert updated_state.severity == Severity.LOW
    assert len(updated_state.hypotheses) >= 1
    assert "Authorized Administrative Maintenance" in updated_state.hypotheses[0].hypothesis
