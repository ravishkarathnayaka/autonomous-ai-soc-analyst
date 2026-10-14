"""
Unit tests for NetworkX attack graph construction and causal correlation.
"""

from analyst_core.correlation.attack_graph import AttackGraphBuilder
from analyst_core.parsers.sysmon_parser import SysmonParser


def test_attack_graph_parent_child_lineage():
    parser = SysmonParser()
    builder = AttackGraphBuilder()

    # Alert 1: Word spawns PowerShell
    alert1 = parser.parse({
        "EventID": 1,
        "ProcessId": 4120,
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -enc XYZ",
        "ParentProcessId": 1844,
        "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "Computer": "FIN-WS-04",
        "User": "CORP\\finance_user",
    })

    # Alert 2: PowerShell connects to external IP
    alert2 = parser.parse({
        "EventID": 3,
        "ProcessId": 4120,
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "DestinationIp": "45.33.32.156",
        "DestinationPort": 443,
        "Computer": "FIN-WS-04",
    })

    # Alert 3: Encrypted file created
    alert3 = parser.parse({
        "EventID": 11,
        "ProcessId": 4120,
        "TargetFilename": "C:\\Data\\Finance.xlsx.locked",
        "Computer": "FIN-WS-04",
    })

    graph = builder.build_from_alerts([alert1, alert2, alert3])

    assert graph.number_of_nodes() > 0
    assert graph.number_of_edges() > 0

    # Verify parent spawned child edge
    parent_node = "proc::FIN-WS-04::1844"
    child_node = "proc::FIN-WS-04::4120"
    assert graph.has_edge(parent_node, child_node)
    assert graph.edges[parent_node, child_node]["relation"] == "SPAWNED"

    # Verify process connected to external IP edge
    ip_node = "ip::45.33.32.156"
    assert graph.has_edge(child_node, ip_node)
    assert graph.edges[child_node, ip_node]["relation"] == "CONNECTED_TO"

    # Verify file modification edge
    file_node = "file::FIN-WS-04::C:\\Data\\Finance.xlsx.locked"
    assert graph.has_edge(child_node, file_node)
    assert graph.edges[child_node, file_node]["relation"] == "MODIFIED_FILE"

    # Verify graph summary and suspicious chain detection
    summary = builder.summarize()
    assert summary.total_nodes >= 5
    assert len(summary.suspicious_chains) > 0


def test_attack_graph_cytoscape_export():
    parser = SysmonParser()
    builder = AttackGraphBuilder()

    alert = parser.parse({
        "EventID": 1,
        "ProcessId": 1000,
        "Image": "C:\\Windows\\System32\\whoami.exe",
        "Computer": "SERVER-01",
    })

    builder.build_from_alerts([alert])
    cyto = builder.to_cytoscape_json()

    assert "nodes" in cyto
    assert "edges" in cyto
    assert len(cyto["nodes"]) >= 2
