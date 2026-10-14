"""
In-memory attack graph modeling using NetworkX.
Correlates processes, network connections, users, and files across time,
discovering causal lineages, lateral movement, and blast radius.
"""

from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx

from ..state import GraphSummary, NormalizedAlert, Observable, ObservableType


class AttackGraphBuilder:
    """Constructs and queries directed attack graphs from normalized telemetry."""

    def __init__(self):
        self.graph = nx.DiGraph()

    def build_from_alerts(self, alerts: List[NormalizedAlert]) -> nx.DiGraph:
        """Populates the directed graph with nodes and causal relationships from alerts."""
        for alert in alerts:
            self._add_alert_to_graph(alert)
        return self.graph

    def _add_alert_to_graph(self, alert: NormalizedAlert) -> None:
        g = self.graph

        # Add Host node
        host_id = f"host::{alert.host or 'unknown'}"
        if not g.has_node(host_id):
            g.add_node(host_id, node_type="HOST", label=alert.host or "Unknown Host")

        # Add User node
        if alert.user:
            user_id = f"user::{alert.user}"
            if not g.has_node(user_id):
                g.add_node(user_id, node_type="USER", label=alert.user)
            g.add_edge(user_id, host_id, relation="LOGGED_INTO", timestamp=str(alert.timestamp))

        # Process creation (Sysmon Event 1)
        if alert.process_name or alert.pid:
            proc_id = (
                f"proc::{alert.host}::{alert.pid}"
                if alert.pid
                else f"proc::{alert.host}::{alert.process_name}"
            )

            if not g.has_node(proc_id):
                g.add_node(
                    proc_id,
                    node_type="PROCESS",
                    label=alert.process_name or "UnknownProcess",
                    pid=alert.pid,
                    image=alert.process_name,
                    command_line=alert.command_line,
                    user=alert.user,
                    timestamp=str(alert.timestamp),
                )

            g.add_edge(host_id, proc_id, relation="EXECUTED_ON", timestamp=str(alert.timestamp))

            # Link parent to child (SPAWNED)
            if alert.ppid:
                parent_id = f"proc::{alert.host}::{alert.ppid}"
                if not g.has_node(parent_id):
                    g.add_node(
                        parent_id,
                        node_type="PROCESS",
                        label=alert.parent_process_name or f"PID-{alert.ppid}",
                        pid=alert.ppid,
                        image=alert.parent_process_name,
                    )
                g.add_edge(parent_id, proc_id, relation="SPAWNED", timestamp=str(alert.timestamp))

            # Process Network connection (Sysmon Event 3 or Zeek)
            if alert.dest_ip:
                ip_id = f"ip::{alert.dest_ip}"
                if not g.has_node(ip_id):
                    g.add_node(
                        ip_id,
                        node_type="IP_ADDRESS",
                        label=alert.dest_ip,
                        port=alert.dest_port,
                    )
                g.add_edge(
                    proc_id,
                    ip_id,
                    relation="CONNECTED_TO",
                    dest_port=alert.dest_port,
                    timestamp=str(alert.timestamp),
                )

            # File activity (Sysmon Event 11)
            if alert.file_path:
                file_id = f"file::{alert.host}::{alert.file_path}"
                if not g.has_node(file_id):
                    g.add_node(
                        file_id,
                        node_type="FILE",
                        label=alert.file_path,
                        hash=alert.file_hash,
                    )
                g.add_edge(
                    proc_id,
                    file_id,
                    relation="MODIFIED_FILE",
                    timestamp=str(alert.timestamp),
                )

        # Network only (Zeek connection / DNS)
        elif alert.src_ip and alert.dest_ip:
            src_node = f"ip::{alert.src_ip}"
            dest_node = f"ip::{alert.dest_ip}"

            if not g.has_node(src_node):
                g.add_node(src_node, node_type="IP_ADDRESS", label=alert.src_ip)
            if not g.has_node(dest_node):
                g.add_node(
                    dest_node,
                    node_type="IP_ADDRESS",
                    label=alert.dest_ip,
                    port=alert.dest_port,
                )

            g.add_edge(
                src_node,
                dest_node,
                relation="NETWORK_TRAFFIC",
                dest_port=alert.dest_port,
                query=alert.query,
                timestamp=str(alert.timestamp),
            )

        # CloudTrail API Call
        if alert.api_call:
            api_node = f"api::{alert.api_call}"
            if not g.has_node(api_node):
                g.add_node(
                    api_node,
                    node_type="CLOUD_API",
                    label=alert.api_call,
                    params=alert.request_parameters,
                )

            actor_id = f"user::{alert.user}" if alert.user else host_id
            g.add_edge(
                actor_id,
                api_node,
                relation="INVOKED_API",
                caller_ip=alert.src_ip,
                timestamp=str(alert.timestamp),
            )

            # If caller IP exists, link caller IP -> actor
            if alert.src_ip:
                caller_node = f"ip::{alert.src_ip}"
                if not g.has_node(caller_node):
                    g.add_node(caller_node, node_type="IP_ADDRESS", label=alert.src_ip)
                g.add_edge(
                    caller_node,
                    actor_id,
                    relation="ORIGINATED_FROM",
                    timestamp=str(alert.timestamp),
                )

    def find_suspicious_chains(self) -> List[str]:
        """Detects high-risk execution lineages (e.g., PowerShell -> C2 or Process Injection)."""
        chains: List[str] = []
        g = self.graph

        for node, data in g.nodes(data=True):
            if data.get("node_type") == "PROCESS":
                label = (data.get("label") or "").lower()
                cmd = (data.get("command_line") or "").lower()

                # Suspicious script interpreters or dumpers
                if any(k in label or k in cmd for k in ("powershell", "cmd.exe", "wscript", "cscript", "mshta", "mimikatz", "procdump")):
                    # Check outbound edges
                    for successor in g.successors(node):
                        edge_data = g.get_edge_data(node, successor)
                        succ_data = g.nodes[successor]
                        rel = edge_data.get("relation", "CONNECTED")

                        # Process -> Outbound IP
                        if succ_data.get("node_type") == "IP_ADDRESS":
                            chains.append(
                                f"Suspicious Process [{data.get('label')}] (PID {data.get('pid')}) {rel} -> External Network [{succ_data.get('label')}]"
                            )
                        # Process -> File creation / ransomware
                        elif succ_data.get("node_type") == "FILE":
                            chains.append(
                                f"Script / Execution Tool [{data.get('label')}] {rel} -> File [{succ_data.get('label')}]"
                            )
                        # Process -> Process access (e.g. LSASS access)
                        elif succ_data.get("node_type") == "PROCESS":
                            chains.append(
                                f"Process Parent-Child / Access: [{data.get('label')}] -> [{succ_data.get('label')}]"
                            )

            # Tor / External IP calling AWS API
            elif data.get("node_type") == "IP_ADDRESS":
                for succ in g.successors(node):
                    succ_data = g.nodes[succ]
                    if succ_data.get("node_type") in ("USER", "CLOUD_API"):
                        chains.append(
                            f"Remote Address [{data.get('label')}] invoked Cloud Identity / API [{succ_data.get('label')}]"
                        )

        return chains

    def summarize(self) -> GraphSummary:
        """Calculates graph metrics, root causes, and chain findings."""
        g = self.graph
        node_types: Dict[str, int] = {}
        for _, data in g.nodes(data=True):
            ntype = data.get("node_type", "OTHER")
            node_types[ntype] = node_types.get(ntype, 0) + 1

        root_nodes = [
            n for n in g.nodes()
            if g.in_degree(n) == 0 and g.out_degree(n) > 0
        ]
        leaf_nodes = [
            n for n in g.nodes()
            if g.out_degree(n) == 0 and g.in_degree(n) > 0
        ]

        suspicious_chains = self.find_suspicious_chains()

        return GraphSummary(
            total_nodes=g.number_of_nodes(),
            total_edges=g.number_of_edges(),
            suspicious_chains=suspicious_chains,
            root_nodes=root_nodes[:10],
            leaf_nodes=leaf_nodes[:10],
            node_types=node_types,
        )

    def to_cytoscape_json(self) -> Dict[str, Any]:
        """Exports graph in Cytoscape format for web UI visualization."""
        nodes = []
        for n, data in self.graph.nodes(data=True):
            nodes.append({
                "data": {
                    "id": n,
                    "label": data.get("label", n),
                    "type": data.get("node_type", "OTHER"),
                    **{k: v for k, v in data.items() if k not in ("label", "node_type") and isinstance(v, (str, int, float, bool))},
                }
            })

        edges = []
        for u, v, data in self.graph.edges(data=True):
            edges.append({
                "data": {
                    "id": f"{u}->{v}",
                    "source": u,
                    "target": v,
                    "label": data.get("relation", "RELATION"),
                    **{k: v for k, v in data.items() if k != "relation" and isinstance(v, (str, int, float, bool))},
                }
            })

        return {"nodes": nodes, "edges": edges}
