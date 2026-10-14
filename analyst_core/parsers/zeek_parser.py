"""
Parser for Zeek (Bro) network security monitor logs.
Normalizes conn.log, dns.log, http.log, and ssl.log telemetry records.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from ..state import AlertSource, NormalizedAlert, Observable, ObservableType


class ZeekParser:
    """Extracts network observables and normalizes Zeek network log entries."""

    @staticmethod
    def _parse_timestamp(val: Any) -> datetime:
        if isinstance(val, datetime):
            return val
        if isinstance(val, (int, float)):
            try:
                return datetime.fromtimestamp(val, tz=timezone.utc)
            except (ValueError, OverflowError):
                pass
        if isinstance(val, str) and val:
            try:
                # Might be epoch float string e.g. "1710403200.1234"
                return datetime.fromtimestamp(float(val), tz=timezone.utc)
            except ValueError:
                pass
            for fmt in (
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%d %H:%M:%S",
            ):
                try:
                    return datetime.strptime(val, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
        return datetime.now(timezone.utc)

    def parse(self, raw_record: Dict[str, Any]) -> NormalizedAlert:
        """Parses a raw Zeek JSON log record into a NormalizedAlert."""
        ts_val = raw_record.get("ts") or raw_record.get("timestamp")
        timestamp = self._parse_timestamp(ts_val)

        # Support nested Zeek record structure (id.orig_h or orig_h)
        id_block = raw_record.get("id", {})
        src_ip = (
            id_block.get("orig_h")
            or raw_record.get("id.orig_h")
            or raw_record.get("orig_h")
            or raw_record.get("src_ip")
        )
        src_port_val = (
            id_block.get("orig_p")
            or raw_record.get("id.orig_p")
            or raw_record.get("orig_p")
            or raw_record.get("src_port")
        )
        dest_ip = (
            id_block.get("resp_h")
            or raw_record.get("id.resp_h")
            or raw_record.get("resp_h")
            or raw_record.get("dest_ip")
        )
        dest_port_val = (
            id_block.get("resp_p")
            or raw_record.get("id.resp_p")
            or raw_record.get("resp_p")
            or raw_record.get("dest_port")
        )

        src_port = int(src_port_val) if src_port_val is not None and str(src_port_val).isdigit() else None
        dest_port = int(dest_port_val) if dest_port_val is not None and str(dest_port_val).isdigit() else None

        proto = raw_record.get("proto", "tcp")
        service = raw_record.get("service") or raw_record.get("_path") or "conn"
        query = raw_record.get("query") or raw_record.get("host") or raw_record.get("server_name")
        uri = raw_record.get("uri")
        conn_state = raw_record.get("conn_state")
        uid = raw_record.get("uid") or f"zeek-{uuid.uuid4().hex[:8]}"

        observables: List[Observable] = []

        if src_ip:
            observables.append(
                Observable(
                    obs_type=ObservableType.IP,
                    value=src_ip,
                    context="zeek_originator",
                    tags=["zeek_client"],
                )
            )
        if dest_ip:
            observables.append(
                Observable(
                    obs_type=ObservableType.IP,
                    value=dest_ip,
                    context="zeek_responder",
                    tags=["zeek_destination"],
                )
            )
        if query:
            observables.append(
                Observable(
                    obs_type=ObservableType.DOMAIN,
                    value=query,
                    context=f"zeek_{service}_query",
                    tags=["dns_or_http_host"],
                )
            )
        if dest_port:
            observables.append(
                Observable(
                    obs_type=ObservableType.PORT,
                    value=str(dest_port),
                    context="destination_port",
                )
            )

        cmd_repr = f"Zeek {service.upper()} [{proto}] {src_ip}:{src_port} -> {dest_ip}:{dest_port}"
        if query:
            cmd_repr += f" query={query}"
        if uri:
            cmd_repr += f" uri={uri}"

        return NormalizedAlert(
            alert_id=str(raw_record.get("alert_id") or uid),
            timestamp=timestamp,
            source=AlertSource.ZEEK,
            raw_event=raw_record,
            host=src_ip or "network-sensor",
            user=raw_record.get("username"),
            process_name=f"zeek-{service}",
            command_line=cmd_repr,
            src_ip=src_ip,
            src_port=src_port,
            dest_ip=dest_ip,
            dest_port=dest_port,
            query=query,
            api_call=f"zeek:{service}",
            observables=observables,
        )
