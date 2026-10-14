"""
Parser for Windows Sysmon (System Monitor) telemetry events.
Normalizes Event ID 1 (Process Create), Event ID 3 (Network Connect),
Event ID 10 (Process Access), and Event ID 11 (File Create).
"""

from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional
import uuid

from ..state import AlertSource, NormalizedAlert, Observable, ObservableType


class SysmonParser:
    """Extracts observables and normalizes Windows Sysmon event logs."""

    @staticmethod
    def _parse_hashes(hash_str: Optional[str]) -> Dict[str, str]:
        """Extracts SHA256, MD5, and IMPHASH from Sysmon hash strings."""
        extracted: Dict[str, str] = {}
        if not hash_str:
            return extracted

        # Example format: "SHA256=A1B2...,MD5=C3D4...,IMPHASH=E5F6..."
        parts = hash_str.split(",")
        for part in parts:
            if "=" in part:
                algo, val = part.strip().split("=", 1)
                extracted[algo.upper()] = val.strip()
        return extracted

    @staticmethod
    def _parse_timestamp(val: Any) -> datetime:
        if isinstance(val, datetime):
            return val
        if isinstance(val, str) and val:
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
            ):
                try:
                    return datetime.strptime(val, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
        return datetime.now(timezone.utc)

    def parse(self, raw_record: Dict[str, Any]) -> NormalizedAlert:
        """Parses a raw Sysmon record into a NormalizedAlert."""
        # Check if record has nested Event data or is flattened
        event_data = raw_record.get("EventData", raw_record)
        system_data = raw_record.get("System", {})

        event_id = str(
            raw_record.get(
                "EventID",
                system_data.get("EventID", event_data.get("EventID", "1")),
            )
        )
        time_created = (
            raw_record.get("UtcTime")
            or raw_record.get("TimeCreated")
            or system_data.get("TimeCreated", {}).get("@SystemTime")
            or event_data.get("UtcTime")
        )
        timestamp = self._parse_timestamp(time_created)

        computer = (
            raw_record.get("Computer")
            or system_data.get("Computer")
            or event_data.get("Computer")
            or "UNKNOWN-HOST"
        )
        user = raw_record.get("User") or event_data.get("User")

        # Process-related attributes
        image = (
            raw_record.get("Image")
            or event_data.get("Image")
            or raw_record.get("ProcessName")
        )
        command_line = raw_record.get("CommandLine") or event_data.get("CommandLine")
        parent_image = (
            raw_record.get("ParentImage")
            or event_data.get("ParentImage")
            or raw_record.get("ParentProcessName")
        )

        pid_val = raw_record.get("ProcessId") or event_data.get("ProcessId")
        ppid_val = raw_record.get("ParentProcessId") or event_data.get("ParentProcessId")

        pid = int(pid_val) if pid_val is not None and str(pid_val).isdigit() else None
        ppid = int(ppid_val) if ppid_val is not None and str(ppid_val).isdigit() else None

        # Network attributes
        src_ip = raw_record.get("SourceIp") or event_data.get("SourceIp")
        src_port_val = raw_record.get("SourcePort") or event_data.get("SourcePort")
        src_port = int(src_port_val) if src_port_val is not None and str(src_port_val).isdigit() else None

        dest_ip = raw_record.get("DestinationIp") or event_data.get("DestinationIp")
        dest_port_val = raw_record.get("DestinationPort") or event_data.get("DestinationPort")
        dest_port = int(dest_port_val) if dest_port_val is not None and str(dest_port_val).isdigit() else None
        query = raw_record.get("QueryName") or event_data.get("QueryName")

        # File & Access attributes
        target_filename = raw_record.get("TargetFilename") or event_data.get("TargetFilename")
        target_image = raw_record.get("TargetImage") or event_data.get("TargetImage")

        # Hashes
        raw_hashes = raw_record.get("Hashes") or event_data.get("Hashes")
        parsed_hashes = self._parse_hashes(raw_hashes)
        sha256 = parsed_hashes.get("SHA256") or raw_record.get("sha256") or event_data.get("sha256")
        md5 = parsed_hashes.get("MD5") or raw_record.get("md5") or event_data.get("md5")

        observables: List[Observable] = []

        if computer:
            observables.append(
                Observable(obs_type=ObservableType.HOST, value=computer, context="endpoint")
            )
        if user:
            observables.append(
                Observable(obs_type=ObservableType.USER, value=user, context="process_owner")
            )
        if image:
            observables.append(
                Observable(obs_type=ObservableType.PROCESS_NAME, value=image, context="executable")
            )
        if command_line:
            observables.append(
                Observable(
                    obs_type=ObservableType.COMMAND_LINE,
                    value=command_line,
                    context="process_execution",
                )
            )
        if sha256:
            observables.append(
                Observable(obs_type=ObservableType.HASH_SHA256, value=sha256, context="image_hash")
            )
        if md5:
            observables.append(
                Observable(obs_type=ObservableType.HASH_MD5, value=md5, context="image_hash")
            )
        if dest_ip:
            observables.append(
                Observable(obs_type=ObservableType.IP, value=dest_ip, context="outbound_destination")
            )
        if src_ip:
            observables.append(
                Observable(obs_type=ObservableType.IP, value=src_ip, context="local_source")
            )
        if query:
            observables.append(
                Observable(obs_type=ObservableType.DOMAIN, value=query, context="dns_query")
            )
        if target_filename:
            observables.append(
                Observable(
                    obs_type=ObservableType.FILE_PATH,
                    value=target_filename,
                    context="file_activity",
                )
            )
        if target_image:
            observables.append(
                Observable(
                    obs_type=ObservableType.PROCESS_NAME,
                    value=target_image,
                    context="target_process_access",
                )
            )

        alert_id = str(raw_record.get("alert_id") or raw_record.get("RecordId") or f"sysmon-{uuid.uuid4().hex[:8]}")

        return NormalizedAlert(
            alert_id=alert_id,
            timestamp=timestamp,
            source=AlertSource.SYSMON,
            raw_event=raw_record,
            host=computer,
            user=user,
            process_name=image,
            pid=pid,
            ppid=ppid,
            parent_process_name=parent_image,
            command_line=command_line,
            file_path=target_filename,
            file_hash=sha256 or md5,
            src_ip=src_ip,
            src_port=src_port,
            dest_ip=dest_ip,
            dest_port=dest_port,
            query=query,
            observables=observables,
        )
