"""
Parser for AWS CloudTrail management and data event logs.
Normalizes IAM changes, credential utilization, privilege escalation,
and compute operations across multi-account cloud telemetry.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from ..state import AlertSource, NormalizedAlert, Observable, ObservableType


class CloudTrailParser:
    """Extracts observables and normalizes AWS CloudTrail records."""

    @staticmethod
    def _parse_timestamp(val: Any) -> datetime:
        if isinstance(val, datetime):
            return val
        if isinstance(val, str) and val:
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
        """Parses a raw CloudTrail JSON event into a NormalizedAlert."""
        event_time = raw_record.get("eventTime") or raw_record.get("timestamp")
        timestamp = self._parse_timestamp(event_time)

        event_name = raw_record.get("eventName") or "UnknownAPI"
        event_source = raw_record.get("eventSource") or "aws.general"
        api_call = f"{event_source}:{event_name}"

        user_identity = raw_record.get("userIdentity", {})
        user_name = (
            user_identity.get("userName")
            or user_identity.get("sessionContext", {})
            .get("sessionIssuer", {})
            .get("userName")
            or user_identity.get("principalId")
            or raw_record.get("user")
            or "anonymous"
        )
        access_key_id = user_identity.get("accessKeyId") or raw_record.get("accessKeyId")
        iam_arn = user_identity.get("arn") or raw_record.get("arn")

        source_ip = raw_record.get("sourceIPAddress") or raw_record.get("src_ip")
        user_agent = raw_record.get("userAgent")
        aws_region = raw_record.get("awsRegion") or "global"
        request_params = raw_record.get("requestParameters", {})

        observables: List[Observable] = []

        if user_name and user_name != "anonymous":
            observables.append(
                Observable(
                    obs_type=ObservableType.USER,
                    value=user_name,
                    context=f"iam_identity (type={user_identity.get('type', 'IAMUser')})",
                )
            )

        if access_key_id:
            observables.append(
                Observable(
                    obs_type=ObservableType.ACCESS_KEY_ID,
                    value=access_key_id,
                    context="aws_credentials",
                )
            )

        if source_ip and not source_ip.endswith(".amazonaws.com"):
            observables.append(
                Observable(
                    obs_type=ObservableType.IP,
                    value=source_ip,
                    context="cloud_caller_ip",
                    tags=["aws_cloudtrail_caller"],
                )
            )

        if iam_arn:
            observables.append(
                Observable(
                    obs_type=ObservableType.IAM_ROLE,
                    value=iam_arn,
                    context="aws_resource_arn",
                )
            )

        # Check for targeted user or role in request parameters
        if isinstance(request_params, dict):
            target_user = request_params.get("userName")
            target_role = request_params.get("roleName")
            policy_arn = request_params.get("policyArn")

            if target_user and target_user != user_name:
                observables.append(
                    Observable(
                        obs_type=ObservableType.USER,
                        value=target_user,
                        context="iam_target_user",
                    )
                )
            if target_role:
                observables.append(
                    Observable(
                        obs_type=ObservableType.IAM_ROLE,
                        value=target_role,
                        context="iam_target_role",
                    )
                )

        host_identifier = f"aws::{aws_region}::{event_source.split('.')[0]}"
        alert_id = str(raw_record.get("eventID") or raw_record.get("alert_id") or f"cloudtrail-{uuid.uuid4().hex[:8]}")

        return NormalizedAlert(
            alert_id=alert_id,
            timestamp=timestamp,
            source=AlertSource.CLOUDTRAIL,
            raw_event=raw_record,
            host=host_identifier,
            user=user_name,
            process_name=user_agent or "AWS-API-Client",
            command_line=f"{api_call} params={request_params}",
            src_ip=source_ip,
            dest_ip=f"{event_source}.internal",
            api_call=api_call,
            request_parameters=request_params if isinstance(request_params, dict) else {},
            observables=observables,
        )
