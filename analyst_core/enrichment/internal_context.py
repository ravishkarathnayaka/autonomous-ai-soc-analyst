"""
Internal context database resolving asset criticality tiers,
business impact, privileged user accounts, and baseline operating hours.
"""

from typing import Dict, Optional
from ..state import AssetContext, UserContext


class InternalContextDB:
    """Provides internal asset, identity, and environmental context."""

    DEFAULT_ASSETS: Dict[str, AssetContext] = {
        "DC-01.corp.internal": AssetContext(
            identifier="DC-01.corp.internal",
            asset_tier="Tier-0",
            is_critical=True,
            owner="Identity Team",
            department="IT Infrastructure",
            environment="Production",
            tags=["domain_controller", "active_directory", "kerberos"],
        ),
        "DC-01": AssetContext(
            identifier="DC-01",
            asset_tier="Tier-0",
            is_critical=True,
            owner="Identity Team",
            department="IT Infrastructure",
            environment="Production",
            tags=["domain_controller", "active_directory"],
        ),
        "FIN-WS-04": AssetContext(
            identifier="FIN-WS-04",
            asset_tier="Tier-2",
            is_critical=False,
            owner="Accounting Dept",
            department="Finance",
            environment="Corporate Workstation",
            tags=["workstation", "windows_11", "finance_segment"],
        ),
        "SRV-BACKUP-01": AssetContext(
            identifier="SRV-BACKUP-01",
            asset_tier="Tier-1",
            is_critical=True,
            owner="Storage Operations",
            department="IT Infrastructure",
            environment="Production",
            tags=["backup_server", "scheduled_maintenance"],
        ),
        "PROD-K8S-WORKER-09": AssetContext(
            identifier="PROD-K8S-WORKER-09",
            asset_tier="Tier-0",
            is_critical=True,
            owner="Cloud SRE",
            department="Platform Engineering",
            environment="AWS EKS",
            tags=["kubernetes_node", "workload_runtime"],
        ),
    }

    DEFAULT_USERS: Dict[str, UserContext] = {
        "CORP\\svc-backup": UserContext(
            username="CORP\\svc-backup",
            role="Automated Backup Service Account",
            is_privileged=True,
            department="IT Infrastructure",
            normal_working_hours="24x7 (Scheduled Batch)",
        ),
        "svc-backup": UserContext(
            username="svc-backup",
            role="Automated Backup Service Account",
            is_privileged=True,
            department="IT Infrastructure",
            normal_working_hours="24x7 (Scheduled Batch)",
        ),
        "CORP\\admin_jdoe": UserContext(
            username="CORP\\admin_jdoe",
            role="Domain Administrator",
            is_privileged=True,
            department="Cybersecurity & Operations",
            normal_working_hours="08:00-18:00 UTC",
        ),
        "CORP\\finance_user": UserContext(
            username="CORP\\finance_user",
            role="Accounts Payable Specialist",
            is_privileged=False,
            department="Finance",
            normal_working_hours="09:00-17:00 UTC",
        ),
        "finance_user": UserContext(
            username="finance_user",
            role="Accounts Payable Specialist",
            is_privileged=False,
            department="Finance",
            normal_working_hours="09:00-17:00 UTC",
        ),
        "devops-ci": UserContext(
            username="devops-ci",
            role="GitHub Actions CI/CD Provisioner",
            is_privileged=True,
            department="DevOps",
            normal_working_hours="24x7 (Automated Pipelines)",
        ),
    }

    def __init__(self):
        self.assets: Dict[str, AssetContext] = dict(self.DEFAULT_ASSETS)
        self.users: Dict[str, UserContext] = dict(self.DEFAULT_USERS)

    def resolve_asset(self, identifier: Optional[str]) -> AssetContext:
        """Looks up asset criticality and environment details."""
        if not identifier:
            return AssetContext(identifier="unknown-asset")

        clean_id = identifier.strip()
        # Direct lookup
        if clean_id in self.assets:
            return self.assets[clean_id]

        # Case-insensitive or partial match
        for key, asset in self.assets.items():
            if key.lower() == clean_id.lower() or clean_id.lower().startswith(key.lower()):
                return asset

        # Fallback heuristic
        is_dc = "dc" in clean_id.lower() or "ad" in clean_id.lower()
        is_prod = "prod" in clean_id.lower() or "srv" in clean_id.lower()
        tier = "Tier-0" if is_dc else ("Tier-1" if is_prod else "Tier-2")

        return AssetContext(
            identifier=clean_id,
            asset_tier=tier,
            is_critical=is_dc or is_prod,
            owner="Unregistered Endpoint",
            department="Corporate IT",
            environment="Production" if is_prod else "Workstation Network",
            tags=["dynamic_resolved"],
        )

    def resolve_user(self, username: Optional[str]) -> UserContext:
        """Looks up identity privileges, role, and department."""
        if not username:
            return UserContext(username="anonymous")

        clean_name = username.strip()
        if clean_name in self.users:
            return self.users[clean_name]

        # Normalized without domain prefix
        short_name = clean_name.split("\\")[-1]
        if short_name in self.users:
            return self.users[short_name]

        for key, user in self.users.items():
            if key.lower() == clean_name.lower() or short_name.lower() == key.lower():
                return user

        is_admin = any(term in clean_name.lower() for term in ("admin", "svc-", "root", "system"))
        return UserContext(
            username=clean_name,
            role="System Administrator" if is_admin else "Standard Enterprise User",
            is_privileged=is_admin,
            department="IT" if is_admin else "General",
            normal_working_hours="09:00-17:00 UTC",
        )
