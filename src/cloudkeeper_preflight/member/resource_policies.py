from __future__ import annotations

from cloudkeeper_preflight.management.resource_policy_scanner import (
    scan_resource_policies,
)
from cloudkeeper_preflight.util.org_id_matcher import OrgIdMatcher


def scan_member_resource_policies(
    member_session,
    regions: list[str],
    matcher: OrgIdMatcher,
) -> tuple[dict, list[dict]]:
    """Run the standard resource-policy scanner with a member-account session."""
    return scan_resource_policies(regions=regions, matcher=matcher, session=member_session)
