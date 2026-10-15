from __future__ import annotations

from cloudkeeper_preflight.management.identity_center_scanner import (
    scan_identity_center_services,
)
from cloudkeeper_preflight.util.org_id_matcher import OrgIdMatcher


def scan_member_identity_center_services(
    member_session,
    regions: list[str],
    matcher: OrgIdMatcher,
) -> tuple[dict, list[dict]]:
    """Run the Identity Center service probes with a member-account session."""
    return scan_identity_center_services(
        regions=regions, matcher=matcher, session=member_session
    )
