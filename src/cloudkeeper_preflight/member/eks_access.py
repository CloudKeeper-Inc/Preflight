from __future__ import annotations

from cloudkeeper_preflight.management.eks_access_scanner import scan_eks_access
from cloudkeeper_preflight.util.org_id_matcher import OrgIdMatcher


def scan_member_eks_access(
    member_session,
    regions: list[str],
    matcher: OrgIdMatcher,
) -> tuple[dict, list[dict]]:
    """Run the EKS access-entry scanner with a member-account session."""
    return scan_eks_access(regions=regions, matcher=matcher, session=member_session)
