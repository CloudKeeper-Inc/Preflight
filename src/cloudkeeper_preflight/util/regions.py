from __future__ import annotations

from cloudkeeper_preflight.session import create_client

_ENABLED_OPT_IN_STATUSES = frozenset({"opt-in-not-required", "opted-in"})


def get_enabled_regions(session=None) -> list[str]:
    """Return the list of region names this account has access to.

    Includes always-on regions and any opt-in regions the account has opted into.
    """
    ec2 = create_client("ec2", region="us-east-1", session=session)
    response = ec2.describe_regions(AllRegions=True)
    regions = [
        r["RegionName"]
        for r in response.get("Regions", [])
        if r.get("OptInStatus") in _ENABLED_OPT_IN_STATUSES
    ]
    regions.sort()
    return regions
