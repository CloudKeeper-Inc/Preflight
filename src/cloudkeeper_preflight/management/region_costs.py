"""Choose which regions to assess, using Cost Explorer spend as the signal.

Scanning every *enabled* region is the single largest driver of PreFlight's
wall-clock: `resource_policy_scanner` alone issues ~16 calls per region per
account, and most orgs have real workloads in a handful of regions and nothing
at all in the rest. The bulk of that work exists only to prove a negative.

This module makes one Cost Explorer call from the management account for
previous-month spend grouped by `REGION`, and keeps only the regions that cost
the customer at least `_COST_THRESHOLD`. `us-east-1` is always kept — global
services (IAM, CloudFront, Route 53, Organizations) bill to `us-east-1` or to
the pseudo-region `global`, so an org whose only footprint is IAM roles must
still be scanned.

Two fallbacks deliberately *widen* the net rather than narrow it, because
silently under-scanning yields a confident-looking but incomplete assessment:

  - Cost Explorer call fails (CE not enabled, AccessDenied, SCP) -> assess all
    enabled regions.
  - Cost Explorer returns no spend at all (org created this month, so the
    previous-month window is empty) -> assess all enabled regions.

Both are recorded in `selection_detail["strategy"]` so an analyst reading the
output can tell a cost-filtered run from a fell-back one.
"""

from __future__ import annotations

import re
from datetime import date

from botocore.exceptions import ClientError

from cloudkeeper_preflight.management.billing import previous_month_range
from cloudkeeper_preflight.session import create_client

# Cost Explorer is global; pinned to us-east-1 (same as `billing.py`).
_CE_REGION = "us-east-1"

# Minimum previous-month spend, in the org's billing currency, for a region to
# be worth scanning.
_COST_THRESHOLD = 1.0

# Always assessed regardless of spend — global services report here.
_ALWAYS_ASSESS = ("us-east-1",)

# CE reports unattributable spend under pseudo-regions ("global", "NoRegion",
# ""). Only strings shaped like a real region name are scannable.
_REGION_NAME_RE = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d+$")

_MAX_PAGES = 10


def select_assessment_regions(
    enabled_regions: list[str],
    session=None,
    today: date | None = None,
    threshold: float = _COST_THRESHOLD,
) -> tuple[list[str], dict, list[dict]]:
    """Narrow `enabled_regions` to the ones worth scanning.

    Returns `(regions_to_assess, selection_detail, errors)`. `errors` follows
    the standard scanner shape so the caller can fold it into the Phase 1 list.

    `today` — overridable so tests can pin the Cost Explorer window.
    """
    errors: list[dict] = []
    enabled = list(enabled_regions or [])
    period = previous_month_range(today or date.today())

    detail: dict = {
        "strategy": "cost_filtered",
        "threshold": threshold,
        "currency": None,
        "period": period,
        "enabled_region_count": len(enabled),
        "always_assessed": [r for r in _ALWAYS_ASSESS if r in enabled],
        "region_costs": {},
        "non_regional_cost": 0.0,
        "selected_regions": [],
        "skipped_regions": [],
    }

    if not enabled:
        return enabled, detail, errors

    costs, currency, non_regional, ce_errors = _region_costs(period, session)
    errors.extend(ce_errors)

    if ce_errors:
        # Any Cost Explorer failure means the cost picture is incomplete, and
        # incomplete data can only ever cause us to *under*-select: a region
        # whose spend was on the page that failed reads as $0 and gets skipped.
        # Partial data is therefore treated exactly like no data — scan
        # everything. A slow assessment beats a silently partial one.
        detail["strategy"] = "all_enabled_cost_explorer_unavailable"
        detail["selected_regions"] = enabled
        detail["region_costs"] = {r: costs[r] for r in sorted(costs) if r in set(enabled)}
        return enabled, detail, errors

    detail["currency"] = currency
    detail["non_regional_cost"] = non_regional
    detail["region_costs"] = {
        r: costs[r]
        for r in sorted(costs, key=lambda k: (-costs[k], k))
        if r in set(enabled)
    }

    if not any(amount > 0 for amount in costs.values()):
        # No spend anywhere in the window — typically an org created this
        # month. The filter would leave us with us-east-1 only.
        detail["strategy"] = "all_enabled_no_cost_data"
        detail["selected_regions"] = enabled
        return enabled, detail, errors

    always = set(_ALWAYS_ASSESS)
    selected = [
        r for r in enabled if r in always or costs.get(r, 0.0) >= threshold
    ]
    detail["selected_regions"] = selected
    detail["skipped_regions"] = [r for r in enabled if r not in set(selected)]
    return selected, detail, errors


def _region_costs(
    period: dict,
    session,
) -> tuple[dict[str, float], str | None, float, list[dict]]:
    """`GetCostAndUsage` grouped by REGION. Returns partial data on failure."""
    client = create_client("ce", region=_CE_REGION, session=session)

    costs: dict[str, float] = {}
    currency: str | None = None
    non_regional = 0.0
    next_token: str | None = None

    for _ in range(_MAX_PAGES):
        kwargs: dict = {
            "TimePeriod": {"Start": period["start"], "End": period["end"]},
            "Granularity": "MONTHLY",
            "Metrics": ["UnblendedCost"],
            "GroupBy": [{"Type": "DIMENSION", "Key": "REGION"}],
            # Same exclusion as `assess_billing`, so the per-region numbers
            # reconcile against the org total reported in `billing`.
            "Filter": {
                "Not": {
                    "Dimensions": {
                        "Key": "RECORD_TYPE",
                        "Values": ["Marketplace", "Tax"],
                    }
                }
            },
        }
        if next_token:
            kwargs["NextPageToken"] = next_token

        try:
            response = client.get_cost_and_usage(**kwargs)
        except ClientError as exc:
            return (
                costs,
                currency,
                round(non_regional, 4),
                [
                    {
                        "module": "region_costs",
                        "service": "ce",
                        "operation": "GetCostAndUsage",
                        "code": exc.response.get("Error", {}).get(
                            "Code", "ClientError"
                        ),
                        "message": str(exc),
                    }
                ],
            )

        for block in response.get("ResultsByTime", []):
            for group in block.get("Groups", []):
                keys = group.get("Keys") or []
                region = keys[0] if keys else ""
                metric = (group.get("Metrics") or {}).get("UnblendedCost", {})
                amount = float(metric.get("Amount", 0) or 0)
                if currency is None:
                    currency = metric.get("Unit")
                if _REGION_NAME_RE.match(region):
                    costs[region] = round(costs.get(region, 0.0) + amount, 4)
                else:
                    non_regional += amount

        next_token = response.get("NextPageToken")
        if not next_token:
            return costs, currency, round(non_regional, 4), []

    # Fell out of the loop with a token still outstanding: the cost picture is
    # truncated. Report it as an error so the caller widens to all regions
    # rather than filtering on a partial view. Unreachable in practice — a
    # MONTHLY REGION-grouped query returns ~36 groups in a single page.
    return (
        costs,
        currency,
        round(non_regional, 4),
        [
            {
                "module": "region_costs",
                "service": "ce",
                "operation": "GetCostAndUsage",
                "code": "PaginationLimitReached",
                "message": (
                    f"Stopped after {_MAX_PAGES} pages with more results "
                    "outstanding; region cost data is incomplete."
                ),
            }
        ],
    )
