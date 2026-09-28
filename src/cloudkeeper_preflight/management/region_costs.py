"""Choose which regions to assess, using Cost Explorer spend as the signal.

Scanning every *enabled* region is the single largest driver of PreFlight's
wall-clock: `resource_policy_scanner` alone issues ~16 calls per region per
account, and most orgs have real workloads in a handful of regions and nothing
at all in the rest. The bulk of that work exists only to prove a negative.

This module makes one Cost Explorer call from the management account for
previous-month spend grouped by `LINKED_ACCOUNT` × `REGION`, and keeps only the
regions that cost the customer at least `_COST_THRESHOLD`. `us-east-1` is
always kept — global services (IAM, CloudFront, Route 53, Organizations) bill
to `us-east-1` or to the pseudo-region `global`, so an org whose only footprint
is IAM roles must still be scanned.

Grouping by two dimensions (the CE maximum) costs the same ~$0.01 as grouping
by one and yields both answers at once: summing across accounts gives the
org-wide region set, while the un-summed map gives each member its own set.
Most members live in 1-3 regions rather than the org's union, so handing every
account the union — which is what the caller used to do — scans regions that
member demonstrably has no spend in.

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

# Grouping by LINKED_ACCOUNT x REGION multiplies the group count: a 200-account
# org across 30 regions can produce thousands of groups against CE's ~1000-per-
# page ceiling, where the old REGION-only query fit in a single page. Hitting
# the cap is failure-safe (it widens to all regions) but throws away the whole
# optimisation, so the ceiling is set well clear of any real org.
_MAX_PAGES = 50


def select_assessment_regions(
    enabled_regions: list[str],
    session=None,
    today: date | None = None,
    threshold: float = _COST_THRESHOLD,
) -> tuple[list[str], dict[str, list[str]], dict, list[dict]]:
    """Narrow `enabled_regions` to the ones worth scanning.

    Returns `(regions_to_assess, account_regions, selection_detail, errors)`.

    `regions_to_assess` is the org-wide set — the union across every account,
    used for management-account work and as the fallback for any account Cost
    Explorer had nothing to say about. `account_regions` maps account ID to
    that account's own narrower set; accounts absent from it should be scanned
    with `regions_to_assess`.

    The map is returned separately rather than folded into `selection_detail`
    because the detail block ships in the assessment payload and a full
    account x region map would bloat it; only per-account region *counts* go
    into the detail, which is enough to audit the narrowing after the fact.

    `errors` follows the standard scanner shape so the caller can fold it into
    the Phase 1 list.

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
        "per_account_scoping": {
            "enabled": False,
            "accounts_with_cost_data": 0,
            "region_count_by_account": {},
        },
    }

    if not enabled:
        return enabled, {}, detail, errors

    costs, per_account, currency, non_regional, ce_errors = _region_costs(
        period, session
    )
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
        # Empty map: every account falls back to the widened org-wide list.
        return enabled, {}, detail, errors

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
        return enabled, {}, detail, errors

    always = set(_ALWAYS_ASSESS)
    selected = [
        r for r in enabled if r in always or costs.get(r, 0.0) >= threshold
    ]
    detail["selected_regions"] = selected
    detail["skipped_regions"] = [r for r in enabled if r not in set(selected)]

    # Same rule, applied per account instead of to the org total. An account
    # Cost Explorer reported nothing for is deliberately left out of the map:
    # the caller then scans it with the org-wide set, matching the two
    # widening fallbacks above rather than scanning it in us-east-1 alone.
    account_regions: dict[str, list[str]] = {}
    for account_id, region_costs in per_account.items():
        account_regions[account_id] = [
            r for r in enabled if r in always or region_costs.get(r, 0.0) >= threshold
        ]

    detail["per_account_scoping"] = {
        "enabled": bool(account_regions),
        "accounts_with_cost_data": len(account_regions),
        "region_count_by_account": {
            a: len(rs) for a, rs in sorted(account_regions.items())
        },
    }
    return selected, account_regions, detail, errors


def _region_costs(
    period: dict,
    session,
) -> tuple[dict[str, float], dict[str, dict[str, float]], str | None, float, list[dict]]:
    """`GetCostAndUsage` grouped by LINKED_ACCOUNT x REGION.

    Returns `(org_costs, per_account_costs, currency, non_regional, errors)`,
    where `org_costs` is `per_account_costs` summed across accounts — identical
    to what the old REGION-only query produced, so the org-wide selection and
    its reconciliation against `billing` are unchanged. Returns partial data on
    failure.
    """
    client = create_client("ce", region=_CE_REGION, session=session)

    costs: dict[str, float] = {}
    per_account: dict[str, dict[str, float]] = {}
    currency: str | None = None
    non_regional = 0.0
    next_token: str | None = None

    for _ in range(_MAX_PAGES):
        kwargs: dict = {
            "TimePeriod": {"Start": period["start"], "End": period["end"]},
            "Granularity": "MONTHLY",
            "Metrics": ["UnblendedCost"],
            "GroupBy": [
                {"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"},
                {"Type": "DIMENSION", "Key": "REGION"},
            ],
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
                per_account,
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
                # Keys arrive in GroupBy order: LINKED_ACCOUNT then REGION.
                keys = group.get("Keys") or []
                account_id = keys[0] if keys else ""
                region = keys[1] if len(keys) > 1 else ""
                metric = (group.get("Metrics") or {}).get("UnblendedCost", {})
                amount = float(metric.get("Amount", 0) or 0)
                if currency is None:
                    currency = metric.get("Unit")
                if _REGION_NAME_RE.match(region):
                    costs[region] = round(costs.get(region, 0.0) + amount, 4)
                    if account_id:
                        acct = per_account.setdefault(account_id, {})
                        acct[region] = round(acct.get(region, 0.0) + amount, 4)
                else:
                    non_regional += amount
                    # Register the account even when all its spend is
                    # non-regional, so it counts as "Cost Explorer had data"
                    # and gets the us-east-1 floor rather than the org fallback.
                    if account_id:
                        per_account.setdefault(account_id, {})

        next_token = response.get("NextPageToken")
        if not next_token:
            return costs, per_account, currency, round(non_regional, 4), []

    # Fell out of the loop with a token still outstanding: the cost picture is
    # truncated. Report it as an error so the caller widens to all regions
    # rather than filtering on a partial view. Reachable only for an org whose
    # accounts x active regions exceeds roughly _MAX_PAGES * 1000 groups.
    return (
        costs,
        per_account,
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
