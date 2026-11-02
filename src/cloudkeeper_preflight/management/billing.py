from __future__ import annotations

from datetime import date, timedelta

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.pagination import paginate_with_token

# Cost Explorer is global; pinned to us-east-1.
_CE_REGION = "us-east-1"


def assess_billing(
    session=None,
    today: date | None = None,
) -> tuple[dict, list[dict]]:
    """Org-wide cost for the previous calendar month plus enabled cost-allocation tags.

    Only the organization total is collected — no per-account or per-service
    breakdown. The Cost Explorer call is therefore ungrouped, so the total comes
    straight off `ResultsByTime[].Total`.

    `today` — overridable so tests can pin the date range deterministically.
    """
    errors: list[dict] = []
    today = today or date.today()
    period = previous_month_range(today)

    client = create_client("ce", region=_CE_REGION, session=session)

    result: dict = {
        "period": period,
        "total_cost_excluding_marketplace_and_tax": 0.0,
        "currency": None,
        "cost_allocation_tags": [],
    }

    try:
        cost_response = client.get_cost_and_usage(
            TimePeriod={"Start": period["start"], "End": period["end"]},
            Granularity="MONTHLY",
            Filter={
                "Not": {
                    "Dimensions": {
                        "Key": "RECORD_TYPE",
                        "Values": ["Marketplace", "Tax"],
                    }
                }
            },
            Metrics=["UnblendedCost"],
        )
    except ClientError as exc:
        errors.append(
            {
                "module": "billing",
                "operation": "GetCostAndUsage",
                "code": exc.response.get("Error", {}).get("Code", "ClientError"),
                "message": str(exc),
            }
        )
    else:
        total, currency = _summarize_total(cost_response)
        result["total_cost_excluding_marketplace_and_tax"] = total
        result["currency"] = currency

    try:
        # Status="Active" filter — only currently-enabled cost allocation tags
        # are actionable for onboarding; inactive ones are noise.
        tag_items = paginate_with_token(
            client,
            "list_cost_allocation_tags",
            "CostAllocationTags",
            Status="Active",
        )
        result["cost_allocation_tags"] = [
            {
                "tag_key": t.get("TagKey"),
                "type": t.get("Type"),
                "last_updated": (
                    t["LastUpdatedDate"].isoformat()
                    if t.get("LastUpdatedDate") is not None
                    and not isinstance(t["LastUpdatedDate"], str)
                    else t.get("LastUpdatedDate")
                ),
            }
            for t in tag_items
        ]
    except ClientError as exc:
        errors.append(
            {
                "module": "billing",
                "operation": "ListCostAllocationTags",
                "code": exc.response.get("Error", {}).get("Code", "ClientError"),
                "message": str(exc),
            }
        )

    return result, errors


def previous_month_range(today: date) -> dict:
    """Returns {'start': YYYY-MM-DD, 'end': YYYY-MM-DD} for the previous full month.
    `end` is the first day of the current month — Cost Explorer treats end as exclusive.

    Public because `region_costs.py` pins its REGION-grouped call to the same
    window, so the per-region breakdown reconciles against the org total here.
    """
    first_of_this_month = today.replace(day=1)
    last_of_prev_month = first_of_this_month - timedelta(days=1)
    first_of_prev_month = last_of_prev_month.replace(day=1)
    return {
        "start": first_of_prev_month.isoformat(),
        "end": first_of_this_month.isoformat(),
    }


def _summarize_total(response: dict) -> tuple[float, str | None]:
    """Sum the ungrouped `Total` block across the returned time periods."""
    total = 0.0
    currency: str | None = None

    for period in response.get("ResultsByTime", []):
        metric = (period.get("Total") or {}).get("UnblendedCost", {})
        amount = float(metric.get("Amount", 0) or 0)
        if currency is None:
            currency = metric.get("Unit")
        total += amount

    return round(total, 4), currency
