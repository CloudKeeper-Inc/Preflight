from __future__ import annotations

from datetime import date, timedelta

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.pagination import paginate_with_token

# Cost Explorer is global; pinned to us-east-1.
_CE_REGION = "us-east-1"


def assess_billing(
    session=None,
    accounts: list[dict] | None = None,
    today: date | None = None,
) -> tuple[dict, list[dict]]:
    """Cost Explorer pull for the previous calendar month plus enabled cost-allocation tags.

    `accounts` — list from `assess_accounts()`; used only to enrich per-account
    rows with the account name (Cost Explorer returns IDs only).

    `today` — overridable so tests can pin the date range deterministically.
    """
    errors: list[dict] = []
    today = today or date.today()
    period = _previous_month_range(today)

    name_by_id = {a["account_id"]: a.get("name") for a in (accounts or [])}
    client = create_client("ce", region=_CE_REGION, session=session)

    result: dict = {
        "period": period,
        "total_cost_excluding_marketplace_and_tax": 0.0,
        "currency": None,
        "per_account_costs": [],
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
            GroupBy=[
                {"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"},
                {"Type": "DIMENSION", "Key": "SERVICE"},
            ],
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
        per_account, total, currency = _summarize_cost_response(cost_response, name_by_id)
        result["per_account_costs"] = per_account
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


def _previous_month_range(today: date) -> dict:
    """Returns {'start': YYYY-MM-DD, 'end': YYYY-MM-DD} for the previous full month.
    `end` is the first day of the current month — Cost Explorer treats end as exclusive.
    """
    first_of_this_month = today.replace(day=1)
    last_of_prev_month = first_of_this_month - timedelta(days=1)
    first_of_prev_month = last_of_prev_month.replace(day=1)
    return {
        "start": first_of_prev_month.isoformat(),
        "end": first_of_this_month.isoformat(),
    }


def _summarize_cost_response(
    response: dict,
    name_by_id: dict[str, str | None],
) -> tuple[list[dict], float, str | None]:
    per_account: dict[str, dict] = {}
    total = 0.0
    currency: str | None = None

    for period in response.get("ResultsByTime", []):
        for group in period.get("Groups", []):
            keys = group.get("Keys", [])
            account_id = keys[0] if len(keys) > 0 else "unknown"
            service = keys[1] if len(keys) > 1 else "unknown"
            metric = group.get("Metrics", {}).get("UnblendedCost", {})
            amount = float(metric.get("Amount", 0) or 0)
            if currency is None:
                currency = metric.get("Unit")

            if account_id not in per_account:
                per_account[account_id] = {
                    "account_id": account_id,
                    "account_name": name_by_id.get(account_id),
                    "total": 0.0,
                    "services": [],
                }
            entry = per_account[account_id]
            entry["total"] += amount
            entry["services"].append({"service": service, "cost": amount})
            total += amount

    rows = list(per_account.values())
    rows.sort(key=lambda r: r["total"], reverse=True)
    for r in rows:
        r["services"].sort(key=lambda s: s["cost"], reverse=True)
        r["total"] = round(r["total"], 4)
        for s in r["services"]:
            s["cost"] = round(s["cost"], 4)

    return rows, round(total, 4), currency
