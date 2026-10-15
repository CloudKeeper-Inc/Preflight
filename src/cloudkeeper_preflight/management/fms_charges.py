"""Firewall Manager charges for the previous and current month, per account.

Gated at the caller — only submitted when `fms.amazonaws.com` has trusted
access in the org. Firewall Manager bills per policy per region, so an org
with trusted access but no spend has it switched on with no live policies,
while nonzero spend means policies the onboarding has to carry across.

The window runs from the first of the previous month to today, grouped by
month, so `months[0]` is the previous full month and `months[1]` is the
current month to date. Only the Firewall Manager line item is counted — the
WAF, Shield and Network Firewall resources its policies deploy bill under
their own services.

The `flag` field is `true` when any nonzero Firewall Manager cost is
observed in the window.
"""

from __future__ import annotations

from datetime import date

from botocore.exceptions import ClientError

from cloudkeeper_preflight.management.billing import previous_month_range
from cloudkeeper_preflight.session import create_client

_CE_REGION = "us-east-1"
_FMS_SERVICE_NAME = "AWS Firewall Manager"


def assess_fms_charges(
    session=None, today: date | None = None
) -> tuple[dict, list[dict]]:
    """Return `{"checked": True, ..., "months": [...], "flag": bool}`.

    `flag` is `true` iff total Firewall Manager cost across both months is > 0.
    """
    errors: list[dict] = []
    today = today or date.today()
    previous = previous_month_range(today)
    current = {"start": previous["end"], "end": today.isoformat()}

    result: dict = {
        "checked": True,
        "period": {"start": previous["start"], "end": current["end"]},
        "total_cost": 0.0,
        "currency": None,
        "months": [
            {"month": "previous", **previous, "total_cost": 0.0, "per_account": []},
            {"month": "current", **current, "total_cost": 0.0, "per_account": []},
        ],
        "flag": False,
    }

    client = create_client("ce", region=_CE_REGION, session=session)
    try:
        response = client.get_cost_and_usage(
            TimePeriod={"Start": previous["start"], "End": current["end"]},
            Granularity="MONTHLY",
            Filter={
                "Dimensions": {"Key": "SERVICE", "Values": [_FMS_SERVICE_NAME]}
            },
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"}],
        )
    except ClientError as exc:
        errors.append(
            {
                "module": "fms_charges",
                "service": "ce",
                "operation": "GetCostAndUsage",
                "code": exc.response.get("Error", {}).get("Code", "ClientError"),
                "message": str(exc),
            }
        )
        return result, errors

    months_by_start = {m["start"]: m for m in result["months"]}
    total = 0.0
    currency: str | None = None
    for period in response.get("ResultsByTime", []):
        month = months_by_start.get(period.get("TimePeriod", {}).get("Start"))
        if month is None:
            continue
        per_account: dict[str, float] = {}
        for group in period.get("Groups", []):
            keys = group.get("Keys", [])
            acct = keys[0] if keys else "unknown"
            metric = group.get("Metrics", {}).get("UnblendedCost", {})
            amount = float(metric.get("Amount", 0) or 0)
            if currency is None:
                currency = metric.get("Unit")
            per_account[acct] = per_account.get(acct, 0.0) + amount
        month_total = sum(per_account.values())
        month["total_cost"] = round(month_total, 4)
        month["per_account"] = [
            {"account_id": aid, "cost": round(cost, 4)}
            for aid, cost in sorted(
                per_account.items(), key=lambda x: x[1], reverse=True
            )
        ]
        total += month_total

    result["total_cost"] = round(total, 4)
    result["currency"] = currency
    result["flag"] = total > 0.0
    return result, errors


def not_checked_because_no_fms() -> dict:
    """Sentinel result when FMS trusted access is off and the check is skipped."""
    return {
        "checked": False,
        "reason": "Firewall Manager trusted access not enabled",
        "period": None,
        "total_cost": None,
        "currency": None,
        "months": [],
        "flag": False,
    }
