"""EKS charges over the last 14 days, per account.

Gated at the caller — only submitted when IAM Identity Center is in use.
The onboarding heuristic: SSO-in-use signals a customer at production scale,
and EKS charges then indicate a Kubernetes footprint that changes the
onboarding conversation (support tier, node sizing, cluster inventory).

The `flag` field is `true` when any nonzero EKS cost is observed in the
window — that's the signal analysts scan for.
"""

from __future__ import annotations

from datetime import date, timedelta

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client

_CE_REGION = "us-east-1"
_WINDOW_DAYS = 14

# Cost Explorer service names for EKS. AWS currently uses the first; the
# second is the historical name — filter matches either to be safe.
_EKS_SERVICE_NAMES = (
    "Amazon Elastic Kubernetes Service",
    "Amazon Elastic Container Service for Kubernetes",
)


def assess_eks_charges(
    session=None, today: date | None = None
) -> tuple[dict, list[dict]]:
    """Return `{"checked": True, ..., "flag": bool}`.

    `flag` is `true` iff total EKS cost in the 14-day window is > 0.
    """
    errors: list[dict] = []
    today = today or date.today()
    start = (today - timedelta(days=_WINDOW_DAYS)).isoformat()
    end = today.isoformat()

    result: dict = {
        "checked": True,
        "period": {"start": start, "end": end, "days": _WINDOW_DAYS},
        "total_cost": 0.0,
        "currency": None,
        "per_account": [],
        "flag": False,
    }

    client = create_client("ce", region=_CE_REGION, session=session)
    try:
        response = client.get_cost_and_usage(
            TimePeriod={"Start": start, "End": end},
            Granularity="DAILY",
            Filter={
                "Dimensions": {
                    "Key": "SERVICE",
                    "Values": list(_EKS_SERVICE_NAMES),
                }
            },
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"}],
        )
    except ClientError as exc:
        errors.append(
            {
                "module": "eks_charges",
                "service": "ce",
                "operation": "GetCostAndUsage",
                "code": exc.response.get("Error", {}).get("Code", "ClientError"),
                "message": str(exc),
            }
        )
        return result, errors

    per_account: dict[str, float] = {}
    total = 0.0
    currency: str | None = None
    for period in response.get("ResultsByTime", []):
        for group in period.get("Groups", []):
            keys = group.get("Keys", [])
            acct = keys[0] if keys else "unknown"
            metric = group.get("Metrics", {}).get("UnblendedCost", {})
            amount = float(metric.get("Amount", 0) or 0)
            if currency is None:
                currency = metric.get("Unit")
            per_account[acct] = per_account.get(acct, 0.0) + amount
            total += amount

    result["total_cost"] = round(total, 4)
    result["currency"] = currency
    result["per_account"] = [
        {"account_id": aid, "cost": round(cost, 4)}
        for aid, cost in sorted(
            per_account.items(), key=lambda x: x[1], reverse=True
        )
    ]
    result["flag"] = total > 0.0
    return result, errors


def not_checked_because_no_sso() -> dict:
    """Sentinel result when SSO is not in use and the check is skipped."""
    return {
        "checked": False,
        "reason": "IAM Identity Center not in use",
        "period": None,
        "total_cost": None,
        "currency": None,
        "per_account": [],
        "flag": False,
    }
