"""AWS Budgets in the management account, plus per-budget notifications and subscribers.

Budgets is a global service pinned to us-east-1. `DescribeBudgets` requires
`AccountId` — the account whose budgets to list (here, the management account).
Per-budget we walk `DescribeNotificationsForBudget` → `DescribeSubscribersForNotification`
so an analyst can see the full alert chain (threshold → who gets emailed / SNS'd).
"""

from __future__ import annotations

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.pagination import paginate

_BUDGETS_REGION = "us-east-1"


def assess_budgets(management_account_id: str, session=None) -> tuple[dict, list[dict]]:
    """Return `{"budget_alerts": [...]}` — one entry per budget with notifications/subscribers."""
    errors: list[dict] = []
    result: dict = {"budget_alerts": []}

    client = create_client("budgets", region=_BUDGETS_REGION, session=session)

    try:
        budgets = paginate(
            client, "describe_budgets", "Budgets", AccountId=management_account_id
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        if code == "NotFoundException":
            # No budgets configured — not an error.
            return result, errors
        errors.append(_err("DescribeBudgets", exc))
        return result, errors

    formatted: list[dict] = []
    for b in budgets:
        entry = {
            "budget_name": b.get("BudgetName"),
            "budget_type": b.get("BudgetType"),
            "time_unit": b.get("TimeUnit"),
            "budget_limit": _amount(b.get("BudgetLimit")),
            "cost_filters": b.get("CostFilters"),
            "cost_types": b.get("CostTypes"),
            "notifications": [],
        }

        try:
            notifs = paginate(
                client,
                "describe_notifications_for_budget",
                "Notifications",
                AccountId=management_account_id,
                BudgetName=b["BudgetName"],
            )
        except ClientError as exc:
            errors.append(
                _err("DescribeNotificationsForBudget", exc, budget_name=b.get("BudgetName"))
            )
            notifs = []

        for n in notifs:
            n_entry = {
                "notification_type": n.get("NotificationType"),
                "comparison_operator": n.get("ComparisonOperator"),
                "threshold": n.get("Threshold"),
                "threshold_type": n.get("ThresholdType"),
                "notification_state": n.get("NotificationState"),
                "subscribers": [],
            }
            try:
                subs = paginate(
                    client,
                    "describe_subscribers_for_notification",
                    "Subscribers",
                    AccountId=management_account_id,
                    BudgetName=b["BudgetName"],
                    Notification=n,
                )
                n_entry["subscribers"] = [
                    {"type": s.get("SubscriptionType"), "address": s.get("Address")}
                    for s in subs
                ]
            except ClientError as exc:
                errors.append(
                    _err(
                        "DescribeSubscribersForNotification",
                        exc,
                        budget_name=b.get("BudgetName"),
                    )
                )
            entry["notifications"].append(n_entry)

        formatted.append(entry)

    result["budget_alerts"] = formatted
    return result, errors


def _amount(limit) -> dict | None:
    if not limit:
        return None
    return {"amount": limit.get("Amount"), "unit": limit.get("Unit")}


def _err(operation: str, exc: ClientError, **extra) -> dict:
    payload = {
        "module": "budgets",
        "service": "budgets",
        "operation": operation,
        "code": exc.response.get("Error", {}).get("Code", "ClientError"),
        "message": str(exc),
    }
    payload.update(extra)
    return payload
