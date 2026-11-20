from __future__ import annotations

from datetime import datetime

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.pagination import paginate


def assess_delegated_admins(session=None) -> tuple[list[dict], list[dict]]:
    """Return the org's delegated-administrator accounts and the services each manages."""
    errors: list[dict] = []
    client = create_client("organizations", region="us-east-1", session=session)

    try:
        admins = paginate(
            client, "list_delegated_administrators", "DelegatedAdministrators"
        )
    except ClientError as exc:
        errors.append(
            {
                "module": "delegated_admins",
                "operation": "ListDelegatedAdministrators",
                "code": exc.response.get("Error", {}).get("Code", "ClientError"),
                "message": str(exc),
            }
        )
        return [], errors

    result: list[dict] = []
    for admin in admins:
        account_id = admin["Id"]
        services: list[dict] = []
        try:
            raw_services = paginate(
                client,
                "list_delegated_services_for_account",
                "DelegatedServices",
                AccountId=account_id,
            )
            services = [
                {
                    "service_principal": s.get("ServicePrincipal"),
                    "delegation_date": _to_iso(s.get("DelegationEnabledDate")),
                }
                for s in raw_services
            ]
        except ClientError as exc:
            errors.append(
                {
                    "module": "delegated_admins",
                    "operation": "ListDelegatedServicesForAccount",
                    "account_id": account_id,
                    "code": exc.response.get("Error", {}).get("Code", "ClientError"),
                    "message": str(exc),
                }
            )

        result.append(
            {
                "account_id": account_id,
                "account_name": admin.get("Name"),
                "email": admin.get("Email"),
                "status": admin.get("Status"),
                "joined_method": admin.get("JoinedMethod"),
                "joined_timestamp": _to_iso(admin.get("JoinedTimestamp")),
                "delegation_enabled_date": _to_iso(admin.get("DelegationEnabledDate")),
                "services": services,
            }
        )
    return result, errors


def _to_iso(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)
