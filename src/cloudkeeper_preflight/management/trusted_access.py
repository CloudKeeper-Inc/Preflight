from __future__ import annotations

from datetime import datetime

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.pagination import paginate


def assess_trusted_access(session=None) -> tuple[list[dict], list[dict]]:
    """Return the AWS services with trusted access enabled in the org."""
    errors: list[dict] = []
    client = create_client("organizations", region="us-east-1", session=session)

    try:
        raw = paginate(
            client,
            "list_aws_service_access_for_organization",
            "EnabledServicePrincipals",
        )
    except ClientError as exc:
        errors.append(
            {
                "module": "trusted_access",
                "operation": "ListAWSServiceAccessForOrganization",
                "code": exc.response.get("Error", {}).get("Code", "ClientError"),
                "message": str(exc),
            }
        )
        return [], errors

    services = [
        {
            "service_principal": item.get("ServicePrincipal"),
            "date_enabled": _to_iso(item.get("DateEnabled")),
        }
        for item in raw
    ]
    return services, errors


def _to_iso(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)
