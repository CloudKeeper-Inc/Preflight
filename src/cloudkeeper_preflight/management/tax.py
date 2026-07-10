"""Tax-settings registration for the management account, with seller of record.

The `taxsettings:ListTaxRegistrations` API returns one entry per org account
that has tax data. Each entry's `accountMetaData.seller` is the AWS legal
entity that bills that account (e.g. "Amazon Web Services, Inc.", "AWS EMEA
SARL", "Amazon Web Services Singapore Private Limited"). We only care about
the management account's seller — that's what drives which AWS entity
CloudKeeper contracts through — so we filter the list client-side.
"""

from __future__ import annotations

from botocore.exceptions import ClientError, UnknownServiceError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.pagination import paginate_with_token

# taxsettings is a global service; pinned to us-east-1.
_TAX_REGION = "us-east-1"


def assess_tax_settings(
    management_account_id: str, session=None
) -> tuple[dict, list[dict]]:
    """Return `{"seller_of_record": {...} | None}` for the management account only.

    `seller_of_record` is `None` when the taxsettings API is unreachable, the
    account has no tax data, or the management account is not present in the
    ListTaxRegistrations response.
    """
    errors: list[dict] = []
    result: dict = {"seller_of_record": None}

    try:
        client = create_client("taxsettings", region=_TAX_REGION, session=session)
    except UnknownServiceError:
        errors.append(
            {
                "module": "tax",
                "service": "taxsettings",
                "operation": "CreateClient",
                "code": "UnknownServiceError",
                "message": (
                    "boto3 in this environment doesn't know about the "
                    "'taxsettings' service; upgrade boto3 to fetch tax data."
                ),
            }
        )
        return result, errors

    try:
        entries = paginate_with_token(
            client,
            "list_tax_registrations",
            "accountDetails",
            token_key="nextToken",
        )
    except ClientError as exc:
        errors.append(
            {
                "module": "tax",
                "service": "taxsettings",
                "operation": "ListTaxRegistrations",
                "code": exc.response.get("Error", {}).get("Code", "ClientError"),
                "message": str(exc),
            }
        )
        return result, errors

    for entry in entries:
        if entry.get("accountId") != management_account_id:
            continue
        meta = entry.get("accountMetaData") or {}
        address = meta.get("address") or {}
        reg = entry.get("taxRegistration") or {}
        jurisdiction = reg.get("jurisdiction") or {}
        result["seller_of_record"] = {
            "account_id": entry.get("accountId"),
            "account_name": meta.get("accountName"),
            "seller": meta.get("seller"),
            "billing_country_code": address.get("countryCode")
            or jurisdiction.get("countryCode"),
            "registration_type": reg.get("registrationType"),
            "registration_id": reg.get("registrationId"),
            "registration_status": reg.get("status"),
            "legal_name": reg.get("legalName"),
            "tax_inheritance_reason": (
                (entry.get("taxInheritanceDetails") or {}).get(
                    "inheritanceObtainedReason"
                )
            ),
        }
        break

    return result, errors
