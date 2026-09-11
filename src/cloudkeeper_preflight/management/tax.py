"""Seller of record for the management account.

The `taxsettings:ListTaxRegistrations` API returns one entry per org account
that has tax data. Each entry's `accountMetaData.seller` is the AWS legal
entity that bills that account (e.g. "Amazon Web Services, Inc.", "AWS EMEA
SARL", "Amazon Web Services Singapore Private Limited"). That seller is the
only thing we need — it drives which AWS entity CloudKeeper contracts
through — so we filter the list to the management account client-side and
keep nothing else.

The API response also carries the customer's VAT/GST registration ID,
registration status, legal name, and billing address. None of it is
retained: it isn't used downstream and it's needlessly sensitive to ship
back to CloudKeeper.
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
    """Return `{"seller_of_record": {"seller": ...} | None}` for the management account.

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
        result["seller_of_record"] = {"seller": meta.get("seller")}
        break

    return result, errors
