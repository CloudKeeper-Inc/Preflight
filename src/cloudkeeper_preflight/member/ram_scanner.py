"""Member-account RAM scan.

Same per-region structure as `management/ram.py` but uses the assumed
member-account session and flags account-to-account principals (the
management module focuses on org-level dependencies; this one catches
direct cross-account shares from the member's perspective).
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.pagination import paginate_with_token

_ORG_ARN_REGEX = re.compile(r"^arn:aws:organizations::\d+:organization/o-[a-z0-9]+$")
_OU_ARN_REGEX = re.compile(r"^arn:aws:organizations::\d+:ou/o-[a-z0-9]+/ou-[a-z0-9-]+$")
_ACCOUNT_ID_REGEX = re.compile(r"^\d{12}$")


def scan_member_ram(
    member_session,
    regions: list[str],
) -> tuple[list[dict], list[dict]]:
    if not regions:
        return [], []

    shares: list[dict] = []
    errors: list[dict] = []
    max_workers = min(len(regions), 6)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_scan_region, r, member_session): r for r in regions
        }
        for future in futures:
            region_shares, region_errors = future.result()
            shares.extend(region_shares)
            errors.extend(region_errors)

    shares.sort(key=lambda s: (s["region"], s.get("name") or "", s["resource_share_arn"]))
    return shares, errors


def _scan_region(region: str, session) -> tuple[list[dict], list[dict]]:
    errors: list[dict] = []
    try:
        client = create_client("ram", region=region, session=session)
    except ClientError as exc:
        return [], [_err(region, "create_client:ram", exc)]

    try:
        raw_shares = paginate_with_token(
            client,
            "get_resource_shares",
            "resourceShares",
            token_key="nextToken",
            resourceOwner="SELF",
        )
    except ClientError as exc:
        return [], [_err(region, "GetResourceShares(SELF)", exc)]

    out: list[dict] = []
    for share in raw_shares:
        arn = share.get("resourceShareArn")
        if not arn:
            continue
        principals: list[dict] = []
        resources: list[dict] = []
        try:
            raw_principals = paginate_with_token(
                client,
                "list_principals",
                "principals",
                token_key="nextToken",
                resourceOwner="SELF",
                resourceShareArns=[arn],
            )
            principals = [_format_principal(p) for p in raw_principals]
        except ClientError as exc:
            errors.append(_err(region, "ListPrincipals", exc, share_arn=arn))
        try:
            raw_resources = paginate_with_token(
                client,
                "list_resources",
                "resources",
                token_key="nextToken",
                resourceOwner="SELF",
                resourceShareArns=[arn],
            )
            resources = [
                {"type": r.get("type"), "arn": r.get("arn"), "status": r.get("status")}
                for r in raw_resources
            ]
        except ClientError as exc:
            errors.append(_err(region, "ListResources", exc, share_arn=arn))

        out.append(
            {
                "region": region,
                "resource_share_arn": arn,
                "name": share.get("name"),
                "owner_id": share.get("owningAccountId"),
                "status": share.get("status"),
                "allow_external_principals": share.get("allowExternalPrincipals", False),
                "resources": resources,
                "principals": principals,
                "has_account_principal": any(p["type"] == "ACCOUNT" for p in principals),
                "has_org_principal": any(
                    p["type"] in ("ORGANIZATION", "ORGANIZATIONAL_UNIT") for p in principals
                ),
            }
        )
    return out, errors


def _format_principal(principal: dict) -> dict:
    pid = principal.get("id") or ""
    if _ORG_ARN_REGEX.match(pid):
        ptype = "ORGANIZATION"
    elif _OU_ARN_REGEX.match(pid):
        ptype = "ORGANIZATIONAL_UNIT"
    elif _ACCOUNT_ID_REGEX.match(pid):
        ptype = "ACCOUNT"
    else:
        ptype = "OTHER"
    return {"id": pid, "type": ptype}


def _err(region: str, operation: str, exc: ClientError, **extra) -> dict:
    payload = {
        "module": "ram_scanner",
        "service": "ram",
        "region": region,
        "operation": operation,
        "code": exc.response.get("Error", {}).get("Code", "ClientError"),
        "message": str(exc),
    }
    payload.update(extra)
    return payload
