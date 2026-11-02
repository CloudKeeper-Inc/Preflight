from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.pagination import paginate_with_token

# Resource types that AWS docs say can only be shared within the same organization.
# Conservative starter list — verify against the current RAM "shareable resources"
# matrix during M3 polish (the API doesn't expose this attribute directly).
_NON_SHAREABLE_RESOURCE_TYPES: frozenset[str] = frozenset(
    {
        "ec2:Subnet",
        "ec2:LocalGateway",
        "ec2:LocalGatewayRouteTable",
        "ec2:CoipPool",
        "ec2:TransitGatewayMulticastDomain",
        "outposts:Outpost",
    }
)

_ORG_ARN_REGEX = re.compile(r"^arn:aws:organizations::\d+:organization/o-[a-z0-9]+$")
_OU_ARN_REGEX = re.compile(r"^arn:aws:organizations::\d+:ou/o-[a-z0-9]+/ou-[a-z0-9-]+$")
_ACCOUNT_ID_REGEX = re.compile(r"^\d{12}$")
_RESOURCE_OWNERS = ("SELF", "OTHER-ACCOUNTS")


def assess_ram(
    regions: list[str],
    session=None,
) -> tuple[dict, list[dict]]:
    shares: list[dict] = []
    errors: list[dict] = []

    if not regions:
        return {"resource_shares": shares}, errors

    max_workers = min(len(regions), 6)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_assess_region, r, session): r for r in regions}
        for future in futures:
            region_shares, region_errors = future.result()
            shares.extend(region_shares)
            errors.extend(region_errors)

    shares.sort(key=lambda s: (s["region"], s.get("name") or "", s["resource_share_arn"]))
    return {"resource_shares": shares}, errors


def _assess_region(region: str, session) -> tuple[list[dict], list[dict]]:
    errors: list[dict] = []
    try:
        client = create_client("ram", region=region, session=session)
    except ClientError as exc:
        errors.append(_err(region, "create_client:ram", exc))
        return [], errors

    # Discover shares in both directions. Each share is tagged with the owner
    # side it came from so downstream ListResources / ListPrincipals can pass
    # the matching resourceOwner (SELF for outbound, OTHER-ACCOUNTS for inbound) —
    # RAM's API rejects a SELF query against a share we don't own, which is why
    # the older single-owner code produced empty resources+principals for
    # inbound shares.
    raw_shares: list[tuple[str, dict]] = []
    for owner in _RESOURCE_OWNERS:
        try:
            for share in paginate_with_token(
                client,
                "get_resource_shares",
                "resourceShares",
                token_key="nextToken",
                resourceOwner=owner,
            ):
                raw_shares.append((owner, share))
        except ClientError as exc:
            errors.append(_err(region, f"GetResourceShares({owner})", exc))

    formatted: list[dict] = []
    for owner, share in raw_shares:
        arn = share.get("resourceShareArn")
        if not arn:
            continue

        resources, res_errors = _list_resources(client, region, arn, owner)
        principals, prin_errors = _list_principals(client, region, arn, owner)
        errors.extend(res_errors)
        errors.extend(prin_errors)

        formatted_resources = [_format_resource(r) for r in resources]
        formatted_principals = [_format_principal(p) for p in principals]

        formatted.append(
            {
                "region": region,
                "resource_share_arn": arn,
                "name": share.get("name"),
                "owner_id": share.get("owningAccountId"),
                "direction": "outbound" if owner == "SELF" else "inbound",
                "status": share.get("status"),
                "allow_external_principals": share.get("allowExternalPrincipals", False),
                "resources": formatted_resources,
                "principals": formatted_principals,
                "is_org_dependent": any(
                    p["type"] in ("ORGANIZATION", "ORGANIZATIONAL_UNIT")
                    for p in formatted_principals
                ),
            }
        )

    return formatted, errors


def _list_resources(
    client, region: str, share_arn: str, owner: str
) -> tuple[list[dict], list[dict]]:
    try:
        items = paginate_with_token(
            client,
            "list_resources",
            "resources",
            token_key="nextToken",
            resourceOwner=owner,
            resourceShareArns=[share_arn],
        )
        return items, []
    except ClientError as exc:
        return [], [_err(region, "ListResources", exc, share_arn=share_arn)]


def _list_principals(
    client, region: str, share_arn: str, owner: str
) -> tuple[list[dict], list[dict]]:
    try:
        items = paginate_with_token(
            client,
            "list_principals",
            "principals",
            token_key="nextToken",
            resourceOwner=owner,
            resourceShareArns=[share_arn],
        )
        return items, []
    except ClientError as exc:
        return [], [_err(region, "ListPrincipals", exc, share_arn=share_arn)]


def _format_resource(resource: dict) -> dict:
    rtype = resource.get("type")
    return {
        "type": rtype,
        "arn": resource.get("arn"),
        "status": resource.get("status"),
        "non_shareable_outside_org": rtype in _NON_SHAREABLE_RESOURCE_TYPES,
    }


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
    return {
        "id": pid,
        "type": ptype,
    }


def _err(region: str, operation: str, exc: ClientError, **extra) -> dict:
    payload = {
        "module": "ram",
        "region": region,
        "operation": operation,
        "code": exc.response.get("Error", {}).get("Code", "ClientError"),
        "message": str(exc),
    }
    payload.update(extra)
    return payload
