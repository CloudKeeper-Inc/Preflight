from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.pagination import paginate, paginate_with_token

_ASSIGNMENT_FANOUT_WORKERS = 20
_TOP_LEVEL_FANOUT_WORKERS = 5


def assess_sso(
    accounts: list[dict],
    regions: list[str],
    session=None,
) -> tuple[dict, list[dict]]:
    """Full IAM Identity Center inventory.

    Discovers the SSO region (parallel scan), then fans out to pull users,
    groups+members, permission sets (with policies), account assignments,
    and applications. Returns `{'enabled': False}` if no SSO instance exists.
    """
    errors: list[dict] = []

    sso_region, find_errors = _find_sso_region(regions, session)
    errors.extend(find_errors)
    if not sso_region:
        return {"enabled": False}, errors

    sso_client = create_client("sso-admin", region=sso_region, session=session)
    identity_client = create_client("identitystore", region=sso_region, session=session)

    try:
        instances = sso_client.list_instances().get("Instances", [])
    except ClientError as exc:
        errors.append(_err("ListInstances", exc, region=sso_region))
        return {"enabled": False}, errors
    if not instances:
        return {"enabled": False}, errors

    instance = instances[0]
    instance_arn = instance["InstanceArn"]
    identity_store_id = instance["IdentityStoreId"]

    with ThreadPoolExecutor(max_workers=_TOP_LEVEL_FANOUT_WORKERS) as executor:
        users_future = executor.submit(_list_users, identity_client, identity_store_id)
        groups_future = executor.submit(_list_groups, identity_client, identity_store_id)
        psets_future = executor.submit(_list_permission_sets, sso_client, instance_arn)
        apps_future = executor.submit(_list_applications, sso_client, instance_arn)

        users, user_errs = users_future.result()
        groups, group_errs = groups_future.result()
        permission_sets, pset_errs = psets_future.result()
        applications, app_errs = apps_future.result()

    errors.extend(user_errs)
    errors.extend(group_errs)
    errors.extend(pset_errs)
    errors.extend(app_errs)

    account_ids = [a["account_id"] for a in (accounts or [])]
    ps_arns = [ps["arn"] for ps in permission_sets]
    assignments, assignment_errs = _list_account_assignments(
        sso_client, instance_arn, account_ids, ps_arns
    )
    errors.extend(assignment_errs)

    return {
        "enabled": True,
        "region": sso_region,
        "instance_arn": instance_arn,
        "identity_store_id": identity_store_id,
        "users": users,
        "groups": groups,
        "permission_sets": permission_sets,
        "account_assignments": assignments,
        "applications": applications,
    }, errors


def _find_sso_region(
    regions: list[str], session
) -> tuple[str | None, list[dict]]:
    """Parallel-probe each region for an SSO instance. Returns the first hit."""
    if not regions:
        return None, []

    errors: list[dict] = []

    def probe(region: str) -> str | None:
        try:
            client = create_client("sso-admin", region=region, session=session)
            instances = client.list_instances().get("Instances", [])
            return region if instances else None
        except ClientError as exc:
            errors.append(_err("ListInstances", exc, region=region))
            return None

    found: str | None = None
    max_workers = min(len(regions), 6)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(probe, r): r for r in regions}
        for future in as_completed(futures):
            result = future.result()
            if result and not found:
                found = result
                # Best-effort cancellation of pending probes; in-flight ones still finish.
                for f in futures:
                    f.cancel()
    return found, errors


def _list_users(client, identity_store_id: str) -> tuple[list[dict], list[dict]]:
    try:
        users = paginate_with_token(
            client, "list_users", "Users", IdentityStoreId=identity_store_id
        )
    except ClientError as exc:
        return [], [_err("ListUsers", exc)]

    formatted: list[dict] = []
    for u in users:
        primary_email = next(
            (e.get("Value") for e in (u.get("Emails") or []) if e.get("Primary")),
            None,
        )
        if primary_email is None and u.get("Emails"):
            primary_email = u["Emails"][0].get("Value")
        formatted.append(
            {
                "user_id": u.get("UserId"),
                "user_name": u.get("UserName"),
                "display_name": u.get("DisplayName"),
                "email": primary_email,
            }
        )
    return formatted, []


def _list_groups(client, identity_store_id: str) -> tuple[list[dict], list[dict]]:
    errors: list[dict] = []
    try:
        groups = paginate_with_token(
            client, "list_groups", "Groups", IdentityStoreId=identity_store_id
        )
    except ClientError as exc:
        return [], [_err("ListGroups", exc)]

    formatted: list[dict] = []
    for g in groups:
        group_id = g.get("GroupId")
        members: list[dict] = []
        try:
            raw_members = paginate_with_token(
                client,
                "list_group_memberships",
                "GroupMemberships",
                IdentityStoreId=identity_store_id,
                GroupId=group_id,
            )
            for m in raw_members:
                member_id_obj = m.get("MemberId") or {}
                # MemberId is a tagged union: {'UserId': '...'} or {'GroupId': '...'}
                if "UserId" in member_id_obj:
                    members.append(
                        {"member_id": member_id_obj["UserId"], "member_type": "USER"}
                    )
                elif "GroupId" in member_id_obj:
                    members.append(
                        {"member_id": member_id_obj["GroupId"], "member_type": "GROUP"}
                    )
        except ClientError as exc:
            errors.append(_err("ListGroupMemberships", exc, group_id=group_id))

        formatted.append(
            {
                "group_id": group_id,
                "display_name": g.get("DisplayName"),
                "description": g.get("Description"),
                "members": members,
            }
        )
    return formatted, errors


def _list_permission_sets(
    sso_client, instance_arn: str
) -> tuple[list[dict], list[dict]]:
    errors: list[dict] = []
    try:
        ps_arns = paginate(
            sso_client,
            "list_permission_sets",
            "PermissionSets",
            InstanceArn=instance_arn,
        )
    except ClientError as exc:
        return [], [_err("ListPermissionSets", exc)]

    results: list[dict] = []
    for arn in ps_arns:
        entry: dict[str, Any] = {
            "arn": arn,
            "name": None,
            "description": None,
            "session_duration": None,
            "relay_state": None,
            "created_date": None,
            "managed_policies": [],
            "customer_managed_policies": [],
            "inline_policy": None,
            "permissions_boundary": None,
        }
        try:
            detail = sso_client.describe_permission_set(
                InstanceArn=instance_arn, PermissionSetArn=arn
            )["PermissionSet"]
            entry["name"] = detail.get("Name")
            entry["description"] = detail.get("Description")
            entry["session_duration"] = detail.get("SessionDuration")
            entry["relay_state"] = detail.get("RelayState")
            cd = detail.get("CreatedDate")
            entry["created_date"] = cd.isoformat() if cd is not None and not isinstance(cd, str) else cd
        except ClientError as exc:
            errors.append(_err("DescribePermissionSet", exc, permission_set_arn=arn))

        try:
            managed = paginate(
                sso_client,
                "list_managed_policies_in_permission_set",
                "AttachedManagedPolicies",
                InstanceArn=instance_arn,
                PermissionSetArn=arn,
            )
            entry["managed_policies"] = [
                {"name": p.get("Name"), "arn": p.get("Arn")} for p in managed
            ]
        except ClientError as exc:
            errors.append(
                _err("ListManagedPoliciesInPermissionSet", exc, permission_set_arn=arn)
            )

        try:
            customer = paginate(
                sso_client,
                "list_customer_managed_policy_references_in_permission_set",
                "CustomerManagedPolicyReferences",
                InstanceArn=instance_arn,
                PermissionSetArn=arn,
            )
            entry["customer_managed_policies"] = [
                {"name": p.get("Name"), "path": p.get("Path")} for p in customer
            ]
        except ClientError as exc:
            errors.append(
                _err(
                    "ListCustomerManagedPolicyReferencesInPermissionSet",
                    exc,
                    permission_set_arn=arn,
                )
            )

        try:
            inline = sso_client.get_inline_policy_for_permission_set(
                InstanceArn=instance_arn, PermissionSetArn=arn
            ).get("InlinePolicy")
            entry["inline_policy"] = inline if inline else None
        except ClientError as exc:
            errors.append(
                _err("GetInlinePolicyForPermissionSet", exc, permission_set_arn=arn)
            )

        try:
            boundary = sso_client.get_permissions_boundary_for_permission_set(
                InstanceArn=instance_arn, PermissionSetArn=arn
            ).get("PermissionsBoundary")
            if boundary:
                entry["permissions_boundary"] = {
                    "managed_policy_arn": boundary.get("ManagedPolicyArn"),
                    "customer_managed_policy_reference": boundary.get(
                        "CustomerManagedPolicyReference"
                    ),
                }
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "ResourceNotFoundException":
                errors.append(
                    _err(
                        "GetPermissionsBoundaryForPermissionSet",
                        exc,
                        permission_set_arn=arn,
                    )
                )

        results.append(entry)
    return results, errors


def _list_account_assignments(
    sso_client,
    instance_arn: str,
    account_ids: list[str],
    permission_set_arns: list[str],
) -> tuple[list[dict], list[dict]]:
    """Fan out across (account_id, permission_set_arn) pairs."""
    errors: list[dict] = []
    if not account_ids or not permission_set_arns:
        return [], errors

    pairs = [(a, p) for a in account_ids for p in permission_set_arns]

    def fetch(pair: tuple[str, str]) -> tuple[list[dict], dict | None]:
        account_id, ps_arn = pair
        try:
            items = paginate(
                sso_client,
                "list_account_assignments",
                "AccountAssignments",
                InstanceArn=instance_arn,
                AccountId=account_id,
                PermissionSetArn=ps_arn,
            )
            return items, None
        except ClientError as exc:
            return [], _err(
                "ListAccountAssignments",
                exc,
                account_id=account_id,
                permission_set_arn=ps_arn,
            )

    assignments: list[dict] = []
    workers = min(len(pairs), _ASSIGNMENT_FANOUT_WORKERS)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for items, err in executor.map(fetch, pairs):
            if err is not None:
                errors.append(err)
            for item in items:
                assignments.append(
                    {
                        "account_id": item.get("AccountId"),
                        "permission_set_arn": item.get("PermissionSetArn"),
                        "principal_id": item.get("PrincipalId"),
                        "principal_type": item.get("PrincipalType"),
                    }
                )
    return assignments, errors


def _list_applications(
    sso_client, instance_arn: str
) -> tuple[list[dict], list[dict]]:
    try:
        apps = paginate_with_token(
            sso_client,
            "list_applications",
            "Applications",
            InstanceArn=instance_arn,
        )
    except ClientError as exc:
        return [], [_err("ListApplications", exc)]

    formatted = [
        {
            "arn": a.get("ApplicationArn"),
            "name": a.get("Name"),
            "status": a.get("Status"),
            "application_provider_arn": a.get("ApplicationProviderArn"),
            "instance_arn": a.get("InstanceArn"),
        }
        for a in apps
    ]
    return formatted, []


def _err(operation: str, exc: ClientError, **extra) -> dict:
    payload = {
        "module": "sso",
        "operation": operation,
        "code": exc.response.get("Error", {}).get("Code", "ClientError"),
        "message": str(exc),
    }
    payload.update(extra)
    return payload
