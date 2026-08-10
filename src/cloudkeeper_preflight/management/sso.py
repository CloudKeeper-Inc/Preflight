from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.pagination import paginate, paginate_with_token

_ASSIGNMENT_FANOUT_WORKERS = 20
_TOP_LEVEL_FANOUT_WORKERS = 3


def assess_sso(
    accounts: list[dict],
    regions: list[str],
    session=None,
) -> tuple[dict, list[dict]]:
    """Count-only IAM Identity Center inventory.

    Discovers the SSO region (parallel probe), then counts users, groups,
    permission sets, and account assignments. No per-principal detail is
    collected — onboarding only needs the magnitudes, and the detail pull was
    by far the most expensive part of Phase 1 (a describe + four policy calls
    per permission set, plus a memberships call per group).

    Returns `{'enabled': False}` if no SSO instance exists.
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
        users_future = executor.submit(_count_users, identity_client, identity_store_id)
        groups_future = executor.submit(_count_groups, identity_client, identity_store_id)
        psets_future = executor.submit(
            _list_permission_set_arns, sso_client, instance_arn
        )

        user_count, user_errs = users_future.result()
        group_count, group_errs = groups_future.result()
        permission_set_arns, pset_errs = psets_future.result()

    errors.extend(user_errs)
    errors.extend(group_errs)
    errors.extend(pset_errs)

    account_ids = [a["account_id"] for a in (accounts or [])]
    assignment_count, assignment_errs = _count_account_assignments(
        sso_client, instance_arn, account_ids, permission_set_arns
    )
    errors.extend(assignment_errs)

    return {
        "enabled": True,
        "region": sso_region,
        "instance_arn": instance_arn,
        "identity_store_id": identity_store_id,
        "user_count": user_count,
        "group_count": group_count,
        "permission_set_count": len(permission_set_arns),
        "account_assignment_count": assignment_count,
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


def _count_users(client, identity_store_id: str) -> tuple[int, list[dict]]:
    try:
        users = paginate_with_token(
            client, "list_users", "Users", IdentityStoreId=identity_store_id
        )
    except ClientError as exc:
        return 0, [_err("ListUsers", exc)]
    return len(users), []


def _count_groups(client, identity_store_id: str) -> tuple[int, list[dict]]:
    try:
        groups = paginate_with_token(
            client, "list_groups", "Groups", IdentityStoreId=identity_store_id
        )
    except ClientError as exc:
        return 0, [_err("ListGroups", exc)]
    return len(groups), []


def _list_permission_set_arns(
    sso_client, instance_arn: str
) -> tuple[list[str], list[dict]]:
    """Collect ARNs, not just a count — the assignment fan-out needs them."""
    try:
        arns = paginate(
            sso_client,
            "list_permission_sets",
            "PermissionSets",
            InstanceArn=instance_arn,
        )
    except ClientError as exc:
        return [], [_err("ListPermissionSets", exc)]
    return arns, []


def _count_account_assignments(
    sso_client,
    instance_arn: str,
    account_ids: list[str],
    permission_set_arns: list[str],
) -> tuple[int, list[dict]]:
    """Fan out across (account_id, permission_set_arn) pairs, summing the hits."""
    errors: list[dict] = []
    if not account_ids or not permission_set_arns:
        return 0, errors

    pairs = [(a, p) for a in account_ids for p in permission_set_arns]

    def fetch(pair: tuple[str, str]) -> tuple[int, dict | None]:
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
            return len(items), None
        except ClientError as exc:
            return 0, _err(
                "ListAccountAssignments",
                exc,
                account_id=account_id,
                permission_set_arn=ps_arn,
            )

    total = 0
    workers = min(len(pairs), _ASSIGNMENT_FANOUT_WORKERS)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for count, err in executor.map(fetch, pairs):
            if err is not None:
                errors.append(err)
            total += count
    return total, errors


def _err(operation: str, exc: ClientError, **extra) -> dict:
    payload = {
        "module": "sso",
        "operation": operation,
        "code": exc.response.get("Error", {}).get("Code", "ClientError"),
        "message": str(exc),
    }
    payload.update(extra)
    return payload
