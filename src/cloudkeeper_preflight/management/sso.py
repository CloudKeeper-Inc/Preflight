from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.pagination import paginate, paginate_with_token

_ASSIGNMENT_FANOUT_WORKERS = 20
_TOP_LEVEL_FANOUT_WORKERS = 4
_APPLICATION_FANOUT_WORKERS = 8

# ApplicationProviderArns starting with these prefixes are the AWS-managed
# application providers (SageMaker Studio, QuickSight, etc.). Customer-managed
# SAML 2.0 / OAuth 2.0 applications use `.../custom` or `.../custom-saml`.
# Prefixes MUST be lowercase — `_is_customer_managed` normalises input via
# `.lower()` before comparison.
_AWS_MANAGED_PROVIDER_PREFIXES = (
    "arn:aws:sso::aws:applicationprovider/sagemaker",
    "arn:aws:sso::aws:applicationprovider/quicksight",
    "arn:aws:sso::aws:applicationprovider/awsmanagedapplication",
)
_CUSTOMER_MANAGED_PROVIDER_MARKERS = ("custom",)


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
        apps_future = executor.submit(_scan_applications, sso_client, instance_arn)

        user_count, user_errs = users_future.result()
        group_count, group_errs = groups_future.result()
        permission_set_arns, pset_errs = psets_future.result()
        applications, app_errs = apps_future.result()

    errors.extend(user_errs)
    errors.extend(group_errs)
    errors.extend(pset_errs)
    errors.extend(app_errs)

    account_ids = [a["account_id"] for a in (accounts or [])]
    assignment_count, assignment_errs = _count_account_assignments(
        sso_client, instance_arn, account_ids, permission_set_arns
    )
    errors.extend(assignment_errs)

    customer_managed_count = sum(
        1 for a in applications if a.get("is_customer_managed")
    )

    return {
        "enabled": True,
        "region": sso_region,
        "instance_arn": instance_arn,
        "identity_store_id": identity_store_id,
        "user_count": user_count,
        "group_count": group_count,
        "permission_set_count": len(permission_set_arns),
        "account_assignment_count": assignment_count,
        "enabled_application_count": len(applications),
        "customer_managed_application_count": customer_managed_count,
        "enabled_applications": applications,
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


def _scan_applications(
    sso_client, instance_arn: str
) -> tuple[list[dict], list[dict]]:
    """List every application on the IdC instance, then for each ENABLED one
    fetch its principal counts and assignment-required flag.

    Only enabled applications are returned — disabled ones don't need
    migration attention. Every enabled application needs to be re-registered
    on the new SSO at cutover regardless of provider (AWS-managed apps like
    SageMaker Studio do NOT transfer automatically). The `is_customer_managed`
    flag on each entry is a hint for analysts distinguishing SAML / OAuth
    apps the customer added themselves from AWS-managed integrations, but
    both categories require attention at cutover.
    """
    errors: list[dict] = []

    try:
        applications = paginate(
            sso_client,
            "list_applications",
            "Applications",
            InstanceArn=instance_arn,
        )
    except ClientError as exc:
        return [], [_err("ListApplications", exc)]

    enabled = [a for a in applications if a.get("Status") == "ENABLED"]
    if not enabled:
        return [], errors

    def enrich(app: dict) -> tuple[dict, list[dict]]:
        app_arn = app.get("ApplicationArn")
        provider_arn = app.get("ApplicationProviderArn") or ""
        app_errors: list[dict] = []

        try:
            assignments = paginate(
                sso_client,
                "list_application_assignments",
                "ApplicationAssignments",
                ApplicationArn=app_arn,
            )
        except ClientError as exc:
            app_errors.append(
                _err(
                    "ListApplicationAssignments",
                    exc,
                    application_arn=app_arn,
                )
            )
            assignments = []

        user_count = sum(
            1 for a in assignments if a.get("PrincipalType") == "USER"
        )
        group_count = sum(
            1 for a in assignments if a.get("PrincipalType") == "GROUP"
        )

        try:
            config = sso_client.get_application_assignment_configuration(
                ApplicationArn=app_arn
            )
            assignment_required = bool(config.get("AssignmentRequired", True))
        except ClientError as exc:
            app_errors.append(
                _err(
                    "GetApplicationAssignmentConfiguration",
                    exc,
                    application_arn=app_arn,
                )
            )
            assignment_required = True

        return {
            "application_arn": app_arn,
            "name": app.get("Name"),
            "description": app.get("Description"),
            "application_provider_arn": provider_arn,
            "is_customer_managed": _is_customer_managed(provider_arn),
            "status": app.get("Status"),
            "visibility": (app.get("PortalOptions") or {}).get("Visibility"),
            "assignment_required": assignment_required,
            "assigned_user_count": user_count,
            "assigned_group_count": group_count,
        }, app_errors

    enriched: list[dict] = []
    workers = min(len(enabled), _APPLICATION_FANOUT_WORKERS)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for entry, entry_errors in executor.map(enrich, enabled):
            enriched.append(entry)
            errors.extend(entry_errors)

    enriched.sort(key=lambda a: ((a.get("name") or "").lower(), a.get("application_arn") or ""))
    return enriched, errors


def _is_customer_managed(provider_arn: str) -> bool:
    """Heuristic: AWS-managed providers use known service-name prefixes; the
    generic customer-managed SAML / OAuth apps use `.../custom*`. Anything
    that isn't clearly AWS-managed is treated as customer-managed — bias
    toward surfacing than silently dropping.
    """
    if not provider_arn:
        return False
    lowered = provider_arn.lower()
    if any(lowered.startswith(p) for p in _AWS_MANAGED_PROVIDER_PREFIXES):
        return False
    if any(marker in lowered for marker in _CUSTOMER_MANAGED_PROVIDER_MARKERS):
        return True
    # Unknown provider — surface it as customer-managed so an analyst looks.
    return True


def _err(operation: str, exc: ClientError, **extra) -> dict:
    payload = {
        "module": "sso",
        "operation": operation,
        "code": exc.response.get("Error", {}).get("Code", "ClientError"),
        "message": str(exc),
    }
    payload.update(extra)
    return payload
