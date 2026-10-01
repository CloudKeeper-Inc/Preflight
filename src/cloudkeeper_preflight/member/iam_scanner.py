"""Deep IAM scan for org references in a member account.

Three things are examined, however they're fetched:
  1. Role trust policies (AssumeRolePolicyDocument on each role)
  2. Customer-managed policies (default version document)
  3. Inline policies attached directly to roles

Two fetch strategies, in order:

  `account_authorization_details` — one paginated
  `iam:GetAccountAuthorizationDetails` returns roles, their trust documents,
  their inline policy documents *and* customer-managed policy versions
  together. An account with 400 roles costs a handful of calls.

  `per_role_calls` — the original path: `ListRoles`, then a serial
  `ListRolePolicies` + `GetRolePolicy` per role and a `GetPolicyVersion` per
  customer-managed policy. Same 400-role account costs 400+ sequential round
  trips.

GetAccountAuthorizationDetails is the more throttle-prone of the two, so any
failure falls back to the per-role path rather than degrading the scan. The
strategy actually used is reported as `scan_strategy` in the payload.

Skips AWS service-linked roles (`/aws-service-role/` paths) — they're
managed by AWS and won't reference customer org IDs.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.org_id_matcher import OrgIdMatcher
from cloudkeeper_preflight.util.pagination import paginate


def scan_iam(
    member_session,
    matcher: OrgIdMatcher,
) -> tuple[dict, list[dict]]:
    client = create_client("iam", region="us-east-1", session=member_session)

    collapsed = _scan_via_authorization_details(client, matcher)
    if collapsed is not None:
        return collapsed

    return _scan_via_per_role_calls(client, matcher)


def _scan_via_authorization_details(
    client,
    matcher: OrgIdMatcher,
) -> tuple[dict, list[dict]] | None:
    """One paginated GetAccountAuthorizationDetails covering all three scans.

    Returns `None` if the call is unusable (AccessDenied, throttled out,
    malformed) so the caller can fall back. Deliberately all-or-nothing: a
    partial result here would silently under-report org references, and a
    missed reference is the one failure mode this tool cannot have.
    """
    roles: list[dict] = []
    policies: list[dict] = []
    try:
        paginator = client.get_paginator("get_account_authorization_details")
        for page in paginator.paginate(Filter=["Role", "LocalManagedPolicy"]):
            roles.extend(page.get("RoleDetailList", []))
            policies.extend(page.get("Policies", []))
    except ClientError:
        return None
    except Exception:  # pragma: no cover - defensive
        return None

    customer_roles = [
        r for r in roles if not (r.get("Path") or "").startswith("/aws-service-role/")
    ]

    trust = _scan_trust_policies(customer_roles, matcher)

    inline: list[dict] = []
    for r in customer_roles:
        for p in r.get("RolePolicyList") or []:
            doc = p.get("PolicyDocument")
            text = doc if isinstance(doc, str) else json.dumps(doc, default=str)
            if not matcher.has_match(text):
                continue
            inline.append(
                {
                    "role_name": r.get("RoleName"),
                    "role_arn": r.get("Arn"),
                    "policy_name": p.get("PolicyName"),
                    "matches": matcher.find_matches(text),
                }
            )

    managed: list[dict] = []
    for p in policies:
        doc = _default_policy_document(p)
        if doc is None:
            continue
        text = doc if isinstance(doc, str) else json.dumps(doc, default=str)
        if not matcher.has_match(text):
            continue
        managed.append(
            {
                "policy_arn": p.get("Arn"),
                "policy_name": p.get("PolicyName"),
                "matches": matcher.find_matches(text),
            }
        )

    return {
        "scan_strategy": "account_authorization_details",
        "roles_with_org_trust": trust,
        "policies_with_org_references": managed,
        "inline_policies_with_org_references": inline,
    }, []


def _default_policy_document(policy: dict):
    """Pull the default version's document out of a GAAD ManagedPolicyDetail.

    `PolicyVersionList` can carry several versions; only the default one is
    in force, which is what the per-role path's `GetPolicyVersion` fetched.
    """
    versions = policy.get("PolicyVersionList") or []
    default_id = policy.get("DefaultVersionId")
    for v in versions:
        if v.get("IsDefaultVersion") or (
            default_id and v.get("VersionId") == default_id
        ):
            return v.get("Document")
    return None


def _scan_via_per_role_calls(
    client,
    matcher: OrgIdMatcher,
) -> tuple[dict, list[dict]]:
    errors: list[dict] = []

    try:
        roles = paginate(client, "list_roles", "Roles")
    except ClientError as exc:
        errors.append(_err("ListRoles", exc))
        roles = []

    customer_roles = [
        r for r in roles if not (r.get("Path") or "").startswith("/aws-service-role/")
    ]

    with ThreadPoolExecutor(max_workers=3) as executor:
        trust_future = executor.submit(_scan_trust_policies, customer_roles, matcher)
        managed_future = executor.submit(
            _scan_customer_managed_policies, client, matcher
        )
        inline_future = executor.submit(
            _scan_inline_role_policies, client, customer_roles, matcher
        )

        trust = trust_future.result()
        managed, managed_errors = managed_future.result()
        inline, inline_errors = inline_future.result()

    errors.extend(managed_errors)
    errors.extend(inline_errors)

    return {
        "scan_strategy": "per_role_calls",
        "roles_with_org_trust": trust,
        "policies_with_org_references": managed,
        "inline_policies_with_org_references": inline,
    }, errors


def _scan_trust_policies(roles: list[dict], matcher: OrgIdMatcher) -> list[dict]:
    findings: list[dict] = []
    for r in roles:
        doc = r.get("AssumeRolePolicyDocument")
        if doc is None:
            continue
        text = doc if isinstance(doc, str) else json.dumps(doc, default=str)
        if not matcher.has_match(text):
            continue
        findings.append(
            {
                "role_arn": r.get("Arn"),
                "role_name": r.get("RoleName"),
                "matches": matcher.find_matches(text),
            }
        )
    return findings


def _scan_customer_managed_policies(
    client, matcher: OrgIdMatcher
) -> tuple[list[dict], list[dict]]:
    errors: list[dict] = []
    findings: list[dict] = []
    try:
        policies = paginate(client, "list_policies", "Policies", Scope="Local")
    except ClientError as exc:
        return [], [_err("ListPolicies", exc)]

    for p in policies:
        arn = p.get("Arn")
        version_id = p.get("DefaultVersionId")
        if not (arn and version_id):
            continue
        try:
            version = client.get_policy_version(
                PolicyArn=arn, VersionId=version_id
            ).get("PolicyVersion", {})
            doc = version.get("Document")
            text = doc if isinstance(doc, str) else json.dumps(doc, default=str)
            if not matcher.has_match(text):
                continue
            findings.append(
                {
                    "policy_arn": arn,
                    "policy_name": p.get("PolicyName"),
                    "matches": matcher.find_matches(text),
                }
            )
        except ClientError as exc:
            errors.append(_err("GetPolicyVersion", exc, policy_arn=arn))
    return findings, errors


def _scan_inline_role_policies(
    client,
    roles: list[dict],
    matcher: OrgIdMatcher,
) -> tuple[list[dict], list[dict]]:
    errors: list[dict] = []
    findings: list[dict] = []
    for r in roles:
        role_name = r.get("RoleName")
        if not role_name:
            continue
        try:
            names = paginate(
                client, "list_role_policies", "PolicyNames", RoleName=role_name
            )
        except ClientError as exc:
            errors.append(_err("ListRolePolicies", exc, role_name=role_name))
            continue
        for pname in names:
            try:
                response = client.get_role_policy(RoleName=role_name, PolicyName=pname)
                doc = response.get("PolicyDocument")
                text = doc if isinstance(doc, str) else json.dumps(doc, default=str)
                if not matcher.has_match(text):
                    continue
                findings.append(
                    {
                        "role_name": role_name,
                        "role_arn": r.get("Arn"),
                        "policy_name": pname,
                        "matches": matcher.find_matches(text),
                    }
                )
            except ClientError as exc:
                errors.append(
                    _err(
                        "GetRolePolicy", exc, role_name=role_name, policy_name=pname
                    )
                )
    return findings, errors


def _err(operation: str, exc: ClientError, **extra) -> dict:
    payload = {
        "module": "iam_scanner",
        "service": "iam",
        "operation": operation,
        "code": exc.response.get("Error", {}).get("Code", "ClientError"),
        "message": str(exc),
    }
    payload.update(extra)
    return payload
