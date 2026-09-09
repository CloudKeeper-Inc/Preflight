"""Deep IAM scan for org references in a member account.

Three sub-scans run in parallel:
  1. Role trust policies (AssumeRolePolicyDocument on each role)
  2. Customer-managed policies (default version document)
  3. Inline policies attached directly to roles

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
