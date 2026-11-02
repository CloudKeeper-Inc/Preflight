from __future__ import annotations

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.pagination import paginate


def assess_existing_stacksets(session=None) -> tuple[dict, list[dict]]:
    """Inventory active CloudFormation StackSets in the management account.

    Categorizes by `PermissionModel` (SERVICE_MANAGED vs SELF_MANAGED). Only
    StackSets created from this account are visible — delegated-admin-owned
    sets aren't listed here.
    """
    client = create_client("cloudformation", region="us-east-1", session=session)
    result: dict[str, list[dict]] = {"service_managed": [], "self_managed": []}
    errors: list[dict] = []

    try:
        summaries = paginate(
            client, "list_stack_sets", "Summaries", Status="ACTIVE"
        )
    except ClientError as exc:
        errors.append(
            {
                "module": "stacksets",
                "operation": "ListStackSets",
                "code": exc.response.get("Error", {}).get("Code", "ClientError"),
                "message": str(exc),
            }
        )
        return result, errors

    for summary in summaries:
        name = summary.get("StackSetName")
        try:
            detail = client.describe_stack_set(StackSetName=name)["StackSet"]
        except ClientError as exc:
            errors.append(
                {
                    "module": "stacksets",
                    "operation": "DescribeStackSet",
                    "stackset": name,
                    "code": exc.response.get("Error", {}).get("Code", "ClientError"),
                    "message": str(exc),
                }
            )
            continue

        entry = _format_stackset(detail)
        bucket = (
            "service_managed"
            if entry["permission_model"] == "SERVICE_MANAGED"
            else "self_managed"
        )
        result[bucket].append(entry)

    return result, errors


def _format_stackset(detail: dict) -> dict:
    auto = detail.get("AutoDeployment") or {}
    org_targets = detail.get("OrganizationalUnitIds") or []
    return {
        "name": detail.get("StackSetName"),
        "id": detail.get("StackSetId"),
        "status": detail.get("Status"),
        "description": detail.get("Description"),
        "permission_model": detail.get("PermissionModel"),
        "auto_deployment": {
            "enabled": auto.get("Enabled"),
            "retain_stacks_on_account_removal": auto.get(
                "RetainStacksOnAccountRemoval"
            ),
        },
        "deployment_targets": {
            "ous": org_targets,
        },
        "template_description": (detail.get("TemplateBody") or "")[:200] or None,
        "capabilities": detail.get("Capabilities", []),
        "execution_role_name": detail.get("ExecutionRoleName"),
        "administration_role_arn": detail.get("AdministrationRoleARN"),
    }
