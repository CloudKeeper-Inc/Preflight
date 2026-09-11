from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.pagination import paginate


def assess_organization(session=None) -> tuple[dict, list[dict]]:
    """Fetch org metadata, root, and the full OU tree.

    Returns (result, errors). On a fatal error (e.g. Organizations not enabled),
    `result` may be empty or partial; the failure is captured in `errors`.
    """
    errors: list[dict] = []
    result: dict[str, Any] = {
        "org_id": None,
        "org_arn": None,
        "feature_set": None,
        "master_account_id": None,
        "master_account_email": None,
        "root_id": None,
        "root_name": None,
        "ou_tree": [],
        "all_ou_ids": [],
    }

    client = create_client("organizations", region="us-east-1", session=session)

    try:
        org = client.describe_organization()["Organization"]
        result["org_id"] = org.get("Id")
        result["org_arn"] = org.get("Arn")
        result["feature_set"] = org.get("FeatureSet")
        result["master_account_id"] = org.get("MasterAccountId")
        result["master_account_email"] = org.get("MasterAccountEmail")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        errors.append(
            {
                "module": "organization",
                "operation": "DescribeOrganization",
                "code": code,
                "message": str(exc),
            }
        )
        if code == "AWSOrganizationsNotInUseException":
            return result, errors

    try:
        roots = paginate(client, "list_roots", "Roots")
        if roots:
            root = roots[0]
            result["root_id"] = root.get("Id")
            result["root_name"] = root.get("Name")
    except ClientError as exc:
        errors.append(
            {
                "module": "organization",
                "operation": "ListRoots",
                "code": exc.response.get("Error", {}).get("Code", "ClientError"),
                "message": str(exc),
            }
        )
        return result, errors

    if result["root_id"]:
        try:
            result["ou_tree"] = _build_ou_tree(client, result["root_id"])
            result["all_ou_ids"] = _flatten_ou_ids(result["ou_tree"])
        except ClientError as exc:
            errors.append(
                {
                    "module": "organization",
                    "operation": "ListOrganizationalUnitsForParent",
                    "code": exc.response.get("Error", {}).get("Code", "ClientError"),
                    "message": str(exc),
                }
            )

    return result, errors


def _build_ou_tree(client, parent_id: str) -> list[dict]:
    ous = paginate(
        client,
        "list_organizational_units_for_parent",
        "OrganizationalUnits",
        ParentId=parent_id,
    )
    tree: list[dict] = []
    for ou in ous:
        tree.append(
            {
                "ou_id": ou["Id"],
                "ou_name": ou["Name"],
                "parent_id": parent_id,
                "children": _build_ou_tree(client, ou["Id"]),
            }
        )
    return tree


def _flatten_ou_ids(tree: list[dict]) -> list[str]:
    ids: list[str] = []
    for node in tree:
        ids.append(node["ou_id"])
        ids.extend(_flatten_ou_ids(node.get("children", [])))
    return ids
