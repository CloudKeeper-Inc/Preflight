from __future__ import annotations

import json

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.pagination import paginate

# (output key, Organizations Filter value)
_POLICY_TYPES: tuple[tuple[str, str], ...] = (
    ("service_control_policies", "SERVICE_CONTROL_POLICY"),
    ("tag_policies", "TAG_POLICY"),
    ("backup_policies", "BACKUP_POLICY"),
    ("ai_opt_out_policies", "AISERVICES_OPT_OUT_POLICY"),
    ("chatbot_policies", "CHATBOT_POLICY"),
)


def assess_policies(session=None) -> tuple[dict, list[dict]]:
    """Enumerate all 5 org policy types with full content + targets.

    Policy types not enabled in the org return an empty list with no error.
    Per-policy DescribePolicy / ListTargetsForPolicy failures land in `errors`.
    """
    client = create_client("organizations", region="us-east-1", session=session)
    result: dict[str, list[dict]] = {key: [] for key, _ in _POLICY_TYPES}
    errors: list[dict] = []

    for key, filter_value in _POLICY_TYPES:
        policies, type_errors = _assess_policy_type(client, filter_value)
        result[key] = policies
        errors.extend(type_errors)

    return result, errors


def _assess_policy_type(client, policy_type: str) -> tuple[list[dict], list[dict]]:
    errors: list[dict] = []
    try:
        policies = paginate(
            client, "list_policies", "Policies", Filter=policy_type
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        if code == "PolicyTypeNotEnabledException":
            return [], []
        errors.append(
            {
                "module": "policies",
                "operation": "ListPolicies",
                "policy_type": policy_type,
                "code": code,
                "message": str(exc),
            }
        )
        return [], errors

    results: list[dict] = []
    for policy in policies:
        policy_id = policy["Id"]
        entry = {
            "id": policy_id,
            "name": policy.get("Name"),
            "description": policy.get("Description", ""),
            "type": policy.get("Type"),
            "aws_managed": policy.get("AwsManaged", False),
            "content": None,
            "targets": [],
        }

        try:
            detail = client.describe_policy(PolicyId=policy_id)
            entry["content"] = _parse_policy_content(detail["Policy"]["Content"])
        except ClientError as exc:
            errors.append(
                {
                    "module": "policies",
                    "operation": "DescribePolicy",
                    "policy_id": policy_id,
                    "code": exc.response.get("Error", {}).get("Code", "ClientError"),
                    "message": str(exc),
                }
            )

        try:
            targets = paginate(
                client, "list_targets_for_policy", "Targets", PolicyId=policy_id
            )
            entry["targets"] = [
                {
                    "target_id": t.get("TargetId"),
                    "type": t.get("Type"),
                    "name": t.get("Name"),
                    "arn": t.get("Arn"),
                }
                for t in targets
            ]
        except ClientError as exc:
            errors.append(
                {
                    "module": "policies",
                    "operation": "ListTargetsForPolicy",
                    "policy_id": policy_id,
                    "code": exc.response.get("Error", {}).get("Code", "ClientError"),
                    "message": str(exc),
                }
            )

        results.append(entry)
    return results, errors


def _parse_policy_content(raw: str):
    """Org policy content is a JSON string. Return parsed structure, or the raw
    string if it's a non-JSON format (declarative tag policy snippets etc.).
    """
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return raw
