"""StackSet lifecycle: create → poll (streaming) → cleanup.

The deployer owns nothing about *what* the role does — that's in
`template.py`. This module is purely the CFN orchestration: create the
StackSet, drop a single stack instance per member account in `us-east-1`
(IAM is global so one region is enough), stream account IDs onto a Queue
as they go CURRENT, then tear it all down at the end.
"""

from __future__ import annotations

import sys
import time
from queue import Queue
from typing import Iterable

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.stackset_deploy.template import get_cfn_template
from cloudkeeper_preflight.util.pagination import paginate

STACKSET_NAME_PREFIX = "CloudKeeperPreFlightStackSet"
STACKSET_REGION = "us-east-1"
STACKSET_DEPLOY_REGIONS = [STACKSET_REGION]
STACKSET_TIMEOUT_SECONDS = 30 * 60
STACKSET_DELETE_TIMEOUT_SECONDS = 30 * 60
STACKSET_POLL_INTERVAL_SECONDS = 5

_READY_STATUSES = frozenset({"CURRENT", "SUCCEEDED"})
_TERMINAL_OP_STATUSES = frozenset({"SUCCEEDED", "FAILED", "STOPPED"})


def deploy_stackset(
    management_account_id: str,
    role_name: str,
    org_root_id: str,
    session=None,
) -> tuple[str, str]:
    """Create the StackSet + initial stack instances over the given OU root.

    Returns (stackset_name, operation_id). Raises if creation itself fails;
    per-account deployment failures surface during polling.
    """
    cfn = create_client("cloudformation", region=STACKSET_REGION, session=session)
    stackset_name = f"{STACKSET_NAME_PREFIX}-{int(time.time())}"
    template_body = get_cfn_template(management_account_id, role_name)

    cfn.create_stack_set(
        StackSetName=stackset_name,
        Description="CloudKeeper PreFlight temporary assessment role",
        TemplateBody=template_body,
        PermissionModel="SERVICE_MANAGED",
        AutoDeployment={"Enabled": False},
        Capabilities=["CAPABILITY_NAMED_IAM"],
        CallAs="SELF",
    )

    response = cfn.create_stack_instances(
        StackSetName=stackset_name,
        DeploymentTargets={"OrganizationalUnitIds": [org_root_id]},
        Regions=STACKSET_DEPLOY_REGIONS,
        OperationPreferences={
            "MaxConcurrentPercentage": 100,
            "FailureTolerancePercentage": 10,
        },
        CallAs="SELF",
    )
    return stackset_name, response["OperationId"]


def poll_stack_instances(
    stackset_name: str,
    operation_id: str,
    account_queue: "Queue[str | None]",
    all_account_ids: Iterable[str],
    session=None,
    timeout_seconds: int = STACKSET_TIMEOUT_SECONDS,
    poll_interval_seconds: int = STACKSET_POLL_INTERVAL_SECONDS,
) -> list[str]:
    """Poll the StackSet operation, stream READY accounts onto `account_queue`.

    Drops a `None` sentinel onto the queue when polling stops (operation
    finished or timeout), then returns the list of accounts that never went
    READY. Always emits the sentinel even on exception.
    """
    expected = set(all_account_ids)
    enqueued: set[str] = set()
    cfn = create_client("cloudformation", region=STACKSET_REGION, session=session)
    deadline = time.time() + timeout_seconds

    try:
        while time.time() < deadline:
            try:
                instances = paginate(
                    cfn,
                    "list_stack_instances",
                    "Summaries",
                    StackSetName=stackset_name,
                    CallAs="SELF",
                )
            except ClientError as exc:
                print(
                    f"  [warn] ListStackInstances: {exc}", file=sys.stderr, flush=True
                )
                instances = []

            for inst in instances:
                acct = inst.get("Account")
                if not acct or acct in enqueued:
                    continue
                detailed = (inst.get("StackInstanceStatus") or {}).get("DetailedStatus")
                status = detailed or inst.get("Status") or ""
                if status in _READY_STATUSES:
                    account_queue.put(acct)
                    enqueued.add(acct)

            try:
                op = cfn.describe_stack_set_operation(
                    StackSetName=stackset_name,
                    OperationId=operation_id,
                    CallAs="SELF",
                )
                op_status = op["StackSetOperation"]["Status"]
            except ClientError as exc:
                print(
                    f"  [warn] DescribeStackSetOperation: {exc}",
                    file=sys.stderr,
                    flush=True,
                )
                op_status = ""

            if op_status in _TERMINAL_OP_STATUSES:
                # One last sweep — instances may have flipped to CURRENT in this poll cycle.
                try:
                    final = paginate(
                        cfn,
                        "list_stack_instances",
                        "Summaries",
                        StackSetName=stackset_name,
                        CallAs="SELF",
                    )
                    for inst in final:
                        acct = inst.get("Account")
                        if not acct or acct in enqueued:
                            continue
                        detailed = (inst.get("StackInstanceStatus") or {}).get(
                            "DetailedStatus"
                        )
                        status = detailed or inst.get("Status") or ""
                        if status in _READY_STATUSES:
                            account_queue.put(acct)
                            enqueued.add(acct)
                except ClientError:
                    pass
                break

            time.sleep(poll_interval_seconds)
    finally:
        account_queue.put(None)

    failed = sorted(expected - enqueued) if expected else []
    return failed


def cleanup_stackset(
    stackset_name: str,
    org_root_id: str,
    session=None,
    timeout_seconds: int = STACKSET_DELETE_TIMEOUT_SECONDS,
    poll_interval_seconds: int = STACKSET_POLL_INTERVAL_SECONDS,
) -> None:
    """Delete all stack instances, wait for them to drain, then delete the StackSet itself.

    Tolerates "already gone" errors (StackSetNotFoundException etc.) so re-running
    cleanup after a partial failure is idempotent.
    """
    cfn = create_client("cloudformation", region=STACKSET_REGION, session=session)

    try:
        cfn.delete_stack_instances(
            StackSetName=stackset_name,
            DeploymentTargets={"OrganizationalUnitIds": [org_root_id]},
            Regions=STACKSET_DEPLOY_REGIONS,
            RetainStacks=False,
            CallAs="SELF",
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code not in ("StackSetNotFoundException",):
            print(
                f"  [warn] DeleteStackInstances({stackset_name}): {exc}",
                file=sys.stderr,
                flush=True,
            )

    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            instances = paginate(
                cfn,
                "list_stack_instances",
                "Summaries",
                StackSetName=stackset_name,
                CallAs="SELF",
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "StackSetNotFoundException":
                return
            instances = []
        if not instances:
            break
        time.sleep(poll_interval_seconds)

    try:
        cfn.delete_stack_set(StackSetName=stackset_name, CallAs="SELF")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code not in ("StackSetNotFoundException",):
            print(
                f"  [warn] DeleteStackSet({stackset_name}): {exc}",
                file=sys.stderr,
                flush=True,
            )
