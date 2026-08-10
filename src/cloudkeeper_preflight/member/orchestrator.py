"""Per-account fan-out for the member assessment phase.

Consumes account IDs from a Queue (fed by the StackSet poller in
`stackset_deploy.deployer`). For each account, assumes the assessor role
and runs the five member scanners in parallel within that account.

The management account is special-cased: when its ID is enqueued we
reuse the current credentials instead of attempting AssumeRole on it
(no role exists in the management account, and we don't need one).
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from typing import Any

from cloudkeeper_preflight.member.delegated_services import assess_delegated_services
from cloudkeeper_preflight.member.eks_access import scan_member_eks_access
from cloudkeeper_preflight.member.iam_scanner import scan_iam
from cloudkeeper_preflight.member.ram_scanner import scan_member_ram
from cloudkeeper_preflight.member.resource_policies import scan_member_resource_policies
from cloudkeeper_preflight.session import assume_role


def run_member_assessments(
    account_queue: "Queue[str | None]",
    org_context: dict,
    role_name: str,
    max_concurrent: int,
    progress_callback=None,
) -> tuple[dict, list[dict]]:
    """Drain the account queue and assess each account in parallel.

    `org_context` must include:
      - `matcher` (OrgIdMatcher)
      - `regions` (list[str])
      - `delegated_admin_map` (dict[str, list[str]])
      - `management_account_id` (str)

    Returns `(results_by_account_id, errors)`. Each account result has
    `assessment_status` ∈ {success, partial, failed}.
    """
    matcher = org_context["matcher"]
    regions = org_context["regions"]
    delegated_admin_map: dict[str, list[str]] = org_context.get(
        "delegated_admin_map", {}
    )
    management_account_id = org_context["management_account_id"]

    results: dict[str, dict] = {}
    all_errors: list[dict] = []
    lock = threading.Lock()

    def assess_account(account_id: str) -> tuple[str, dict, list[dict]]:
        if account_id == management_account_id:
            session = None  # Use ambient credentials.
        else:
            session = assume_role(account_id, role_name)
            if session is None:
                return (
                    account_id,
                    {
                        "assessment_status": "failed",
                        "error": "AssumeRole failed",
                    },
                    [],
                )

        account_errors: list[dict] = []
        account_result: dict[str, Any] = {"assessment_status": "success"}
        delegated_principals = delegated_admin_map.get(account_id, [])

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures: dict = {}
            futures[executor.submit(scan_member_resource_policies, session, regions, matcher)] = "resource_policies"
            futures[executor.submit(scan_iam, session, matcher)] = "iam"
            futures[executor.submit(scan_member_ram, session, regions)] = "ram"
            futures[executor.submit(scan_member_eks_access, session, regions, matcher)] = "eks_access"
            if delegated_principals:
                futures[
                    executor.submit(
                        assess_delegated_services,
                        session,
                        delegated_principals,
                        regions,
                    )
                ] = "delegated_services"

            for future in as_completed(futures):
                name = futures[future]
                try:
                    payload, errs = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    account_errors.append(
                        {
                            "module": name,
                            "account_id": account_id,
                            "code": exc.__class__.__name__,
                            "message": str(exc),
                        }
                    )
                    continue
                account_result[name] = payload
                for e in errs:
                    e.setdefault("account_id", account_id)
                account_errors.extend(errs)

        if account_errors:
            account_result["assessment_status"] = "partial"
        return account_id, account_result, account_errors

    in_flight: dict = {}
    workers = max(1, max_concurrent)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        while True:
            account_id = account_queue.get()
            if account_id is None:
                break
            future = executor.submit(assess_account, account_id)
            in_flight[future] = account_id
            if progress_callback:
                try:
                    progress_callback("submitted", account_id)
                except Exception:
                    pass

        for future in as_completed(in_flight):
            account_id = in_flight[future]
            try:
                aid, result, errors = future.result()
            except Exception as exc:  # pragma: no cover - defensive
                with lock:
                    results[account_id] = {
                        "assessment_status": "failed",
                        "error": f"{exc.__class__.__name__}: {exc}",
                    }
                if progress_callback:
                    try:
                        progress_callback("failed", account_id)
                    except Exception:
                        pass
                continue
            with lock:
                results[aid] = result
                all_errors.extend(errors)
            if progress_callback:
                try:
                    progress_callback(result["assessment_status"], aid)
                except Exception:
                    pass

    return results, all_errors
