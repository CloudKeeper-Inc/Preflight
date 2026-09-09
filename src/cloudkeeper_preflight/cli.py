from __future__ import annotations

import argparse
import re
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from queue import Queue

from cloudkeeper_preflight import __version__
from cloudkeeper_preflight.management.accounts import assess_accounts
from cloudkeeper_preflight.management.delegated_admins import assess_delegated_admins
from cloudkeeper_preflight.management.organization import assess_organization
from cloudkeeper_preflight.management.phase1 import run_phase1
from cloudkeeper_preflight.management.region_costs import select_assessment_regions
from cloudkeeper_preflight.member.orchestrator import run_member_assessments
from cloudkeeper_preflight.output import assemble_output, submit_to_api
from cloudkeeper_preflight.progress import ProgressReporter
from cloudkeeper_preflight.session import get_management_account_id
from cloudkeeper_preflight.stackset_deploy.deployer import (
    cleanup_stackset,
    deploy_stackset,
    poll_stack_instances,
)
from cloudkeeper_preflight.util.org_id_matcher import OrgIdMatcher
from cloudkeeper_preflight.util.regions import get_enabled_regions

_EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cloudkeeper-preflight",
        description="CloudKeeper PreFlight - AWS Organization Dependency Assessor",
    )
    parser.add_argument("--customer-uuid", required=True, help="Pre-whitelisted customer UUID (v4)")
    parser.add_argument(
        "--customer-emails",
        required=True,
        help="Comma-separated email addresses for the customer contact",
    )
    parser.add_argument("--api-endpoint", default=None, help="Backend API endpoint (omit to skip submission)")
    parser.add_argument(
        "--assess-member-accounts",
        action="store_true",
        help="Also assess linked member accounts (deploys a temporary read-only "
             "StackSet role, runs per-account scanners). Default: management "
             "account only.",
    )
    parser.add_argument(
        "--skip-stackset-cleanup",
        action="store_true",
        help="Leave the deployed StackSet in place after the assessment completes",
    )
    parser.add_argument(
        "--max-concurrent-accounts",
        type=int,
        default=10,
        help="Maximum number of member accounts to assess concurrently",
    )
    parser.add_argument(
        "--role-name",
        default="CloudKeeperPreFlightReadOnlyRole",
        help="IAM role name to assume in each member account",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    return parser.parse_args(argv)


def validate_args(args: argparse.Namespace) -> None:
    try:
        uuid.UUID(args.customer_uuid, version=4)
    except ValueError:
        print(f"Error: '{args.customer_uuid}' is not a valid UUID v4", file=sys.stderr)
        sys.exit(1)

    emails = [e.strip() for e in args.customer_emails.split(",") if e.strip()]
    if not emails:
        print("Error: --customer-emails must contain at least one address", file=sys.stderr)
        sys.exit(1)
    for email in emails:
        if not _EMAIL_REGEX.match(email):
            print(f"Error: '{email}' is not a valid email address", file=sys.stderr)
            sys.exit(1)
    args.customer_emails_list = emails

    if args.max_concurrent_accounts < 1:
        print("Error: --max-concurrent-accounts must be >= 1", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    args = parse_args()
    validate_args(args)

    print(f"CloudKeeper PreFlight v{__version__}")
    print(f"Customer: {args.customer_uuid}")
    print(f"Contacts: {', '.join(args.customer_emails_list)}")
    print()

    management_account_id = get_management_account_id()
    enabled_regions = get_enabled_regions()

    bootstrap_t0 = time.time()
    org, org_errors = assess_organization()

    # Refuse to proceed unless the caller IS the org's management account.
    # Everything downstream (StackSet ops, member fan-out, org-scoped reads)
    # assumes this, and running from a member yields either partial garbage or
    # AccessDenied floods. Emit a lightweight submission so we still learn
    # about the mis-run.
    _guard_management_account(
        args=args,
        caller_account_id=management_account_id,
        org=org,
        org_errors=org_errors,
    )

    # Ask Cost Explorer which regions the customer actually spends money in.
    # Runs after the management-account guard so a mis-run doesn't pay for a
    # CE call it will never use.
    (
        regions,
        account_regions,
        region_selection,
        region_selection_errors,
    ) = select_assessment_regions(enabled_regions)

    print(f"Management account: {management_account_id}")
    print(f"Enabled regions   : {len(enabled_regions)}")
    _print_region_selection(regions, region_selection)
    print()

    accounts, accounts_errors = assess_accounts(
        ou_tree=org.get("ou_tree") or [], root_id=org.get("root_id")
    )
    delegated, delegated_errors = assess_delegated_admins()
    print(
        f"Bootstrap done in {time.time() - bootstrap_t0:.1f}s "
        f"(org={org.get('org_id')}, accounts={len(accounts)}, delegated_admins={len(delegated)})"
    )
    feature_set = org.get("feature_set")
    if feature_set and feature_set != "ALL":
        print(
            f"  [warn] Org FeatureSet is {feature_set!r} — SCP / tag / backup / "
            f"AI-opt-out / chatbot policies will be empty.",
            file=sys.stderr,
        )
    print()

    matcher = (
        OrgIdMatcher(org["org_id"], org["all_ou_ids"]) if org.get("org_id") else None
    )
    delegated_admin_map: dict[str, list[str]] = {
        a["account_id"]: [s["service_principal"] for s in (a.get("services") or [])]
        for a in delegated
    }

    prefetched = {
        "organization": org,
        "organization_errors": org_errors,
        "accounts": accounts,
        "accounts_errors": accounts_errors,
        "delegated_admins": delegated,
        "delegated_admins_errors": delegated_errors,
    }

    phase1_results: dict = {}
    phase1_errors: list = []
    member_results: dict = {}
    member_errors: list = []
    stackset_name: str | None = None
    poll_failed_accounts: list[str] = []

    started_at = time.time()
    progress = ProgressReporter(verbose=args.verbose)

    try:
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="phase1") as p1_executor:
            phase1_started_at = time.time()
            phase1_future = p1_executor.submit(
                run_phase1,
                regions,
                prefetched=prefetched,
                management_account_id=management_account_id,
                discovery_regions=enabled_regions,
                region_selection=region_selection,
                region_selection_errors=region_selection_errors,
            )
            print("[Phase 1/3] Management Account Assessment (running in background)")

            if not args.assess_member_accounts:
                print("[Phase 2/3] Skipped (management-account-only mode; pass --assess-member-accounts to enable)")
                print("[Phase 3/3] Skipped (management-account-only mode; pass --assess-member-accounts to enable)")
            else:
                print("[Phase 2/3] StackSet Deployment")
                if not (org.get("root_id") and matcher is not None):
                    print("  [skip] Org metadata unavailable; cannot deploy StackSet")
                else:
                    phase23_t0 = time.time()
                    stackset_name, op_id = deploy_stackset(
                        management_account_id, args.role_name, org["root_id"]
                    )
                    print(f"  StackSet: {stackset_name}  operation: {op_id}")

                    account_queue: Queue = Queue()
                    # Skip non-ACTIVE accounts (suspended/pending close): the StackSet
                    # won't deploy to them and we shouldn't try to assume role into them.
                    expected_member_ids = {
                        a["account_id"]
                        for a in accounts
                        if a["account_id"] != management_account_id
                        and a.get("status") == "ACTIVE"
                    }
                    non_active = [
                        a["account_id"]
                        for a in accounts
                        if a.get("status") != "ACTIVE"
                    ]
                    if non_active:
                        print(
                            f"  [info] Skipping {len(non_active)} non-ACTIVE accounts: "
                            f"{', '.join(non_active[:5])}"
                            + (f" ... (+{len(non_active) - 5} more)" if len(non_active) > 5 else "")
                        )

                    def _poll() -> None:
                        nonlocal poll_failed_accounts
                        poll_failed_accounts = poll_stack_instances(
                            stackset_name,
                            op_id,
                            account_queue,
                            expected_member_ids,
                        )

                    poller = threading.Thread(
                        target=_poll, name="stackset-poller", daemon=True
                    )
                    poller.start()

                    # Management account doesn't get a StackSet instance; assess it
                    # using ambient credentials by enqueueing it directly.
                    account_queue.put(management_account_id)

                    print("[Phase 3/3] Member Account Assessment (streaming as accounts go ready)")
                    org_context = {
                        "matcher": matcher,
                        "regions": regions,
                        "account_regions": account_regions,
                        "delegated_admin_map": delegated_admin_map,
                        "management_account_id": management_account_id,
                    }
                    member_results, member_errors = run_member_assessments(
                        account_queue,
                        org_context,
                        args.role_name,
                        args.max_concurrent_accounts,
                        progress_callback=progress.member_event,
                    )
                    poller.join()
                    print(
                        f"  Phase 2+3 done in {time.time() - phase23_t0:.1f}s "
                        f"(assessed={len(member_results)}, "
                        f"failed_to_provision={len(poll_failed_accounts)})"
                    )

            # Wait for Phase 1 to finish (already running concurrently).
            print("[Phase 1/3] Awaiting completion...")
            phase1_results, phase1_errors = phase1_future.result()
            phase1_elapsed = time.time() - phase1_started_at
            _summarize_phase1(
                phase1_results, phase1_errors, phase1_elapsed, verbose=args.verbose
            )

        print(f"[Total elapsed pre-cleanup] {time.time() - started_at:.1f}s")

        if member_results:
            _summarize_members(member_results, member_errors, poll_failed_accounts, args.verbose)
    finally:
        if (
            args.assess_member_accounts
            and stackset_name is not None
            and not args.skip_stackset_cleanup
        ):
            print("[Cleanup] Deleting StackSet instances and StackSet")
            cleanup_t0 = time.time()
            try:
                cleanup_stackset(stackset_name, org["root_id"])
                print(f"  Cleanup done in {time.time() - cleanup_t0:.1f}s")
            except Exception as exc:
                print(
                    f"  [error] StackSet cleanup failed: {exc}",
                    file=sys.stderr,
                )
                print(
                    f"  Delete StackSet '{stackset_name}' by hand — the "
                    f"assessor role is still deployed in each member account.",
                    file=sys.stderr,
                )
        elif stackset_name is not None and args.skip_stackset_cleanup:
            print(f"[Cleanup] Skipped — StackSet '{stackset_name}' left in place")

    output = assemble_output(
        args=args,
        phase1_results=phase1_results,
        phase1_errors=phase1_errors,
        member_results=member_results,
        member_errors=member_errors,
        poll_failed_accounts=poll_failed_accounts,
        management_account_id=management_account_id,
        started_at=started_at,
    )
    submit_to_api(output, args.api_endpoint, args.customer_uuid)
    print(f"[Total elapsed] {time.time() - started_at:.1f}s")


def _print_region_selection(regions: list[str], selection: dict) -> None:
    """One-or-two line summary of which regions we're going to scan and why."""
    strategy = selection.get("strategy")
    threshold = selection.get("threshold")
    currency = selection.get("currency") or ""
    period = (selection.get("period") or {}).get("start", "")

    if strategy == "cost_filtered":
        why = f"cost >= {threshold} {currency}".strip()
        why = f"{why} since {period}, plus us-east-1"
    elif strategy == "all_enabled_cost_explorer_unavailable":
        why = "Cost Explorer unavailable — falling back to all enabled regions"
    elif strategy == "all_enabled_no_cost_data":
        why = "no billed spend in the window — falling back to all enabled regions"
    else:
        why = "all enabled regions"

    print(f"Regions to assess : {len(regions)} ({why})")

    costs = selection.get("region_costs") or {}
    if strategy == "cost_filtered" and costs:
        shown = [f"{r}={costs.get(r, 0.0):,.2f}" for r in regions[:8] if r in costs]
        if shown:
            print(f"  {' '.join(shown)}" + (" ..." if len(regions) > 8 else ""))
    skipped = selection.get("skipped_regions") or []
    if skipped:
        print(f"  [info] Skipping {len(skipped)} region(s) with no material spend")

    per_account = selection.get("per_account_scoping") or {}
    if per_account.get("enabled"):
        counts = (per_account.get("region_count_by_account") or {}).values()
        if counts:
            print(
                f"  [info] Per-account scoping: {len(counts)} account(s) with cost "
                f"data, {min(counts)}-{max(counts)} region(s) each "
                f"(vs {len(regions)} org-wide)"
            )


def _guard_management_account(
    args: argparse.Namespace,
    caller_account_id: str,
    org: dict,
    org_errors: list,
) -> None:
    """Exit if the caller is not the management (payer) account of the org.

    On failure we still post a minimal `run_in_wrong_account` submission so the
    CK backend records the misfire — analysts can then reach out with the
    correct account details before the customer retries.
    """
    master_id = org.get("master_account_id")
    master_email = org.get("master_account_email")
    org_id = org.get("org_id")

    if master_id and caller_account_id == master_id:
        return

    if any(
        e.get("code") == "AWSOrganizationsNotInUseException" for e in org_errors
    ):
        reason = "not-part-of-organization"
        headline = "This account is not part of an AWS Organization."
        followup = (
            "PreFlight must be run in the management (payer) account of the "
            "customer's AWS Organization."
        )
    elif master_id and caller_account_id != master_id:
        reason = "member-account"
        headline = (
            "PreFlight must be run in the management account of the organization."
        )
        followup = (
            f"  Current account       : {caller_account_id} (member account)\n"
            f"  Management account    : {master_id}\n"
            f"  Management root email : {master_email or '(unknown)'}\n"
            "\nSign in to the management account and re-run this command."
        )
    else:
        reason = "management-account-unknown"
        headline = (
            "Could not determine the organization's management account "
            "(DescribeOrganization did not return a master account id)."
        )
        followup = "See the error above. Aborting to avoid a partial assessment."

    print("", file=sys.stderr)
    print(f"ERROR: {headline}", file=sys.stderr)
    print(followup, file=sys.stderr)
    print("", file=sys.stderr)

    _submit_wrong_account_notice(
        args=args,
        caller_account_id=caller_account_id,
        master_account_id=master_id,
        master_account_email=master_email,
        org_id=org_id,
        reason=reason,
    )
    sys.exit(2)


def _submit_wrong_account_notice(
    args: argparse.Namespace,
    caller_account_id: str,
    master_account_id: str | None,
    master_account_email: str | None,
    org_id: str | None,
    reason: str,
) -> None:
    payload = {
        "metadata": {
            "customer_uuid": args.customer_uuid,
            "customer_emails": args.customer_emails_list,
            "assessment_timestamp": datetime.now(timezone.utc).isoformat(),
            "tool_version": __version__,
            "management_account_id": master_account_id or "",
            "run_in_wrong_account": True,
            "wrong_account_reason": reason,
        },
        "wrong_account_details": {
            "caller_account_id": caller_account_id,
            "expected_management_account_id": master_account_id,
            "expected_management_account_email": master_account_email,
            "org_id": org_id,
            "reason": reason,
        },
    }
    submit_to_api(payload, args.api_endpoint, args.customer_uuid)


def _summarize_members(
    member_results: dict,
    member_errors: list,
    failed_to_provision: list,
    verbose: bool,
) -> None:
    statuses: dict[str, int] = {}
    for r in member_results.values():
        s = r.get("assessment_status", "unknown")
        statuses[s] = statuses.get(s, 0) + 1
    print(f"  member accounts assessed: {len(member_results)}")
    for s in sorted(statuses):
        print(f"    {s:<10s} {statuses[s]}")
    print(f"  failed to provision     : {len(failed_to_provision)}")
    if failed_to_provision:
        for aid in failed_to_provision[:10]:
            print(f"    - {aid}")
    print(f"  member errors           : {len(member_errors)}")
    if verbose and member_errors:
        print("  --- member error detail ---")
        for e in member_errors[:25]:
            module = e.get("module", "?")
            op = e.get("operation", "?")
            code = e.get("code", "?")
            aid = e.get("account_id", "-")
            print(f"    [{aid} {module}/{op}] {code}: {e.get('message', '')[:140]}")
        if len(member_errors) > 25:
            print(f"    ... and {len(member_errors) - 25} more")


def _summarize_phase1(
    results: dict,
    errors: list,
    elapsed: float,
    verbose: bool,
) -> None:
    org = results.get("organization") or {}
    accounts = results.get("accounts") or []
    sso = results.get("sso") or {}
    billing = results.get("billing") or {}
    policies = results.get("policies") or {}
    rp = results.get("resource_policies") or {}
    sc = results.get("service_configurations") or {}

    rs = results.get("region_selection") or {}
    print(f"  organization      : {org.get('org_id')} ({org.get('feature_set')})")
    print(f"  accounts          : {len(accounts)}")
    if rs:
        print(
            f"  regions assessed  : {len(rs.get('selected_regions') or [])} of "
            f"{rs.get('enabled_region_count', 0)} enabled ({rs.get('strategy')})"
        )
    print(f"  trusted services  : {len(results.get('trusted_access') or [])}")
    print(f"  delegated admins  : {len(results.get('delegated_admins') or [])}")
    print(
        "  policies          : "
        f"SCP={len(policies.get('service_control_policies', []))} "
        f"tag={len(policies.get('tag_policies', []))} "
        f"backup={len(policies.get('backup_policies', []))} "
        f"ai={len(policies.get('ai_opt_out_policies', []))} "
        f"chatbot={len(policies.get('chatbot_policies', []))}"
    )
    print(f"  RAM shares        : {len(((results.get('ram') or {}).get('resource_shares') or []))}")
    ss = results.get("existing_stacksets") or {}
    print(
        f"  stacksets         : service-managed={len(ss.get('service_managed', []))} "
        f"self-managed={len(ss.get('self_managed', []))}"
    )
    print(f"  config aggregators: {len(results.get('config_aggregators') or [])}")
    print(
        f"  billing           : {billing.get('total_cost_excluding_marketplace_and_tax')} "
        f"{billing.get('currency') or ''} (org total)"
    )
    if sso.get("enabled"):
        print(
            f"  SSO               : region={sso.get('region')} users={sso.get('user_count', 0)} "
            f"groups={sso.get('group_count', 0)} permission_sets={sso.get('permission_set_count', 0)} "
            f"assignments={sso.get('account_assignment_count', 0)}"
        )
        print(
            f"  IdC applications  : {sso.get('enabled_application_count', 0)} enabled "
            f"({sso.get('customer_managed_application_count', 0)} customer-managed, "
            f"{sso.get('enabled_application_count', 0) - sso.get('customer_managed_application_count', 0)} AWS-managed) "
            f"— all need re-registration at cutover"
        )
    else:
        print("  SSO               : not enabled")
    rp_total = sum(len(v) for k, v in rp.items() if isinstance(v, list))
    print(f"  resource policies : {rp_total} matches across {len([k for k, v in rp.items() if isinstance(v, list) and v])} services")
    print(
        f"  service configs   : {len([k for k in sc if k != 'unhandled_services'])} handled, "
        f"{len(sc.get('unhandled_services') or [])} unhandled"
    )
    sor = (results.get("tax_settings") or {}).get("seller_of_record")
    if sor:
        print(f"  seller of record  : {sor.get('seller')!r}")
    else:
        print("  seller of record  : (no tax data for management account)")
    b = (results.get("budgets") or {}).get("budget_alerts") or []
    print(f"  budget alerts     : {len(b)} budget(s)")
    eks = results.get("eks_charges") or {}
    if eks.get("checked"):
        flag = "FLAGGED" if eks.get("flag") else "no EKS spend"
        print(
            f"  EKS charges (14d) : {flag} — total={eks.get('total_cost')} "
            f"{eks.get('currency') or ''}"
        )
    else:
        print(f"  EKS charges (14d) : not checked ({eks.get('reason', 'unknown')})")
    eks_access = results.get("eks_access") or {}
    if eks_access.get("checked"):
        sso_clusters = eks_access.get("clusters_with_sso_access_entries") or []
        cm_clusters = eks_access.get("clusters_needing_configmap_inspection") or []
        print(
            f"  EKS access entries: {len(sso_clusters)} cluster(s) with SSO refs, "
            f"{len(cm_clusters)} cluster(s) need aws-auth ConfigMap inspection "
            f"(scanned {eks_access.get('clusters_scanned', 0)})"
        )
    else:
        print(
            f"  EKS access entries: not checked ({eks_access.get('reason', 'unknown')})"
        )
    print(f"  errors            : {len(errors)}")
    print(f"  elapsed           : {elapsed:.1f}s")
    if verbose and errors:
        print("  --- error detail ---")
        for e in errors[:25]:
            module = e.get("module", "?")
            op = e.get("operation", "?")
            code = e.get("code", "?")
            print(f"    [{module}/{op}] {code}: {e.get('message', '')[:160]}")
        if len(errors) > 25:
            print(f"    ... and {len(errors) - 25} more")


if __name__ == "__main__":
    main()
