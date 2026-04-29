"""Phase 1 — management-account orchestration.

Topology:
  1. `assess_organization` runs first; everything else needs at least the org id.
  2. The remaining 9 modules fan out under a single `ThreadPoolExecutor`.
  3. `assess_sso` is submitted only after `assess_accounts` returns (it needs
     the account list to fan out assignment lookups).
  4. `assess_service_configs` is submitted only after `assess_trusted_access`
     returns (it needs the principal list to dispatch handlers).

`cli.main` may pre-compute org/accounts/delegated_admins before kicking
Phase 1 off in the background (those values are also needed by Phase 2/3
right away). Pass them via `prefetched=` to skip the duplicate fetches.
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor

from cloudkeeper_preflight.management.accounts import assess_accounts
from cloudkeeper_preflight.management.billing import assess_billing
from cloudkeeper_preflight.management.config_aggregators import assess_config_aggregators
from cloudkeeper_preflight.management.delegated_admins import assess_delegated_admins
from cloudkeeper_preflight.management.organization import assess_organization
from cloudkeeper_preflight.management.policies import assess_policies
from cloudkeeper_preflight.management.ram import assess_ram
from cloudkeeper_preflight.management.resource_policy_scanner import (
    scan_resource_policies,
)
from cloudkeeper_preflight.management.service_configs import assess_service_configs
from cloudkeeper_preflight.management.sso import assess_sso
from cloudkeeper_preflight.management.stacksets import assess_existing_stacksets
from cloudkeeper_preflight.management.trusted_access import assess_trusted_access
from cloudkeeper_preflight.util.org_id_matcher import OrgIdMatcher


def run_phase1(
    regions: list[str],
    session=None,
    *,
    prefetched: dict | None = None,
) -> tuple[dict, list[dict]]:
    """Run the 12 management-account assessment modules.

    `prefetched` may contain any subset of:
      - `organization`: result from `assess_organization()`
      - `organization_errors`: errors list from same
      - `accounts`: result from `assess_accounts(...)`
      - `accounts_errors`: errors list from same
      - `delegated_admins`: result from `assess_delegated_admins()`
      - `delegated_admins_errors`: errors list from same
    Anything not provided is fetched here.
    """
    prefetched = prefetched or {}
    results: dict = {}
    errors: list[dict] = []

    if "organization" in prefetched:
        org = prefetched["organization"]
        errors.extend(prefetched.get("organization_errors") or [])
    else:
        org, org_errors = assess_organization(session=session)
        errors.extend(org_errors)
    results["organization"] = org

    matcher = (
        OrgIdMatcher(org["org_id"], org["all_ou_ids"]) if org.get("org_id") else None
    )

    with ThreadPoolExecutor(max_workers=12) as executor:
        if "accounts" in prefetched:
            accounts = prefetched["accounts"]
            accounts_errors = prefetched.get("accounts_errors") or []
            accounts_f: Future | None = None
        else:
            accounts_f = executor.submit(
                assess_accounts,
                session=session,
                ou_tree=org.get("ou_tree") or [],
                root_id=org.get("root_id"),
            )
            accounts = None
            accounts_errors = []

        if "delegated_admins" in prefetched:
            delegated = prefetched["delegated_admins"]
            delegated_errors = prefetched.get("delegated_admins_errors") or []
            da_f: Future | None = None
        else:
            da_f = executor.submit(assess_delegated_admins, session=session)
            delegated = None
            delegated_errors = []

        ta_f = executor.submit(assess_trusted_access, session=session)
        pol_f = executor.submit(assess_policies, session=session)
        ram_f = executor.submit(assess_ram, regions, session=session)
        ss_f = executor.submit(assess_existing_stacksets, session=session)
        ca_f = executor.submit(assess_config_aggregators, regions, session=session)
        bill_f = executor.submit(assess_billing, session=session)
        rp_f = (
            executor.submit(scan_resource_policies, regions, matcher, session=session)
            if matcher is not None
            else None
        )

        if accounts_f is not None:
            accounts, accounts_errors = accounts_f.result()
        sso_f = executor.submit(assess_sso, accounts, regions, session=session)

        trusted, ta_errors = ta_f.result()
        sc_f = executor.submit(
            assess_service_configs, trusted, regions, session=session
        )

        if da_f is not None:
            delegated, delegated_errors = da_f.result()

    results["accounts"] = accounts
    errors.extend(accounts_errors)
    results["trusted_access"] = trusted
    errors.extend(ta_errors)
    results["delegated_admins"] = delegated
    errors.extend(delegated_errors)

    for key, future in (
        ("policies", pol_f),
        ("ram", ram_f),
        ("existing_stacksets", ss_f),
        ("config_aggregators", ca_f),
        ("billing", bill_f),
        ("sso", sso_f),
        ("service_configurations", sc_f),
    ):
        value, value_errors = future.result()
        results[key] = value
        errors.extend(value_errors)

    if rp_f is not None:
        rp, rp_errors = rp_f.result()
        results["resource_policies"] = rp
        errors.extend(rp_errors)
    else:
        results["resource_policies"] = {}

    bill = results.get("billing") or {}
    if bill.get("per_account_costs"):
        name_by_id = {a["account_id"]: a.get("name") for a in (accounts or [])}
        for row in bill["per_account_costs"]:
            if row.get("account_name") is None:
                row["account_name"] = name_by_id.get(row["account_id"])

    return results, errors
