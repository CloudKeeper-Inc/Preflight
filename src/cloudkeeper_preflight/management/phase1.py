"""Phase 1 — management-account orchestration.

Topology:
  1. `assess_organization` runs first; everything else needs at least the org id.
  2. Independent modules fan out under a single `ThreadPoolExecutor`.
  3. `assess_sso` is submitted only after `assess_accounts` returns (it needs
     the account list to fan out assignment lookups).
  4. `assess_service_configs` is submitted only after `assess_trusted_access`
     returns (it needs the principal list to dispatch handlers).
  5. `assess_eks_charges` is submitted only after `assess_sso` returns AND
     only if SSO is enabled — an onboarding heuristic that EKS spend on a
     production-scale customer changes the conversation.
  6. `assess_budgets` needs the management account ID.

`cli.main` may pre-compute org/accounts/delegated_admins before kicking
Phase 1 off in the background (those values are also needed by Phase 2/3
right away). Pass them via `prefetched=` to skip the duplicate fetches.
Pass the management account ID via `management_account_id=` so the budgets
scanner can address the right account.
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor

from cloudkeeper_preflight.management.accounts import assess_accounts
from cloudkeeper_preflight.management.billing import assess_billing
from cloudkeeper_preflight.management.budgets import assess_budgets
from cloudkeeper_preflight.management.config_aggregators import assess_config_aggregators
from cloudkeeper_preflight.management.delegated_admins import assess_delegated_admins
from cloudkeeper_preflight.management.eks_access_scanner import scan_eks_access
from cloudkeeper_preflight.management.eks_charges import (
    assess_eks_charges,
    not_checked_because_no_sso,
)
from cloudkeeper_preflight.management.organization import assess_organization
from cloudkeeper_preflight.management.policies import assess_policies
from cloudkeeper_preflight.management.ram import assess_ram
from cloudkeeper_preflight.management.resource_policy_scanner import (
    scan_resource_policies,
)
from cloudkeeper_preflight.management.service_configs import assess_service_configs
from cloudkeeper_preflight.management.sso import assess_sso
from cloudkeeper_preflight.management.stacksets import assess_existing_stacksets
from cloudkeeper_preflight.management.tax import assess_tax_settings
from cloudkeeper_preflight.management.trusted_access import assess_trusted_access
from cloudkeeper_preflight.util.org_id_matcher import OrgIdMatcher


def run_phase1(
    regions: list[str],
    session=None,
    *,
    prefetched: dict | None = None,
    management_account_id: str | None = None,
) -> tuple[dict, list[dict]]:
    """Run the management-account assessment modules.

    `prefetched` may contain any subset of:
      - `organization`: result from `assess_organization()`
      - `organization_errors`: errors list from same
      - `accounts`: result from `assess_accounts(...)`
      - `accounts_errors`: errors list from same
      - `delegated_admins`: result from `assess_delegated_admins()`
      - `delegated_admins_errors`: errors list from same
    Anything not provided is fetched here.

    `management_account_id` is required for the budgets scanner. If not
    provided, the budgets scan is skipped (with an error entry).
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

    with ThreadPoolExecutor(max_workers=16) as executor:
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
        if management_account_id:
            tax_f: Future | None = executor.submit(
                assess_tax_settings, management_account_id, session=session
            )
        else:
            tax_f = None
            errors.append(
                {
                    "module": "tax",
                    "service": "taxsettings",
                    "operation": "assess_tax_settings",
                    "code": "MissingAccountId",
                    "message": (
                        "management_account_id not provided to run_phase1; "
                        "tax settings scan skipped"
                    ),
                }
            )
        if management_account_id:
            budgets_f: Future | None = executor.submit(
                assess_budgets, management_account_id, session=session
            )
        else:
            budgets_f = None
            errors.append(
                {
                    "module": "budgets",
                    "service": "budgets",
                    "operation": "assess_budgets",
                    "code": "MissingAccountId",
                    "message": (
                        "management_account_id not provided to run_phase1; "
                        "budgets scan skipped"
                    ),
                }
            )
        rp_f = (
            executor.submit(scan_resource_policies, regions, matcher, session=session)
            if matcher is not None
            else None
        )
        eks_access_f = (
            executor.submit(scan_eks_access, regions, matcher, session=session)
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

        # EKS charge check is gated on SSO. Wait for the SSO result here so we
        # can decide inside the executor block (leaves eks_f as a future the
        # collection loop below can uniformly `.result()`).
        sso, sso_errors = sso_f.result()
        if sso.get("enabled"):
            eks_f: Future | None = executor.submit(
                assess_eks_charges, session=session
            )
        else:
            eks_f = None

    results["accounts"] = accounts
    errors.extend(accounts_errors)
    results["trusted_access"] = trusted
    errors.extend(ta_errors)
    results["delegated_admins"] = delegated
    errors.extend(delegated_errors)
    results["sso"] = sso
    errors.extend(sso_errors)

    for key, future in (
        ("policies", pol_f),
        ("ram", ram_f),
        ("existing_stacksets", ss_f),
        ("config_aggregators", ca_f),
        ("billing", bill_f),
        ("service_configurations", sc_f),
    ):
        value, value_errors = future.result()
        results[key] = value
        errors.extend(value_errors)

    if tax_f is not None:
        tax_value, tax_errors = tax_f.result()
        results["tax_settings"] = tax_value
        errors.extend(tax_errors)
    else:
        results["tax_settings"] = {"seller_of_record": None}

    if budgets_f is not None:
        b_value, b_errors = budgets_f.result()
        results["budgets"] = b_value
        errors.extend(b_errors)
    else:
        results["budgets"] = {"budget_alerts": []}

    if eks_f is not None:
        eks_value, eks_errors = eks_f.result()
        results["eks_charges"] = eks_value
        errors.extend(eks_errors)
    else:
        results["eks_charges"] = not_checked_because_no_sso()

    if rp_f is not None:
        rp, rp_errors = rp_f.result()
        results["resource_policies"] = rp
        errors.extend(rp_errors)
    else:
        results["resource_policies"] = {}

    if eks_access_f is not None:
        eks_access, eks_access_errors = eks_access_f.result()
        results["eks_access"] = eks_access
        errors.extend(eks_access_errors)
    else:
        results["eks_access"] = {
            "checked": False,
            "reason": "organization id unknown",
            "clusters_scanned": 0,
            "clusters_with_sso_access_entries": [],
            "clusters_needing_configmap_inspection": [],
        }

    return results, errors
