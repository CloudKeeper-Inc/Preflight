"""Deterministic normalisation of a PreFlight assessment JSON into the
compact structure the Bedrock prompt will consume.

Nothing here calls AWS or an LLM. Same input dict → same output dict.

The output is designed to be trivially templatable: the LLM keys off the
`kind` of each entry in `reconfig_blocks` and renders the block with real
IDs/ARNs/counts from the `data` payload — never invents them.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

_CFN_TEMPLATE_URL = (
    "https://ck-prism-cfn.s3.us-east-1.amazonaws.com/CloudKeeper-Replication-Role.yml"
)
_CFN_STACK_NAME = "CloudKeeper-Replication-Role"
_CFN_ATTACHMENT_FILENAME = "CloudKeeper-Replication-Role.yml"

_DOC_CLOUDTRAIL_MULTI = (
    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/"
    "cloudtrail-receive-logs-from-multiple-accounts.html"
)
_DOC_GUARDDUTY_INVITES = (
    "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_invitations.html"
)
_DOC_CONFIG_AGGREGATOR = (
    "https://docs.aws.amazon.com/config/latest/developerguide/aggregated-create.html"
)
_DOC_MACIE_INVITES = (
    "https://docs.aws.amazon.com/macie/latest/user/accounts-mgmt-invitations.html"
)

# Per-block effort weight in business days. Rough — refine as we see real
# customer runs. Unlisted blocks default to _DEFAULT_BLOCK_DAYS.
_BLOCK_EFFORT_DAYS: dict[str, float] = {
    "identity_center":              1.5,   # Prism install + IdC migration
    "cloudtrail_org_trail":         0.5,
    "guardduty":                    0.5,
    "config_aggregators":           0.5,
    "aws_config_org_rules":         0.5,
    "macie":                        0.5,
    "security_hub_cspm":            0.5,
    "fms":                          0.5,
    "aws_backup_org":               0.5,
    "ram_shares":                   0.5,
    "stacksets_service_managed":    0.5,
    "resource_policy_org_references": 0.5,
    "eks_prism_access_entries":     0.5,
}
_DEFAULT_BLOCK_DAYS = 0.5

# AWS Support reinstatement turnaround. Filed in parallel, so a single
# range covers any count of closed accounts.
_REINSTATE_DAYS_LOW = 2
_REINSTATE_DAYS_HIGH = 5


def summarize_for_email(assessment: dict) -> dict:
    """Convert a PreFlight assessment JSON into the normalised email input."""
    accounts = assessment.get("accounts") or []
    identity_center = assessment.get("identity_center") or {}

    non_active = [a for a in accounts if a.get("status") != "ACTIVE"]
    reconfig_blocks = _build_reconfig_blocks(assessment)
    cfn_required = bool(reconfig_blocks)
    prism_eligible = bool(identity_center.get("enabled"))

    return {
        "customer": _customer(assessment),
        "org": _org(assessment),
        "findings_summary": _findings_summary(assessment, non_active),
        "prism_pitch": {
            "eligible": prism_eligible,
            "reason": _prism_pitch_reason(identity_center) if prism_eligible else None,
        },
        "reinstate_accounts": [
            {
                "account_id": a.get("account_id"),
                "name": a.get("name"),
                "status": a.get("status"),
                "email": a.get("email"),
            }
            for a in non_active
        ],
        "reconfig_blocks": reconfig_blocks,
        "cfn_handoff": {
            "required": cfn_required,
            "attachment_filename": _CFN_ATTACHMENT_FILENAME,
            "template_s3_url": _CFN_TEMPLATE_URL,
            "launch_stack_url": _launch_stack_url() if cfn_required else None,
        },
        "post_reconfig_cleanup": _post_reconfig_cleanup(assessment),
        "effort_estimate": _effort_estimate(reconfig_blocks, len(non_active)),
    }


# ------- top-level sections -------------------------------------------------


def _customer(a: dict) -> dict:
    m = a.get("metadata") or {}
    return {
        "uuid": m.get("customer_uuid"),
        "emails": m.get("customer_emails") or [],
        "assessed_at": m.get("assessment_timestamp"),
        "tool_version": m.get("tool_version"),
    }


def _org(a: dict) -> dict:
    o = a.get("organization") or {}
    m = a.get("metadata") or {}
    return {
        "org_id": o.get("org_id"),
        "management_account_id": m.get("management_account_id"),
        "management_account_email": o.get("master_account_email"),
        "feature_set": o.get("feature_set"),
    }


def _findings_summary(a: dict, non_active: list[dict]) -> dict:
    accounts = a.get("accounts") or []
    policies = a.get("policies") or {}
    billing = a.get("billing") or {}
    seller = a.get("seller_of_record") or {}
    return {
        "total_accounts": len(accounts),
        "non_active_count": len(non_active),
        "non_active_ids": [x.get("account_id") for x in non_active],
        "policy_counts": {
            "scp": len(policies.get("service_control_policies") or []),
            "tag": len(policies.get("tag_policies") or []),
            "backup": len(policies.get("backup_policies") or []),
            "ai_opt_out": len(policies.get("ai_opt_out_policies") or []),
            "chatbot": len(policies.get("chatbot_policies") or []),
        },
        "seller_of_record": (seller or {}).get("seller"),
        "billing_period_start": (billing.get("period") or {}).get("start"),
        "billing_total": billing.get("total_cost_excluding_marketplace_and_tax"),
        "billing_currency": billing.get("currency"),
    }


def _prism_pitch_reason(ic: dict) -> str:
    users = len(ic.get("users") or [])
    groups = len(ic.get("groups") or [])
    ps = len(ic.get("permission_sets") or [])
    ass = len(ic.get("account_assignments") or [])
    region = ic.get("region") or "unknown region"
    return (
        f"IAM Identity Center is enabled in {region} with {users} user(s), "
        f"{groups} group(s), {ps} permission set(s), {ass} account assignment(s)."
    )


# ------- reconfig blocks (the meat) -----------------------------------------


def _build_reconfig_blocks(a: dict) -> list[dict]:
    """One entry per reconfig-triggering finding, in email display order."""
    blocks: list[dict] = []
    ic = a.get("identity_center") or {}
    sc = a.get("service_configurations") or {}
    policies = a.get("policies") or {}

    # 4.1 IAM Identity Center — Prism replacement.
    if ic.get("enabled"):
        blocks.append(
            {
                "kind": "identity_center",
                "prism_covers": True,
                "doc_ref": None,
                "data": {
                    "region": ic.get("region"),
                    "users": len(ic.get("users") or []),
                    "groups": len(ic.get("groups") or []),
                    "permission_sets": len(ic.get("permission_sets") or []),
                    "account_assignments": len(ic.get("account_assignments") or []),
                },
            }
        )

    # 5.01 CloudTrail — org trail present anywhere.
    ct = sc.get("cloudtrail.amazonaws.com") or {}
    org_trails = ct.get("organization_trails") or []
    if org_trails:
        blocks.append(
            {
                "kind": "cloudtrail_org_trail",
                "prism_covers": True,
                "doc_ref": _DOC_CLOUDTRAIL_MULTI,
                "data": {
                    "trails": [
                        {
                            "name": t.get("name"),
                            "trail_arn": t.get("trail_arn"),
                            "s3_bucket": t.get("s3_bucket"),
                            "home_region": t.get("home_region"),
                        }
                        for t in org_trails
                    ],
                },
            }
        )

    # 5.02 GuardDuty — delegated admin OR any enabled detector.
    gd = sc.get("guardduty.amazonaws.com") or {}
    gd_admins = gd.get("admin_accounts") or []
    gd_orgwide = _guardduty_orgwide(gd)
    if gd_admins or gd_orgwide:
        blocks.append(
            {
                "kind": "guardduty",
                "prism_covers": True,
                "doc_ref": _DOC_GUARDDUTY_INVITES,
                "data": {
                    "delegated_admin_account_ids": [
                        x.get("account_id") for x in gd_admins
                    ],
                    "regions_with_detectors": [
                        r.get("region")
                        for r in (gd.get("detectors_by_region") or [])
                        if r.get("detectors")
                    ],
                },
            }
        )

    # 4.4 AWS Config aggregators (org-wide only — the scanner already
    # filters to OrganizationAggregationSource entries).
    cfg_aggs = a.get("config_aggregators") or []
    if cfg_aggs:
        blocks.append(
            {
                "kind": "config_aggregators",
                "prism_covers": True,
                "doc_ref": _DOC_CONFIG_AGGREGATOR,
                "data": {
                    "aggregators": [
                        {
                            "name": ag.get("name"),
                            "region": ag.get("region"),
                            "all_regions": ag.get("all_regions"),
                        }
                        for ag in cfg_aggs
                    ],
                },
            }
        )

    # 5.04 AWS Config — org rules / conformance packs.
    aws_config = sc.get("config.amazonaws.com") or {}
    org_rules = sum(
        len(r.get("rules") or []) for r in (aws_config.get("by_region") or [])
    )
    org_packs = sum(
        len(r.get("conformance_packs") or [])
        for r in (aws_config.get("by_region") or [])
    )
    if org_rules or org_packs:
        blocks.append(
            {
                "kind": "aws_config_org_rules",
                "prism_covers": True,
                "doc_ref": _DOC_CONFIG_AGGREGATOR,
                "data": {
                    "org_rule_count": org_rules,
                    "org_pack_count": org_packs,
                },
            }
        )

    # 5.06 Macie — org-managed if any region has auto-enable set.
    macie = sc.get("macie.amazonaws.com") or {}
    macie_regions = [
        r.get("region")
        for r in (macie.get("by_region") or [])
        if r.get("auto_enable")
    ]
    if macie_regions:
        blocks.append(
            {
                "kind": "macie",
                "prism_covers": True,
                "doc_ref": _DOC_MACIE_INVITES,
                "data": {"regions": macie_regions},
            }
        )

    # 5.03 Security Hub CSPM — flagged by v1.1.3+ CSPM patch.
    sh = sc.get("securityhub.amazonaws.com") or {}
    if sh.get("cspm_active"):
        blocks.append(
            {
                "kind": "security_hub_cspm",
                "prism_covers": True,
                "doc_ref": _DOC_GUARDDUTY_INVITES,  # same invite-based idea
                "data": {
                    "regions_with_standards": [
                        r.get("region")
                        for r in (sh.get("hubs_by_region") or [])
                        if r.get("enabled_standards")
                    ],
                    "regions_with_aggregators": [
                        r.get("region")
                        for r in (sh.get("hubs_by_region") or [])
                        if r.get("finding_aggregators")
                    ],
                    "delegated_admin_account_ids": [
                        x.get("account_id") for x in (sh.get("admin_accounts") or [])
                    ],
                },
            }
        )

    # 5.07 FMS — any policy present.
    fms = sc.get("fms.amazonaws.com") or {}
    fms_policies = fms.get("policies") or []
    if fms_policies:
        blocks.append(
            {
                "kind": "fms",
                "prism_covers": False,
                "doc_ref": None,
                "data": {
                    "policy_count": len(fms_policies),
                    "policy_names": [p.get("policy_name") for p in fms_policies],
                    "admin_account": fms.get("admin_account"),
                    "monthly_cost_hint_usd": len(fms_policies) * 100,
                },
            }
        )

    # 5.09 AWS Backup — org-wide backup policies (from top-level
    # policies.backup_policies, not the service_configs handler).
    backup_policies = policies.get("backup_policies") or []
    if backup_policies:
        blocks.append(
            {
                "kind": "aws_backup_org",
                "prism_covers": False,
                "doc_ref": None,
                "data": {
                    "policy_count": len(backup_policies),
                    "policy_names": [p.get("name") for p in backup_policies],
                },
            }
        )

    # 4.2 RAM — any outbound share.
    ram = (a.get("ram_shares") or {}).get("resource_shares") or []
    outbound = [s for s in ram if s.get("direction") == "outbound"]
    if outbound:
        blocks.append(
            {
                "kind": "ram_shares",
                "prism_covers": False,
                "doc_ref": None,
                "data": {
                    "shares": [
                        {
                            "name": s.get("name"),
                            "arn": s.get("resource_share_arn"),
                            "region": s.get("region"),
                            "owner_id": s.get("owner_id"),
                            "resource_types": sorted(
                                {
                                    r.get("type")
                                    for r in (s.get("resources") or [])
                                    if r.get("type")
                                }
                            ),
                            "is_org_dependent": s.get("is_org_dependent", False),
                        }
                        for s in outbound
                    ],
                },
            }
        )

    # 4.3 StackSets — service-managed.
    ss = a.get("stacksets") or {}
    ss_sm = ss.get("service_managed") or []
    if ss_sm:
        blocks.append(
            {
                "kind": "stacksets_service_managed",
                "prism_covers": False,
                "doc_ref": None,
                "data": {
                    "stacksets": [
                        {
                            "name": s.get("name"),
                            "permission_model": s.get("permission_model"),
                        }
                        for s in ss_sm
                    ],
                },
            }
        )

    # 6.x Resource-policy references — one combined block covering all
    # services with hits.
    mor = a.get("management_account_org_references") or {}
    services_with_hits = [
        k for k, v in mor.items() if isinstance(v, list) and v
    ]
    if services_with_hits:
        blocks.append(
            {
                "kind": "resource_policy_org_references",
                "prism_covers": False,
                "doc_ref": None,
                "data": {
                    "services": sorted(services_with_hits),
                    "total_hits": sum(
                        len(v) for v in mor.values() if isinstance(v, list)
                    ),
                },
            }
        )

    # 7.5 EKS access entries — Prism role ARNs needed when both EKS spend
    # and IdC are present.
    eks = a.get("eks_charges") or {}
    if eks.get("flag") and ic.get("enabled"):
        blocks.append(
            {
                "kind": "eks_prism_access_entries",
                "prism_covers": True,
                "doc_ref": None,
                "data": {
                    "cost": eks.get("total_cost"),
                    "currency": eks.get("currency"),
                    "period_days": (eks.get("period") or {}).get("days"),
                },
            }
        )

    return blocks


def _guardduty_orgwide(gd: dict) -> bool:
    for r in gd.get("detectors_by_region") or []:
        for d in r.get("detectors") or []:
            if d.get("status") == "ENABLED":
                return True
    return False


# ------- post-reconfig cleanup ----------------------------------------------


def _post_reconfig_cleanup(a: dict) -> list[dict]:
    """One deregister-CLI per (delegated-admin account × service_principal)."""
    admins = a.get("delegated_administrators") or []
    commands: list[dict] = []
    for admin in admins:
        account_id = admin.get("account_id")
        for s in admin.get("services") or []:
            sp = s.get("service_principal")
            if not (account_id and sp):
                continue
            commands.append(
                {
                    "account_id": account_id,
                    "service_principal": sp,
                    "cmd": (
                        "aws organizations deregister-delegated-administrator "
                        f"--account-id {account_id} --service-principal {sp}"
                    ),
                }
            )
    return commands


# ------- CFN handoff --------------------------------------------------------


def _launch_stack_url() -> str:
    encoded = quote(_CFN_TEMPLATE_URL, safe="")
    return (
        "https://console.aws.amazon.com/cloudformation/home?region=us-east-1"
        f"#/stacks/create/review?templateURL={encoded}"
        f"&stackName={_CFN_STACK_NAME}"
    )


# ------- effort estimate ----------------------------------------------------


def _effort_estimate(blocks: list[dict], reinstate_count: int) -> dict:
    """Per-block weights + a separate reinstatement line.

    Reconfig work: sum per-block days, spread ±20/30% for the low/high bounds.
    Reinstatement: independent AWS Support waiting time; reported separately
    because it runs in parallel with reconfig work.
    """
    total_days = sum(
        _BLOCK_EFFORT_DAYS.get(b["kind"], _DEFAULT_BLOCK_DAYS) for b in blocks
    )
    low = _round_half(total_days * 0.8)
    high = _round_half(total_days * 1.3)
    if blocks and high <= low:
        high = low + 0.5

    parts: list[str] = []
    if blocks:
        parts.append(
            f"{len(blocks)} reconfiguration item(s) — estimated "
            f"{_fmt_days(low)}-{_fmt_days(high)} business days."
        )
    else:
        parts.append("No technical reconfiguration required.")
    if reinstate_count:
        parts.append(
            f"Reinstating {reinstate_count} closed/suspended account(s) is "
            f"handled by AWS Support (typically "
            f"{_REINSTATE_DAYS_LOW}-{_REINSTATE_DAYS_HIGH} business days per "
            "case, filed in parallel)."
        )

    return {
        "reconfig_item_count": len(blocks),
        "reconfig_days_low": low,
        "reconfig_days_high": high,
        "reinstate_account_count": reinstate_count,
        "reinstate_days_low": _REINSTATE_DAYS_LOW if reinstate_count else 0,
        "reinstate_days_high": _REINSTATE_DAYS_HIGH if reinstate_count else 0,
        "human_summary": " ".join(parts),
    }


def _round_half(x: float) -> float:
    return round(x * 2) / 2


def _fmt_days(x: float) -> str:
    return str(int(x)) if x == int(x) else f"{x:.1f}"
