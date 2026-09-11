"""Deterministic normalisation of a PreFlight assessment JSON into the
compact structure the Bedrock prompt will consume.

Nothing here calls AWS or an LLM. Same input dict → same output dict.

The output is designed to be trivially templatable: the LLM keys off the
`kind` of each entry in `reconfig_blocks` and renders the block with real
IDs/ARNs/counts from the `data` payload — never invents them. Every `kind`
emitted here needs a matching prose template in `prompt_templates.py`, or the
block lands in the email as improvised prose.

`prism_covers` is the other load-bearing flag: it drives the "Prism automates
this." sentence and the shape of the two reconfiguration paths. Set it True
only where Prism genuinely does the work — the customer reads it as a promise.
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
_DOC_SECURITY_HUB_CSPM = (
    "https://docs.aws.amazon.com/securityhub/latest/userguide/"
    "account-management-manual.html"
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
    "resource_policy_sso_role_references": 0.5,
    "resource_policy_orphaned_principals": 0.5,
    "eks_access_entry_sso_refs":    0.5,
    "eks_configmap_inspection":     0.5,
    "identity_center_applications": 0.5,
    "identity_center_coupled_services": 1.0,
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
    prism_pitch = _build_prism_pitch(identity_center, reconfig_blocks)

    return {
        "customer": _customer(assessment),
        "org": _org(assessment),
        "findings_summary": _findings_summary(assessment, non_active),
        "prism_pitch": prism_pitch,
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
    non_active_by_status: dict[str, int] = {}
    for acct in non_active:
        s = acct.get("status") or "UNKNOWN"
        non_active_by_status[s] = non_active_by_status.get(s, 0) + 1
    return {
        "total_accounts": len(accounts),
        "non_active_count": len(non_active),
        "non_active_by_status": non_active_by_status,
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


def _build_prism_pitch(ic: dict, reconfig_blocks: list[dict]) -> dict:
    """Prism is worth pitching whenever any triggered block has a Prism path.

    Two modes:
      - `sso_and_org_services`: IdC in use — Prism replaces IdC end-to-end
        AND handles the org-scoped service reconfigurations.
      - `org_services_only`: no IdC — Prism still automates the org-scoped
        service reconfigurations (CloudTrail / GuardDuty / Config / Macie)
        even without doing the SSO handoff.

    Either way, `eligible=false` when no reconfig_block has prism_covers=true
    (nothing for Prism to actually do).
    """
    prism_covered = [b for b in reconfig_blocks if b.get("prism_covers")]
    if not prism_covered:
        return {"eligible": False, "mode": None, "reason": None,
                "covered_kinds": []}

    if ic.get("enabled"):
        mode = "sso_and_org_services"
        users = ic.get("user_count") or 0
        groups = ic.get("group_count") or 0
        ps = ic.get("permission_set_count") or 0
        ass = ic.get("account_assignment_count") or 0
        region = ic.get("region") or "unknown region"
        reason = (
            f"IAM Identity Center is enabled in {region} with "
            f"{_plur(users, 'user', 'users')}, "
            f"{_plur(groups, 'group', 'groups')}, "
            f"{_plur(ps, 'permission set', 'permission sets')}, "
            f"{_plur(ass, 'account assignment', 'account assignments')}. "
            "CloudKeeper Prism replaces IdC end-to-end and also handles the "
            "org-scoped service reconfigurations automatically."
        )
    else:
        mode = "org_services_only"
        reason = (
            "CloudKeeper Prism is our self-hosted, free Org services "
            "manager. It automates the reconfiguration of the org-scoped "
            "services in one click, even without an SSO handoff."
        )

    return {
        "eligible": True,
        "mode": mode,
        "reason": reason,
        "covered_kinds": [b["kind"] for b in prism_covered],
    }


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
                    "users": ic.get("user_count") or 0,
                    "groups": ic.get("group_count") or 0,
                    "permission_sets": ic.get("permission_set_count") or 0,
                    "account_assignments": ic.get("account_assignment_count") or 0,
                },
            }
        )

    # 4.1b Enabled IdC applications — every enabled application (customer-
    # managed SAML/OAuth AND AWS-managed integrations like SageMaker Studio)
    # needs to be re-registered on the new SSO at cutover. Nothing transfers
    # automatically. Filter to `status == ENABLED` was already applied by the
    # scanner.
    enabled_apps = ic.get("enabled_applications") or []
    if enabled_apps:
        scored = sorted(
            (
                {
                    "name": app.get("name"),
                    "application_arn": app.get("application_arn"),
                    "application_provider_arn": app.get("application_provider_arn"),
                    "is_customer_managed": app.get("is_customer_managed"),
                    "assignment_required": app.get("assignment_required"),
                    "assigned_user_count": app.get("assigned_user_count") or 0,
                    "assigned_group_count": app.get("assigned_group_count") or 0,
                    "severity": _application_severity(app),
                }
                for app in enabled_apps
            ),
            key=lambda a: (
                {"high": 0, "review": 1, "medium": 2, "low": 3}.get(a["severity"], 4),
                (a["name"] or "").lower(),
            ),
        )
        blocks.append(
            {
                "kind": "identity_center_applications",
                "prism_covers": False,
                "doc_ref": None,
                "data": {
                    "application_count": len(scored),
                    "customer_managed_count": sum(
                        1 for a in scored if a.get("is_customer_managed")
                    ),
                    "high_severity_count": sum(
                        1 for a in scored if a["severity"] == _HIGH_SEVERITY
                    ),
                    "review_count": sum(
                        1 for a in scored if a["severity"] == _REVIEW_SEVERITY
                    ),
                    "high_severity_names": [
                        a["name"] for a in scored if a["severity"] == _HIGH_SEVERITY
                    ],
                    "applications": scored,
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
                "doc_ref": _DOC_SECURITY_HUB_CSPM,
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

    # 6.x Resource-policy references. Split by what the policy actually
    # references: an org/OU reference needs repointing at the new Org ID,
    # whereas a pinned `AWSReservedSSO_*` role name needs repointing at the
    # role ARNs Prism generates. Different remediation, different owner —
    # so they can't share one block.
    mor = a.get("management_account_org_references") or {}
    org_hits, sso_hits, orphan_hits = _partition_org_references(mor)

    if org_hits:
        blocks.append(
            {
                "kind": "resource_policy_org_references",
                "prism_covers": False,
                "doc_ref": None,
                "data": {
                    "services": _display_services(org_hits),
                    "total_hits": sum(org_hits.values()),
                },
            }
        )

    if sso_hits:
        # Prism generates the new role ARNs but cannot edit the customer's
        # resource policies — repointing each one is a manual / hand-off item,
        # same as the EKS access entries below. `prism_covers` stays False so
        # the email doesn't claim Prism automates it.
        blocks.append(
            {
                "kind": "resource_policy_sso_role_references",
                "prism_covers": False,
                "doc_ref": None,
                "data": {
                    "services": _display_services(sso_hits),
                    "total_hits": sum(sso_hits.values()),
                },
            }
        )

    if orphan_hits:
        blocks.append(
            {
                "kind": "resource_policy_orphaned_principals",
                "prism_covers": False,
                "doc_ref": None,
                "data": {
                    "services": _display_services(orphan_hits),
                    "total_hits": sum(orphan_hits.values()),
                },
            }
        )

    # 7.5 EKS access entries — enumerate every cluster (management + member)
    # whose access entries reference AWSReservedSSO_* roles. Different remediation
    # from ConfigMap-only clusters, so split into two blocks. Prism cannot repoint
    # EKS access entries at the new SSO role ARNs — that stays a manual / hand-off
    # item — so prism_covers is False here.
    sso_clusters, cm_clusters = _collect_eks_access_findings(a)

    if sso_clusters:
        blocks.append(
            {
                "kind": "eks_access_entry_sso_refs",
                "prism_covers": False,
                "doc_ref": None,
                "data": {
                    "cluster_count": len(sso_clusters),
                    "clusters": sso_clusters,
                },
            }
        )

    if cm_clusters:
        blocks.append(
            {
                "kind": "eks_configmap_inspection",
                "prism_covers": False,
                "doc_ref": None,
                "data": {
                    "cluster_count": len(cm_clusters),
                    "clusters": cm_clusters,
                },
            }
        )

    coupled = _collect_idc_service_findings(a)
    if coupled:
        by_service: dict[str, int] = {}
        for c in coupled:
            by_service[c["service"]] = by_service.get(c["service"], 0) + 1
        blocks.append(
            {
                "kind": "identity_center_coupled_services",
                "prism_covers": False,
                "doc_ref": None,
                "data": {
                    "resource_count": len(coupled),
                    "services": sorted(by_service),
                    "by_service": by_service,
                    "resources": coupled,
                },
            }
        )

    return blocks


def _collect_idc_service_findings(a: dict) -> list[dict]:
    """Every directly probed Identity Center-coupled resource, management and
    member accounts merged, each tagged with the account it was found in.

    These are confirmed bindings rather than inferred ones: the service was asked
    and answered. They are the blocking items in the reconfiguration list because
    the resources behind them - user profiles, home directories, saved work - do
    not survive the instance being torn down.
    """
    management_account_id = (a.get("metadata") or {}).get("management_account_id")
    found: list[dict] = []

    def collect(block, account_id):
        if not isinstance(block, dict) or not block.get("checked"):
            return
        for resource in block.get("coupled_resources") or []:
            entry = dict(resource)
            entry["account_id"] = account_id
            found.append(entry)

    collect(a.get("identity_center_services") or {}, management_account_id)
    for aid, payload in (a.get("member_accounts") or {}).items():
        if isinstance(payload, dict):
            collect(payload.get("identity_center_services") or {}, aid)
    return found


_APPLICATION_PROVIDER_SEVERITY: dict[str, str] = {
    "sagemaker": "high",
    "datazone": "high",
    "quicksight": "high",
    "quick": "high",
    "emr": "high",
    "grafana": "high",
    "monitron": "high",
    "repostspace": "high",
    "deadline": "high",
    "scn": "high",
    "iotsitewise": "high",
    "workspaces": "high",
    "workspacesweb": "high",
    "appstudio": "high",
    "transfer": "high",
    "kendra": "high",
    "workmail": "high",
    "qbusiness": "high",
    "redshift": "medium",
    "athena": "medium",
    "lakeformation": "medium",
    "s3accessgrants": "medium",
    "opensearch": "medium",
    "glue": "medium",
    "securitylake": "medium",
    "q": "medium",
    "codecatalyst": "medium",
    "ssm": "medium",
    "systemsmanager": "medium",
    "verifiedaccess": "medium",
    "eks": "medium",
    "transform": "medium",
    "kiro": "medium",
}
_APPLICATION_PROVIDER_PREFIX = "applicationprovider/"
_ACCOUNT_ASSIGNMENT_PROVIDERS = ("catalog/externalawsaccount",)

_HIGH_SEVERITY = "high"
_LOW_SEVERITY = "low"
_REVIEW_SEVERITY = "review"
_CUSTOMER_MANAGED_SEVERITY = "medium"

_ORG_MATCH_TYPES = frozenset({"org_id", "ou_id", "condition_key"})
_SSO_MATCH_TYPES = frozenset({"sso_role", "sso_role_path", "idc_instance"})
_ORPHAN_MATCH_TYPES = frozenset({"orphaned_principal"})

# `resource_policy_scanner` keys its results by internal scanner name. Those
# names go straight into customer-facing prose, so map them to how AWS spells
# the service. Anything unmapped falls back to a title-cased key.
_SERVICE_DISPLAY_NAMES = {
    "api_gateway": "API Gateway",
    "backup": "AWS Backup",
    "ecr": "ECR",
    "efs": "EFS",
    "eventbridge": "EventBridge",
    "glacier": "S3 Glacier",
    "glue": "Glue",
    "iam_policies": "IAM policies",
    "iam_roles": "IAM role trust policies",
    "kms": "KMS",
    "lakeformation": "Lake Formation",
    "lambda": "Lambda",
    "opensearch": "OpenSearch",
    "resource_tags": "Resource tags",
    "codebuild": "CodeBuild",
    "dynamodb": "DynamoDB",
    "msk": "Amazon MSK",
    "opensearch_serverless": "OpenSearch Serverless",
    "s3_access_points": "S3 access points",
    "ses_v2": "SES v2 identity policies",
    "signer": "AWS Signer",
    "codeartifact": "CodeArtifact",
    "kinesis": "Kinesis Data Streams",
    "oam": "CloudWatch cross-account observability",
    "s3tables": "S3 Tables",
    "sagemaker_model_registry": "SageMaker Model Registry",
    "vpc_lattice": "VPC Lattice",
    "s3": "S3",
    "secrets_manager": "Secrets Manager",
    "ses": "SES",
    "sns": "SNS",
    "sqs": "SQS",
    "vpc_endpoints": "VPC endpoints",
}


def _application_severity(app: dict) -> str:
    """Rank one Identity Center application by what breaks when it's torn down.

    Keyed on the last segment of `arn:aws:sso::aws:applicationProvider/<slug>`.

    "high"   — the service's own user state lives behind Identity Center.
               Re-registering does not bring it back: user profiles, home
               directories and saved work are orphaned at cutover.
    "medium" — access is Identity Center-mediated but the resources survive;
               re-registration plus re-assignment restores service. All
               customer-managed SAML/OAuth apps land here.
    "review" — AWS-managed and unrecognised, or a customer-managed SAML app whose
               name matches a high-severity service. A service can be Identity
               Center-coupled without registering under its AWS-managed provider,
               so the name is a hint worth a look, not a verdict.
    "low"    — account-assignment plumbing (catalog/ExternalAWSAccount). Rebuilt
               as part of the Identity Center migration itself, not separate work.

    The slug list is best-effort, since AWS adds and renames providers and
    publishes no enumeration, so the "review" fallback carries the weight: an
    unknown provider is never assumed benign. A silent miss is the exact failure
    this check exists to prevent.
    """
    provider_arn = (app.get("application_provider_arn") or "").strip().lower()
    _, _, slug = provider_arn.partition(_APPLICATION_PROVIDER_PREFIX)
    slug = slug.strip("/")

    if slug in _ACCOUNT_ASSIGNMENT_PROVIDERS:
        return _LOW_SEVERITY

    if app.get("is_customer_managed"):
        name = (app.get("name") or "").lower()
        if any(known in name for known, sev in _APPLICATION_PROVIDER_SEVERITY.items()
               if sev == _HIGH_SEVERITY):
            return _REVIEW_SEVERITY
        return _CUSTOMER_MANAGED_SEVERITY

    if not slug:
        return _REVIEW_SEVERITY
    if slug in _APPLICATION_PROVIDER_SEVERITY:
        return _APPLICATION_PROVIDER_SEVERITY[slug]
    for known, severity in _APPLICATION_PROVIDER_SEVERITY.items():
        if known in slug:
            return severity
    return _REVIEW_SEVERITY


def _display_services(hits: dict) -> list[str]:
    """Scanner service keys -> customer-readable names, alphabetical."""
    return sorted(
        (_SERVICE_DISPLAY_NAMES.get(k, k.replace("_", " ").title()) for k in hits),
        key=str.lower,
    )


def _partition_org_references(mor: dict) -> tuple[dict, dict, dict]:
    """Split resource-policy findings into (org_hits, sso_hits, orphan_hits).

    Returns three `{service: finding_count}` dicts. A single finding can land in
    more than one — a bucket policy that gates on `aws:PrincipalOrgID` *and*
    names an Identity Center role genuinely needs both remediations.

    Orphaned principals (`AROA…`) get their own bucket rather than joining the
    SSO one: they are already-broken references, not references that are about
    to break, and the remediation is to clean up or repoint a dead statement
    rather than to swap in a new role ARN.

    A finding whose matches carry no recognised type (or no `matches` key at
    all) still falls into the org bucket, which is where everything was reported
    before match types were distinguished.
    """
    org_hits: dict[str, int] = {}
    sso_hits: dict[str, int] = {}
    orphan_hits: dict[str, int] = {}

    for service, findings in (mor or {}).items():
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            types = {
                m.get("type")
                for m in (finding.get("matches") or [])
                if isinstance(m, dict)
            }
            is_sso = bool(types & _SSO_MATCH_TYPES)
            is_orphan = bool(types & _ORPHAN_MATCH_TYPES)
            if is_sso:
                sso_hits[service] = sso_hits.get(service, 0) + 1
            if is_orphan:
                orphan_hits[service] = orphan_hits.get(service, 0) + 1
            if (types & _ORG_MATCH_TYPES) or not (is_sso or is_orphan):
                org_hits[service] = org_hits.get(service, 0) + 1

    return org_hits, sso_hits, orphan_hits


def _collect_eks_access_findings(
    a: dict,
) -> tuple[list[dict], list[dict]]:
    """Merge management + per-member `eks_access` results into two flat lists.

    Returns `(sso_clusters, configmap_clusters)`. Each entry carries
    `account_id` (the management account for the top-level block, or the
    member account ID otherwise) so the email can attribute clusters.
    """
    m = a.get("metadata") or {}
    management_account_id = m.get("management_account_id")

    sso_clusters: list[dict] = []
    configmap_clusters: list[dict] = []

    def collect(block: dict, account_id: str | None) -> None:
        if not isinstance(block, dict) or not block.get("checked"):
            return
        for c in block.get("clusters_with_sso_access_entries") or []:
            entry = dict(c)
            entry["account_id"] = account_id
            sso_clusters.append(entry)
        for c in block.get("clusters_needing_configmap_inspection") or []:
            entry = dict(c)
            entry["account_id"] = account_id
            configmap_clusters.append(entry)

    collect(a.get("eks_access") or {}, management_account_id)
    for aid, payload in (a.get("member_accounts") or {}).items():
        if isinstance(payload, dict):
            collect(payload.get("eks_access") or {}, aid)

    sso_clusters.sort(
        key=lambda c: (c.get("account_id") or "", c.get("region") or "", c.get("cluster_name") or "")
    )
    configmap_clusters.sort(
        key=lambda c: (c.get("account_id") or "", c.get("region") or "", c.get("cluster_name") or "")
    )
    return sso_clusters, configmap_clusters


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

    # `human_summary` is reproduced verbatim in the email body, so it has to
    # already obey the drafting rules: natural singular/plural, no "(s)", no
    # em-dashes.
    parts: list[str] = []
    if blocks:
        parts.append(
            f"{_plur(len(blocks), 'reconfiguration item', 'reconfiguration items')}"
            f" - estimated {_fmt_days(low)}-{_fmt_days(high)} business days."
        )
    else:
        parts.append("No technical reconfiguration required.")
    if reinstate_count:
        parts.append(
            "Reinstating "
            f"{_plur(reinstate_count, 'closed/suspended account', 'closed/suspended accounts')}"
            " is handled by AWS Support (typically "
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


def _plur(n: int, singular: str, plural: str) -> str:
    return f"{n} {singular if n == 1 else plural}"


def _round_half(x: float) -> float:
    return round(x * 2) / 2


def _fmt_days(x: float) -> str:
    return str(int(x)) if x == int(x) else f"{x:.1f}"
