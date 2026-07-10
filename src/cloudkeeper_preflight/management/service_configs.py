"""Per-service configuration probes for trusted-access services.

Registry pattern: `_HANDLERS` maps a service principal to a callable that
returns a service-specific dict. Service principals not in the registry land
in `unhandled_services` so we can spot AWS adding new ones.

Each handler returns a dict; on failure it appends an entry to `errors` (a
list passed by reference) rather than raising. Failures should not poison
the rest of the assessment.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.pagination import paginate, paginate_with_token
from cloudkeeper_preflight.util.principal import short_service_name


def assess_service_configs(
    trusted_services: list[dict],
    regions: list[str],
    session=None,
) -> tuple[dict, list[dict]]:
    results: dict = {}
    errors: list[dict] = []
    unhandled: list[str] = []

    for svc in trusted_services or []:
        principal = svc.get("service_principal")
        handler = _HANDLERS.get(principal)
        if handler is None:
            unhandled.append(principal)
            continue
        try:
            results[principal] = handler(regions, session)
        except ClientError as exc:
            errors.append(_err(principal, "handler", exc))
            results[principal] = {}
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(
                {
                    "module": "service_configs",
                    "service_principal": principal,
                    "operation": "handler",
                    "code": exc.__class__.__name__,
                    "message": str(exc),
                }
            )
            results[principal] = {}

    results["unhandled_services"] = sorted(unhandled)
    return results, errors


# --------------------------------------------------------------------------
# Handlers
# --------------------------------------------------------------------------


def _check_cloudtrail(regions: list[str], session) -> dict:
    client = create_client("cloudtrail", region="us-east-1", session=session)
    trails = client.describe_trails().get("trailList", [])
    org_trails = []
    for t in trails:
        if t.get("IsOrganizationTrail"):
            org_trails.append(
                {
                    "name": t.get("Name"),
                    "trail_arn": t.get("TrailARN"),
                    "s3_bucket": t.get("S3BucketName"),
                    "s3_key_prefix": t.get("S3KeyPrefix"),
                    "kms_key_id": t.get("KmsKeyId"),
                    "cloudwatch_log_group": t.get("CloudWatchLogsLogGroupArn"),
                    "home_region": t.get("HomeRegion"),
                    "is_multi_region": t.get("IsMultiRegionTrail", False),
                    "include_global_service_events": t.get(
                        "IncludeGlobalServiceEvents", False
                    ),
                }
            )
    return {"organization_trails": org_trails}


def _check_guardduty(regions: list[str], session) -> dict:
    def per_region(region: str) -> dict:
        client = create_client("guardduty", region=region, session=session)
        try:
            detector_ids = client.list_detectors().get("DetectorIds", [])
        except ClientError:
            return {"region": region, "detectors": []}
        detectors = []
        for did in detector_ids:
            try:
                detail = client.get_detector(DetectorId=did)
                detectors.append(
                    {
                        "detector_id": did,
                        "status": detail.get("Status"),
                        "finding_publishing_frequency": detail.get(
                            "FindingPublishingFrequency"
                        ),
                        "features": detail.get("Features", []),
                    }
                )
            except ClientError:
                detectors.append({"detector_id": did, "status": None})
        return {"region": region, "detectors": detectors}

    org_admins: list[dict] = []
    org_client = create_client("guardduty", region="us-east-1", session=session)
    try:
        admins = paginate(
            org_client, "list_organization_admin_accounts", "AdminAccounts"
        )
        org_admins = [
            {"account_id": a.get("AdminAccountId"), "status": a.get("AdminStatus")}
            for a in admins
        ]
    except ClientError:
        pass

    return {
        "detectors_by_region": _fanout_regions(regions, per_region),
        "admin_accounts": org_admins,
    }


def _check_securityhub(regions: list[str], session) -> dict:
    def per_region(region: str) -> dict:
        client = create_client("securityhub", region=region, session=session)
        info: dict = {
            "region": region,
            "enabled": False,
            "enabled_standards": [],
            "finding_aggregators": [],
        }
        try:
            hub = client.describe_hub()
            info["enabled"] = True
            info["hub_arn"] = hub.get("HubArn")
            info["subscribed_at"] = (
                hub.get("SubscribedAt").isoformat()
                if hub.get("SubscribedAt") and not isinstance(hub["SubscribedAt"], str)
                else hub.get("SubscribedAt")
            )
            info["auto_enable_controls"] = hub.get("AutoEnableControls")
        except ClientError:
            # Hub not enabled here — skip standards / aggregators, they'd 400.
            return info

        # CSPM signal #1: which security standards (AWS FSBP, CIS, PCI-DSS,
        # NIST 800-53, etc.) are actually being enforced in this region.
        try:
            standards = paginate(
                client, "get_enabled_standards", "StandardsSubscriptions"
            )
            info["enabled_standards"] = [
                {
                    "standards_arn": s.get("StandardsArn"),
                    "standards_subscription_arn": s.get("StandardsSubscriptionArn"),
                    "status": s.get("StandardsStatus"),
                }
                for s in standards
            ]
        except ClientError:
            pass

        # CSPM signal #2: cross-region finding aggregators. Presence here
        # means the org is treating Security Hub as its CSPM aggregation
        # point, not just as a per-account tool.
        try:
            aggs = paginate(
                client, "list_finding_aggregators", "FindingAggregators"
            )
            for a in aggs:
                arn = a.get("FindingAggregatorArn")
                entry: dict = {"finding_aggregator_arn": arn}
                try:
                    detail = client.get_finding_aggregator(FindingAggregatorArn=arn)
                    entry.update(
                        {
                            "aggregation_region": detail.get("FindingAggregationRegion"),
                            "region_linking_mode": detail.get("RegionLinkingMode"),
                            "regions": detail.get("Regions") or [],
                        }
                    )
                except ClientError:
                    pass
                info["finding_aggregators"].append(entry)
        except ClientError:
            pass

        return info

    org_admins: list[dict] = []
    org_client = create_client("securityhub", region="us-east-1", session=session)
    try:
        admins = paginate(
            org_client, "list_organization_admin_accounts", "AdminAccounts"
        )
        org_admins = [
            {"account_id": a.get("AdminAccountId"), "status": a.get("Status")}
            for a in admins
        ]
    except ClientError:
        pass

    hubs_by_region = _fanout_regions(regions, per_region)

    # Roll-up CSPM flags — cheap for consumers (the email summariser) and
    # keeps the "is CSPM in use?" question a one-line check.
    cspm_active = any(
        (h.get("enabled_standards") or []) or (h.get("finding_aggregators") or [])
        for h in hubs_by_region
    )

    return {
        "hubs_by_region": hubs_by_region,
        "admin_accounts": org_admins,
        "cspm_active": cspm_active,
    }


def _check_config(regions: list[str], session) -> dict:
    def per_region(region: str) -> dict:
        client = create_client("config", region=region, session=session)
        rules: list[dict] = []
        packs: list[dict] = []
        try:
            raw_rules = paginate(
                client, "describe_organization_config_rules", "OrganizationConfigRules"
            )
            rules = [
                {
                    "name": r.get("OrganizationConfigRuleName"),
                    "arn": r.get("OrganizationConfigRuleArn"),
                    "excluded_accounts": r.get("ExcludedAccounts", []),
                    "last_update_time": _iso(r.get("LastUpdateTime")),
                }
                for r in raw_rules
            ]
        except ClientError:
            pass
        try:
            raw_packs = paginate(
                client,
                "describe_organization_conformance_packs",
                "OrganizationConformancePacks",
            )
            packs = [
                {
                    "name": p.get("OrganizationConformancePackName"),
                    "arn": p.get("OrganizationConformancePackArn"),
                    "delivery_s3_bucket": p.get("DeliveryS3Bucket"),
                }
                for p in raw_packs
            ]
        except ClientError:
            pass
        return {"region": region, "rules": rules, "conformance_packs": packs}

    return {"by_region": _fanout_regions(regions, per_region)}


def _check_inspector2(regions: list[str], session) -> dict:
    client = create_client("inspector2", region="us-east-1", session=session)
    try:
        config = client.describe_organization_configuration()
        return {
            "auto_enable": config.get("autoEnable"),
            "max_account_limit_reached": config.get("maxAccountLimitReached"),
        }
    except ClientError:
        return {}


def _check_macie(regions: list[str], session) -> dict:
    def per_region(region: str) -> dict:
        client = create_client("macie2", region=region, session=session)
        try:
            org_config = client.describe_organization_configuration()
            return {
                "region": region,
                "auto_enable": org_config.get("autoEnable"),
                "max_account_limit_reached": org_config.get("maxAccountLimitReached"),
            }
        except ClientError:
            return {"region": region, "enabled": False}

    return {"by_region": _fanout_regions(regions, per_region)}


def _check_fms(regions: list[str], session) -> dict:
    client = create_client("fms", region="us-east-1", session=session)
    info: dict = {}
    try:
        admin = client.get_admin_account()
        info["admin_account"] = admin.get("AdminAccount")
        info["role_status"] = admin.get("RoleStatus")
    except ClientError:
        pass
    try:
        policies = paginate(client, "list_policies", "PolicyList")
        info["policies"] = [
            {
                "policy_arn": p.get("PolicyArn"),
                "policy_id": p.get("PolicyId"),
                "policy_name": p.get("PolicyName"),
                "resource_type": p.get("ResourceType"),
                "security_service_type": (p.get("SecurityServiceType") or {})
                if isinstance(p.get("SecurityServiceType"), str)
                else p.get("SecurityServiceType"),
            }
            for p in policies
        ]
    except ClientError:
        info["policies"] = []
    return info


def _check_access_analyzer(regions: list[str], session) -> dict:
    def per_region(region: str) -> dict:
        client = create_client("accessanalyzer", region=region, session=session)
        try:
            analyzers = paginate(
                client, "list_analyzers", "analyzers", type="ORGANIZATION"
            )
            return {
                "region": region,
                "analyzers": [
                    {
                        "name": a.get("name"),
                        "arn": a.get("arn"),
                        "status": a.get("status"),
                        "last_resource_analyzed": a.get("lastResourceAnalyzed"),
                        "last_resource_analyzed_at": _iso(
                            a.get("lastResourceAnalyzedAt")
                        ),
                    }
                    for a in analyzers
                ],
            }
        except ClientError:
            return {"region": region, "analyzers": []}

    return {"by_region": _fanout_regions(regions, per_region)}


def _check_backup(regions: list[str], session) -> dict:
    client = create_client("backup", region="us-east-1", session=session)
    try:
        settings = client.describe_global_settings()
        return {"global_settings": settings.get("GlobalSettings", {})}
    except ClientError:
        return {}


def _check_ssm(regions: list[str], session) -> dict:
    client = create_client("ssm", region="us-east-1", session=session)
    setting_ids = (
        "/ssm/managed-instance/default-ec2-instance-management-role",
        "/ssm/automation/customer-script-log-destination",
        "/ssm/parameter-store/high-throughput-enabled",
    )
    out: list[dict] = []
    for sid in setting_ids:
        try:
            response = client.get_service_setting(SettingId=sid)
            ss = response.get("ServiceSetting", {})
            out.append(
                {
                    "setting_id": sid,
                    "value": ss.get("SettingValue"),
                    "status": ss.get("Status"),
                    "last_modified": _iso(ss.get("LastModifiedDate")),
                }
            )
        except ClientError:
            out.append({"setting_id": sid, "value": None})
    return {"service_settings": out}


def _check_detective(regions: list[str], session) -> dict:
    def per_region(region: str) -> dict:
        client = create_client("detective", region=region, session=session)
        graphs: list[dict] = []
        admins: list[dict] = []
        try:
            for g in paginate_with_token(client, "list_graphs", "GraphList"):
                graphs.append({"arn": g.get("Arn"), "created_time": _iso(g.get("CreatedTime"))})
        except ClientError:
            pass
        try:
            for a in paginate_with_token(
                client, "list_organization_admin_accounts", "Administrators"
            ):
                admins.append(
                    {"account_id": a.get("AccountId"), "graph_arn": a.get("GraphArn")}
                )
        except ClientError:
            pass
        return {"region": region, "graphs": graphs, "admin_accounts": admins}

    return {"by_region": _fanout_regions(regions, per_region)}


def _check_compute_optimizer(regions: list[str], session) -> dict:
    client = create_client("compute-optimizer", region="us-east-1", session=session)
    try:
        status = client.get_enrollment_status()
        return {
            "status": status.get("status"),
            "status_reason": status.get("statusReason"),
            "member_accounts_enrolled": status.get("memberAccountsEnrolled"),
        }
    except ClientError:
        return {}


def _check_health(regions: list[str], session) -> dict:
    client = create_client("health", region="us-east-1", session=session)
    try:
        status = client.describe_health_service_status_for_organization()
        return {"status": status.get("healthServiceAccessStatusForOrganization")}
    except ClientError:
        return {}


def _check_license_manager(regions: list[str], session) -> dict:
    client = create_client("license-manager", region="us-east-1", session=session)
    try:
        settings = client.get_service_settings()
        return {
            "organization_configuration": settings.get("OrganizationConfiguration"),
            "s3_bucket_arn": settings.get("S3BucketArn"),
            "sns_topic_arn": settings.get("SnsTopicArn"),
            "enable_cross_accounts_discovery": settings.get(
                "EnableCrossAccountsDiscovery"
            ),
        }
    except ClientError:
        return {}


def _check_ipam(regions: list[str], session) -> dict:
    def per_region(region: str) -> dict:
        client = create_client("ec2", region=region, session=session)
        try:
            ipams = paginate(client, "describe_ipams", "Ipams")
            return {
                "region": region,
                "ipams": [
                    {
                        "ipam_id": i.get("IpamId"),
                        "ipam_arn": i.get("IpamArn"),
                        "tier": i.get("Tier"),
                        "default_resource_discovery_id": i.get(
                            "DefaultResourceDiscoveryId"
                        ),
                        "operating_regions": [
                            r.get("RegionName") for r in i.get("OperatingRegions", [])
                        ],
                    }
                    for i in ipams
                ],
            }
        except ClientError:
            return {"region": region, "ipams": []}

    return {"by_region": _fanout_regions(regions, per_region)}


def _check_audit_manager(regions: list[str], session) -> dict:
    def per_region(region: str) -> dict:
        client = create_client("auditmanager", region=region, session=session)
        try:
            admin = client.get_organization_admin_account()
            return {
                "region": region,
                "admin_account_id": admin.get("adminAccountId"),
                "organization_id": admin.get("organizationId"),
            }
        except ClientError:
            return {"region": region, "admin_account_id": None}

    return {"by_region": _fanout_regions(regions, per_region)}


def _check_service_catalog(regions: list[str], session) -> dict:
    def per_region(region: str) -> dict:
        client = create_client("servicecatalog", region=region, session=session)
        try:
            portfolios = paginate_with_token(
                client, "list_portfolios", "PortfolioDetails", token_key="PageToken"
            )
            return {
                "region": region,
                "portfolios": [
                    {
                        "id": p.get("Id"),
                        "arn": p.get("ARN"),
                        "name": p.get("DisplayName"),
                        "provider_name": p.get("ProviderName"),
                    }
                    for p in portfolios
                ],
            }
        except ClientError:
            return {"region": region, "portfolios": []}

    return {"by_region": _fanout_regions(regions, per_region)}


def _check_devops_guru(regions: list[str], session) -> dict:
    def per_region(region: str) -> dict:
        client = create_client("devops-guru", region=region, session=session)
        try:
            health = client.describe_organization_health()
            return {
                "region": region,
                "open_reactive_insights": health.get("OpenReactiveInsights"),
                "open_proactive_insights": health.get("OpenProactiveInsights"),
                "metrics_analyzed": health.get("MetricsAnalyzed"),
                "resource_hours": health.get("ResourceHours"),
            }
        except ClientError:
            return {"region": region, "enabled": False}

    return {"by_region": _fanout_regions(regions, per_region)}


def _check_storage_lens(regions: list[str], session) -> dict:
    sts = create_client("sts", session=session)
    try:
        account_id = sts.get_caller_identity()["Account"]
    except ClientError:
        return {}
    client = create_client("s3control", region="us-east-1", session=session)
    try:
        items: list[dict] = []
        token = None
        while True:
            kwargs = {"AccountId": account_id}
            if token:
                kwargs["NextToken"] = token
            response = client.list_storage_lens_configurations(**kwargs)
            items.extend(response.get("StorageLensConfigurationList", []))
            token = response.get("NextToken")
            if not token:
                break
        return {
            "configurations": [
                {
                    "id": c.get("Id"),
                    "arn": c.get("StorageLensArn"),
                    "home_region": c.get("HomeRegion"),
                    "is_enabled": c.get("IsEnabled"),
                }
                for c in items
            ]
        }
    except ClientError:
        return {}


def _check_trusted_advisor(regions: list[str], session) -> dict:
    client = create_client(
        "trustedadvisor", region="us-east-1", session=session
    )
    try:
        recs = paginate(
            client,
            "list_organization_recommendations",
            "organizationRecommendationSummaries",
        )
        return {
            "recommendations": [
                {
                    "id": r.get("id"),
                    "arn": r.get("arn"),
                    "name": r.get("name"),
                    "status": r.get("status"),
                    "type": r.get("type"),
                }
                for r in recs[:200]
            ],
            "total_recommendations": len(recs),
        }
    except ClientError:
        return {}


def _check_cost_optimization_hub(regions: list[str], session) -> dict:
    client = create_client(
        "cost-optimization-hub", region="us-east-1", session=session
    )
    try:
        prefs = client.get_preferences()
        return {
            "savings_estimation_mode": prefs.get("savingsEstimationMode"),
            "member_account_discount_visibility": prefs.get(
                "memberAccountDiscountVisibility"
            ),
        }
    except ClientError:
        return {}


def _check_account(regions: list[str], session) -> dict:
    client = create_client("account", region="us-east-1", session=session)
    try:
        items = paginate(client, "list_regions", "Regions")
        return {
            "regions": [
                {
                    "region": r.get("RegionName"),
                    "opt_status": r.get("RegionOptStatus"),
                }
                for r in items
            ]
        }
    except ClientError:
        return {}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


_HANDlerType = Callable[[list[str], object], dict]

_HANDLERS: dict[str, _HANDlerType] = {
    "cloudtrail.amazonaws.com": _check_cloudtrail,
    "guardduty.amazonaws.com": _check_guardduty,
    "securityhub.amazonaws.com": _check_securityhub,
    "config.amazonaws.com": _check_config,
    "config-multiaccountsetup.amazonaws.com": _check_config,
    "inspector2.amazonaws.com": _check_inspector2,
    "macie.amazonaws.com": _check_macie,
    "fms.amazonaws.com": _check_fms,
    "access-analyzer.amazonaws.com": _check_access_analyzer,
    "backup.amazonaws.com": _check_backup,
    "ssm.amazonaws.com": _check_ssm,
    "detective.amazonaws.com": _check_detective,
    "compute-optimizer.amazonaws.com": _check_compute_optimizer,
    "health.amazonaws.com": _check_health,
    "license-manager.amazonaws.com": _check_license_manager,
    "ipam.amazonaws.com": _check_ipam,
    "auditmanager.amazonaws.com": _check_audit_manager,
    "servicecatalog.amazonaws.com": _check_service_catalog,
    "devops-guru.amazonaws.com": _check_devops_guru,
    "storage-lens.s3.amazonaws.com": _check_storage_lens,
    "reporting.trustedadvisor.amazonaws.com": _check_trusted_advisor,
    "cost-optimization-hub.bcm.amazonaws.com": _check_cost_optimization_hub,
    "account.amazonaws.com": _check_account,
}


def _fanout_regions(
    regions: list[str], fn: Callable[[str], dict]
) -> list[dict]:
    if not regions:
        return []
    workers = min(len(regions), 6)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        return list(executor.map(fn, regions))


def _iso(value):
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _err(service_principal: str, operation: str, exc: ClientError) -> dict:
    return {
        "module": "service_configs",
        "service": short_service_name(service_principal),
        "service_principal": service_principal,
        "operation": operation,
        "code": exc.response.get("Error", {}).get("Code", "ClientError"),
        "message": str(exc),
    }
