"""Per-service deep dives for accounts that are delegated administrators.

Only invoked when an account appears in `delegated_admins` with at least
one service. The orchestrator passes the list of service principals this
account manages, and we dispatch to the right handler.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.pagination import paginate, paginate_with_token
from cloudkeeper_preflight.util.principal import short_service_name


def assess_delegated_services(
    member_session,
    delegated_services: list[str],
    regions: list[str],
) -> tuple[dict, list[dict]]:
    results: dict = {}
    errors: list[dict] = []
    unhandled: list[str] = []

    for principal in delegated_services or []:
        handler = _HANDLERS.get(principal)
        if handler is None:
            unhandled.append(principal)
            continue
        try:
            results[principal] = handler(member_session, regions)
        except ClientError as exc:
            errors.append(_err(principal, "handler", exc))
            results[principal] = {}
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(
                {
                    "module": "delegated_services",
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


def _check_guardduty(session, regions: list[str]) -> dict:
    def per_region(region: str) -> dict:
        client = create_client("guardduty", region=region, session=session)
        out: dict = {"region": region, "detectors": [], "members": [], "auto_enable": None}
        try:
            ids = client.list_detectors().get("DetectorIds", [])
        except ClientError:
            return out
        for did in ids:
            try:
                detail = client.get_detector(DetectorId=did)
                out["detectors"].append(
                    {
                        "detector_id": did,
                        "status": detail.get("Status"),
                        "features": detail.get("Features", []),
                    }
                )
            except ClientError:
                continue
            try:
                members = paginate_with_token(
                    client, "list_members", "Members", DetectorId=did
                )
                out["members"].extend(
                    {
                        "detector_id": did,
                        "account_id": m.get("AccountId"),
                        "relationship_status": m.get("RelationshipStatus"),
                        "email": m.get("Email"),
                    }
                    for m in members
                )
            except ClientError:
                pass
            try:
                config = client.get_organization_configuration(DetectorId=did)
                out["auto_enable"] = config.get("AutoEnable")
            except ClientError:
                pass
        return out

    return {"by_region": _fanout(regions, per_region)}


def _check_securityhub(session, regions: list[str]) -> dict:
    def per_region(region: str) -> dict:
        client = create_client("securityhub", region=region, session=session)
        out: dict = {"region": region, "enabled": False, "members": [], "standards": []}
        try:
            client.describe_hub()
            out["enabled"] = True
        except ClientError:
            return out
        try:
            members = paginate_with_token(client, "list_members", "Members")
            out["members"] = [
                {
                    "account_id": m.get("AccountId"),
                    "email": m.get("Email"),
                    "member_status": m.get("MemberStatus"),
                }
                for m in members
            ]
        except ClientError:
            pass
        try:
            standards = client.get_enabled_standards().get("StandardsSubscriptions", [])
            out["standards"] = [
                {
                    "standards_arn": s.get("StandardsArn"),
                    "standards_status": s.get("StandardsStatus"),
                }
                for s in standards
            ]
        except ClientError:
            pass
        return out

    return {"by_region": _fanout(regions, per_region)}


def _check_inspector2(session, regions: list[str]) -> dict:
    client = create_client("inspector2", region="us-east-1", session=session)
    out: dict = {}
    try:
        config = client.describe_organization_configuration()
        out["auto_enable"] = config.get("autoEnable")
        out["max_account_limit_reached"] = config.get("maxAccountLimitReached")
    except ClientError:
        pass
    try:
        statuses = client.batch_get_account_status().get("accounts", [])
        out["account_statuses"] = [
            {"account_id": s.get("accountId"), "state": s.get("state"), "resource_state": s.get("resourceState")}
            for s in statuses
        ]
    except ClientError:
        out["account_statuses"] = []
    return out


def _check_macie(session, regions: list[str]) -> dict:
    def per_region(region: str) -> dict:
        client = create_client("macie2", region=region, session=session)
        out: dict = {"region": region, "members": [], "auto_enable": None}
        try:
            members = paginate_with_token(client, "list_members", "members")
            out["members"] = [
                {
                    "account_id": m.get("accountId"),
                    "relationship_status": m.get("relationshipStatus"),
                    "email": m.get("email"),
                }
                for m in members
            ]
        except ClientError:
            pass
        try:
            config = client.describe_organization_configuration()
            out["auto_enable"] = config.get("autoEnable")
        except ClientError:
            pass
        return out

    return {"by_region": _fanout(regions, per_region)}


def _check_config(session, regions: list[str]) -> dict:
    def per_region(region: str) -> dict:
        client = create_client("config", region=region, session=session)
        out: dict = {"region": region, "rules": [], "conformance_packs": [], "aggregators": []}
        try:
            rules = paginate(
                client,
                "describe_organization_config_rules",
                "OrganizationConfigRules",
            )
            out["rules"] = [
                {
                    "name": r.get("OrganizationConfigRuleName"),
                    "arn": r.get("OrganizationConfigRuleArn"),
                }
                for r in rules
            ]
        except ClientError:
            pass
        try:
            packs = paginate(
                client,
                "describe_organization_conformance_packs",
                "OrganizationConformancePacks",
            )
            out["conformance_packs"] = [
                {
                    "name": p.get("OrganizationConformancePackName"),
                    "arn": p.get("OrganizationConformancePackArn"),
                }
                for p in packs
            ]
        except ClientError:
            pass
        try:
            aggs = paginate(
                client,
                "describe_configuration_aggregators",
                "ConfigurationAggregators",
            )
            out["aggregators"] = [
                {
                    "name": a.get("ConfigurationAggregatorName"),
                    "arn": a.get("ConfigurationAggregatorArn"),
                }
                for a in aggs
            ]
        except ClientError:
            pass
        return out

    return {"by_region": _fanout(regions, per_region)}


def _check_fms(session, regions: list[str]) -> dict:
    client = create_client("fms", region="us-east-1", session=session)
    out: dict = {"policies": [], "member_accounts": []}
    try:
        policies = paginate(client, "list_policies", "PolicyList")
        out["policies"] = [
            {
                "policy_id": p.get("PolicyId"),
                "policy_name": p.get("PolicyName"),
                "resource_type": p.get("ResourceType"),
            }
            for p in policies
        ]
    except ClientError:
        pass
    try:
        members = paginate_with_token(
            client, "list_member_accounts", "MemberAccounts"
        )
        out["member_accounts"] = list(members)
    except ClientError:
        pass
    return out


def _check_audit_manager(session, regions: list[str]) -> dict:
    def per_region(region: str) -> dict:
        client = create_client("auditmanager", region=region, session=session)
        try:
            settings = client.get_settings(attribute="ALL")
            return {"region": region, "settings": settings.get("settings", {})}
        except ClientError:
            return {"region": region, "settings": {}}

    return {"by_region": _fanout(regions, per_region)}


def _check_detective(session, regions: list[str]) -> dict:
    def per_region(region: str) -> dict:
        client = create_client("detective", region=region, session=session)
        out: dict = {"region": region, "graphs": []}
        try:
            graphs = paginate_with_token(client, "list_graphs", "GraphList")
        except ClientError:
            return out
        for g in graphs:
            graph_arn = g.get("Arn")
            members: list[dict] = []
            try:
                raw_members = paginate_with_token(
                    client,
                    "list_members",
                    "MemberDetails",
                    GraphArn=graph_arn,
                )
                members = [
                    {
                        "account_id": m.get("AccountId"),
                        "email": m.get("EmailAddress"),
                        "status": m.get("Status"),
                    }
                    for m in raw_members
                ]
            except ClientError:
                pass
            out["graphs"].append({"arn": graph_arn, "members": members})
        return out

    return {"by_region": _fanout(regions, per_region)}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


_HandlerType = Callable[[object, list[str]], dict]

_HANDLERS: dict[str, _HandlerType] = {
    "guardduty.amazonaws.com": _check_guardduty,
    "securityhub.amazonaws.com": _check_securityhub,
    "inspector2.amazonaws.com": _check_inspector2,
    "macie.amazonaws.com": _check_macie,
    "config.amazonaws.com": _check_config,
    "config-multiaccountsetup.amazonaws.com": _check_config,
    "fms.amazonaws.com": _check_fms,
    "auditmanager.amazonaws.com": _check_audit_manager,
    "detective.amazonaws.com": _check_detective,
}


def _fanout(regions: list[str], fn: Callable[[str], dict]) -> list[dict]:
    if not regions:
        return []
    workers = min(len(regions), 6)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        return list(executor.map(fn, regions))


def _err(service_principal: str, operation: str, exc: ClientError) -> dict:
    return {
        "module": "delegated_services",
        "service": short_service_name(service_principal),
        "service_principal": service_principal,
        "operation": operation,
        "code": exc.response.get("Error", {}).get("Code", "ClientError"),
        "message": str(exc),
    }
