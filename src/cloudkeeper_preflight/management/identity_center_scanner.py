"""Probe Identity Center-coupled services directly, per account and per Region.

Used in Phase 1 (management account) and Phase 3 (member accounts), with the
session swapped to point at the right credentials.

These services bind to the Identity Center *instance*, not to an
`AWSReservedSSO_*` role ARN, so no amount of policy scanning finds them — the
service has to be asked. That is what this module does, and it is the difference
between "no SSO references found" and knowing a SageMaker Studio domain full of
user profiles dies at cutover.

Output shape:
    {
      "checked": True,
      "services_scanned": <int>,
      "coupled_resources": [ {region, service, resource, arn, signals, matches} ],
    }

A resource counts as coupled when its own description carries an Identity Center
identifier (`ssoins-`, `apl-`, `d-…`, an `AWSReservedSSO_*` name), or when it
carries one of the explicit auth-mode markers below, or when the service cannot
exist without Identity Center at all. Reading the whole description rather than
one named field means a renamed or newly added binding field still trips the
check instead of silently reading clean.

Failures land in the shared errors list following the standard scanner contract;
`_partition_errors` in `output.py` classifies them into access-denied / throttles
/ real errors, so a missing permission is reported rather than read as absence.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.org_id_matcher import OrgIdMatcher
from cloudkeeper_preflight.util.pagination import paginate

_REGION_PARALLELISM = 6
_PER_SERVICE_PARALLELISM = 4
_MAX_RESOURCES_PER_SERVICE = 200

_ABSENT_CODES = (
    "ResourceNotFoundException",
    "ResourceNotFound",
    "EntityNotFoundException",
    "NotFoundException",
    "InvalidRequestException",
    "ValidationException",
    "SubscriptionNotFoundException",
)


class _Probe:
    """One service's enumerate-then-describe recipe."""

    def __init__(
        self,
        service,
        client,
        describe_op,
        *,
        list_op=None,
        list_key=None,
        id_field=None,
        describe_arg=None,
        describe_key=None,
        name_field=None,
        arn_field=None,
        signals=(),
        always_coupled=False,
    ):
        self.service = service
        self.client = client
        self.list_op = list_op
        self.list_key = list_key
        self.id_field = id_field
        self.describe_op = describe_op
        self.describe_arg = describe_arg
        self.describe_key = describe_key
        self.name_field = name_field or id_field
        self.arn_field = arn_field
        self.signals = signals
        self.always_coupled = always_coupled


_PROBES: tuple[_Probe, ...] = (
    _Probe("quicksight", "quicksight", "describe_account_subscription",
           describe_key="AccountInfo", name_field="AccountName",
           signals=('"AuthenticationType": "IAM_IDENTITY_CENTER"',)),
    _Probe("sagemaker_studio", "sagemaker", "describe_domain",
           list_op="list_domains", list_key="Domains", id_field="DomainId",
           describe_arg="DomainId", name_field="DomainName", arn_field="DomainArn",
           signals=('"AuthMode": "SSO"',)),
    _Probe("emr_studio", "emr", "describe_studio",
           list_op="list_studios", list_key="Studios", id_field="StudioId",
           describe_arg="StudioId", describe_key="Studio",
           name_field="Name", arn_field="StudioArn",
           signals=('"AuthMode": "SSO"', '"AuthMode": "IAM_IDENTITY_CENTER"')),
    _Probe("managed_grafana", "grafana", "describe_workspace",
           list_op="list_workspaces", list_key="workspaces", id_field="id",
           describe_arg="workspaceId", describe_key="workspace",
           name_field="name", signals=('"AWS_SSO"',)),
    _Probe("datazone", "datazone", "get_domain",
           list_op="list_domains", list_key="items", id_field="id",
           describe_arg="identifier", name_field="name", arn_field="arn",
           signals=('"IAM_IDC"',)),
    _Probe("athena_workgroups", "athena", "get_work_group",
           list_op="list_work_groups", list_key="WorkGroups", id_field="Name",
           describe_arg="WorkGroup", describe_key="WorkGroup", name_field="Name"),
    _Probe("workspaces_web", "workspaces-web", "get_portal",
           list_op="list_portals", list_key="portals", id_field="portalArn",
           describe_arg="portalArn", describe_key="portal",
           name_field="displayName", arn_field="portalArn",
           signals=('"IAM_Identity_Center"',)),
    _Probe("repostspace", "repostspace", "get_space",
           list_op="list_spaces", list_key="spaces", id_field="spaceId",
           describe_arg="spaceId", name_field="name", arn_field="arn",
           always_coupled=True),
    _Probe("supply_chain", "supplychain", "get_instance",
           list_op="list_instances", list_key="instances", id_field="instanceId",
           describe_arg="instanceId", describe_key="instance",
           name_field="instanceName", always_coupled=True),
    _Probe("thin_client", "workspaces-thin-client", "get_environment",
           list_op="list_environments", list_key="environments", id_field="id",
           describe_arg="identifier", describe_key="environment",
           name_field="name", arn_field="arn", always_coupled=True),
    _Probe("q_business", "qbusiness", "get_data_accessor",
           list_op="list_data_accessors", list_key="dataAccessors",
           id_field="dataAccessorId", describe_arg="dataAccessorId",
           name_field="displayName", arn_field="dataAccessorArn"),
    _Probe("iot_twinmaker", "iottwinmaker", "get_workspace",
           list_op="list_workspaces", list_key="workspaceSummaries",
           id_field="workspaceId", describe_arg="workspaceId",
           name_field="workspaceId", arn_field="arn"),
    _Probe("mwaa", "mwaa", "get_environment",
           list_op="list_environments", list_key="Environments",
           describe_arg="Name", describe_key="Environment",
           name_field="Name", arn_field="Arn"),
    _Probe("redshift_idc", "redshift", "describe_redshift_idc_applications",
           describe_key="RedshiftIdcApplications", always_coupled=True),
    _Probe("workspaces_directories", "workspaces", "describe_workspace_directories",
           describe_key="Directories",
           signals=('"AWS_IAM_IDENTITY_CENTER"',)),
    _Probe("deadline_cloud", "deadline", "list_monitors",
           describe_key="monitors", always_coupled=True),
    _Probe("iot_sitewise_monitor", "iotsitewise", "describe_portal",
           list_op="list_portals", list_key="portalSummaries", id_field="id",
           describe_arg="portalId", name_field="portalName", arn_field="portalArn",
           signals=('"portalAuthMode": "SSO"',)),
    _Probe("kendra", "kendra", "describe_index",
           list_op="list_indices", list_key="IndexConfigurationSummaryItems",
           id_field="Id", describe_arg="Id", name_field="Name",
           signals=('"AWS_SSO"',)),
    _Probe("workmail", "workmail", "describe_organization",
           list_op="list_organizations", list_key="OrganizationSummaries",
           id_field="OrganizationId", describe_arg="OrganizationId",
           name_field="Alias"),
    _Probe("transfer_web_apps", "transfer", "describe_web_app",
           list_op="list_web_apps", list_key="WebApps", id_field="WebAppId",
           describe_arg="WebAppId", describe_key="WebApp", arn_field="Arn"),
)


def scan_identity_center_services(
    regions: list[str],
    matcher: OrgIdMatcher,
    session=None,
) -> tuple[dict, list[dict]]:
    result: dict = {
        "checked": True,
        "services_scanned": 0,
        "coupled_resources": [],
    }
    errors: list[dict] = []
    if not regions:
        return result, errors

    with ThreadPoolExecutor(
        max_workers=min(len(regions), _REGION_PARALLELISM)
    ) as executor:
        futures = {
            executor.submit(_scan_region, region, matcher, session): region
            for region in regions
        }
        for future in as_completed(futures):
            region = futures[future]
            try:
                found, region_errors = future.result()
            except Exception as exc:  # pragma: no cover - defensive
                errors.append(_generic_err(region, "_scan_region", exc))
                continue
            result["coupled_resources"].extend(found)
            result["services_scanned"] += len(_PROBES)
            errors.extend(region_errors)

    result["coupled_resources"].sort(
        key=lambda c: (c["region"], c["service"], c.get("resource") or "")
    )
    return result, errors


def _scan_region(
    region: str, matcher: OrgIdMatcher, session
) -> tuple[list[dict], list[dict]]:
    found: list[dict] = []
    errors: list[dict] = []
    with ThreadPoolExecutor(
        max_workers=min(len(_PROBES), _PER_SERVICE_PARALLELISM)
    ) as executor:
        futures = {
            executor.submit(_run_probe, probe, region, matcher, session): probe
            for probe in _PROBES
        }
        for future in as_completed(futures):
            probe = futures[future]
            try:
                probe_found, probe_errors = future.result()
            except Exception as exc:  # pragma: no cover - defensive
                errors.append(_generic_err(region, probe.service, exc))
                continue
            found.extend(probe_found)
            errors.extend(probe_errors)
    return found, errors


def _run_probe(
    probe: _Probe, region: str, matcher: OrgIdMatcher, session
) -> tuple[list[dict], list[dict]]:
    try:
        client = create_client(probe.client, region=region, session=session)
    except Exception:  # pragma: no cover - service not available in this region
        return [], []

    found: list[dict] = []
    errors: list[dict] = []

    if probe.list_op is None:
        described, err = _describe(client, probe, {}, region)
        if err is not None:
            return [], [err]
        if described is not None:
            entry = _evaluate(probe, region, described, described, matcher)
            if entry is not None:
                found.append(entry)
        return found, errors

    try:
        if client.can_paginate(probe.list_op):
            items = paginate(client, probe.list_op, probe.list_key)
        else:
            items = getattr(client, probe.list_op)().get(probe.list_key) or []
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in _ABSENT_CODES:
            return [], []
        return [], [_err(region, probe.service, probe.list_op, exc)]
    except Exception:  # pragma: no cover - unsupported region / no endpoint
        return [], []

    for item in items[:_MAX_RESOURCES_PER_SERVICE]:
        identifier = item.get(probe.id_field) if probe.id_field else item.get("Name")
        if identifier is None and probe.describe_arg:
            continue
        kwargs = {probe.describe_arg: identifier} if probe.describe_arg else {}
        described, err = _describe(client, probe, kwargs, region)
        if err is not None:
            errors.append(err)
            continue
        if described is None:
            continue
        entry = _evaluate(probe, region, described, item, matcher)
        if entry is not None:
            found.append(entry)

    if len(items) > _MAX_RESOURCES_PER_SERVICE:
        errors.append(
            {
                "module": "identity_center_scanner",
                "region": region,
                "service": probe.service,
                "operation": probe.list_op,
                "code": "ResultsTruncated",
                "message": (
                    f"{len(items)} resources found; only the first "
                    f"{_MAX_RESOURCES_PER_SERVICE} were probed"
                ),
            }
        )
    return found, errors


def _describe(client, probe: _Probe, kwargs: dict, region: str):
    try:
        response = getattr(client, probe.describe_op)(**kwargs)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in _ABSENT_CODES:
            return None, None
        return None, _err(region, probe.service, probe.describe_op, exc)
    except Exception:  # pragma: no cover - unsupported region / no endpoint
        return None, None
    payload = response.get(probe.describe_key) if probe.describe_key else response
    if payload in (None, [], {}):
        return None, None
    return payload, None


def _evaluate(
    probe: _Probe, region: str, described, listed, matcher: OrgIdMatcher
) -> dict | None:
    blob = json.dumps(described, default=str)
    signals = [s for s in probe.signals if s in blob]
    matches = matcher.find_matches(blob)
    if not (probe.always_coupled or signals or matches):
        return None

    source = described if isinstance(described, dict) else (listed or {})
    return {
        "region": region,
        "service": probe.service,
        "resource": source.get(probe.name_field) if probe.name_field else None,
        "arn": source.get(probe.arn_field) if probe.arn_field else None,
        "signals": signals or (["service requires Identity Center"]
                               if probe.always_coupled else []),
        "matches": matches,
    }


def _err(region: str, service: str, operation: str, exc: ClientError, **extra) -> dict:
    payload = {
        "module": "identity_center_scanner",
        "region": region,
        "service": service,
        "operation": operation,
        "code": exc.response.get("Error", {}).get("Code", "ClientError"),
        "message": str(exc),
    }
    payload.update(extra)
    return payload


def _generic_err(region: str, service: str, exc: Exception) -> dict:
    return {
        "module": "identity_center_scanner",
        "region": region,
        "service": service,
        "operation": "probe",
        "code": exc.__class__.__name__,
        "message": str(exc),
    }
