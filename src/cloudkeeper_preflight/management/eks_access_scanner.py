"""Scan EKS clusters for Identity Center role references in Access Entries,
and flag clusters where the legacy `aws-auth` ConfigMap is in the auth path.

Used in Phase 1 (management account) and Phase 3 (member accounts), with the
session swapped to point at the right credentials.

Output shape:
    {
      "checked": True,
      "clusters_scanned": <int>,
      "clusters_with_sso_access_entries": [ {region, cluster_name, ...} ],
      "clusters_needing_configmap_inspection": [ {region, cluster_name, ...} ],
    }

`clusters_with_sso_access_entries` lists clusters whose access entries include
at least one principal ARN matched by `OrgIdMatcher` (i.e. `AWSReservedSSO_*`
or org/OU references). `clusters_needing_configmap_inspection` lists clusters
whose `AuthenticationMode` is `CONFIG_MAP` or `API_AND_CONFIG_MAP` — a `kubectl`
read of `kube-system/aws-auth` is the only way to enumerate SSO role bindings
there, so we surface the cluster but cannot enumerate the mappings ourselves.

Failures land in the shared errors list following the standard scanner
contract; `_partition_errors` in `output.py` classifies them into
access-denied / throttles / real errors.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.org_id_matcher import OrgIdMatcher
from cloudkeeper_preflight.util.pagination import paginate

_REGION_PARALLELISM = 6
_PER_CLUSTER_PARALLELISM = 4

# Modes that include the legacy ConfigMap in the auth path. `describe_cluster`
# may omit AuthenticationMode on very old clusters — treat that as CONFIG_MAP.
_CONFIGMAP_MODES = frozenset({"CONFIG_MAP", "API_AND_CONFIG_MAP"})
_ACCESS_ENTRY_MODES = frozenset({"API", "API_AND_CONFIG_MAP"})


def scan_eks_access(
    regions: list[str],
    matcher: OrgIdMatcher,
    session=None,
) -> tuple[dict, list[dict]]:
    result: dict = {
        "checked": True,
        "clusters_scanned": 0,
        "clusters_with_sso_access_entries": [],
        "clusters_needing_configmap_inspection": [],
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
                region_result, region_errors = future.result()
            except Exception as exc:  # pragma: no cover - defensive
                errors.append(
                    {
                        "module": "eks_access_scanner",
                        "service": "eks",
                        "region": region,
                        "operation": "_scan_region",
                        "code": exc.__class__.__name__,
                        "message": str(exc),
                    }
                )
                continue
            result["clusters_scanned"] += region_result["clusters_scanned"]
            result["clusters_with_sso_access_entries"].extend(
                region_result["clusters_with_sso_access_entries"]
            )
            result["clusters_needing_configmap_inspection"].extend(
                region_result["clusters_needing_configmap_inspection"]
            )
            errors.extend(region_errors)

    result["clusters_with_sso_access_entries"].sort(
        key=lambda c: (c["region"], c["cluster_name"])
    )
    result["clusters_needing_configmap_inspection"].sort(
        key=lambda c: (c["region"], c["cluster_name"])
    )
    return result, errors


def _scan_region(
    region: str,
    matcher: OrgIdMatcher,
    session,
) -> tuple[dict, list[dict]]:
    region_result: dict = {
        "clusters_scanned": 0,
        "clusters_with_sso_access_entries": [],
        "clusters_needing_configmap_inspection": [],
    }
    errors: list[dict] = []

    client = create_client("eks", region=region, session=session)
    try:
        cluster_names = paginate(client, "list_clusters", "clusters")
    except ClientError as exc:
        return region_result, [_err(region, "ListClusters", exc)]

    if not cluster_names:
        return region_result, errors

    with ThreadPoolExecutor(
        max_workers=min(len(cluster_names), _PER_CLUSTER_PARALLELISM)
    ) as executor:
        futures = {
            executor.submit(
                _scan_cluster, client, region, name, matcher
            ): name
            for name in cluster_names
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                cluster_findings, cluster_errors = future.result()
            except Exception as exc:  # pragma: no cover - defensive
                errors.append(_generic_err(region, name, "_scan_cluster", exc))
                continue
            region_result["clusters_scanned"] += 1
            if cluster_findings.get("sso_cluster") is not None:
                region_result["clusters_with_sso_access_entries"].append(
                    cluster_findings["sso_cluster"]
                )
            if cluster_findings.get("configmap_cluster") is not None:
                region_result["clusters_needing_configmap_inspection"].append(
                    cluster_findings["configmap_cluster"]
                )
            errors.extend(cluster_errors)

    return region_result, errors


def _scan_cluster(
    client,
    region: str,
    cluster_name: str,
    matcher: OrgIdMatcher,
) -> tuple[dict, list[dict]]:
    findings: dict = {"sso_cluster": None, "configmap_cluster": None}
    errors: list[dict] = []

    try:
        cluster = client.describe_cluster(name=cluster_name).get("cluster", {})
    except ClientError as exc:
        return findings, [_err(region, "DescribeCluster", exc, resource=cluster_name)]

    access_config = cluster.get("accessConfig") or {}
    # Absent AuthenticationMode is a very old cluster — legacy ConfigMap only.
    auth_mode = access_config.get("authenticationMode") or "CONFIG_MAP"
    cluster_arn = cluster.get("arn")

    if auth_mode in _CONFIGMAP_MODES:
        findings["configmap_cluster"] = {
            "region": region,
            "cluster_name": cluster_name,
            "cluster_arn": cluster_arn,
            "authentication_mode": auth_mode,
            "note": (
                "aws-auth ConfigMap is in the auth path — inspect via "
                "`kubectl -n kube-system get cm aws-auth -o yaml` for "
                "AWSReservedSSO_* mappings; not enumerable via AWS API"
            ),
        }

    if auth_mode not in _ACCESS_ENTRY_MODES:
        return findings, errors

    sso_references, entry_errors = _collect_sso_access_entries(
        client, region, cluster_name, matcher
    )
    errors.extend(entry_errors)
    if sso_references:
        findings["sso_cluster"] = {
            "region": region,
            "cluster_name": cluster_name,
            "cluster_arn": cluster_arn,
            "authentication_mode": auth_mode,
            "sso_references": sso_references,
        }
    return findings, errors


def _collect_sso_access_entries(
    client,
    region: str,
    cluster_name: str,
    matcher: OrgIdMatcher,
) -> tuple[list[dict], list[dict]]:
    errors: list[dict] = []
    try:
        principal_arns = paginate(
            client,
            "list_access_entries",
            "accessEntries",
            clusterName=cluster_name,
        )
    except ClientError as exc:
        return [], [_err(region, "ListAccessEntries", exc, resource=cluster_name)]

    references: list[dict] = []
    for principal_arn in principal_arns:
        if not matcher.has_match(principal_arn):
            continue
        try:
            entry = (
                client.describe_access_entry(
                    clusterName=cluster_name, principalArn=principal_arn
                ).get("accessEntry")
                or {}
            )
        except ClientError as exc:
            errors.append(
                _err(
                    region,
                    "DescribeAccessEntry",
                    exc,
                    resource=f"{cluster_name}::{principal_arn}",
                )
            )
            entry = {}
        try:
            associated = paginate(
                client,
                "list_associated_access_policies",
                "associatedAccessPolicies",
                clusterName=cluster_name,
                principalArn=principal_arn,
            )
        except ClientError as exc:
            errors.append(
                _err(
                    region,
                    "ListAssociatedAccessPolicies",
                    exc,
                    resource=f"{cluster_name}::{principal_arn}",
                )
            )
            associated = []

        references.append(
            {
                "principal_arn": principal_arn,
                "kubernetes_groups": entry.get("kubernetesGroups") or [],
                "type": entry.get("type"),
                "access_policies": [
                    {
                        "policy_arn": p.get("policyArn"),
                        "access_scope": p.get("accessScope") or {},
                    }
                    for p in associated
                ],
                "matches": matcher.find_matches(principal_arn),
            }
        )
    return references, errors


def _err(
    region: str,
    operation: str,
    exc: ClientError,
    **extra,
) -> dict:
    payload = {
        "module": "eks_access_scanner",
        "service": "eks",
        "region": region,
        "operation": operation,
        "code": exc.response.get("Error", {}).get("Code", "ClientError"),
        "message": str(exc),
    }
    payload.update(extra)
    return payload


def _generic_err(
    region: str,
    cluster_name: str,
    operation: str,
    exc: Exception,
) -> dict:
    return {
        "module": "eks_access_scanner",
        "service": "eks",
        "region": region,
        "operation": operation,
        "resource": cluster_name,
        "code": exc.__class__.__name__,
        "message": str(exc),
    }
