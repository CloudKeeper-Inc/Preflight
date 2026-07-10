"""Scan all resource-based policies in an account for org/OU/condition-key references.

Used in Phase 1 (management account) and Phase 3 (member accounts), with the
session swapped to point at the right credentials. The result is a dict keyed
by service with a list of `{resource_arn, matches}` entries.

Each per-service scanner is wrapped so a single bad region/service can't bring
down the whole assessment — failures land in `errors` instead.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.org_id_matcher import OrgIdMatcher
from cloudkeeper_preflight.util.pagination import paginate, paginate_with_token

# Total live threads at peak = max-concurrent-accounts × _REGIONAL_SCANNERS_PARALLELISM
# × _PER_REGION_SCANNER_PARALLELISM. Keep this product modest — Python's GIL and
# macOS thread limits both bite hard above ~500-1000 active threads.
_REGIONAL_SCANNERS_PARALLELISM = 6
_PER_REGION_SCANNER_PARALLELISM = 4


def scan_resource_policies(
    regions: list[str],
    matcher: OrgIdMatcher,
    session=None,
) -> tuple[dict, list[dict]]:
    results: dict[str, list[dict]] = {}
    errors: list[dict] = []

    # Global services run alongside the regional fan-out.
    with ThreadPoolExecutor(max_workers=2) as global_executor:
        iam_roles_future = global_executor.submit(_scan_iam_roles, matcher, session)
        iam_policies_future = global_executor.submit(_scan_iam_policies, matcher, session)

        if regions:
            with ThreadPoolExecutor(
                max_workers=min(len(regions), _REGIONAL_SCANNERS_PARALLELISM)
            ) as region_executor:
                futures = {
                    region_executor.submit(
                        _scan_region, region, matcher, session
                    ): region
                    for region in regions
                }
                for future in as_completed(futures):
                    region = futures[future]
                    try:
                        region_results, region_errors = future.result()
                    except Exception as exc:  # pragma: no cover - defensive
                        errors.append(
                            {
                                "module": "resource_policy_scanner",
                                "region": region,
                                "operation": "_scan_region",
                                "code": exc.__class__.__name__,
                                "message": str(exc),
                            }
                        )
                        continue
                    for service, findings in region_results.items():
                        results.setdefault(service, []).extend(findings)
                    errors.extend(region_errors)

        roles_findings, role_errors = iam_roles_future.result()
        policies_findings, policy_errors = iam_policies_future.result()

    results["iam_roles"] = roles_findings
    results["iam_policies"] = policies_findings
    errors.extend(role_errors)
    errors.extend(policy_errors)
    return results, errors


def _scan_region(
    region: str,
    matcher: OrgIdMatcher,
    session,
) -> tuple[dict[str, list[dict]], list[dict]]:
    scanners: dict[str, Callable] = {
        "s3": _scan_s3,
        "sns": _scan_sns,
        "sqs": _scan_sqs,
        "lambda": _scan_lambda,
        "kms": _scan_kms,
        "ecr": _scan_ecr,
        "secrets_manager": _scan_secrets_manager,
        "eventbridge": _scan_eventbridge,
        "backup": _scan_backup,
        "api_gateway": _scan_api_gateway,
        "vpc_endpoints": _scan_vpc_endpoints,
        "opensearch": _scan_opensearch,
        "glue": _scan_glue,
        "efs": _scan_efs,
        "ses": _scan_ses,
        "glacier": _scan_glacier,
    }

    region_results: dict[str, list[dict]] = {name: [] for name in scanners}
    region_errors: list[dict] = []
    with ThreadPoolExecutor(
        max_workers=min(len(scanners), _PER_REGION_SCANNER_PARALLELISM)
    ) as executor:
        futures = {
            executor.submit(scanner, region, matcher, session): name
            for name, scanner in scanners.items()
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                findings, scanner_errors = future.result()
                region_results[name] = findings
                region_errors.extend(scanner_errors)
            except Exception as exc:  # pragma: no cover - defensive
                region_errors.append(
                    {
                        "module": "resource_policy_scanner",
                        "region": region,
                        "service": name,
                        "operation": "scanner",
                        "code": exc.__class__.__name__,
                        "message": str(exc),
                    }
                )
    return region_results, region_errors


# --------------------------------------------------------------------------
# Per-service scanners. Each returns `(findings, errors)`.
# --------------------------------------------------------------------------


def _scan_s3(region: str, matcher: OrgIdMatcher, session) -> tuple[list[dict], list[dict]]:
    """S3 buckets are global; only scan from us-east-1 to avoid duplicates."""
    if region != "us-east-1":
        return [], []
    client = create_client("s3", region="us-east-1", session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        buckets = client.list_buckets().get("Buckets", [])
    except ClientError as exc:
        return [], [_err(region, "s3", "ListBuckets", exc)]

    for b in buckets:
        name = b["Name"]
        try:
            policy = client.get_bucket_policy(Bucket=name).get("Policy")
            _record_match(findings, f"arn:aws:s3:::{name}", policy, matcher)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("NoSuchBucketPolicy", "AccessDenied", "NoSuchBucket"):
                continue
            errors.append(_err(region, "s3", "GetBucketPolicy", exc, resource=name))
    return findings, errors


def _scan_sns(region: str, matcher: OrgIdMatcher, session) -> tuple[list[dict], list[dict]]:
    client = create_client("sns", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        topics = paginate(client, "list_topics", "Topics")
    except ClientError as exc:
        return [], [_err(region, "sns", "ListTopics", exc)]
    for t in topics:
        arn = t.get("TopicArn")
        if not arn:
            continue
        try:
            attrs = client.get_topic_attributes(TopicArn=arn).get("Attributes", {})
            _record_match(findings, arn, attrs.get("Policy"), matcher)
        except ClientError as exc:
            errors.append(_err(region, "sns", "GetTopicAttributes", exc, resource=arn))
    return findings, errors


def _scan_sqs(region: str, matcher: OrgIdMatcher, session) -> tuple[list[dict], list[dict]]:
    client = create_client("sqs", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        queues = paginate(client, "list_queues", "QueueUrls")
    except ClientError as exc:
        return [], [_err(region, "sqs", "ListQueues", exc)]
    for url in queues:
        try:
            attrs = client.get_queue_attributes(
                QueueUrl=url, AttributeNames=["Policy", "QueueArn"]
            ).get("Attributes", {})
            _record_match(
                findings, attrs.get("QueueArn") or url, attrs.get("Policy"), matcher
            )
        except ClientError as exc:
            errors.append(_err(region, "sqs", "GetQueueAttributes", exc, resource=url))
    return findings, errors


def _scan_lambda(region: str, matcher: OrgIdMatcher, session) -> tuple[list[dict], list[dict]]:
    client = create_client("lambda", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        funcs = paginate(client, "list_functions", "Functions")
    except ClientError as exc:
        return [], [_err(region, "lambda", "ListFunctions", exc)]
    for f in funcs:
        arn = f.get("FunctionArn")
        try:
            policy = client.get_policy(FunctionName=arn).get("Policy")
            _record_match(findings, arn, policy, matcher)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                continue
            errors.append(_err(region, "lambda", "GetPolicy", exc, resource=arn))
    return findings, errors


def _scan_kms(region: str, matcher: OrgIdMatcher, session) -> tuple[list[dict], list[dict]]:
    client = create_client("kms", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        keys = paginate(client, "list_keys", "Keys")
    except ClientError as exc:
        return [], [_err(region, "kms", "ListKeys", exc)]
    for k in keys:
        kid = k.get("KeyId")
        if not kid:
            continue
        try:
            metadata = client.describe_key(KeyId=kid).get("KeyMetadata", {})
            if metadata.get("KeyManager") != "CUSTOMER":
                continue
            policy = client.get_key_policy(KeyId=kid, PolicyName="default").get("Policy")
            _record_match(findings, metadata.get("Arn") or kid, policy, matcher)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("NotFoundException", "AccessDeniedException"):
                continue
            errors.append(_err(region, "kms", "DescribeKey/GetKeyPolicy", exc, resource=kid))
    return findings, errors


def _scan_ecr(region: str, matcher: OrgIdMatcher, session) -> tuple[list[dict], list[dict]]:
    client = create_client("ecr", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        repos = paginate(client, "describe_repositories", "repositories")
    except ClientError as exc:
        return [], [_err(region, "ecr", "DescribeRepositories", exc)]
    for r in repos:
        name = r.get("repositoryName")
        arn = r.get("repositoryArn")
        try:
            policy = client.get_repository_policy(repositoryName=name).get("policyText")
            _record_match(findings, arn or name, policy, matcher)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "RepositoryPolicyNotFoundException":
                continue
            errors.append(
                _err(region, "ecr", "GetRepositoryPolicy", exc, resource=name)
            )
    return findings, errors


def _scan_secrets_manager(
    region: str, matcher: OrgIdMatcher, session
) -> tuple[list[dict], list[dict]]:
    client = create_client("secretsmanager", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        secrets = paginate(client, "list_secrets", "SecretList")
    except ClientError as exc:
        return [], [_err(region, "secrets_manager", "ListSecrets", exc)]
    for s in secrets:
        arn = s.get("ARN")
        try:
            policy = client.get_resource_policy(SecretId=arn).get("ResourcePolicy")
            _record_match(findings, arn, policy, matcher)
        except ClientError as exc:
            errors.append(
                _err(region, "secrets_manager", "GetResourcePolicy", exc, resource=arn)
            )
    return findings, errors


def _scan_eventbridge(
    region: str, matcher: OrgIdMatcher, session
) -> tuple[list[dict], list[dict]]:
    client = create_client("events", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        buses = paginate_with_token(
            client, "list_event_buses", "EventBuses"
        )
    except ClientError as exc:
        return [], [_err(region, "eventbridge", "ListEventBuses", exc)]
    for b in buses:
        _record_match(findings, b.get("Arn") or b.get("Name"), b.get("Policy"), matcher)
    return findings, errors


def _scan_backup(region: str, matcher: OrgIdMatcher, session) -> tuple[list[dict], list[dict]]:
    client = create_client("backup", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        vaults = paginate(client, "list_backup_vaults", "BackupVaultList")
    except ClientError as exc:
        return [], [_err(region, "backup", "ListBackupVaults", exc)]
    for v in vaults:
        arn = v.get("BackupVaultArn")
        name = v.get("BackupVaultName")
        try:
            policy = client.get_backup_vault_access_policy(
                BackupVaultName=name
            ).get("Policy")
            _record_match(findings, arn or name, policy, matcher)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                continue
            errors.append(
                _err(region, "backup", "GetBackupVaultAccessPolicy", exc, resource=name)
            )
    return findings, errors


def _scan_api_gateway(
    region: str, matcher: OrgIdMatcher, session
) -> tuple[list[dict], list[dict]]:
    client = create_client("apigateway", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        apis = paginate_with_token(
            client, "get_rest_apis", "items", token_key="position"
        )
    except ClientError as exc:
        return [], [_err(region, "api_gateway", "GetRestApis", exc)]
    for api in apis:
        api_id = api.get("id")
        arn = (
            f"arn:aws:apigateway:{region}::/restapis/{api_id}" if api_id else None
        )
        _record_match(findings, arn, api.get("policy"), matcher)
    return findings, errors


def _scan_vpc_endpoints(
    region: str, matcher: OrgIdMatcher, session
) -> tuple[list[dict], list[dict]]:
    client = create_client("ec2", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        endpoints = paginate(
            client, "describe_vpc_endpoints", "VpcEndpoints"
        )
    except ClientError as exc:
        return [], [_err(region, "vpc_endpoints", "DescribeVpcEndpoints", exc)]
    for ep in endpoints:
        epid = ep.get("VpcEndpointId")
        arn = (
            f"arn:aws:ec2:{region}:{ep.get('OwnerId', '')}:vpc-endpoint/{epid}"
            if epid
            else None
        )
        _record_match(findings, arn, ep.get("PolicyDocument"), matcher)
    return findings, errors


def _scan_opensearch(
    region: str, matcher: OrgIdMatcher, session
) -> tuple[list[dict], list[dict]]:
    client = create_client("opensearch", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        domains = client.list_domain_names().get("DomainNames", [])
    except ClientError as exc:
        return [], [_err(region, "opensearch", "ListDomainNames", exc)]
    for d in domains:
        name = d.get("DomainName")
        if not name:
            continue
        try:
            detail = client.describe_domain(DomainName=name).get("DomainStatus", {})
            _record_match(findings, detail.get("ARN") or name, detail.get("AccessPolicies"), matcher)
        except ClientError as exc:
            errors.append(_err(region, "opensearch", "DescribeDomain", exc, resource=name))
    return findings, errors


def _scan_glue(
    region: str, matcher: OrgIdMatcher, session
) -> tuple[list[dict], list[dict]]:
    client = create_client("glue", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        policies = paginate_with_token(
            client, "get_resource_policies", "GetResourcePoliciesResponseList"
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in ("EntityNotFoundException", "AccessDeniedException"):
            return [], []
        return [], [_err(region, "glue", "GetResourcePolicies", exc)]
    for p in policies:
        _record_match(
            findings,
            p.get("PolicyHash") or f"glue-catalog-policy:{region}",
            p.get("PolicyInJson"),
            matcher,
        )
    return findings, errors


def _scan_efs(
    region: str, matcher: OrgIdMatcher, session
) -> tuple[list[dict], list[dict]]:
    client = create_client("efs", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        filesystems = paginate(
            client, "describe_file_systems", "FileSystems"
        )
    except ClientError as exc:
        return [], [_err(region, "efs", "DescribeFileSystems", exc)]
    for fs in filesystems:
        fsid = fs.get("FileSystemId")
        arn = fs.get("FileSystemArn")
        try:
            policy = client.describe_file_system_policy(FileSystemId=fsid).get("Policy")
            _record_match(findings, arn or fsid, policy, matcher)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "PolicyNotFound":
                continue
            errors.append(
                _err(region, "efs", "DescribeFileSystemPolicy", exc, resource=fsid)
            )
    return findings, errors


def _scan_ses(
    region: str, matcher: OrgIdMatcher, session
) -> tuple[list[dict], list[dict]]:
    client = create_client("ses", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        identities = paginate(client, "list_identities", "Identities")
    except ClientError as exc:
        return [], [_err(region, "ses", "ListIdentities", exc)]
    for ident in identities:
        try:
            policy_names = client.list_identity_policies(Identity=ident).get(
                "PolicyNames", []
            )
            if not policy_names:
                continue
            policies_resp = client.get_identity_policies(
                Identity=ident, PolicyNames=policy_names
            ).get("Policies", {})
            for pname, body in policies_resp.items():
                _record_match(findings, f"{ident}#{pname}", body, matcher)
        except ClientError as exc:
            errors.append(_err(region, "ses", "GetIdentityPolicies", exc, resource=ident))
    return findings, errors


def _scan_glacier(
    region: str, matcher: OrgIdMatcher, session
) -> tuple[list[dict], list[dict]]:
    client = create_client("glacier", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        vaults = paginate(client, "list_vaults", "VaultList", accountId="-")
    except ClientError as exc:
        return [], [_err(region, "glacier", "ListVaults", exc)]
    for v in vaults:
        name = v.get("VaultName")
        arn = v.get("VaultARN")
        try:
            policy = client.get_vault_access_policy(
                accountId="-", vaultName=name
            ).get("policy", {}).get("Policy")
            _record_match(findings, arn or name, policy, matcher)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                continue
            errors.append(_err(region, "glacier", "GetVaultAccessPolicy", exc, resource=name))
    return findings, errors


# --------------------------------------------------------------------------
# Global (IAM) scanners
# --------------------------------------------------------------------------


def _scan_iam_roles(matcher: OrgIdMatcher, session) -> tuple[list[dict], list[dict]]:
    client = create_client("iam", region="us-east-1", session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        roles = paginate(client, "list_roles", "Roles")
    except ClientError as exc:
        return [], [_err("global", "iam", "ListRoles", exc)]
    for r in roles:
        if (r.get("Path") or "").startswith("/aws-service-role/"):
            continue
        _record_match(
            findings, r.get("Arn") or r.get("RoleName"), r.get("AssumeRolePolicyDocument"), matcher
        )
    return findings, errors


def _scan_iam_policies(matcher: OrgIdMatcher, session) -> tuple[list[dict], list[dict]]:
    client = create_client("iam", region="us-east-1", session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        policies = paginate(client, "list_policies", "Policies", Scope="Local")
    except ClientError as exc:
        return [], [_err("global", "iam", "ListPolicies", exc)]
    for p in policies:
        arn = p.get("Arn")
        version_id = p.get("DefaultVersionId")
        if not (arn and version_id):
            continue
        try:
            version = client.get_policy_version(
                PolicyArn=arn, VersionId=version_id
            ).get("PolicyVersion", {})
            _record_match(findings, arn, version.get("Document"), matcher)
        except ClientError as exc:
            errors.append(_err("global", "iam", "GetPolicyVersion", exc, resource=arn))
    return findings, errors


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _record_match(
    findings: list[dict],
    resource_arn: str | None,
    policy,
    matcher: OrgIdMatcher,
) -> None:
    if policy is None or resource_arn is None:
        return
    text = policy if isinstance(policy, str) else json.dumps(policy, default=str)
    if not matcher.has_match(text):
        return
    findings.append(
        {"resource_arn": resource_arn, "matches": matcher.find_matches(text)}
    )


def _err(
    region: str,
    service: str,
    operation: str,
    exc: ClientError,
    **extra,
) -> dict:
    payload = {
        "module": "resource_policy_scanner",
        "region": region,
        "service": service,
        "operation": operation,
        "code": exc.response.get("Error", {}).get("Code", "ClientError"),
        "message": str(exc),
    }
    payload.update(extra)
    return payload
