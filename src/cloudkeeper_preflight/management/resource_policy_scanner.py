"""Scan all resource-based policies in an account for org/OU/condition-key/SSO-role references.

Used in Phase 1 (management account) and Phase 3 (member accounts), with the
session swapped to point at the right credentials. The result is a dict keyed
by service with a list of `{resource_arn, matches}` entries.

Most scanners here read a policy document. `lakeformation` is the exception: its
grants live in a separate permission store with no policy document to fetch, so
it matches on principal identifiers instead. It emits the same finding shape
plus `principal` / `permissions`, so everything downstream stays generic.

Each per-service scanner is wrapped so a single bad region/service can't bring
down the whole assessment — failures land in `errors` instead.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
from typing import Callable

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.org_id_matcher import OrgIdMatcher
from cloudkeeper_preflight.util.pagination import paginate, paginate_with_token

# Total live threads at peak from this scanner alone =
#   max-concurrent-accounts × _REGIONAL_SCANNERS_PARALLELISM × _PER_REGION_SCANNER_PARALLELISM.
# The EKS access-entry scanner runs in parallel at the per-account level (member
# orchestrator has 5 sibling scanners, one of which is this one), so add its
# region × cluster fanout on top when reasoning about total live threads.
# Keep the product modest — Python's GIL and macOS thread limits both bite
# hard above ~500-1000 active threads.
_REGIONAL_SCANNERS_PARALLELISM = 6
_PER_REGION_SCANNER_PARALLELISM = 4

# `lakeformation:ListPermissions` has no registered paginator and no server-side
# filter for "principals matching a pattern", so the only way to find SSO-role
# grants is to walk every grant in the catalog. Cap the walk: a data lake with
# more than 20k explicit grants is an outlier, and an unbounded walk would stall
# the region behind it. Truncation is reported in `errors`, never swallowed.
_LF_PERMISSIONS_PAGE_SIZE = 1000
_LF_PERMISSIONS_MAX_PAGES = 20

_TAG_SCAN_PAGE_SIZE = 100
_TAG_SCAN_MAX_PAGES = 50


def scan_resource_policies(
    regions: list[str],
    matcher: OrgIdMatcher,
    session=None,
) -> tuple[dict, list[dict]]:
    results: dict[str, list[dict]] = {}
    errors: list[dict] = []

    # Resolved once per account, not per region: the Lake Formation scanner needs
    # it to say whether this run can see the whole grant store.
    caller_arn = _caller_arn(session)
    account_id = _account_id_from_arn(caller_arn)

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
                        _scan_region, region, matcher, session, caller_arn, account_id
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
    caller_arn: str | None = None,
    account_id: str | None = None,
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
        # Only scanner that needs to know who the run is authenticating as.
        "lakeformation": partial(_scan_lakeformation, caller_arn=caller_arn),
        "efs": _scan_efs,
        "ses": _scan_ses,
        "glacier": _scan_glacier,
        "oam": _scan_oam,
        "s3tables": _scan_s3tables,
        "vpc_lattice": _scan_vpc_lattice,
        "codeartifact": _scan_codeartifact,
        "kinesis": _scan_kinesis,
        "sagemaker_model_registry": _scan_sagemaker_model_registry,
        "resource_tags": _scan_resource_tags,
        "msk": _scan_msk,
        "signer": _scan_signer,
        "ses_v2": _scan_ses_v2,
        "opensearch_serverless": _scan_opensearch_serverless,
        "dynamodb": partial(_scan_dynamodb, account_id=account_id),
        "codebuild": partial(_scan_codebuild, account_id=account_id),
        "s3_access_points": partial(_scan_s3_access_points, account_id=account_id),
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
    """General-purpose buckets plus S3 Express One Zone directory buckets.

    General-purpose buckets are global, so they are enumerated once from
    us-east-1 to avoid reporting each of them in every region. Directory buckets
    are a different story: they live in their own `s3express` namespace, they are
    regional, and `ListBuckets` does not return them — they need their own
    per-region call or they are invisible to this scan entirely.
    """
    client = create_client("s3", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []

    if region == "us-east-1":
        general_findings, general_errors = _scan_s3_general_buckets(
            client, region, matcher
        )
        findings.extend(general_findings)
        errors.extend(general_errors)

    directory_findings, directory_errors = _scan_s3_directory_buckets(
        client, region, matcher
    )
    findings.extend(directory_findings)
    errors.extend(directory_errors)
    return findings, errors


def _scan_s3_general_buckets(
    client, region: str, matcher: OrgIdMatcher
) -> tuple[list[dict], list[dict]]:
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


def _scan_s3_directory_buckets(
    client, region: str, matcher: OrgIdMatcher
) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        buckets = paginate(client, "list_directory_buckets", "Buckets")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in ("InvalidRequest", "NotImplemented", "MethodNotAllowed"):
            return [], []
        return [], [_err(region, "s3", "ListDirectoryBuckets", exc)]
    except EndpointConnectionError:  # pragma: no cover - region without S3 Express
        return [], []

    for b in buckets:
        name = b.get("Name")
        if not name:
            continue
        arn = b.get("BucketArn") or name
        try:
            policy = client.get_bucket_policy(Bucket=name).get("Policy")
            _record_match(findings, arn, policy, matcher)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("NoSuchBucketPolicy", "AccessDenied", "NoSuchBucket"):
                continue
            errors.append(
                _err(region, "s3", "GetBucketPolicy(directory)", exc, resource=name)
            )
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

    try:
        registry = client.get_registry_policy()
        _record_match(
            findings,
            f"ecr-registry:{region}:{registry.get('registryId', '')}",
            registry.get("policyText"),
            matcher,
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "RegistryPolicyNotFoundException":
            errors.append(_err(region, "ecr", "GetRegistryPolicy", exc))
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


def _scan_lakeformation(
    region: str, matcher: OrgIdMatcher, session, caller_arn: str | None = None
) -> tuple[list[dict], list[dict]]:
    """Lake Formation keeps its grants in its own permission store, not in a
    resource policy. An `AWSReservedSSO_*` role can be a data lake admin, or hold
    database/table/LF-tag grants, without appearing in any policy document the
    other scanners read — `_scan_glue` sees only the catalog resource policy, and
    Lake Formation grants are invisible to it. Two surfaces, both principal-based:

      - `GetDataLakeSettings` — `DataLakeAdmins`, `ReadOnlyAdmins`, and the
        default database/table permissions. Matched as one blob, like a policy
        document, since every principal in it carries the same remediation.
      - `ListPermissions` — every explicit grant. Matched on the principal
        identifier alone (as `eks_access_scanner` does for access entries):
        the resource side is a database/table/S3 ARN, and matching it whole
        would report grants that merely *sit on* an org-named resource.

    Both calls stay quiet when Lake Formation was never set up in the region —
    that is the common case, not a scan failure. A *denial* is not the same
    thing, and is reported so it lands in `coverage_gaps`.
    """
    client = create_client("lakeformation", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []

    settings: dict | None = None
    try:
        settings = client.get_data_lake_settings().get("DataLakeSettings", {})
        _record_match(findings, f"lakeformation-settings:{region}", settings, matcher)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        # EntityNotFound is "no catalog in this region" — nothing to report. A
        # denial means the settings are there and this run was not allowed to
        # read them, which is a coverage gap and must not read as a clean pass.
        if code != "EntityNotFoundException":
            errors.append(_err(region, "lakeformation", "GetDataLakeSettings", exc))

    try:
        idc = client.describe_lake_formation_identity_center_configuration()
        _record_match(findings, f"lakeformation-idc-config:{region}", idc, matcher)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code not in ("EntityNotFoundException", "InvalidInputException"):
            errors.append(
                _err(
                    region,
                    "lakeformation",
                    "DescribeLakeFormationIdentityCenterConfiguration",
                    exc,
                )
            )

    grants, walk_errors, truncated, walked = _walk_lakeformation_grants(client, region)
    errors.extend(walk_errors)

    for grant in grants:
        principal = (grant.get("Principal") or {}).get("DataLakePrincipalIdentifier")
        if not principal or not matcher.has_match(principal):
            continue
        findings.append(
            {
                "resource_arn": _lakeformation_resource_label(
                    region, grant.get("Resource") or {}
                ),
                "principal": principal,
                "permissions": grant.get("Permissions") or [],
                "permissions_with_grant_option": grant.get(
                    "PermissionsWithGrantOption"
                )
                or [],
                "matches": matcher.find_matches(principal),
            }
        )

    if truncated:
        errors.append(
            {
                "module": "resource_policy_scanner",
                "region": region,
                "service": "lakeformation",
                "operation": "ListPermissions",
                "code": "ResultsTruncated",
                "message": (
                    f"stopped after {_LF_PERMISSIONS_MAX_PAGES} pages "
                    f"(~{_LF_PERMISSIONS_MAX_PAGES * _LF_PERMISSIONS_PAGE_SIZE} "
                    "grants); Lake Formation grants beyond that were not scanned"
                ),
            }
        )

    if walked:
        note = _lakeformation_visibility_note(
            region, caller_arn, settings, len(grants)
        )
        if note:
            errors.append(note)

    return findings, errors


def _walk_lakeformation_grants(
    client, region: str
) -> tuple[list[dict], list[dict], bool, bool]:
    """Walk `ListPermissions` to the page cap.

    Returns `(grants, errors, truncated, walked)`. `walked` says the store was
    actually read — a caller that was denied, or a region with no catalog, gets
    `False`, so the visibility note doesn't fire on a walk that never happened.
    """
    grants: list[dict] = []
    errors: list[dict] = []
    kwargs: dict = {"MaxResults": _LF_PERMISSIONS_PAGE_SIZE}

    for page in range(_LF_PERMISSIONS_MAX_PAGES):
        try:
            response = client.list_permissions(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            # EntityNotFound / InvalidInput both mean "no catalog to list here".
            # A denial is a gap — record it so it reaches `coverage_gaps`.
            if code not in ("EntityNotFoundException", "InvalidInputException"):
                errors.append(_err(region, "lakeformation", "ListPermissions", exc))
            return grants, errors, False, False
        grants.extend(response.get("PrincipalResourcePermissions", []))
        token = response.get("NextToken")
        if not token:
            return grants, errors, False, True
        kwargs["NextToken"] = token

    return grants, errors, True, True


def _lakeformation_visibility_note(
    region: str,
    caller_arn: str | None,
    settings: dict | None,
    grant_count: int,
) -> dict | None:
    """Say so when this run may be seeing only part of the grant store.

    `ListPermissions` answers 200 with a *filtered* list when the caller is not a
    Lake Formation admin — no denial, no error, just a short answer. Nothing
    downstream can tell that from a genuinely small data lake, so the undercount
    would otherwise read as a clean "no SSO grants here".

    Silent when the region has no Lake Formation footprint at all — no admins
    registered and no grants returned means there is nothing to be partial about,
    which is the overwhelmingly common case and must not generate noise.
    """
    admins = _data_lake_admin_principals(settings or {})
    if not admins and not grant_count:
        return None
    if _is_data_lake_admin(caller_arn, admins):
        return None

    if settings is None:
        detail = "data lake settings were unreadable, so admin status is unknown"
    elif not caller_arn:
        detail = "the scan identity could not be resolved (sts:GetCallerIdentity failed)"
    elif not admins:
        detail = (
            "no Lake Formation admins are registered in this region, so this "
            "run's visibility into the grant store could not be confirmed"
        )
    else:
        detail = (
            f"{caller_arn} is not among the {len(admins)} registered Lake "
            "Formation admin(s)"
        )

    return {
        "module": "resource_policy_scanner",
        "region": region,
        "service": "lakeformation",
        "operation": "ListPermissions",
        "code": "PartialGrantVisibility",
        "message": (
            f"{detail}; ListPermissions returns only the grants the caller is "
            f"allowed to see, so the {grant_count} grant(s) walked in this region "
            "may be a subset"
        ),
    }


def _data_lake_admin_principals(settings: dict) -> list[str]:
    """Every principal Lake Formation treats as an admin. Read-only admins see
    the whole store too, so both lists count for visibility purposes."""
    principals: list[str] = []
    for key in ("DataLakeAdmins", "ReadOnlyAdmins"):
        for entry in settings.get(key) or []:
            identifier = (entry or {}).get("DataLakePrincipalIdentifier")
            if identifier:
                principals.append(identifier)
    return principals


def _is_data_lake_admin(caller_arn: str | None, admins: list[str]) -> bool:
    """Whether the running identity is one of the registered admins.

    `sts:GetCallerIdentity` reports the assumed-role *session* ARN
    (`…:assumed-role/<Role>/<session>`) while Lake Formation registers admins by
    *role* ARN (`…:role/<Role>`, path-prefixed for Identity Center roles). A
    literal comparison therefore never matches an assumed role, so fall back to
    the role name — which is unique within an account.
    """
    if not caller_arn or not admins:
        return False
    if caller_arn in admins:
        return True
    role_name = _role_name_from_arn(caller_arn)
    if not role_name:
        return False
    return any(_role_name_from_arn(admin) == role_name for admin in admins)


def _role_name_from_arn(arn: str) -> str | None:
    """Role name out of an IAM role ARN or an STS assumed-role ARN.

        arn:aws:sts::<acct>:assumed-role/<Role>/<session>  -> <Role>
        arn:aws:iam::<acct>:role/<path…>/<Role>            -> <Role>

    Anything else (an IAM user, an account root) returns None — those only ever
    match by full ARN, which the caller has already tried.
    """
    resource = arn.rsplit(":", 1)[-1]
    kind, _, rest = resource.partition("/")
    if not rest:
        return None
    if kind == "assumed-role":
        return rest.split("/")[0]
    if kind == "role":
        return rest.rsplit("/", 1)[-1]
    return None


def _account_id_from_arn(arn: str | None) -> str | None:
    """Account ID out of any ARN. Some policy getters take a resource ARN while
    their list call returns only names, so the ARN has to be built."""
    if not arn:
        return None
    parts = arn.split(":")
    return parts[4] if len(parts) > 5 and parts[4] else None


def _caller_arn(session) -> str | None:
    """The ARN this scan is authenticating as, or None if it can't be resolved.

    Resolved once per account and threaded through to the Lake Formation
    scanner. A failure here is not a scan failure — it downgrades that scanner's
    visibility note to "unknown" rather than stopping anything.
    """
    try:
        sts = create_client("sts", region="us-east-1", session=session)
        return sts.get_caller_identity().get("Arn")
    except Exception:  # pragma: no cover - defensive
        return None


def _lakeformation_resource_label(region: str, resource: dict) -> str:
    """Name the thing a Lake Formation grant is on.

    Lake Formation resources are structured, not ARNs — `Resource` is a union
    with exactly one member set. Render the identifying fields so the finding
    says which database/table/tag has to be re-granted after cutover; fall back
    to the union key when a resource type gains fields we don't render.
    """
    prefix = f"lakeformation:{region}"
    if "Catalog" in resource:
        return f"{prefix}:catalog"
    db = resource.get("Database")
    if db:
        return f"{prefix}:database/{db.get('Name')}"
    for key in ("Table", "TableWithColumns"):
        table = resource.get(key)
        if table:
            name = table.get("Name") or ("*" if table.get("TableWildcard") is not None else None)
            return f"{prefix}:table/{table.get('DatabaseName')}.{name}"
    location = resource.get("DataLocation")
    if location:
        return f"{prefix}:datalocation/{location.get('ResourceArn')}"
    cells = resource.get("DataCellsFilter")
    if cells:
        return (
            f"{prefix}:datacellsfilter/{cells.get('DatabaseName')}"
            f".{cells.get('TableName')}.{cells.get('Name')}"
        )
    tag = resource.get("LFTag")
    if tag:
        return f"{prefix}:lftag/{tag.get('TagKey')}"
    tag_policy = resource.get("LFTagPolicy")
    if tag_policy:
        return f"{prefix}:lftagpolicy/{tag_policy.get('ResourceType')}"
    expression = resource.get("LFTagExpression")
    if expression:
        return f"{prefix}:lftagexpression/{expression.get('Name')}"
    return f"{prefix}:{next(iter(resource), 'unknown')}"


def _scan_oam(
    region: str, matcher: OrgIdMatcher, session
) -> tuple[list[dict], list[dict]]:
    client = create_client("oam", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        sinks = paginate(client, "list_sinks", "Items")
    except ClientError as exc:
        return [], [_err(region, "oam", "ListSinks", exc)]
    for sink in sinks:
        arn = sink.get("Arn")
        if not arn:
            continue
        try:
            policy = client.get_sink_policy(SinkIdentifier=arn).get("Policy")
            _record_match(findings, arn, policy, matcher)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                continue
            errors.append(_err(region, "oam", "GetSinkPolicy", exc, resource=arn))
    return findings, errors


def _scan_s3tables(
    region: str, matcher: OrgIdMatcher, session
) -> tuple[list[dict], list[dict]]:
    """Table bucket policies. Per-table policies are a nested fan-out (tables per
    bucket) and are not walked here; the bucket policy is where cross-account and
    SSO-role grants are set in practice."""
    client = create_client("s3tables", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        buckets = paginate(client, "list_table_buckets", "tableBuckets")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in ("NotFoundException", "AccessDeniedException", "ForbiddenException"):
            return [], []
        return [], [_err(region, "s3tables", "ListTableBuckets", exc)]
    for bucket in buckets:
        arn = bucket.get("arn")
        if not arn:
            continue
        try:
            policy = client.get_table_bucket_policy(tableBucketARN=arn).get(
                "resourcePolicy"
            )
            _record_match(findings, arn, policy, matcher)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in (
                "NotFoundException",
                "ForbiddenException",
            ):
                continue
            errors.append(
                _err(region, "s3tables", "GetTableBucketPolicy", exc, resource=arn)
            )
    return findings, errors


def _scan_vpc_lattice(
    region: str, matcher: OrgIdMatcher, session
) -> tuple[list[dict], list[dict]]:
    client = create_client("vpc-lattice", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    for op, key in (("list_services", "items"), ("list_service_networks", "items")):
        try:
            items = paginate(client, op, key)
        except ClientError as exc:
            errors.append(_err(region, "vpc_lattice", op, exc))
            continue
        for item in items:
            arn = item.get("arn")
            if not arn:
                continue
            try:
                policy = client.get_auth_policy(resourceIdentifier=arn).get("policy")
                _record_match(findings, arn, policy, matcher)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") in (
                    "ResourceNotFoundException",
                    "AccessDeniedException",
                ):
                    continue
                errors.append(
                    _err(region, "vpc_lattice", "GetAuthPolicy", exc, resource=arn)
                )
    return findings, errors


def _scan_codeartifact(
    region: str, matcher: OrgIdMatcher, session
) -> tuple[list[dict], list[dict]]:
    client = create_client("codeartifact", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        domains = paginate(client, "list_domains", "domains")
    except ClientError as exc:
        return [], [_err(region, "codeartifact", "ListDomains", exc)]
    for domain in domains:
        name = domain.get("name")
        if not name:
            continue
        try:
            policy = client.get_domain_permissions_policy(domain=name).get("policy") or {}
            _record_match(
                findings, domain.get("arn") or name, policy.get("document"), matcher
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                errors.append(
                    _err(
                        region,
                        "codeartifact",
                        "GetDomainPermissionsPolicy",
                        exc,
                        resource=name,
                    )
                )
    try:
        repos = paginate(client, "list_repositories", "repositories")
    except ClientError as exc:
        return findings, errors + [_err(region, "codeartifact", "ListRepositories", exc)]
    for repo in repos:
        name, domain_name = repo.get("name"), repo.get("domainName")
        if not (name and domain_name):
            continue
        try:
            policy = client.get_repository_permissions_policy(
                domain=domain_name, repository=name
            ).get("policy") or {}
            _record_match(
                findings, repo.get("arn") or name, policy.get("document"), matcher
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                errors.append(
                    _err(
                        region,
                        "codeartifact",
                        "GetRepositoryPermissionsPolicy",
                        exc,
                        resource=f"{domain_name}/{name}",
                    )
                )
    return findings, errors


def _scan_kinesis(
    region: str, matcher: OrgIdMatcher, session
) -> tuple[list[dict], list[dict]]:
    client = create_client("kinesis", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        streams = paginate(client, "list_streams", "StreamSummaries")
    except ClientError as exc:
        return [], [_err(region, "kinesis", "ListStreams", exc)]
    for stream in streams:
        arn = stream.get("StreamARN")
        if not arn:
            continue
        try:
            policy = client.get_resource_policy(ResourceARN=arn).get("Policy")
            _record_match(findings, arn, policy, matcher)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                continue
            errors.append(
                _err(region, "kinesis", "GetResourcePolicy", exc, resource=arn)
            )
    return findings, errors


def _scan_sagemaker_model_registry(
    region: str, matcher: OrgIdMatcher, session
) -> tuple[list[dict], list[dict]]:
    client = create_client("sagemaker", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        groups = paginate(
            client, "list_model_package_groups", "ModelPackageGroupSummaryList"
        )
    except ClientError as exc:
        return [], [_err(region, "sagemaker_model_registry", "ListModelPackageGroups", exc)]
    for group in groups:
        name = group.get("ModelPackageGroupName")
        if not name:
            continue
        try:
            policy = client.get_model_package_group_policy(
                ModelPackageGroupName=name
            ).get("ResourcePolicy")
            _record_match(
                findings, group.get("ModelPackageGroupArn") or name, policy, matcher
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in (
                "ValidationException",
                "ResourceNotFound",
                "ResourceNotFoundException",
            ):
                continue
            errors.append(
                _err(
                    region,
                    "sagemaker_model_registry",
                    "GetModelPackageGroupPolicy",
                    exc,
                    resource=name,
                )
            )
    return findings, errors


def _scan_msk(region: str, matcher: OrgIdMatcher, session) -> tuple[list[dict], list[dict]]:
    client = create_client("kafka", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        clusters = paginate(client, "list_clusters_v2", "ClusterInfoList")
    except ClientError as exc:
        return [], [_err(region, "msk", "ListClustersV2", exc)]
    for cluster in clusters:
        arn = cluster.get("ClusterArn")
        if not arn:
            continue
        try:
            policy = client.get_cluster_policy(ClusterArn=arn).get("Policy")
            _record_match(findings, arn, policy, matcher)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NotFoundException":
                continue
            errors.append(_err(region, "msk", "GetClusterPolicy", exc, resource=arn))
    return findings, errors


def _scan_signer(region: str, matcher: OrgIdMatcher, session) -> tuple[list[dict], list[dict]]:
    client = create_client("signer", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        profiles = paginate(client, "list_signing_profiles", "profiles")
    except ClientError as exc:
        return [], [_err(region, "signer", "ListSigningProfiles", exc)]
    for profile in profiles:
        name = profile.get("profileName")
        if not name:
            continue
        try:
            permissions = client.list_profile_permissions(profileName=name).get(
                "permissions"
            )
            _record_match(findings, profile.get("arn") or name, permissions, matcher)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                continue
            errors.append(
                _err(region, "signer", "ListProfilePermissions", exc, resource=name)
            )
    return findings, errors


def _scan_ses_v2(region: str, matcher: OrgIdMatcher, session) -> tuple[list[dict], list[dict]]:
    client = create_client("sesv2", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        identities = paginate_with_token(
            client, "list_email_identities", "EmailIdentities"
        )
    except ClientError as exc:
        return [], [_err(region, "ses_v2", "ListEmailIdentities", exc)]
    for identity in identities:
        name = identity.get("IdentityName")
        if not name:
            continue
        try:
            policies = client.get_email_identity_policies(EmailIdentity=name).get(
                "Policies"
            ) or {}
            for policy_name, document in policies.items():
                _record_match(findings, f"{name}#{policy_name}", document, matcher)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NotFoundException":
                continue
            errors.append(
                _err(region, "ses_v2", "GetEmailIdentityPolicies", exc, resource=name)
            )
    return findings, errors


def _scan_opensearch_serverless(
    region: str, matcher: OrgIdMatcher, session
) -> tuple[list[dict], list[dict]]:
    """Data access policies, the OpenSearch Serverless equivalent of a domain
    access policy and a documented gap in the managed-domain scanner."""
    client = create_client("opensearchserverless", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        summaries = paginate_with_token(
            client,
            "list_access_policies",
            "accessPolicySummaries",
            token_key="nextToken",
            type="data",
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in ("ResourceNotFoundException", "ValidationException"):
            return [], []
        return [], [_err(region, "opensearch_serverless", "ListAccessPolicies", exc)]
    for summary in summaries:
        name = summary.get("name")
        if not name:
            continue
        try:
            detail = client.get_access_policy(type="data", name=name).get(
                "accessPolicyDetail"
            ) or {}
            _record_match(
                findings, f"aoss-data-policy:{region}:{name}", detail.get("policy"), matcher
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                continue
            errors.append(
                _err(region, "opensearch_serverless", "GetAccessPolicy", exc, resource=name)
            )
    return findings, errors


def _scan_dynamodb(
    region: str, matcher: OrgIdMatcher, session, account_id: str | None = None
) -> tuple[list[dict], list[dict]]:
    if not account_id:
        return [], []
    client = create_client("dynamodb", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        names = paginate(client, "list_tables", "TableNames")
    except ClientError as exc:
        return [], [_err(region, "dynamodb", "ListTables", exc)]
    for name in names:
        arn = f"arn:aws:dynamodb:{region}:{account_id}:table/{name}"
        try:
            policy = client.get_resource_policy(ResourceArn=arn).get("Policy")
            _record_match(findings, arn, policy, matcher)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in (
                "PolicyNotFoundException",
                "ResourceNotFoundException",
            ):
                continue
            errors.append(
                _err(region, "dynamodb", "GetResourcePolicy", exc, resource=name)
            )
    return findings, errors


def _scan_codebuild(
    region: str, matcher: OrgIdMatcher, session, account_id: str | None = None
) -> tuple[list[dict], list[dict]]:
    if not account_id:
        return [], []
    client = create_client("codebuild", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        names = paginate(client, "list_projects", "projects")
    except ClientError as exc:
        return [], [_err(region, "codebuild", "ListProjects", exc)]
    for name in names:
        arn = f"arn:aws:codebuild:{region}:{account_id}:project/{name}"
        try:
            policy = client.get_resource_policy(resourceArn=arn).get("policy")
            _record_match(findings, arn, policy, matcher)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                continue
            errors.append(
                _err(region, "codebuild", "GetResourcePolicy", exc, resource=name)
            )
    return findings, errors


def _scan_s3_access_points(
    region: str, matcher: OrgIdMatcher, session, account_id: str | None = None
) -> tuple[list[dict], list[dict]]:
    if not account_id:
        return [], []
    client = create_client("s3control", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    try:
        points = paginate_with_token(
            client, "list_access_points", "AccessPointList", AccountId=account_id
        )
    except ClientError as exc:
        return [], [_err(region, "s3_access_points", "ListAccessPoints", exc)]
    for point in points:
        name = point.get("Name")
        if not name:
            continue
        try:
            policy = client.get_access_point_policy(
                AccountId=account_id, Name=name
            ).get("Policy")
            _record_match(findings, point.get("AccessPointArn") or name, policy, matcher)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in (
                "NoSuchAccessPointPolicy",
                "NoSuchAccessPoint",
            ):
                continue
            errors.append(
                _err(region, "s3_access_points", "GetAccessPointPolicy", exc, resource=name)
            )
    return findings, errors


def _scan_resource_tags(
    region: str, matcher: OrgIdMatcher, session
) -> tuple[list[dict], list[dict]]:
    """Customer-set tags naming an Identity Center identity or the organization.

    A tag is not an access grant, but teams key chargeback, cleanup automation
    and ABAC off values like `Owner=jane.doe` or `CreatedBy=AWSReservedSSO_Ops_ab`.
    After cutover the text survives and the identity it names does not: nothing
    errors, the ownership data quietly becomes wrong, and any automation keyed on
    it starts acting on resources it now believes are unowned.

    `tag:GetResources` returns every tagged resource in the region regardless of
    service, so one call covers ground the per-service scanners never reach.

    Tags whose key starts with `aws:` are skipped. They are AWS-generated and
    cannot be edited or repointed, and `aws:createdBy` alone would match nearly
    every resource an SSO user ever created — audit metadata, not a dependency.
    """
    client = create_client("resourcegroupstaggingapi", region=region, session=session)
    findings: list[dict] = []
    errors: list[dict] = []
    kwargs: dict = {"ResourcesPerPage": _TAG_SCAN_PAGE_SIZE}
    truncated = False

    for page in range(_TAG_SCAN_MAX_PAGES):
        try:
            response = client.get_resources(**kwargs)
        except ClientError as exc:
            return findings, errors + [
                _err(region, "resource_tags", "GetResources", exc)
            ]
        for mapping in response.get("ResourceTagMappingList", []):
            finding = _tag_finding(mapping, matcher)
            if finding is not None:
                findings.append(finding)
        token = response.get("PaginationToken")
        if not token:
            break
        kwargs["PaginationToken"] = token
        if page == _TAG_SCAN_MAX_PAGES - 1:
            truncated = True

    if truncated:
        errors.append(
            {
                "module": "resource_policy_scanner",
                "region": region,
                "service": "resource_tags",
                "operation": "GetResources",
                "code": "ResultsTruncated",
                "message": (
                    f"stopped after {_TAG_SCAN_MAX_PAGES} pages "
                    f"(~{_TAG_SCAN_MAX_PAGES * _TAG_SCAN_PAGE_SIZE} tagged "
                    "resources); tags beyond that were not scanned"
                ),
            }
        )

    return findings, errors


def _tag_finding(mapping: dict, matcher: OrgIdMatcher) -> dict | None:
    arn = mapping.get("ResourceARN")
    if not arn:
        return None

    matched_tags: list[dict] = []
    matches: list[dict] = []
    for tag in mapping.get("Tags") or []:
        key = tag.get("Key") or ""
        if key.lower().startswith("aws:"):
            continue
        value = tag.get("Value") or ""
        text = f"{key}={value}"
        if not matcher.has_match(text):
            continue
        matched_tags.append({"key": key, "value": value})
        matches.extend(matcher.find_matches(text))

    if not matched_tags:
        return None
    return {"resource_arn": arn, "tags": matched_tags, "matches": matches}


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
