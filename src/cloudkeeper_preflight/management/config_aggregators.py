from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.pagination import paginate


def assess_config_aggregators(
    regions: list[str],
    session=None,
) -> tuple[list[dict], list[dict]]:
    """Find org-scoped AWS Config aggregators across all regions.

    Skips aggregators backed by `AccountAggregationSources` (those are
    manual non-org configurations); we only care about org-wide ones.
    """
    aggregators: list[dict] = []
    errors: list[dict] = []

    if not regions:
        return aggregators, errors

    max_workers = min(len(regions), 6)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_assess_region, region, session): region for region in regions
        }
        for future in futures:
            region_aggregators, region_errors = future.result()
            aggregators.extend(region_aggregators)
            errors.extend(region_errors)

    aggregators.sort(key=lambda a: (a["region"], a["name"]))
    return aggregators, errors


def _assess_region(region: str, session) -> tuple[list[dict], list[dict]]:
    errors: list[dict] = []
    try:
        client = create_client("config", region=region, session=session)
        items = paginate(
            client,
            "describe_configuration_aggregators",
            "ConfigurationAggregators",
        )
    except ClientError as exc:
        errors.append(
            {
                "module": "config_aggregators",
                "operation": "DescribeConfigurationAggregators",
                "region": region,
                "code": exc.response.get("Error", {}).get("Code", "ClientError"),
                "message": str(exc),
            }
        )
        return [], errors

    results: list[dict] = []
    for agg in items:
        org_source = agg.get("OrganizationAggregationSource")
        if not org_source:
            continue
        results.append(
            {
                "region": region,
                "name": agg.get("ConfigurationAggregatorName"),
                "arn": agg.get("ConfigurationAggregatorArn"),
                "type": "ORGANIZATION",
                "role_arn": org_source.get("RoleArn"),
                "source_regions": list(org_source.get("AwsRegions") or []),
                "all_regions": bool(org_source.get("AllAwsRegions")),
            }
        )
    return results, errors
