"""Cost and Usage Reports and Data Exports defined in the payer account.

Both are payer-scoped: they cover the accounts in the payer's billing family,
and stop covering an account once it leaves. Every definition found here has
to be recreated on the new payer, or the customer's cost pipeline goes quiet
at cutover.

Two sources, both global and pinned to us-east-1:
  - legacy CUR: `cur:DescribeReportDefinitions`
  - Data Exports (CUR 2.0, FOCUS, cost optimization recommendations, carbon
    emissions): `bcm-data-exports:ListExports`, then `GetExport` and
    `ListExecutions` per export. The newest execution is the Data Exports
    counterpart of legacy CUR's last_delivery / last_status.

Tags are read per definition. A failed tag read leaves `tags: null` on that
definition and records an error; it never drops the definition.

`in_place` is `true` when either source returned at least one definition,
`false` when both listings succeeded and returned none, and `null` when
nothing was found but a listing errored — an error is not evidence of absence.
"""

from __future__ import annotations

import re
from datetime import datetime

from botocore.exceptions import ClientError, UnknownServiceError

from cloudkeeper_preflight.session import create_client
from cloudkeeper_preflight.util.pagination import paginate

_REGION = "us-east-1"
_FROM_TABLE = re.compile(r"\bFROM\s+([A-Za-z0-9_]+)", re.IGNORECASE)


def assess_cost_exports(session=None) -> tuple[dict, list[dict]]:
    """Return `{"checked": True, "in_place": ..., "legacy_cur": [...], "data_exports": [...]}`."""
    errors: list[dict] = []
    legacy_cur, cur_ok = _legacy_cur(session, errors)
    data_exports, exports_ok = _data_exports(session, errors)

    if legacy_cur or data_exports:
        in_place: bool | None = True
    elif cur_ok and exports_ok:
        in_place = False
    else:
        in_place = None

    return {
        "checked": True,
        "in_place": in_place,
        "legacy_cur": legacy_cur,
        "data_exports": data_exports,
    }, errors


def _legacy_cur(session, errors: list[dict]) -> tuple[list[dict], bool]:
    try:
        client = create_client("cur", region=_REGION, session=session)
        raw = paginate(client, "describe_report_definitions", "ReportDefinitions")
    except (ClientError, UnknownServiceError) as exc:
        errors.append(_error("cur", "DescribeReportDefinitions", exc))
        return [], False

    reports = []
    for r in raw:
        status = r.get("ReportStatus") or {}
        reports.append(
            {
                "report_name": r.get("ReportName"),
                "time_unit": r.get("TimeUnit"),
                "format": r.get("Format"),
                "compression": r.get("Compression"),
                "additional_schema_elements": r.get("AdditionalSchemaElements") or [],
                "s3_bucket": r.get("S3Bucket"),
                "s3_prefix": r.get("S3Prefix"),
                "s3_region": r.get("S3Region"),
                "additional_artifacts": r.get("AdditionalArtifacts") or [],
                "refresh_closed_reports": r.get("RefreshClosedReports"),
                "report_versioning": r.get("ReportVersioning"),
                "billing_view_arn": r.get("BillingViewArn"),
                # Empty strings until the first delivery; normalised to null.
                "last_delivery": status.get("lastDelivery") or None,
                "last_status": status.get("lastStatus") or None,
                "tags": _tags(
                    client, "cur", errors, ReportName=r.get("ReportName")
                ),
            }
        )
    return reports, True


def _data_exports(session, errors: list[dict]) -> tuple[list[dict], bool]:
    try:
        client = create_client("bcm-data-exports", region=_REGION, session=session)
        listed = paginate(client, "list_exports", "Exports")
    except (ClientError, UnknownServiceError) as exc:
        errors.append(_error("bcm-data-exports", "ListExports", exc))
        return [], False

    exports = []
    for item in listed:
        arn = item.get("ExportArn")
        status = item.get("ExportStatus") or {}
        entry: dict = {
            "export_arn": arn,
            "name": item.get("ExportName"),
            "status_code": status.get("StatusCode"),
            "status_reason": status.get("StatusReason"),
            "created_at": _iso(status.get("CreatedAt")),
            "last_updated_at": _iso(status.get("LastUpdatedAt")),
            "last_refreshed_at": _iso(status.get("LastRefreshedAt")),
        }
        try:
            export = client.get_export(ExportArn=arn).get("Export") or {}
        except ClientError as exc:
            errors.append(_error("bcm-data-exports", "GetExport", exc))
            entry["definition_read"] = False
        else:
            query = export.get("DataQuery") or {}
            s3 = (export.get("DestinationConfigurations") or {}).get(
                "S3Destination"
            ) or {}
            out = s3.get("S3OutputConfigurations") or {}
            statement = query.get("QueryStatement") or ""
            table = _FROM_TABLE.search(statement)
            entry.update(
                {
                    "definition_read": True,
                    "description": export.get("Description"),
                    "table": table.group(1) if table else None,
                    "query_statement": statement or None,
                    "table_configurations": query.get("TableConfigurations") or {},
                    "s3_bucket": s3.get("S3Bucket"),
                    "s3_bucket_owner": s3.get("S3BucketOwner"),
                    "s3_prefix": s3.get("S3Prefix"),
                    "s3_region": s3.get("S3Region"),
                    "output_type": out.get("OutputType"),
                    "format": out.get("Format"),
                    "compression": out.get("Compression"),
                    "overwrite": out.get("Overwrite"),
                    "refresh_frequency": (export.get("RefreshCadence") or {}).get(
                        "Frequency"
                    ),
                }
            )
        entry["last_execution"] = _last_execution(client, arn, errors)
        entry["tags"] = _tags(client, "bcm-data-exports", errors, ResourceArn=arn)
        exports.append(entry)
    return exports, True


def _last_execution(client, arn: str, errors: list[dict]) -> dict | None:
    """Newest execution by CreatedAt (the API documents no order), or None."""
    try:
        executions = paginate(client, "list_executions", "Executions", ExportArn=arn)
    except ClientError as exc:
        errors.append(_error("bcm-data-exports", "ListExecutions", exc))
        return None
    if not executions:
        return None
    newest = max(
        executions,
        key=lambda x: _iso((x.get("ExecutionStatus") or {}).get("CreatedAt")) or "",
    )
    status = newest.get("ExecutionStatus") or {}
    return {
        "execution_id": newest.get("ExecutionId"),
        "status_code": status.get("StatusCode"),
        "status_reason": status.get("StatusReason"),
        "created_at": _iso(status.get("CreatedAt")),
        "completed_at": _iso(status.get("CompletedAt")),
    }


def _tags(client, service: str, errors: list[dict], **kwargs) -> dict | None:
    """Tags as a {key: value} dict, or None when the read failed."""
    # cur returns Tags[].{Key,Value} in one page; bcm-data-exports pages
    # ResourceTags[].{Key,Value} with NextToken.
    tags: dict = {}
    try:
        while True:
            response = client.list_tags_for_resource(**kwargs)
            for t in response.get("Tags") or response.get("ResourceTags") or []:
                tags[t.get("Key")] = t.get("Value")
            token = response.get("NextToken")
            if not token:
                return tags
            kwargs["NextToken"] = token
    except ClientError as exc:
        errors.append(_error(service, "ListTagsForResource", exc))
        return None


def _error(service: str, operation: str, exc: Exception) -> dict:
    code = (
        exc.response.get("Error", {}).get("Code", "ClientError")
        if isinstance(exc, ClientError)
        else type(exc).__name__
    )
    return {
        "module": "cost_exports",
        "service": service,
        "operation": operation,
        "code": code,
        "message": str(exc),
    }


def _iso(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)
