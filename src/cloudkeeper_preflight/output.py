"""Assemble the final assessment JSON, then submit it (or save locally).

Error handling design:
- Scanners catch AWS errors and append `{module, operation, code, ...}` entries
  to a flat errors list. They never raise — Phase 1 / member orchestrator just
  collect everything.
- At assembly time, we partition that flat list into three buckets by error
  code: real errors (kept verbatim), throttles (counted), and access denials
  (aggregated into per-account `coverage_gaps`).
- `coverage_gaps` is the actionable signal for an analyst reviewing the JSON:
  "this account is opaque to us for service X / operation Y because something
  (usually an SCP) blocked the call."
"""

from __future__ import annotations

import gzip
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from cloudkeeper_preflight import __version__

_ACCESS_DENIED_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "AuthorizationError",
        "UnauthorizedOperation",
        "Forbidden",
    }
)
_THROTTLE_CODES = frozenset(
    {
        "ThrottlingException",
        "Throttling",
        "RequestLimitExceeded",
        "TooManyRequestsException",
        "RequestThrottled",
    }
)
_API_TIMEOUT_SECONDS = 30
_API_MAX_ATTEMPTS = 3


def assemble_output(
    args,
    phase1_results: dict,
    phase1_errors: list[dict],
    member_results: dict,
    member_errors: list[dict],
    poll_failed_accounts: list[str],
    management_account_id: str,
    started_at: float,
) -> dict:
    org = phase1_results.get("organization") or {}

    mgmt_real, _, mgmt_throttles = _partition_errors(phase1_errors)
    mgmt_coverage_gaps = _aggregate_coverage_gaps(
        e for e in phase1_errors if _classify(e) == "access_denied"
    )

    annotated_members = _annotate_member_results(member_results, member_errors)
    member_real, _, member_throttles = _partition_errors(member_errors)

    return {
        "metadata": {
            "customer_uuid": args.customer_uuid,
            "customer_emails": args.customer_emails_list,
            "assessment_timestamp": datetime.now(timezone.utc).isoformat(),
            "tool_version": __version__,
            "execution_duration_seconds": round(time.time() - started_at, 2),
            "management_account_id": management_account_id,
            "errors": mgmt_real + member_real,
            "throttling_event_count": len(mgmt_throttles) + len(member_throttles),
            "stackset_provision_failed_accounts": list(poll_failed_accounts or []),
        },
        "organization": org,
        "accounts": phase1_results.get("accounts") or [],
        "trusted_access": phase1_results.get("trusted_access") or [],
        "delegated_administrators": phase1_results.get("delegated_admins") or [],
        "policies": phase1_results.get("policies") or {},
        "identity_center": phase1_results.get("sso") or {},
        "billing": phase1_results.get("billing") or {},
        "ram_shares": phase1_results.get("ram") or {},
        "stacksets": phase1_results.get("existing_stacksets") or {},
        "config_aggregators": phase1_results.get("config_aggregators") or [],
        "service_configurations": phase1_results.get("service_configurations") or {},
        "seller_of_record": (phase1_results.get("tax_settings") or {}).get(
            "seller_of_record"
        ),
        "budget_alerts": (phase1_results.get("budgets") or {}).get("budget_alerts")
        or [],
        "eks_charges": phase1_results.get("eks_charges") or {},
        "management_account_org_references": phase1_results.get("resource_policies")
        or {},
        "management_account_coverage_gaps": mgmt_coverage_gaps,
        "member_accounts": annotated_members,
    }


def submit_to_api(
    output: dict,
    api_endpoint: str | None,
    customer_uuid: str,
) -> bool:
    """POST gzipped JSON to the API, falling back to local save on any failure.

    If `api_endpoint` is None or empty, skip the POST entirely and go straight
    to local fallback — no fake URL, no spurious retries (per BUILD_PLAN locked
    decision: the backend doesn't exist yet).
    """
    if not api_endpoint:
        print("[Submission] No --api-endpoint provided; saving locally.")
        return save_local_fallback(output, customer_uuid)

    json_bytes = json.dumps(output, default=_json_default).encode("utf-8")
    compressed = gzip.compress(json_bytes)
    headers = {
        "Content-Type": "application/json",
        "Content-Encoding": "gzip",
        "X-Customer-UUID": customer_uuid,
    }

    for attempt in range(_API_MAX_ATTEMPTS):
        try:
            req = urllib.request.Request(
                api_endpoint, data=compressed, headers=headers, method="POST"
            )
            with urllib.request.urlopen(req, timeout=_API_TIMEOUT_SECONDS) as response:
                status = response.status
                body = response.read().decode("utf-8", errors="replace")
            if status in (200, 201):
                print(f"[Submission] Submitted to {api_endpoint} (HTTP {status})")
                return True
            if status == 403:
                print(
                    f"[Submission] HTTP 403: customer UUID may not be whitelisted. {body}",
                    file=sys.stderr,
                )
                break
            if status == 400:
                print(f"[Submission] HTTP 400: validation failed. {body}", file=sys.stderr)
                break
        except urllib.error.HTTPError as exc:
            if exc.code >= 500 and attempt < _API_MAX_ATTEMPTS - 1:
                wait = 2**attempt
                print(
                    f"[Submission] HTTP {exc.code} on attempt {attempt + 1}; retrying in {wait}s",
                    file=sys.stderr,
                )
                time.sleep(wait)
                continue
            print(
                f"[Submission] HTTP error: {exc.code} {exc.reason}", file=sys.stderr
            )
            break
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            if attempt < _API_MAX_ATTEMPTS - 1:
                wait = 2**attempt
                print(
                    f"[Submission] {exc.__class__.__name__}: {exc} on attempt {attempt + 1}; "
                    f"retrying in {wait}s",
                    file=sys.stderr,
                )
                time.sleep(wait)
                continue
            print(f"[Submission] Connection error: {exc}", file=sys.stderr)
            break

    return save_local_fallback(output, customer_uuid)


def save_local_fallback(output: dict, customer_uuid: str) -> bool:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    filename = (
        f"cloudkeeper-preflight-assessment-{customer_uuid}-{timestamp}.json.gz"
    )
    payload = json.dumps(output, indent=2, default=_json_default).encode("utf-8")
    with gzip.open(filename, "wb") as f:
        f.write(payload)
    size_kb = len(payload) / 1024
    print(
        f"[Submission] Saved {filename} ({size_kb:.1f} KB uncompressed JSON)."
    )
    return True


# --------------------------------------------------------------------------
# Internals
# --------------------------------------------------------------------------


def _classify(err: dict) -> str:
    code = err.get("code", "")
    if code in _ACCESS_DENIED_CODES:
        return "access_denied"
    if code in _THROTTLE_CODES:
        return "throttle"
    return "error"


def _partition_errors(
    errors: list[dict],
) -> tuple[list[dict], list[dict], list[dict]]:
    real: list[dict] = []
    denied: list[dict] = []
    throttles: list[dict] = []
    for e in errors:
        kind = _classify(e)
        if kind == "access_denied":
            denied.append(e)
        elif kind == "throttle":
            throttles.append(e)
        else:
            real.append(e)
    return real, denied, throttles


def _aggregate_coverage_gaps(denied_errors) -> list[dict]:
    """Collapse per-call AccessDenied entries into per-(service, operation) rows.

    Different scanners use different keys for the service identifier:
      - resource_policy_scanner: `service` (e.g. "s3", "lambda")
      - ram/ram_scanner/iam_scanner/etc: `module`
    Falls back to "unknown" if neither is set.
    """
    counts: dict[tuple[str, str], int] = {}
    for e in denied_errors:
        service = (
            e.get("service")
            or e.get("module")
            or "unknown"
        )
        op = e.get("operation") or "unknown"
        key = (service, op)
        counts[key] = counts.get(key, 0) + 1
    return [
        {"service": service, "operation": operation, "denied_call_count": count}
        for (service, operation), count in sorted(counts.items())
    ]


def _annotate_member_results(
    member_results: dict,
    member_errors: list[dict],
) -> dict:
    """Add per-account coverage_gaps to each member assessment."""
    by_account: dict[str, list[dict]] = {}
    for e in member_errors:
        if _classify(e) != "access_denied":
            continue
        aid = e.get("account_id")
        if aid is None:
            continue
        by_account.setdefault(aid, []).append(e)

    out: dict = {}
    for aid, payload in member_results.items():
        gaps = _aggregate_coverage_gaps(by_account.get(aid, []))
        annotated = dict(payload)
        annotated["coverage_gaps"] = gaps
        out[aid] = annotated
    return out


def _json_default(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, set):
        return sorted(obj)
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    return str(obj)
