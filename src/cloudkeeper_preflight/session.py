from __future__ import annotations

import random
import sys
import threading
import time
from typing import Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, CredentialRetrievalError

_RETRY_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "adaptive"},
    connect_timeout=5,
    read_timeout=30,
)

_ASSUME_ROLE_DURATION_SECONDS = 3600

_CREDENTIAL_MAX_ATTEMPTS = 5
_CREDENTIAL_BACKOFF_BASE_SECONDS = 1.0

_default_session: Optional[boto3.Session] = None
_default_session_lock = threading.Lock()
_default_client_lock = threading.Lock()


def create_client(service: str, region: str | None = None, session: boto3.Session | None = None):
    """Build a boto3 client with the project's standard adaptive-retry config."""
    kwargs = {"config": _RETRY_CONFIG}
    if region:
        kwargs["region_name"] = region
    if session is not None:
        return session.client(service, **kwargs)
    sess = _get_default_session()
    with _default_client_lock:
        return sess.client(service, **kwargs)


def _get_default_session() -> boto3.Session:
    """Return the process-wide session for the ambient credentials."""
    global _default_session
    with _default_session_lock:
        if _default_session is None:
            sess = boto3.Session()
            _resolve_credentials(sess)
            _default_session = sess
        return _default_session


def _resolve_credentials(sess: boto3.Session) -> None:
    """Load `sess`'s credentials, retrying throttled credential-endpoint fetches.

    botocore caches the result on the session, so every client built from it
    shares one (auto-refreshing) credential object.
    """
    for attempt in range(1, _CREDENTIAL_MAX_ATTEMPTS + 1):
        try:
            sess.get_credentials()
            return
        except CredentialRetrievalError as exc:
            if attempt == _CREDENTIAL_MAX_ATTEMPTS:
                raise
            delay = _CREDENTIAL_BACKOFF_BASE_SECONDS * 2 ** (attempt - 1) + random.uniform(0, 1)
            print(
                f"  [warn] Credential fetch failed (attempt {attempt}/"
                f"{_CREDENTIAL_MAX_ATTEMPTS}), retrying in {delay:.1f}s: {exc}",
                file=sys.stderr,
            )
            time.sleep(delay)


def assume_role(account_id: str, role_name: str) -> Optional[boto3.Session]:
    """Assume the assessment role in a member account and return a scoped session.

    The role is expected to trust the management account with an ExternalId of
    `{account_id}-cloudkeeper-preflight`. Returns None if the assume call fails
    (e.g. role missing, AccessDenied), after printing a one-line warning.
    """
    sts = create_client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"cloudkeeper-preflight-{account_id}",
            ExternalId=f"{account_id}-cloudkeeper-preflight",
            DurationSeconds=_ASSUME_ROLE_DURATION_SECONDS,
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        print(
            f"  [warn] AssumeRole failed for {account_id} ({code}): {exc}",
            file=sys.stderr,
        )
        return None

    creds = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def get_management_account_id() -> str:
    """Return the AWS account ID of whichever credentials boto3 picks up."""
    sts = create_client("sts")
    return sts.get_caller_identity()["Account"]
