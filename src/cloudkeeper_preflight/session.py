from __future__ import annotations

import sys
from typing import Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

_RETRY_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "adaptive"},
    connect_timeout=5,
    read_timeout=30,
)

_ASSUME_ROLE_DURATION_SECONDS = 3600


def create_client(service: str, region: str | None = None, session: boto3.Session | None = None):
    """Build a boto3 client with the project's standard adaptive-retry config."""
    sess = session or boto3.Session()
    kwargs = {"config": _RETRY_CONFIG}
    if region:
        kwargs["region_name"] = region
    return sess.client(service, **kwargs)


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
