from __future__ import annotations

import json


def get_cfn_template(management_account_id: str, role_name: str) -> str:
    """Return the CloudFormation template (as a JSON string) that creates the
    temporary read-only assessor role in each member account.

    The role trusts the management account root and requires an ExternalId of
    `{member_account_id}-cloudkeeper-preflight` (the per-account ID is filled
    in via `${AWS::AccountId}` at deploy time, matching `assume_role()` in
    `session.py`).
    """
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "CloudKeeper PreFlight - Temporary read-only role for organization assessment",
        "Parameters": {
            "ManagementAccountId": {
                "Type": "String",
                "Default": management_account_id,
            },
            "RoleName": {
                "Type": "String",
                "Default": role_name,
            },
        },
        "Resources": {
            "AssessorRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Ref": "RoleName"},
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "AWS": {
                                        "Fn::Sub": "arn:aws:iam::${ManagementAccountId}:root"
                                    }
                                },
                                "Action": "sts:AssumeRole",
                                "Condition": {
                                    "StringEquals": {
                                        "sts:ExternalId": {
                                            "Fn::Sub": "${AWS::AccountId}-cloudkeeper-preflight"
                                        }
                                    }
                                },
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/ReadOnlyAccess",
                    ],
                    "Policies": [
                        {
                            "PolicyName": "AdditionalReadPermissions",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "organizations:Describe*",
                                            "organizations:List*",
                                            "lakeformation:GetDataLakeSettings",
                                            "lakeformation:ListPermissions",
                                            "ram:Get*",
                                            "ram:List*",
                                            "sso:Describe*",
                                            "sso:List*",
                                            "sso-directory:Describe*",
                                            "sso-directory:List*",
                                        ],
                                        "Resource": "*",
                                    }
                                ],
                            },
                        }
                    ],
                    "Tags": [
                        {"Key": "CreatedBy", "Value": "CloudKeeperPreFlight"},
                        {"Key": "Purpose", "Value": "TemporaryReadOnlyAssessment"},
                    ],
                },
            }
        },
        "Outputs": {
            "RoleArn": {
                "Value": {"Fn::GetAtt": ["AssessorRole", "Arn"]},
            }
        },
    }
    return json.dumps(template, indent=2)
