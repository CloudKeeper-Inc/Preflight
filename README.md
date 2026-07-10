# CloudKeeper PreFlight

A read-only assessor for your AWS Organization. Runs from your management
account and produces one JSON file describing every dependency CloudKeeper
needs to plan your onboarding.

**By default**, PreFlight only inspects the management account — org
structure, policies, IAM Identity Center, RAM, billing, and per-service org
configuration. It does **not** touch any member accounts. Nothing is
created, nothing is deployed.

If CloudKeeper asks for a deeper assessment that also inspects your
member accounts, pass `--assess-member-accounts`. That mode deploys a
temporary CloudFormation StackSet with a read-only IAM role in each member
account, runs per-account scans, and tears the StackSet down when it's
done. See [What `--assess-member-accounts` does](#what---assess-member-accounts-does) below.

## What you'll need

- AWS Console access to your organization's **management account** with
  permissions to list organization resources. (Full `AdministratorAccess`
  is easiest.)
- A **customer UUID** and **contact emails** — CloudKeeper sends these.
- For `--assess-member-accounts` only: permission to deploy CloudFormation
  StackSets, plus the CloudFormation organizations-access integration
  enabled in the management account (one-time setup — see below).
- Wall-clock time:
  - Default (management account only): ~1–2 minutes.
  - With `--assess-member-accounts`: ~30 minutes for a 50-account org;
    scales roughly linearly.

## Run it (CloudShell — recommended)

CloudShell has Python and boto3 preinstalled and inherits your console
credentials, so there's nothing to configure. Open CloudShell in the
management account and paste:

```bash
git clone --depth 1 https://github.com/CloudKeeper-Inc/Preflight.git && \
  cd Preflight && \
  python3 -m pip install --user . && \
  python3 -m cloudkeeper_preflight \
    --customer-uuid <UUID-FROM-CLOUDKEEPER> \
    --customer-emails <YOUR-EMAIL> \
    2>&1 | tee run.log
```

Replace `<UUID-FROM-CLOUDKEEPER>` and `<YOUR-EMAIL>` with the values we sent.

To also assess member accounts (only when CloudKeeper asks for it), add
the flag:

```bash
python3 -m cloudkeeper_preflight \
  --customer-uuid <UUID-FROM-CLOUDKEEPER> \
  --customer-emails <YOUR-EMAIL> \
  --assess-member-accounts \
  2>&1 | tee run.log
```

When the run finishes, the last line is:

```
[Submission] Saved cloudkeeper-preflight-assessment-<uuid>-<timestamp>.json.gz
```

Send that file back:

1. In CloudShell: **Actions → Download file**, paste the filename above
   (it sits in `~/Preflight/`).
2. Reply to the CloudKeeper email with the downloaded `.json.gz` attached.

You're done.

## One-time setup: enable CloudFormation organizations access

Only needed if you plan to run with `--assess-member-accounts`. Run once
in the management account (CloudShell or local CLI):

```bash
aws cloudformation activate-organizations-access --region us-east-1
aws cloudformation describe-organizations-access --region us-east-1
# Should print {"Status": "ENABLED"}
```

Without this the `--assess-member-accounts` run fails immediately:

> `ValidationError: You must enable organizations access to operate a
> service managed stack set`

Many orgs already have it on. If yours does, the activate command is a
no-op.

## Long-running orgs (50+ accounts) — use `nohup`

Only relevant with `--assess-member-accounts`. CloudShell sessions can
time out; detach so closing your browser doesn't kill the assessment:

```bash
nohup python3 -m cloudkeeper_preflight \
  --customer-uuid <UUID-FROM-CLOUDKEEPER> \
  --customer-emails <YOUR-EMAIL> \
  --assess-member-accounts \
  > run.log 2>&1 &

# Watch progress at any time:
tail -f run.log
```

The `*.json.gz` lands in the same directory when it's done.

## What `--assess-member-accounts` does

When you pass the flag, PreFlight deploys a CloudFormation StackSet
(`CloudKeeperPreFlightStackSet-<timestamp>`) that creates one IAM role
(`CloudKeeperPreFlightReadOnlyRole`) in each member account. The role:

- Trusts **only** your management account, gated by an account-specific
  `ExternalId` of `<member-account-id>-cloudkeeper-preflight`.
- Holds `arn:aws:iam::aws:policy/ReadOnlyAccess` plus a small additional
  Allow for org / RAM / SSO list/describe APIs.
- **Cannot** make any modifications. Read-only.

When the run completes, both the role and the StackSet are deleted. If
the run is interrupted, see [Cleanup](#cleanup) below.

Without the flag, no StackSet is created and no IAM role is deployed
anywhere.

## What's in the output

Always included (management-account-only assessment):

- Organization metadata, OU tree, account list with OU paths.
- All five organization-policy types (SCP / tag / backup / AI-opt-out /
  chatbot) with content and targets.
- IAM Identity Center: users, groups, permission sets (with policies),
  account assignments, applications.
- Trusted-access services, delegated administrators, and per-service
  organization configuration (CloudTrail org trails, GuardDuty admin,
  etc.).
- RAM resource shares at the org level.
- Existing CloudFormation StackSets.
- AWS Config aggregators.
- Previous month's costs (excluding Marketplace + Tax), per account, per
  service, and the list of **currently active** cost-allocation tags.
- Resource-based policies in the management account that reference the
  org or any OU.
- **Seller of record** for the management account — which AWS legal
  entity bills you (from `taxsettings:ListTaxRegistrations`, filtered
  to the management account).
- **Budget alerts** in the management account — every budget with its
  notification thresholds and email/SNS subscribers.
- **EKS charges over the last 14 days** — only checked when IAM Identity
  Center is in use; flagged if any nonzero EKS spend is observed. Signals
  a Kubernetes footprint that changes the onboarding conversation.
- A `management_account_coverage_gaps` list: distinct
  `(service, operation)` pairs we couldn't read. Usually these are SCP
  denials, which is expected and tells us where to ask follow-up
  questions.

Additionally included with `--assess-member-accounts`:

- Per-member-account: deep IAM scan (trust + managed + inline), RAM
  shares, resource policies, and delegated-service configuration where
  applicable.
- A per-account `coverage_gaps` list, same format as above.

To inspect locally before sending:

```bash
gunzip -c cloudkeeper-preflight-assessment-*.json.gz | python3 -m json.tool | less
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ValidationError: You must enable organizations access...` | One-time setup not done (only relevant with `--assess-member-accounts`). | Run the `activate-organizations-access` command above. |
| `Bootstrap done` then long pause | Normal for `--assess-member-accounts` runs — Phase 1 scans the management account while Phase 2 deploys the StackSet. | Wait. `[member]` log lines appear once StackSet instances go ready. |
| `[member] failed <account_id>` | Couldn't assume role — usually the per-account stack instance failed. | Re-run; if it still fails, send the output anyway and note the account ID. |
| Many `partial` statuses | Expected. Your SCPs denied some scanner calls; the per-account `coverage_gaps` list captures which. | No action needed. |
| CloudShell session timed out mid-run | Browser closed or 12-hour limit hit. | Use the `nohup` pattern above. |

### Cleanup

Only relevant with `--assess-member-accounts`. If the tool is interrupted
(Ctrl-C, browser close without `nohup`, session timeout), the StackSet
may still be deployed. List any leftover StackSets:

```bash
aws cloudformation list-stack-sets \
  --region us-east-1 --status ACTIVE \
  --query "Summaries[?contains(StackSetName, 'CloudKeeperPreFlight')]"
```

If anything appears, re-running PreFlight will reuse and clean up its own
StackSet, or send us the StackSet name and we'll talk you through it.

## Scope and partition limits

- `SERVICE_MANAGED` StackSets do not cross AWS partitions. Even with
  `--assess-member-accounts`, GovCloud and China member accounts can't
  be assessed by the same management-account run; let CloudKeeper know
  if you operate in those partitions.
- The assessor reads only — no resources are created or modified anywhere
  in the default (management-only) mode. In `--assess-member-accounts`
  mode, the temporary role and StackSet are the only things created, and
  both are deleted at the end.

## License

Apache-2.0. See [LICENSE](LICENSE).
