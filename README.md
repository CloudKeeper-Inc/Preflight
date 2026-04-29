# CloudKeeper PreFlight

A read-only assessor that walks your AWS Organization and produces one JSON
file describing every dependency CloudKeeper needs to plan your onboarding.
Runs from your management account, scans member accounts through a temporary
read-only role, and tears everything down when it's finished.

## What you'll need

- AWS Console access to your organization's **management account** with
  permissions to deploy CloudFormation StackSets and list organization
  resources.
- A **customer UUID** and **contact emails** — CloudKeeper sends these.
- The CloudFormation organizations-access integration enabled in the
  management account (one-time setup; see below).
- ~30 minutes of wall-clock time for a 50-account org. Larger orgs scale
  roughly linearly.

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

Run once in the management account (CloudShell or local CLI):

```bash
aws cloudformation activate-organizations-access --region us-east-1
aws cloudformation describe-organizations-access --region us-east-1
# Should print {"Status": "ENABLED"}
```

Without this the run fails immediately:

> `ValidationError: You must enable organizations access to operate a
> service managed stack set`

Many orgs already have it on. If yours does, the activate command is a
no-op.

## Long-running orgs (50+ accounts) — use `nohup`

CloudShell sessions can time out. For long runs, detach so closing your
browser doesn't kill the assessment:

```bash
nohup python3 -m cloudkeeper_preflight \
  --customer-uuid <UUID-FROM-CLOUDKEEPER> \
  --customer-emails <YOUR-EMAIL> \
  > run.log 2>&1 &

# Watch progress at any time:
tail -f run.log
```

The `*.json.gz` lands in the same directory when it's done.

## What gets created (and torn down)

While running, PreFlight deploys a CloudFormation StackSet
(`CloudKeeperPreFlightStackSet-<timestamp>`) that creates one IAM role
(`CloudKeeperPreFlightReadOnlyRole`) in each member account. The role:

- Trusts **only** your management account, gated by an account-specific
  `ExternalId` of `<member-account-id>-cloudkeeper-preflight`.
- Holds `arn:aws:iam::aws:policy/ReadOnlyAccess` plus a small additional
  Allow for org / RAM / SSO list/describe APIs.
- **Cannot** make any modifications. Read-only.

When the run completes, both the role and the StackSet are deleted. If
the run is interrupted, see [Cleanup](#cleanup) below.

## What's in the output

The gzipped JSON contains:

- Organization metadata, OU tree, account list with OU paths.
- All five organization-policy types (SCP / tag / backup / AI-opt-out /
  chatbot) with content and targets.
- IAM Identity Center: users, groups, permission sets (with policies),
  account assignments, applications.
- Trusted-access services, delegated administrators, and per-service
  organization configuration (CloudTrail org trails, GuardDuty admin,
  etc.).
- RAM resource shares (org and member-level).
- Existing CloudFormation StackSets.
- AWS Config aggregators.
- Previous month's costs (excluding Marketplace + Tax), per account, per
  service.
- Resource-based policies in the management account that reference the
  org or any OU.
- Per-member-account: deep IAM scan (trust + managed + inline), RAM
  shares, resource policies, and delegated-service configuration where
  applicable.
- A `coverage_gaps` list per account: distinct `(service, operation)`
  pairs we couldn't read. Usually these are SCP denials, which is
  expected and tells us where to ask follow-up questions.

To inspect locally before sending:

```bash
gunzip -c cloudkeeper-preflight-assessment-*.json.gz | python3 -m json.tool | less
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ValidationError: You must enable organizations access...` | One-time setup not done. | Run the `activate-organizations-access` command above. |
| `Bootstrap done` then long pause | Normal — Phase 1 scans the management account while Phase 2 deploys the StackSet. | Wait. `[member]` log lines appear once StackSet instances go ready. |
| `[member] failed <account_id>` | Couldn't assume role — usually the per-account stack instance failed. | Re-run; if it still fails, send the output anyway and note the account ID. |
| Many `partial` statuses | Expected. Your SCPs denied some scanner calls; the per-account `coverage_gaps` list captures which. | No action needed. |
| CloudShell session timed out mid-run | Browser closed or 12-hour limit hit. | Use the `nohup` pattern above. |

### Cleanup

If the tool is interrupted (Ctrl-C, browser close without `nohup`,
session timeout), the StackSet may still be deployed. List any leftover
StackSets:

```bash
aws cloudformation list-stack-sets \
  --region us-east-1 --status ACTIVE \
  --query "Summaries[?contains(StackSetName, 'CloudKeeperPreFlight')]"
```

If anything appears, re-running PreFlight will reuse and clean up its own
StackSet, or send us the StackSet name and we'll talk you through it.

## Scope and partition limits

- `SERVICE_MANAGED` StackSets do not cross AWS partitions. GovCloud and
  China member accounts can't be assessed by the same management-account
  run; let CloudKeeper know if you operate in those partitions.
- The assessor reads only — no resources are created or modified outside
  the temporary role and StackSet, both of which are deleted at the end.

## License

Apache-2.0. See [LICENSE](LICENSE).
