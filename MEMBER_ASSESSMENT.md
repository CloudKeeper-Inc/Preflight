# PreFlight — Member-Account Deep Assessment

The base PreFlight assessment (see [README.md](README.md)) inspects only
your **management account** and is enough for most onboardings.

This document describes the deeper mode that also inspects every member
account in your organization. **Only run this when your CloudKeeper
contact explicitly asks for it.**

## What's different

The command is the same as the base assessment plus one flag:
`--assess-member-accounts`. This mode deploys a temporary CloudFormation
StackSet with a read-only IAM role in each member account, runs
per-account scans, and tears the StackSet down when it's done.

## What you'll need (in addition to the base assessment)

- CloudFormation permissions in the management account (deploy StackSets).
- The CloudFormation organizations-access integration enabled — one-time
  setup, see below.
- Wall-clock time: ~30 minutes for a 50-account org; scales roughly
  linearly with account count.

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

## Run it

```bash
git clone --depth 1 https://github.com/CloudKeeper-Inc/Preflight.git && cd Preflight && python3 -m venv .venv && .venv/bin/pip install --quiet . && .venv/bin/python3 -m cloudkeeper_preflight --customer-uuid <UUID-FROM-CLOUDKEEPER> --customer-emails <YOUR-EMAIL> --api-endpoint https://preflight.cloudkeeper.com/v1/submit --assess-member-accounts 2>&1 | tee run.log
```

## Long-running orgs (50+ accounts) — use `nohup`

CloudShell sessions can time out; detach so closing your browser doesn't
kill the assessment:

```bash
nohup .venv/bin/python3 -m cloudkeeper_preflight \
  --customer-uuid <UUID-FROM-CLOUDKEEPER> \
  --customer-emails <YOUR-EMAIL> \
  --api-endpoint https://preflight.cloudkeeper.com/v1/submit \
  --assess-member-accounts \
  > run.log 2>&1 &

# Watch progress at any time:
tail -f run.log
```

The submission fires as soon as the run finishes.

## What `--assess-member-accounts` does

The tool deploys a CloudFormation StackSet
(`CloudKeeperPreFlightStackSet-<timestamp>`) that creates one IAM role
(`CloudKeeperPreFlightReadOnlyRole`) in each member account. The role:

- Trusts **only** your management account, gated by an account-specific
  `ExternalId` of `<member-account-id>-cloudkeeper-preflight`.
- Holds `arn:aws:iam::aws:policy/ReadOnlyAccess` plus a small additional
  Allow for org / RAM / SSO list/describe APIs.
- **Cannot** make any modifications — read-only.

When the run completes, both the role and the StackSet are deleted.

## Additional output (on top of the base assessment)

- Per-member-account: deep IAM scan (trust + managed + inline), RAM
  shares (both directions), resource policies (16 services + IAM
  globals), and delegated-service configuration where the account is a
  delegated administrator.
- A per-account `coverage_gaps` list — same format as
  `management_account_coverage_gaps` in the base assessment.

## Cleanup

If the tool is interrupted (Ctrl-C, browser close without `nohup`,
session timeout), the StackSet may still be deployed. List any leftover
StackSets:

```bash
aws cloudformation list-stack-sets \
  --region us-east-1 --status ACTIVE \
  --query "Summaries[?contains(StackSetName, 'CloudKeeperPreFlight')]"
```

If anything appears, re-running PreFlight will reuse and clean up its
own StackSet, or send us the StackSet name and we'll talk you through
it.

## Partition limits

`SERVICE_MANAGED` StackSets do not cross AWS partitions. GovCloud and
China member accounts can't be assessed by the same management-account
run; let CloudKeeper know if you operate in those partitions.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ValidationError: You must enable organizations access...` | One-time setup not done. | Run the `activate-organizations-access` command above. |
| `Bootstrap done` then long pause | Normal — Phase 1 scans the management account while Phase 2 deploys the StackSet. | Wait. `[member]` log lines appear as StackSet instances go ready. |
| `[member] failed <account_id>` | Couldn't assume role in that account — the per-account stack instance likely failed. | Re-run; if it still fails, send the output anyway and note the account ID. |
| Many `partial` per-account statuses | Your SCPs denied some scanner calls; per-account `coverage_gaps` captures which. | No action needed. |
| CloudShell session timed out mid-run | Browser closed or 12-hour limit hit. | Use the `nohup` pattern above. |
