# CloudKeeper PreFlight

A read-only assessor for your AWS Organization. Runs from your management
account and produces one JSON file describing every dependency CloudKeeper
needs to plan your onboarding.

**Nothing is created. Nothing is deployed. Nothing persistent.** Only
`Describe*`, `Get*`, `List*` API calls from your CloudShell session.

Source is public — your security team can review it before you run.

## What you'll need

- AWS Console access to your organization's **management account**. Standard
  `ReadOnlyAccess` is sufficient; most admins have it.
- A **customer UUID** and your **contact email** — CloudKeeper sends these
  in a single one-line command.
- ~1–2 minutes of wall clock.

## Run it (CloudShell — recommended)

Open AWS CloudShell in your management account and paste the one-line
command CloudKeeper sent you. It looks like this (the UUID and email are
already substituted in the version you receive):

```bash
git clone --depth 1 https://github.com/CloudKeeper-Inc/Preflight.git && cd Preflight && python3 -m venv .venv && .venv/bin/pip install --quiet . && .venv/bin/python3 -m cloudkeeper_preflight --customer-uuid <UUID-FROM-CLOUDKEEPER> --customer-emails <YOUR-EMAIL> --api-endpoint https://preflight.cloudkeeper.com/v1/submit 2>&1 | tee run.log
```

When the run finishes successfully, the last line is:

```
[Submission] Submitted to https://preflight.cloudkeeper.com/v1/submit (HTTP 201)
```

That's it — the assessment lands with CloudKeeper automatically. An
analyst will reach out within one business day.

### Review before submitting

If you'd rather inspect the assessment JSON before sending it to us — for
example, if your outbound network policy blocks `preflight.cloudkeeper.com`,
or you want your security team to review — **omit** the `--api-endpoint`
argument. The tool writes
`cloudkeeper-preflight-assessment-<uuid>-<timestamp>.json.gz` in the
working directory instead of submitting. Download it via CloudShell's
**Actions → Download file** and email it to your CloudKeeper contact.

To inspect locally:

```bash
gunzip -c cloudkeeper-preflight-assessment-*.json.gz | python3 -m json.tool | less
```

## What's in the output

- Organization metadata, OU tree, account list with OU paths.
- Which regions were assessed, which were skipped, and the previous-month
  spend each decision was based on.
- All five organization-policy types (SCP / tag / backup / AI-opt-out /
  chatbot) with content and targets.
- IAM Identity Center: whether it's in use, in which region, how many
  users, groups, permission sets, and account assignments exist. Counts
  only — no usernames, email addresses, group membership, or policy
  content is collected. Plus, for every ENABLED application on the IdC
  instance (both AWS-managed like SageMaker Studio and customer-managed
  SAML / OAuth apps — all of these require re-registration on the new
  SSO at cutover; nothing transfers automatically), its name, provider,
  and the number of users and groups assigned to it, with an
  informational flag distinguishing AWS-managed from customer-managed
  by the provider ARN.
- Trusted-access services, delegated administrators, and per-service
  organization configuration for the 22 org-scoped services PreFlight
  understands (CloudTrail org trails, GuardDuty delegation, Config org
  rules and conformance packs, Security Hub CSPM standards and finding
  aggregators, Macie, Firewall Manager policies, and more).
- RAM resource shares at the org level — both outbound (owned by an
  account in your org) and inbound (shared into your org from outside).
- Existing CloudFormation StackSets (both service-managed and
  self-managed), excluding any PreFlight has deployed.
- AWS Config aggregators.
- Previous month's total cost for the organization, excluding Marketplace
  and Tax, plus the list of currently active cost-allocation tags. One
  organization-wide figure — no per-account or per-service breakdown.
- Resource-based policies that reference the organization, any OU, or an
  Identity Center role, across 31 surfaces: S3 (including S3 Express
  directory buckets and access points), S3 Tables, SNS, SQS, Lambda, KMS,
  ECR (repository and registry), Secrets Manager, EventBridge, Backup,
  API Gateway, VPC endpoints, VPC Lattice, OpenSearch (managed domains and
  Serverless data access policies), Glue, EFS, SES, SES v2, Glacier,
  CloudWatch cross-account observability sinks, CodeArtifact, CodeBuild,
  Kinesis, MSK, DynamoDB, Signer, SageMaker Model Registry, plus IAM role
  trust policies and customer-managed policies.
- Lake Formation data lake admins, grants, and its Identity Center
  integration. These live in Lake Formation's own permission store rather
  than in a resource policy, so the Glue catalog check does not cover them.
- **Resource tags** whose key or value names the organization or an
  Identity Center identity — for example `Owner=jane.doe` or
  `CreatedBy=AWSReservedSSO_Admin_…`. Chargeback, cleanup automation and
  attribute-based access control are commonly keyed off these, and the tag
  text survives a migration while the identity it names does not. Only
  matching tags are recorded; tags whose key begins with `aws:` are skipped
  entirely, as those are AWS-generated and cannot be repointed.
- Services wired directly to IAM Identity Center, asked service by service
  rather than inferred: QuickSight, SageMaker Studio, EMR Studio, Managed
  Grafana, DataZone, Athena workgroups, WorkSpaces (directories, Web and
  Thin Client), re:Post Private, Supply Chain, Q Business, IoT TwinMaker,
  IoT SiteWise Monitor, MWAA, Redshift, Deadline Cloud, Kendra, WorkMail
  and Transfer Family web apps. These bind to the Identity Center instance
  rather than storing a role ARN, so no policy scan can find them.
  Configuration only — no user lists, no content.
- **Seller of record** for the management account — which AWS legal
  entity bills you (from `taxsettings:ListTaxRegistrations`, filtered to
  the management account). Only the seller name is kept; the VAT/GST
  registration details the same API returns are discarded.
- **Budget alerts** — every budget in the management account with its
  notification thresholds and email / SNS subscribers.
- **EKS charges over the last 14 days** — checked when IAM Identity
  Center is in use; flagged when there's non-zero EKS spend. Signals a
  Kubernetes footprint that shapes the onboarding conversation.
- **EKS Access Entries** for every cluster in the management account —
  enumerated to find any that reference `AWSReservedSSO_*` role ARNs
  directly (those role names carry a generated suffix that changes when
  Identity Center is re-provisioned). Clusters still using the legacy
  `aws-auth` ConfigMap are also flagged for manual `kubectl` inspection,
  since the ConfigMap contents are not readable from a read-only IAM
  role.
- A `management_account_coverage_gaps` list of `(service, operation)`
  pairs we couldn't read. Usually SCP denials — expected — and tells us
  where to ask follow-up questions.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Bootstrap done` then a long-looking pause | Normal — Phase 1 runs the 12 management-account scanners in parallel. | Wait ~30–60 seconds; per-scanner summaries print as they finish. |
| Many `AccessDenied` entries in the run log | Your SCPs denied some scanner calls; each is captured under `management_account_coverage_gaps`. | No action needed. |
| `[Submission] HTTP 403` | The customer UUID isn't whitelisted (or has been disabled). | Ping your CloudKeeper contact. |
| `[Submission] HTTP 429` — cooldown-active | Same UUID submitted less than 5 minutes ago. | Wait and retry, or your contact re-runs from their end. |
| `[Submission] Saved cloudkeeper-preflight-...` | The submission POST failed for any reason (network, backend outage, etc.) and the tool fell back to local. | Download the `.json.gz` (CloudShell → Actions → Download file) and email it to your CloudKeeper contact. |
| `ERROR: PreFlight must be run in the management account of the organization.` | You ran this in a member account by mistake. | Sign in to the management account and re-run. The error message tells you the correct management account ID and root email. |

## Deeper assessment (member accounts too)

When CloudKeeper specifically asks for the deeper assessment that also
inspects every member account, see **[MEMBER_ASSESSMENT.md](MEMBER_ASSESSMENT.md)**.
That mode is opt-in and deploys a temporary read-only IAM role in each
member account via CloudFormation StackSets. It is not part of the
default onboarding flow.

## FAQ

### Security & access

**Q: Is it really read-only?**
Yes. The tool makes only `Describe*`, `Get*`, `List*` API calls. Source
is public at https://github.com/CloudKeeper-Inc/Preflight — your security
team can grep for `create_`, `put_`, `update_`, `delete_` and confirm no
such calls exist against your account. Standard `ReadOnlyAccess` is
sufficient; nothing broader.

**Q: Does it deploy any resources, create IAM roles, or leave anything
behind?**
No. In the default management-account-only mode there are zero writes —
no CloudFormation stacks, no StackSets, no IAM roles, no S3 buckets.
When it finishes, the only footprint is a shell-history entry in
CloudShell and a burst of `Describe*` / `Get*` / `List*` entries in
CloudTrail — the same shape as any admin poking around the console.

**Q: Can it touch my member accounts?**
Not in this mode. The command you're given is scoped to the management
account only. The deeper member-account assessment lives in a separate
mode ([MEMBER_ASSESSMENT.md](MEMBER_ASSESSMENT.md)) that is opt-in and
not part of the default flow.

**Q: What credentials does it use?**
Whatever your CloudShell session inherits — your AWS Console identity.
It never asks for or handles long-lived access keys, and you don't need
to create any IAM role for CloudKeeper.

**Q: Will it trigger my GuardDuty / SIEM / Security Hub?**
Unlikely. It's a burst of standard read APIs from a CloudShell IP. If
your SIEM specifically alerts on high-volume `List*` from a new IP,
whitelist the CloudShell egress or expect a benign notification. No IAM
changes, no privileged actions.

### Data & privacy

**Q: What data leaves my environment?**
The output JSON contains: your Org ID, account IDs and names,
root-user emails on your accounts, OU tree, policy content (SCPs / tag /
backup / AI-opt-out / chatbot policies verbatim), IAM Identity Center
object counts, RAM share ARNs, StackSet names, per-service organization
configuration (CloudTrail trail names + S3 buckets, GuardDuty detector
IDs, Config aggregator names, Security Hub standards, etc.), your
organization's previous-month total spend, budget subscribers, seller of
record, and cost-allocation tag keys.

**Not captured:** KMS key material, secret values, IAM access keys,
resource-level tags on individual EC2/RDS instances, or any of your
application data. Also deliberately not captured: IAM Identity Center
usernames, email addresses, group membership, and permission-set policy
documents (we take counts only); per-account or per-service cost
breakdowns (only the organization total); and your VAT/GST registration
details (only the AWS seller name).

**Q: Where does the data go?**
POSTed over TLS 1.2+ to `preflight.cloudkeeper.com/v1/submit`. Stored in
an encrypted-at-rest S3 bucket (AES-256, versioned, block-public-access,
TLS-enforcing bucket policy) in the CloudKeeper AWS account. Access is
limited to CloudKeeper analysts on `onboarding@cloudkeeper.com`.

**Q: How long is it retained?**
90 days in warm storage, then Glacier for the balance of ~1 year. You
can request deletion at any time by replying to your CloudKeeper contact.

**Q: Are you sending anything to third parties (Anthropic / OpenAI)?**
A **reduced summary** of your assessment goes to Amazon Bedrock (Claude
Sonnet 5, hosted in the CloudKeeper AWS account in `us-east-1`) so we
can auto-draft the post-assessment onboarding email. The summary contains
counts and identifiers (Org ID, account IDs, policy counts, list of
org-scoped services in use) — no policy JSON, no per-resource content,
no secrets. The full assessment JSON never leaves CloudKeeper's AWS
account.

**Q: Can I inspect the output before it's sent?**
Yes. See the "Review before submitting" section above — omit
`--api-endpoint` and the tool writes a local `.json.gz` file instead of
submitting.

### Operational

**Q: Do I need to install anything?**
Just AWS CloudShell (no installation on your side — CloudShell has
Python 3, `boto3`, and your console credentials pre-loaded). If you'd
rather run locally: Python 3.8+, clone the public repo, `pip install .`,
and AWS credentials configured for your management account.

**Q: How long does it take?**
1–2 minutes for a typical org, up to 3–5 for a very large one. No
impact on production — read APIs only.

**Q: What if my SCPs block some of the calls?**
Handled gracefully. `AccessDenied` errors are captured as
`management_account_coverage_gaps` in the output; the run continues.
Genuine transient errors (network blips, transient AWS 500s) retry up
to 5 times with adaptive backoff.

**Q: What if it fails mid-run?**
No cleanup on your side — nothing has been created. Just re-run the
command; it's idempotent.

**Q: What does it cost me?**
Trivial. AWS Cost Explorer API charges apply (~$0.03 per run, for three
`GetCostAndUsage` calls and one `ListCostAllocationTags`). All other APIs
used — Organizations, IAM Identity Center, Budgets, tax settings, Config,
RAM, StackSets — are free reads.

**Q: Does it scan every region?**
No. PreFlight reads your previous month's spend broken down by region and
scans only the regions costing more than $1, plus `us-east-1` (where
global services like IAM and CloudFront bill). Most organizations have a
dozen or more regions enabled and real workloads in three or four, so
this cuts the run time substantially without changing what's found. The
output records exactly which regions were scanned and which were skipped,
along with the figure each decision was based on. If Cost Explorer isn't
available, PreFlight falls back to scanning every enabled region.

### Follow-up

**Q: What happens after I submit?**
Within one business day, an analyst reviews the assessment and sends you
a structured onboarding email covering: what we found, actions you need
to take before we can take over management (e.g. reinstating closed
accounts, exporting Cost Explorer history), and reconfiguration
recommendations for org-scoped services — presented as three options
(CloudKeeper Prism / CloudKeeper does the reconfiguration for you via a
scoped IAM role / your team does it, with per-service walk-throughs).
We then schedule a call to work through anything ambiguous.

**Q: Is this optional?**
No — running PreFlight is a prerequisite for onboarding. It's the
concrete data we need to plan the transition without a lengthy
back-and-forth on org structure and dependencies.

## License

Apache-2.0. See [LICENSE](LICENSE).
