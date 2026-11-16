---
name: exposed-cloud-assets
description: Defender-side discovery and confirmation of an organisation's exposed cloud assets across AWS, Azure, GCP and other providers. Covers public object storage (S3, Blob, GCS, R2, OCI), public snapshots and images (EBS, RDS, AMI, managed disks), publicly reachable managed databases and BaaS (RDS, Azure SQL, Cosmos, Cloud SQL, OpenSearch, BigQuery, Firebase, Supabase), unauthenticated serverless and API endpoints, public Kubernetes control planes, world-open security groups, dangling DNS (subdomain takeover), leaked non-human credentials and over-broad OIDC or cross-account trust, public SaaS links, and cloud AI exposure (notebooks, agents, MCP, LLM keys). Pairs every outside-in check with a read-only inside-out command the owning team runs, plus an org-wide guardrail, all mapped to MITRE ATT&CK Enterprise v20.1. Use when asked to find public buckets or blobs, public snapshots or AMIs, exposed cloud databases, Lambda URLs without auth, public EKS/AKS/GKE APIs, leaked AWS keys, subdomain takeover, or general cloud exposure for our accounts.
---

# Exposed cloud assets: outside-in, confirmed inside-out

You are working **for the cloud owner**. Every cloud exposure finding has three parts:

1. **Outside-in evidence**: what anyone on the internet can see.
2. **Inside-out confirmation**: a read-only command the owning team runs in their own account (rung E4).
3. **Guardrail**: the org-wide preventive control that stops the whole class from recurring.

A finding missing any of the three is incomplete. Point 3 is what turns a weekly whack-a-mole into a closed class.

**Knowledge base location:** look for `catalog/` and `docs/` at the root of the `outside-in` repo (when working inside
it). Otherwise look in `~/.claude/skills/outside-in-kb/`. The cloud knowledge base is `catalog/cloud-assets.yaml`.
Rules of engagement, attribution, the evidence ladder and EPS are in `docs/methodology.md`.

## 0. Scope

| Confirm | Detail |
|---|---|
| **Cloud estate** | AWS accounts and Organizations, Azure tenant and subscriptions, GCP org and projects, plus "other" providers (DigitalOcean, OCI, Cloudflare, Supabase, Firebase, Vercel, Netlify…) |
| **Brand tokens** | Company, product and project names used in resource naming. They drive name-based discovery |
| **Mode** | `passive` (OSINT + metadata-only probes) or `active` (authorised status-code probes). Inside-out steps always use the owner's read-only credentials, never discovered ones |
| **Stranger account** (optional) | A cloud account you control *outside* the org, to see what the world sees (public snapshots and images) without touching target data |

## 1. Discover

Work from three directions and merge the results.

| Direction | Where to look | Feeds |
|---|---|---|
| **From names** (OSINT) | Resource names the org already leaks: CNAME targets, CSP/CORS headers, JS bundles, mobile app configs, public IaC, Postman, docs, job posts. Grep for `*.s3*.amazonaws.com`, `*.blob.core.windows.net`, `storage.googleapis.com`, `*.firebaseio.com`, `*.supabase.co`, `*.lambda-url.*.on.aws`, `*.execute-api.*.amazonaws.com`, `*.azurewebsites.net`, `*.run.app`, `*.eks.amazonaws.com`, `*.azmk8s.io`, `*.r2.dev`, `*.digitaloceanspaces.com`, `objectstorage.*.oraclecloud.com` | Storage, serverless, K8s classes |
| | A small, explainable set of brand permutations (`<brand>-{backup,logs,prod,dev,static,assets,data}`), **existence-only**. A hit is **A3 until proven otherwise**, because lookalike names often belong to strangers | Attribution queue |
| **From owned assets** | `exposed-services` findings on IPs inside cloud ranges | `cloud-fw-open-admin`, `aws-rds-public`, `unexpected-public-ip` |
| | DNS zone walk (inside-out export is best): resolve every CNAME and A record and match targets to cloud patterns | `dangling-dns-cloud`, `dangling-a-record-cloud-ip` |
| **From identities and secrets** | Org code, packages, images, CI logs, Postman, paste sites: AKIA/ASIA keys, Azure client secrets, `"type": "service_account"`, SAS `sig=`, LLM keys | `leaked-cloud-credentials`, `llm-api-keys` |
| | Attribute a leaked AWS key **without using it**: `aws sts get-access-key-info --access-key-id <AKIA…>` with *your own* audit credentials returns the owning account | Attribution |

## 2. Attribute

Cloud names are global and squat-able. Attribute before you probe:

| Evidence | Level |
|---|---|
| Resource appears in the owner's inside-out inventory | **A1** |
| Resource is referenced by an A1 asset (our site loads from it, our DNS CNAMEs to it, our repo configures it) | **A2** |
| Name similarity only | **A3**: attribution queue, existence check only |

## 3. Validate: outside-in, least touch

| Asset type | How to validate | Never |
|---|---|---|
| Storage | The entry's `proof.cmd`: a listing call capped at one key. Record the status code and key names or count | Download objects |
| Snapshots and images | The `stranger` command, from a neutral account | Copy, restore or launch |
| Leaked secrets | Parse offline: SAS expiry and permissions, key type, account ID | Call any API with them |
| Publishable IDs (Firebase apiKey, Supabase anon key, Cognito pool ID) | Use them only as the public app does, metadata only (`?shallow=true`, `Prefer: count=exact` + `Range: 0-0`) | Page through data |
| Write exposure | Prove it inside-out from the policy or ACL | PUT or upload to "test" |

## 4. Confirm inside-out (E4)

Give the owner the entry's `inside_out` command(s), filled in with their resource names. Ask them to paste back the
output, or run it yourself if you have been given **read-only** audit credentials for that account (e.g. SecurityAudit
/ ViewOnlyAccess, Reader, roles/iam.securityReviewer + roles/viewer).

Where the org has CSPM or posture tooling (AWS Security Hub, IAM Access Analyzer, Defender for Cloud, Security Command
Center, or Prowler / ScoutSuite / Steampipe), cross-check the finding there. **Agreement** between outside-in evidence
and CSPM is strong evidence. **Disagreement** is itself a finding: the CSPM is blind to that account, region or
provider.

## 5. Guardrail recommendation

For each finding, quote the entry's `guardrail` and state whether it is **already in place** (inside-out check), so
the fix is "close the instance + close the class". When the same class appears in more than one account, recommend
enforcing the guardrail at the org, management-group or folder level (SCP, declarative policy, Azure Policy at MG root,
GCP org policy) rather than per account.

## 6. ATT&CK mapping and hand-off

Copy `attack`, `soc_watch` and `mitigations` from the entry. Cloud specifics worth calling out to the SOC:

| Situation | Tell the SOC to watch | Note |
|---|---|---|
| Leaked credentials | DET0546 cloud account abuse · DET0531 added cloud credentials · DET0319 new cloud accounts · DET0147 cloud service hijacking (LLMjacking) · activity in unused regions (T1535) | Look back **from the leak date**, not from today |
| Public snapshots or images | DET0573 transfer to another cloud account | If it was ever public, treat its secrets as compromised, logs or no logs |
| Firewall drift | DET0424 cloud firewall modification | Catches attackers *re-opening* what you closed |

Then pass the findings to **exposure-triage**.

## 7. Incident triggers: stop and escalate

Stop probing and escalate to IR (force P1) on any of these:

| Trigger | Example |
|---|---|
| Ransom note in storage | `README_TO_RESTORE` or unexpected objects in a bucket listing |
| Leaked key in use | CloudTrail activity for the key from unknown IPs |
| Takeover already live | A subdomain serving attacker content |
| Unexplained public snapshots | New public snapshots of production disks |

## Output format (per finding)

Shaped to validate against `schemas/finding.schema.json` (shown as YAML for readability; emit JSON for tooling):

```yaml
finding_id: OI-2026-0157
catalog_id: aws-ebs-snapshot-public
asset: {provider: aws, account: "111122223333", region: eu-west-2, resource: "snap-0abc1234def567890",
        attribution: A1, attribution_basis: "owner account in AWS Organization", in_inventory: true,
        owner: "Payments Platform", environment: prod, controls: {edr: not-applicable}}
exposure: {reach: internet-any, window_start_utc: "2026-10-30T14:02:00Z"}
evidence:
  rung: E4
  items:
    - {rung: E3, collected_utc: "2026-11-12T10:05:00Z", source: stranger-account, vantage: "stranger acct 444455556666",
       method: "aws ec2 describe-snapshots --owner-ids 111122223333 --restorable-by-user-ids all --region eu-west-2",
       observed: "1 snapshot listed, 200 GiB, created 2026-10-30"}
    - {rung: E4, collected_utc: "2026-11-12T11:20:00Z", source: owner-cli, vantage: "payments-oncall",
       method: "aws ec2 describe-snapshot-attribute --snapshot-id snap-0abc1234def567890 --attribute createVolumePermission",
       observed: "createVolumePermission Group=all"}
attack: {version: "20.1", access: [T1537], follow_on: [T1552.001, T1552.004, T1078.004]}
soc_watch: [DET0573, DET0307, DET0549, DET0546]
mitigations: [M1018, M1041, M1054]
eps: {reach: 25, class: 25, pressure: 10, blast: 25, total: 85, overrides: [force-p1-unauth-data], band: P1}
remediation:
  fix: "Remove the public permission; rotate secrets present on the source volume"
  guardrail: "EC2 snapshot block public access (block-all-sharing), org-wide via declarative policy"
  guardrail_in_place: false
  inside_out_check: "aws ec2 describe-snapshots --owner-ids self --restorable-by-user-ids all --region eu-west-2"
status: open
first_seen_utc: "2026-11-12T10:05:00Z"
last_seen_utc: "2026-11-12T11:20:00Z"
```

## Quality bar

- Never report an A3 name-match as "your bucket is public". Say "a public bucket with a similar name exists; ownership
  unconfirmed".
- Always state the **exposure window** if it is knowable (creation date, first-seen in scan data, CloudTrail
  `Modify*Attribute`). The exposure window drives breach assessment.
- One finding per **resource**, rolled up per **class** for the exec brief ("7 public snapshots across 3 accounts; no
  org guardrail").
