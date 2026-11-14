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

Confirm:

- **Cloud estate:** AWS account IDs and Organisations, Azure tenant and subscriptions, GCP org and projects, plus any
  "other" providers (DigitalOcean, OCI, Cloudflare, Alibaba, Supabase, Firebase, Vercel, Netlify…).
- **Brand tokens:** company, product and project names used in resource naming. These feed name-based discovery.
- **Mode:** `passive` (OSINT plus metadata-only probes) or `active` (authorised status-code probes). The **inside-out**
  steps are always run by, or with, the owner's read-only credentials. Never use credentials you discovered.
- **A "stranger" account:** a cloud account you control that is **outside** the org, used to see what the world sees
  (public snapshots and images) without touching target data. It is optional but powerful.

## 1. Discover

Work from three directions and merge the results.

### 1a. From names (OSINT)

- Collect resource names the org already leaks: CNAME targets, CSP and CORS headers, JS bundles, mobile app configs,
  IaC in public repos, Postman collections, documentation, job posts.
- Provider host patterns to grep for: `*.s3*.amazonaws.com`, `*.blob.core.windows.net`, `storage.googleapis.com`,
  `*.firebaseio.com`, `*.supabase.co`, `*.lambda-url.*.on.aws`, `*.execute-api.*.amazonaws.com`, `*.azurewebsites.net`,
  `*.run.app`, `*.eks.amazonaws.com`, `*.azmk8s.io`, `*.r2.dev`, `*.digitaloceanspaces.com`,
  `objectstorage.*.oraclecloud.com`.
- **Bounded** name permutations of brand tokens (e.g. `<brand>-{backup,logs,prod,dev,static,assets,data}`) for
  **existence-only** checks. Keep the list small and explainable. A permutation hit is **A3 until proven otherwise**:
  similar names are often owned by strangers.

### 1b. From the outside view of owned assets

- `exposed-services` findings on IPs inside cloud ranges become cloud findings too (`cloud-fw-open-admin`,
  `aws-rds-public`, `unexpected-public-ip`).
- DNS zone walk (an inside-out export is best): resolve every CNAME and A record and match the targets against cloud
  patterns. This feeds `dangling-dns-cloud` and `dangling-a-record-cloud-ip`.

### 1c. From identities and secrets

- Org code, packages, images, CI logs, Postman, paste sites: search for key formats (AKIA/ASIA, Azure client secrets,
  `"type": "service_account"`, SAS `sig=`, LLM provider keys).
- **Attribute leaked AWS keys without using them:** `aws sts get-access-key-info --access-key-id <AKIA…>` run with
  **your own** audit credentials returns the owning account ID.

## 2. Attribute

Cloud names are global and squat-able. Attribute before you probe:

| Evidence | Level |
|---|---|
| Resource appears in the owner's inside-out inventory | **A1** |
| Resource is referenced by an A1 asset (our site loads from it, our DNS CNAMEs to it, our repo configures it) | **A2** |
| Name similarity only | **A3**: attribution queue, existence check only |

## 3. Validate: outside-in, least touch

- Run the catalog entry's `proof.cmd`. For storage this is a **listing call capped at one key** that records the
  status code and key names or count only. **Never download objects.**
- For snapshots and images, prefer the `stranger` command. It proves public sharing from a neutral account without
  touching the data.
- For leaked secrets, **parse offline** (SAS expiry and permissions, key type, account ID). Never call an API with them.
- For publishable identifiers (Firebase apiKey, Supabase anon key, Cognito pool ID), use them only the way the public
  app does, and only for metadata (`?shallow=true`, `Prefer: count=exact` with `Range: 0-0`).
- Write tests (PUT, upload) are **never** used. Write exposure is proven inside-out from the policy or ACL.

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

- **Leaked credentials:** watch DET0546 (cloud account abuse), DET0531 (additional cloud credentials), DET0319
  (cloud account creation), DET0147 (cloud service hijacking / LLMjacking) and T1535 (unused regions) on the
  affected account **from the leak date**, not just from today.
- **Public snapshots and images:** DET0573 (transfer to cloud account). If the asset was public for any period,
  treat its secrets as compromised regardless of whether access logs show a copy.
- **Firewall drift:** DET0424 (cloud firewall modification) catches attackers *re-opening* what you closed.

Then pass the findings to **exposure-triage**.

## 7. Incident triggers: stop and escalate

Stop and escalate to IR (force P1) if you see any of:

- ransom notes or unexpected objects such as `README_TO_RESTORE` in a bucket listing;
- a leaked key with CloudTrail activity from unknown IPs;
- a subdomain already serving attacker content;
- new public snapshots of production disks that nobody can explain.

## Output format (per finding)

Shaped to validate against `schemas/finding.schema.json` (shown as YAML for readability; emit JSON for tooling):

```yaml
finding_id: OI-2026-0157
catalog_id: aws-ebs-snapshot-public
asset: {provider: aws, account: "111122223333", region: eu-west-2, resource: "snap-0abc1234def567890",
        attribution: A1, attribution_basis: "owner account in AWS Organization", in_inventory: true,
        owner: "Payments Platform", environment: prod}
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
