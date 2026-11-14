# RB-02: Weak, leaked or stolen cloud credentials

| | |
|---|---|
| **ID / version** | RB-02 v0.1 (2026-11-14) · Priority **P0** |
| **Threat Horizons anchor** | **Weak or absent credentials = 27.2%** of initial access in Google Cloud in H2 2025 (#2 vector). Across platforms (Mandiant IR), **identity underpinned 83%** of cloud/SaaS intrusions: phishing 31% (vishing 17%), third-party / OAuth tokens 21%, **stolen human and non-human credentials 21%**, supply chain 3%. **Data theft was the objective in 73%** of cases, 45% of them *silent* (no extortion at the time). |
| **Scope** | Any credential that grants cloud, SaaS or CI/CD access: passwords on exposed logins, default credentials, cloud access keys, service-account keys, SAS / storage keys, OAuth and SaaS integration tokens, GitHub PATs, **CI/CD OIDC federation trust**, Kubernetes SA tokens, secrets in env vars. |
| **Catalog IDs** | `leaked-cloud-credentials` `llm-api-keys` `public-iac-state` `ci-public-artifacts` `oidc-trust-too-broad` `cross-account-trust-no-externalid` `cognito-unauth-identities` `registry-anonymous` `azure-sas-overpermissive` · services with login surfaces: `rdp` `ssh` `rd-web-gateway` `ssl-vpn` `mail-legacy` `grafana` `jenkins` and other default-credential classes |
| **ATT&CK v20.1 (core)** | T1078.004 Cloud Accounts · T1078.001 Default Accounts · T1110.003 Password Spraying · T1110.004 Credential Stuffing · T1552.001 Credentials In Files · T1593.003 Code Repositories · T1528 Steal Application Access Token · T1550.001 Application Access Token · T1199 Trusted Relationship · T1195.002 Compromise Software Supply Chain · T1566.004 Spearphishing Voice · T1621 MFA Request Generation · T1556.006 Modify MFA · T1580 Cloud Infrastructure Discovery · T1098.001 / T1098.003 Additional Cloud Credentials / Roles · T1136.003 Create Cloud Account · T1484.002 Trust Modification · T1535 Unused Cloud Regions · T1496.001 / T1496.004 Compute / Cloud Service Hijacking · T1530 Data from Cloud Storage · T1213.004 CRM Software · T1537 Transfer Data to Cloud Account · T1485 / T1485.001 Data Destruction / Lifecycle-Triggered Deletion · T1486 Data Encrypted for Impact · T1685.002 Disable or Modify Cloud Log · T1087.004 Cloud Account discovery · T1069.003 Cloud Groups discovery |
| **SOC watch (DET)** | DET0546 · DET0465 · DET0487 · DET0460 · DET0307 · DET0515 · DET0185 · DET0488 · DET0160 · DET0190 · DET0245 · DET0169 · DET0386 · DET0251 · DET0531 · DET0277 · DET0319 · DET0458 · DET0247 · DET0540 · DET0147 · DET0484 · DET0550 · DET0573 · DET0041 · DET0146 · DET0215 · DET0289 |
| **Hands off to** | The IR plan once misuse is confirmed · RB-01 if the credential came from an exploited workload |

---

## 0. Trigger: pick the scenario

| Scenario | Entry condition | Examples |
|---|---|---|
| **A: Weak or absent credential on an exposed login** | Exposed login surface with no MFA, a default or blank password, or spray / stuffing activity against it | RDP/SSH/VPN/OWA with password auth; Grafana or Jenkins default admin; a DB with no auth |
| **B: Leaked secret** | A credential is found outside its trust boundary | AWS key in a public repo; SA JSON in a container image; GitHub PAT in a paste; SAS URL in a ticket; a provider "exposed key" notice; a GitHub secret-scanning alert |
| **C: Abused trust or federation** | A token, integration or federation path is being, or could be, used by someone else | Over-broad GitHub→cloud **OIDC** role (the UNC6426 pattern); a compromised SaaS OAuth integration (UNC6395 / Drift pattern); a third-party role without ExternalId |
| **D: Stolen human identity** | Signs of account takeover | Help-desk MFA reset after a vishing call; MFA fatigue; impossible-travel sign-in followed by bulk data export |

**Clock:** for a *leaked* secret or *confirmed* takeover, **contain within 1 hour of discovery**. Attackers harvest
public leaks within minutes, and the report's UNC6426 went from a stolen token to cloud admin in **< 72h**. For
scenario A with no sign of misuse: contain within 24h (P1) or per EPS.

**Assume valid and assume used.** The report describes AWS keys **exposed in a 2022 password-manager breach** being
used for access in **late 2025**. The age of a key is not evidence that it is safe.

---

## 1. Roles

| Step | ASM lead | Identity / cloud owner | SOC | IR lead | Privacy / Legal |
|---|---|---|---|---|---|
| 2.1 Attribute and scope | **R/A** | C | I | I | – |
| 2.2 Contain | C | **R** | C | **A** | – |
| 3 Hunt | C | C | **R** | **A** | I |
| 3.3 Data-theft assessment | I | C | C | **A** | **R** (notification decision) |
| 4 Rotate and harden | I | **R/A** | I | C | – |
| 5 Verify | **R/A** | C | C | I | – |

---

## 2. First 60 minutes

### 2.1 Attribute and scope (≤ 15 min)

**Do not use the credential to "test" it.** Attribute it with your own access:

| Credential | How to attribute without using it |
|---|---|
| AWS access key (AKIA… / ASIA…) | `aws sts get-access-key-info --access-key-id <key>` with **your** credentials returns the account. In the owning account, `aws iam get-access-key-last-used` returns the user and last use |
| GCP service-account key JSON | `client_email` and `private_key_id` fields → `gcloud iam service-accounts keys list --iam-account <sa>` |
| Azure app secret / cert | Tenant and client ID from the leak context → `az ad app credential list --id <appId>` |
| Storage key / SAS | Account name in the URL → owning subscription via Resource Graph |
| GitHub PAT | Org admins: the PAT and fine-grained token audit in org settings. GitHub secret-scanning alerts give the token type |
| OAuth / SaaS integration | Connected-app inventory in the SaaS admin console (Salesforce, Workspace, M365 enterprise apps) |
| OIDC trust | Role or WIF provider named in the public workflow file → trust policy (inside-out) |

Then answer: **What can it reach?** Run a permission analysis of the identity (IAM Access Analyzer / Policy Analyzer /
Entra role assignments) and record the blast radius before you contain.

### 2.2 Contain (≤ 45 min), reversible first

| Credential | Contain (**change**) | Notes |
|---|---|---|
| AWS long-term key | **Deactivate** the key (do not delete yet; keep it for log correlation) | If AWS has attached an `AWSCompromisedKeyQuarantine*` policy, leave it until rotation is done |
| AWS temporary creds (ASIA…) / role session | **Revoke active sessions** for the role (an IAM deny on `aws:TokenIssueTime`, the console's "Revoke active sessions") | Temporary keys cannot be deactivated |
| GCP SA key | **Disable** the key, then delete it after investigation | Google Cloud auto-disables SA keys it detects as publicly exposed by default (`iam.serviceAccountKeyExposureResponse`). Confirm it did, and don't rely on it |
| Azure app secret | Remove the credential (`az ad app credential delete`). Revoke refresh tokens for users | Review recently **added** credentials too (attacker persistence) |
| Storage key / SAS | Rotate the signing key, or revoke user-delegation keys | Every SAS signed with that key dies. Coordinate with the app owner |
| GitHub PAT | Revoke. If it is org-wide, audit org tokens | Check whether it reached CI secrets or cloud OIDC (scenario C) |
| OIDC trust (scenario C) | Add a deny on the role, or tighten the trust policy now: pin `sub` to `repo:<org>/<repo>:ref:refs/heads/<branch>` or an environment | Pinning can break pipelines, so tell the CI owners |
| SaaS OAuth app | Revoke the app's tokens and disable the connected app | Third-party / supply chain = 21% of cases in the report |
| Human account (scenario D) | Disable, or force a reset **and** revoke all sessions and tokens. Re-register MFA with a **phishing-resistant** factor | Verify identity out-of-band. Don't trust the caller who "lost their phone" |
| Weak credential on an exposed service (A) | Remove internet exposure or enforce MFA / IAP. Change the default or weak password | RB-01 §2.3 options apply |

**Before and during containment:** confirm cloud audit logs are intact and exported. Threat actors disable logging
(T1685.002 · DET0289).

---

## 3. Investigation: hunt from the *exposure* time

> **Look-back start** = the earliest of: when the secret was committed or published; when the integration or vendor
> was compromised; the first anomalous sign-in. **Not** the discovery time.

### 3.1 Who used it?

Pull every event authenticated by the credential ([Appendix B1](#b1-what-did-this-credential-do-read)) and split
them into **owner-expected** activity (known IPs, workloads, CI runners) and **unexplained** activity. Any
unexplained use = **IR takes command**.

### 3.2 Typical attacker sequence (what to look for)

| Stage | Look for | ATT&CK / DET |
|---|---|---|
| **Recon** | `GetCallerIdentity`, `ListBuckets`, `ListUsers`/`ListRoles`, `GetAccountAuthorizationDetails`, project/IAM policy listing, SES `GetSendQuota`, Bedrock/LLM `ListFoundationModels` / `GetModelInvocationLoggingConfiguration` | T1580 · DET0169, T1087.004 · DET0386, T1069.003 · DET0251 |
| **Persistence and escalation** | New access keys, users, login profiles, roles; trust-policy edits; new SA keys; `setIamPolicy` granting owner/admin; new OIDC/SAML providers; **CloudFormation / Deployment Manager stacks that create admin roles** (UNC6426) | T1098.001 · DET0531, T1098.003 · DET0277, T1136.003 · DET0319, T1484.002 · DET0458 |
| **Spread** | Activity in **regions you never use**; new instances or GPUs; Lambda/Functions created; K8s cluster-admin bindings | T1535 · DET0247, T1496.001 · DET0540 |
| **Monetise** | Crypto-mining; LLMjacking (model invocation spikes); SES/SMS spam (the report saw CPaaS abuse for smishing) | T1496.004 · DET0147 |
| **Data theft (73% of cases)** | **Bulk API reads**: S3 GetObject / List spikes, Storage reads, Snowflake / Salesforce bulk exports, Data Loader use, **cross-account copies to actor-owned buckets** (UNC3944) | T1530 · DET0484, T1213.004 · DET0550, T1537 · DET0573 |
| **Destroy / extort** | Lifecycle rules set to expire objects, SSE-C re-encryption, snapshot/backup deletion, instance termination, repos made public or renamed (UNC6426) | T1485.001 · DET0041, T1486 · DET0215, T1485 · DET0146 |
| **Hide** | Trail / log sink deletion, log bucket lifecycle changes | T1685.002 · DET0289 |

**Scenario-specific add-ons**

- **A (weak credential):** spray or stuffing patterns before a success (DET0487, DET0460). Default-account logons (DET0465).
- **C (federation / OAuth):** `AssumeRoleWithWebIdentity` from repos, branches or workflows that are not yours. OAuth
  token use from new IPs (DET0185). Vendor-wide compromise notices.
- **D (human):** help-desk tickets for MFA resets, MFA push storms (T1621 · DET0160), MFA method changes
  (T1556.006 · DET0190), vishing reports (T1566.004 · DET0245).

### 3.3 Data-theft assessment

If any unexplained **read** of data is found, or logging gaps make it impossible to rule out:

1. List the data stores and objects reached, and classify the data (Macie / Purview / Sensitive Data Protection).
2. Estimate the volume from data-event logs or egress metrics.
3. **Privacy / Legal decide on notification.** Regulatory clocks may start at awareness, so bring them in early.

---

## 4. Remediation and guardrails

### 4.1 Fix the instance

- **Rotate**, don't just disable: issue a new credential via a secrets manager, deploy it, then **delete** the old one
  once the logs are captured.
- **Remove attacker persistence** found in §3.2: keys, users, roles, trust edits, providers, stacks, functions,
  instances, regions, K8s bindings.
- **Purge the leak source:** remove it from the repo history, image layers, CI logs, tickets and pastes. Assume copies
  exist, which is why rotation is the real fix.
- **Rotate what the identity could read:** secrets in Secret Manager / Key Vault / Parameter Store, DB passwords in
  env vars (the UNC4899 pattern), app keys decrypted with its KMS access.

### 4.2 Close the class (guardrails from the report's recommendations)

| Guardrail | Why (report link) | Google Cloud | AWS | Azure / M365 |
|---|---|---|---|---|
| **No long-lived machine credentials**: workload identity and OIDC federation instead of keys | Stolen non-human identities (21%). Static DB creds in env vars (UNC4899) | `constraints/iam.disableServiceAccountKeyCreation`, Workload Identity Federation, Cloud SQL IAM auth, Secret Manager | IAM roles / Roles Anywhere, SCP limiting `iam:CreateAccessKey`, Secrets Manager | Managed identities, federated credentials, Key Vault |
| **OIDC / CI roles least-privileged, subject-pinned, no IAM-create** | UNC6426: an over-broad GitHub→AWS role created an admin role in < 72h | WIF `attributeCondition` required. Impersonate a narrow downstream SA | Trust pinned on `token.actions.githubusercontent.com:sub`. Deny `iam:CreateRole` / `AttachRolePolicy` to CI roles | Federated credential subject pinned |
| **Remove standing high-risk permissions; JIT elevation** | The report: "remove standing permissions for high-risk actions like iam:CreateRole" | PAM / IAM Conditions | IAM Identity Center + time-bound elevation | Entra PIM |
| **Phishing-resistant MFA** (FIDO2 / passkeys) for all humans, admins first | Vishing 17%, MFA fatigue | Titan / passkeys, 2SV enforcement | IAM Identity Center with FIDO2 | Entra phishing-resistant auth strength |
| **Help-desk verification protocol** (video or manager approval for MFA resets) | UNC3944 / UNC6040 | Context-Aware Access | — | Conditional Access + Verified ID |
| **Govern OAuth and SaaS integrations**: scopes, allow-list, review | Third-party / token theft 21% (Drift, Gainsight) | Workspace API controls and app access reports | — | Entra app consent policies |
| **Fine-grained, short-lived PATs; secret scanning with push protection** | Stolen GitHub PATs → repo secrets | *Platform-agnostic (source control):* org policy allowing fine-grained PATs only, with a maximum lifetime, plus secret scanning and push protection on all repos | (same) | (same) |
| **Leak monitoring and auto-disable** | "Monitor for public credential leaks" | SCC leaked-credential monitoring, SA key exposure auto-disable | Partner-alert auto-quarantine | Secret-scanning partner alerts routed to Entra / Defender |
| **Perimeters around data APIs** | Stolen credentials stay useless off-network | VPC Service Controls | Data perimeters (SCP/RCP conditions on network and identity) | Private endpoints + Conditional Access |
| **Detect bulk API and anomalous IAM activity** | 73% data theft, often silent | SCC Event Threat Detection; SecOps rule: *CI/CD SA grants a privileged role to a new identity* | GuardDuty, CloudTrail Insights | Defender for Cloud Apps, Sentinel |
| **Four-eyes approval on destructive actions; protected logs** | Log, snapshot and backup deletion before extortion | Org policy + IAM Conditions; locked log buckets | SCP deny on `cloudtrail:StopLogging`/`DeleteTrail`; S3 Object Lock for logs | Resource locks; immutable storage for logs |

---

## 5. Verification

- [ ] The old credential is **rejected**. Check this from the provider's records (key status Inactive or Deleted,
      token revoked). **Never test by using the leaked secret.**
- [ ] No events authenticated by the old credential or session after containment (re-run B1 24h later).
- [ ] The new credential is stored in a secrets manager or replaced by workload identity. No plaintext copies remain
      in repos or images (re-scan).
- [ ] Persistence removal confirmed: a diff of IAM principals, keys, roles, trust policies and providers against the
      pre-incident baseline.
- [ ] Scenario A: the external proof (exposed-services skill) now shows MFA, IAP or no exposure.

---

## 6. Exit criteria

- Credential rotated or retired, the leak source purged, and persistence removed and verified.
- Hunt complete from the exposure start, with a recorded verdict: **no misuse / misuse without data access / data
  accessed**.
- Notification decision recorded by Privacy / Legal where data was accessed or access cannot be ruled out.
- Missing guardrails from §4.2 recorded with an owner and a date.

---

## 7. Metrics

| Metric | Target |
|---|---|
| Leak published → discovered | Minutes (automated scanning). Track the median |
| Discovered → contained | **< 1h** |
| Long-lived cloud keys / SA keys in use (count) | Trending to zero |
| % CI/CD federation roles with pinned subject and no IAM-create permissions | 100% |
| % human admins on phishing-resistant MFA | 100% |
| % of SaaS OAuth integrations reviewed in the last 90 days | 100% |

---

## Appendix: commands

> **(read)** = read-only. **(change)** = needs an emergency-change record. Run with the **owner's** least-privileged
> credentials, never with the leaked one.

### B1. What did this credential do? (read)

```bash
# AWS: last 90 days of management events for the key (CloudTrail Lake / Athena over the org trail for older
# history, data events and all regions in one query; that is the preferred route)
# IAM, STS and console sign-in are GLOBAL services: their events appear in event history only in us-east-1.
aws cloudtrail lookup-events --region us-east-1 --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<AKIA-or-ASIA-key> \
  --max-results 50 --query 'Events[].[EventTime,EventName,EventSource]' --output table
# Then repeat WITHOUT us-east-1 for each region in use (EC2, Lambda, S3 control plane, Bedrock … are regional).
for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws cloudtrail lookup-events --region "$r" --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<key> \
    --max-results 50 --query 'Events[].[EventTime,EventName,EventSource]' --output text
done
aws iam get-access-key-last-used --access-key-id <AKIA-key>

# Google Cloud: activity by a specific SA key. '--organization' reads ONLY org-level logs, not child projects.
# Query the project(s) the SA can reach, or the central bucket fed by an org aggregated sink:
gcloud logging read 'protoPayload.authenticationInfo.serviceAccountKeyName:"<KEY_ID>"' \
  --project=<project> --freshness=30d \
  --format="table(timestamp,protoPayload.methodName,protoPayload.requestMetadata.callerIp)"
gcloud logging read 'protoPayload.authenticationInfo.serviceAccountKeyName:"<KEY_ID>"' \
  --project=<central-log-project> --bucket=<bucket> --location=europe-west2 --view=_AllLogs --freshness=30d

# Azure: service-principal sign-ins (Log Analytics, KQL)
#   AADServicePrincipalSignInLogs | where AppId == "<appId>" | project TimeGenerated, IPAddress, ResourceDisplayName, ResultType
# Azure: storage access by key or SAS
#   StorageBlobLogs | where AuthenticationType in ("AccountKey","SAS") | summarize count() by CallerIpAddress, OperationName
```

### B2. Contain (change)

```bash
# AWS
aws iam update-access-key --user-name <user> --access-key-id <AKIA-key> --status Inactive
# Google Cloud
gcloud iam service-accounts keys disable <KEY_ID> --iam-account <sa>@<project>.iam.gserviceaccount.com
# Azure
az ad app credential delete --id <appId> --key-id <credentialKeyId>
# Storage keys: FIRST identify which key (key1/key2) leaked or signed the SAS and fail every app over to the OTHER key.
# Renewing a key immediately breaks every app and SAS that uses it.
az storage account keys renew -g <rg> -n <account> --key <key1|key2>
az storage account revoke-delegation-keys -g <rg> -n <account>    # user-delegation SAS only
```

### B3. Persistence sweep (read)

```bash
# AWS: IAM changes since the look-back start (the org trail via Athena / CloudTrail Lake is better; this is a quick view).
# IAM events are global and appear in event history ONLY in us-east-1, whatever your default region is.
for e in CreateAccessKey CreateUser CreateLoginProfile CreateRole UpdateAssumeRolePolicy AttachRolePolicy PutRolePolicy \
         AttachUserPolicy CreateOpenIDConnectProvider CreateSAMLProvider; do
  aws cloudtrail lookup-events --region us-east-1 --lookup-attributes AttributeKey=EventName,AttributeValue=$e \
    --start-time <ISO-8601> --query 'Events[].[EventTime,Username,EventName]' --output text
done
# CloudFormation is regional (the UNC6426 admin-role-via-stack pattern): check every region in use
for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws cloudtrail lookup-events --region "$r" --lookup-attributes AttributeKey=EventName,AttributeValue=CreateStack \
    --start-time <ISO-8601> --query 'Events[].[EventTime,Username,EventName]' --output text
done

# Google Cloud: IAM policy grants and new SA keys since the look-back start. Use ':' (substring) on methodName, because
# services log names such as google.iam.v1.IAMPolicy.SetIamPolicy. Run per project, or against the central log bucket.
gcloud logging read 'protoPayload.methodName:"SetIamPolicy" OR protoPayload.methodName:"CreateServiceAccountKey" OR protoPayload.methodName:"CreateServiceAccount"' \
  --project=<project> --freshness=30d --format="table(timestamp,protoPayload.authenticationInfo.principalEmail,protoPayload.methodName,resource.labels.project_id)"

# Azure: role assignments created recently (Activity Log)
az monitor activity-log list --offset 30d --query "[?operationName.value=='Microsoft.Authorization/roleAssignments/write'].[eventTimestamp,caller,resourceId]" -o table
```

### B4. OIDC trust check (read)

```bash
aws iam get-role --role-name <ci-role> --query 'Role.AssumeRolePolicyDocument'
#   PASS only if the Condition pins token.actions.githubusercontent.com:sub to specific repo/ref/environment
#   AND token.actions.githubusercontent.com:aud = sts.amazonaws.com, and the role cannot create or attach IAM roles/policies.
gcloud iam workload-identity-pools providers describe <provider> --location=global \
  --workload-identity-pool=<pool> --format='value(attributeCondition)'
az ad app federated-credential list --id <appId> --query "[].{subject:subject,issuer:issuer}"
```

---

*Source for the anchoring figures, actor examples (UNC6426, UNC4899, UNC6395, UNC3944, UNC6040) and
recommendations: Google Cloud, Cloud Threat Horizons Report H1 2026 (Office of the CISO). Technique and DET IDs:
MITRE ATT&CK® Enterprise v20.1.*
