# Runbook backlog

## Built (v0.2): the Threat Horizons top 2

The runbook set is anchored on **Google Cloud Threat Horizons H1 2026**. Its two leading initial-access vectors have
been built first, and each one absorbs and widens a backlog item:

| Built | Threat Horizons vector | Replaces |
|---|---|---|
| [RB-01 Exploited internet-facing software](runbooks/RB-01-exploited-internet-facing-software.md) | Software-based entry, **44.5%** | RB-S02 (edge-appliance KEV), now widened to any internet-facing software on VMs, Kubernetes, containers and appliances |
| [RB-02 Weak, leaked or stolen cloud credentials](runbooks/RB-02-weak-leaked-stolen-credentials.md) | Weak or absent credentials, **27.2%** (identity in **83%** of cross-platform cases) | RB-C04 (leaked cloud credential), now widened to weak logins, OAuth/SaaS tokens, CI/CD OIDC trust and human account takeover |

**Next candidates by Threat Horizons weight:**

1. **Misconfiguration (21.0%)**: RB-C01 public object storage, RB-C13 guardrail rollout.
2. **Exposed sensitive UI/API (4.9%)**: RB-S01 remote admin, RB-S05 management planes.

## Remaining backlog (proposed, not yet written)

These are candidate runbooks for the two problem areas, plus the programme processes that keep the exposure loop
running. Rows marked *superseded* are covered by RB-01 / RB-02.

**Priority key:** **P0** = build first (highest-frequency or highest-impact events in the 2026 data). **P1** = next.
**P2** = once the loop is running.

**Runbook vs skill.** A *skill* tells the AI assistant how to find and validate exposures. A *runbook* tells **people** what to do
once a specific exposure or event is confirmed: who does what, in what order, with which decision points. Each runbook
will reference catalog IDs and ATT&CK DETs, so the skill output can link straight to it.

---

## A. Exposed services

| ID | Runbook | Trigger | Catalog IDs | Key ATT&CK (v20.1) | Pri |
|---|---|---|---|---|---|
| RB-S01 | **Emergency removal of internet-exposed remote admin** (RDP, SSH, VNC, WinRM, RDWeb), including safe alternatives for vendors and third parties | E1+ on remote-admin family | rdp, ssh, vnc, winrm, rd-web-gateway, rmm-self-hosted | T1133, T1110.003, T1021.001 · DET0354, DET0487 | **P0** |
| ~~RB-S02~~ | *Superseded by **RB-01**.* Edge-appliance KEV response | — | ssl-vpn, fw-mgmt-ui, mft, onprem-collab | T1190 · DET0080 | built |
| RB-S03 | **Exposed database with attacker evidence** (ransom note or wipe): preserve, contain, scope the data, breach-notification decision path | Ransom DB or note seen at E3 | mongodb, elasticsearch, redis, mysql, postgresql, couchdb | T1213.006, T1485, T1486 · DET0242, DET0146 | **P0** |
| RB-S04 | **Unauthenticated data plane, no attacker evidence yet**: lock down, then review access logs for the exposure window | E3 unauth on a data store | database family, broker family | T1213.006, T1530 · DET0242 | P1 |
| RB-S05 | **Management-plane exposure** (BMC, IPMI, vCenter/ESXi, hypervisor, backup, NAS), BOD 23-02 style: remove, then check for compromise | E1+ on infra-management family | ipmi, bmc-web, vsphere, hypervisor-ui, backup-servers, nas-ui | T1190, T1486, T1490 · DET0080, DET0215 | **P0** |
| RB-S06 | **Exposed container / orchestration control plane** (Docker API, kubelet, etcd, K8s API, dashboards): contain, hunt for rogue workloads and miners, rotate cluster secrets | E2/E3 on container family | docker-api, k8s-api, kubelet, etcd, container-mgmt-ui | T1610, T1609, T1611, T1496.001 · DET0249, DET0065, DET0540 | P1 |
| RB-S07 | **Exposed AI infrastructure** (Ollama, inference servers, Ray, MCP, vector DBs, agent builders): contain, check usage, cost and abuse, review tool permissions | E3 on ai family | ollama, llm-inference, ray, mcp-server, vector-db, ai-app-builders | T1496.004, T1698, T1699, T1700 · DET0147, DET0941, DET0942 | P1 |
| RB-S08 | **Directory services exposed** (LDAP, Kerberos, RPC, SMB on DCs): emergency perimeter block plus AD compromise checks | E1+ on directory family or smb on a DC | ldap, kerberos, msrpc, smb | T1110.003, T1557.001, T1021.002 · DET0487, DET0462 | P1 |
| RB-S09 | **Amplifier clean-up** (open DNS, NTP monlist, SSDP, memcached UDP, CLDAP, SLP): routine fix, ISP and abuse-desk liaison | Shadowserver amplifier report | dns-open-resolver, ntp, ssdp-upnp, memcached, slp, ldap | T1498.002 · DET0408 | P2 |
| RB-S10 | **OT/ICS internet exposure**: safety-first coordination with the OT owner, no active probing, vendor remote-access review | E0 on ot-ics family | ics-fieldbus, ics-vendor | T1190, T1133 (+ ICS T0883) · DET0354 | P1 |
| RB-S11 | **Shadowserver / CISA Cyber Hygiene report intake**: daily feed ingestion, de-duplication, mapping to catalog IDs, ticketing | Report received | (all) | (n/a) | **P0** |
| RB-S12 | **"New port appeared" diff alert**: correlate with change records and IaC, decide intended or unintended, close or escalate | Diff bucket "new" | (all) | T1686.001 / T1686.002 if malicious · DET0424 | P1 |

## B. Exposed cloud assets

| ID | Runbook | Trigger | Catalog IDs | Key ATT&CK (v20.1) | Pri |
|---|---|---|---|---|---|
| RB-C01 | **Public object storage**: contain, find the exposure window (policy history), review access logs (S3 server access / CloudTrail data events / Storage analytics), classify the data, breach-assessment decision | E3 or E4 public read | aws-s3-public-read, azure-blob-anonymous, gcs-allusers, other-object-storage | T1530, T1619, T1567.002 · DET0484, DET0578 | **P0** |
| RB-C02 | **Publicly writable storage / hosted-asset tampering**: integrity check of served JS and binaries, supply-chain impact, customer comms | E4 public write | aws-s3-public-write | T1608.001, T1195.002, T1189 · DET0824, DET0309 | P1 |
| RB-C03 | **Public snapshot / image / disk export**: contain, check whether copies were made (CloudTrail ModifySnapshotAttribute / CopySnapshot), inventory and rotate the secrets on the image | E3 stranger view or E4 | aws-ebs-snapshot-public, aws-rds-snapshot-public, aws-ami-public, azure-disk-sas-export, gcp-public-images | T1537, T1552.001, T1552.004 · DET0573 | **P0** |
| ~~RB-C04~~ | *Superseded by **RB-02**.* Leaked cloud credential | — | leaked-cloud-credentials, public-iac-state, ci-public-artifacts, registry-anonymous | T1078.004 · DET0546 | built |
| RB-C05 | **Leaked AI / LLM key (LLMjacking)**: revoke, review usage and billing, check model-access changes, set quotas | AI key found | llm-api-keys | T1496.004, T1700 · DET0147, DET0927 | P1 |
| RB-C06 | **Subdomain takeover / dangling DNS**: remove or reclaim, check whether it was already claimed (content, CT for new certs on the name), cookie and OAuth scope impact | E2 dangling fingerprint | dangling-dns-cloud, dangling-a-record-cloud-ip | T1584.001, T1189, T1539 · DET0863, DET0509 | P1 |
| RB-C07 | **Publicly reachable managed DB**: move to a private endpoint without downtime, rotate credentials, review auth logs | E1+ / E4 | aws-rds-public, azure-sql-open-firewall, azure-cosmos-public, gcp-cloudsql-open, aws-opensearch-public | T1190, T1213.006 · DET0242 | P1 |
| RB-C08 | **Public Kubernetes control plane**: restrict CIDRs or go private without breaking CI/CD and operators, then audit RBAC for anonymous bindings | E2 / E4 | managed-k8s-public-api, k8s-api | T1078.004, T1613, T1552.007 · DET0546, DET0490 | P1 |
| RB-C09 | **Unauthenticated serverless or API endpoint**: add an authorizer, set concurrency and budget limits, review invocation logs | E2/E3 | aws-lambda-url-none, api-gateway-no-auth, azure-functions-anonymous, gcp-serverless-allusers | T1648, T1499.003 · DET0374, DET0415 | P2 |
| RB-C10 | **Open BaaS rules** (Firebase, Supabase): emergency rules lock, data-access review, app release coordination (mobile apps pin configs) | E3 | baas-firebase-open, baas-supabase-rls-off | T1530, T1565.001 · DET0484, DET0193 | P1 |
| RB-C11 | **Over-broad federation / cross-account trust**: tighten the trust policy, look for unexpected AssumeRoleWithWebIdentity / AssumeRole history | E4 | oidc-trust-too-broad, cross-account-trust-no-externalid, cognito-unauth-identities | T1550.001, T1199, T1078.004 · DET0185, DET0488 | P1 |
| RB-C12 | **SaaS public-link sweep** (SharePoint/OneDrive, Google Drive, Box, Notion, Postman): bulk revoke, notify owners, rotate exposed secrets | Periodic or E3 | saas-public-links | T1213, T1213.002, T1552.001 · DET0413, DET0500 | P2 |
| RB-C13 | **Guardrail rollout** (org-wide preventive controls per provider: S3 BPA, snapshot and AMI blocks, IMDSv2 default, Azure Policy at MG root, GCP org constraints): staged deployment with an exception process | "Class without guardrail" in the exec brief | (all cloud) | M1018, M1022, M1035, M1047 | **P0** |
| RB-C14 | **Cloud firewall drift / re-opened exposure**: decide benign change or attacker persistence, revert, hunt | Diff bucket "regressed" | cloud-fw-open-admin, unexpected-public-ip | T1686.001, T1666 · DET0424, DET0155 | P1 |

## C. Programme and process

| ID | Runbook | Purpose | Pri |
|---|---|---|---|
| RB-P01 | **Active-scan authorisation and safe scanning** | Template authorisation, rate limits, windows, pre-notifying the SOC/MSSP and ISP so scans don't trigger false incidents, stop procedure | **P0** |
| RB-P02 | **Seed and scope maintenance** | Keep domains, ASNs, CIDRs and cloud accounts current, including M&A, divestitures, new subsidiaries and new cloud accounts | P1 |
| RB-P03 | **Attribution queue (A3) resolution** | 5-day SLA to resolve to A1/A2 or "not ours", with escalation | P1 |
| RB-P04 | **Third-party / supplier exposure notification** | What to do when the exposure belongs to a vendor or a stranger: minimum evidence, legal path, responsible disclosure | P1 |
| RB-P05 | **Exception and risk acceptance for intentionally public services** | `exposure=public` tagging, compensating controls, review dates | P1 |
| RB-P06 | **Weekly exposure cycle and diff review** | The operating rhythm: discover → diff → triage → mobilise → verify | **P0** |
| RB-P07 | **SOC detection-gap handling** | Turning `soc_watch` DETs with no coverage into detection engineering backlog items | P2 |
| RB-P08 | **Evidence handling and data minimisation** | What evidence to keep, where, for how long. No data contents or secrets | P1 |
| RB-P09 | **Executive reporting cadence and metrics** | Brief template, KPIs (time to close by band, regression rate, guardrail coverage, ownership coverage) | P2 |
| RB-P10 | **M&A outside-in due diligence** | Authorised exposure assessment of an acquisition target before close, and integration into the loop after | P2 |

---

## Suggested build order (after RB-01 / RB-02)

1. **RB-C01** (public storage) and **RB-C13** (guardrail rollout): Threat Horizons' #3 vector, misconfiguration (21%).
2. **RB-S01** (remote admin) and **RB-S05** (management planes): exposed sensitive UI/API (4.9%). Also high frequency
   in non-cloud reporting (Arctic Wolf, Sophos).
3. **RB-P01** (safe scanning) and **RB-P06** (weekly cycle): the operating rhythm all runbooks rely on.
4. **RB-C03** (public snapshots), **RB-S03** (ransomed DB) and **RB-S11** (Shadowserver intake).

## Proposed runbook format (for when we build them)

Each runbook will follow the same skeleton, so it can be linked from tickets and followed by a person or an AI assistant:

```
runbooks/<ID>-<slug>.md
  0. Trigger and entry criteria (catalog IDs, evidence rung, EPS band)
  1. Roles (RACI): ASM lead, asset owner, SOC, IR, comms, legal
  2. First 60 minutes: containment options and decision points
  3. Investigation: logs to pull, look-back window = exposure window, ATT&CK DETs to hunt
  4. Remediation and guardrail
  5. Verification (outside-in re-test plus inside-out)
  6. Exit criteria and hand-back (to normal triage, or escalation to the IR plan)
  7. Metrics captured
  Appendix: provider-specific commands (AWS / Azure / GCP / on-prem)
```

---

## Tooling backlog

Items that are not runbooks, captured here so they aren't lost:

| Item | What it is |
|---|---|
| Catalog schema linter | Validate `catalog/*.yaml` field structure against a JSON Schema (the DET-to-technique consistency check is already automated in `scripts/Update-AttackMapping.ps1`). |
| CI workflow | Run `scripts/Update-AttackMapping.ps1` on every PR and on each ATT&CK release (April and October). |
| Port-list generator | Build the nmap/naabu port list from `services.yaml`. |
| Feed normalisers | Shadowserver CSV, Shodan/Censys JSON, nmap XML, Security Hub ASFF → `finding.schema.json`. |
| KEV / EPSS enricher | Fetch the CISA KEV JSON and the EPSS API and annotate findings. |
| Diff tool | Cycle-to-cycle new / closed / regressed buckets. |
| ATT&CK Navigator layer | Colour techniques by open-finding count. |
| Detection content | Sigma / KQL / SPL starter analytics for the most common `soc_watch` DETs (DET0354, DET0487, DET0080, DET0484, DET0546, DET0573, DET0424). |
| Skill evaluations | Prompt-based smoke tests for the three skills (scope refusal, least-touch discipline, correct catalog mapping, EPS arithmetic). |
