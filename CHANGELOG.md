# Changelog

## 0.4.1 (2026-11-16): second technical review and readability pass

| Area | Change |
|---|---|
| Second independent review | 21 findings, all fixed. Removed `--max-results` from RB-02 CloudTrail lookups (it silently cut results to one page); Azure Blob query now uses single quotes (backticks broke bash and PowerShell); PostgreSQL firewall flag `-s`; GCS IAM changes logged as `storage.setIamPermissions`; anonymous `allUsers` reads are never in Cloud Audit Logs; org-wide public-access-prevention caution (breaks intentionally public buckets); UBLA warning; `inherited` explained; first key name instead of an object count the probe can't give; quarantine SG and NSG now really deny (default egress and VNet rules removed); IPv6 in RB-01; GKE DNS endpoint; WinRM probe sends a body; install creates folders first |
| EDR rules | `agent_expected` is a class default with per-asset override; `unknown` scored as missing everywhere; `lift-no-edr` doesn't stack with `lift-unmanaged`; an agent is never an exception's compensating control |
| Readability | Lists turned into tables across the methodology, skills, runbooks README, RESEARCH (including sources) and this changelog; ADR index table |

## 0.4.0 (2026-11-14): EDR coverage gaps on exposed hosts

| Area | Change |
|---|---|
| Catalogs | Every class carries `agent_expected`: 65 of 86 service classes and 3 of 43 cloud classes expect an EDR agent |
| Schema | New `asset.controls.edr` (`healthy` / `stale` / `missing` / `not-applicable` / `unknown`), last-seen and source fields; new override `lift-no-edr` |
| Methodology | A missing or stale agent on an `agent_expected` class lifts one band. Endpoint DETs become `detection_gaps`. A healthy agent never lowers the band. Join on resource ID and hostname, never public IP |
| Skills and docs | Triage Step 2b, exec-brief "endpoint coverage" line, operating-model metric, ADR-009 |
| Examples | RDP finding shows a stale agent; GCS bucket is `not-applicable`. New worked example `docs/examples/gcs-public-bucket.md`, `docs/install.md`, 60-second README |

## 0.3.0 (2026-11-14): release readiness

| Area | Change |
|---|---|
| CTEM alignment | Loop is now Scope → Discover → Attribute → Validate → Prioritise → Mobilise → Verify-closed |
| Mobilisation | Remediation campaigns with ITSM tickets, SLAs and exceptions (Reach-reducing compensating control required). New campaign template; `campaign_id` and `exception` in the schema |
| Prioritisation engine | EPS runs alongside it and feeds it Reach, attribution and evidence rung |
| New docs | `docs/operating-model.md` (data sources, RACI, cadence, metrics) and `docs/architecture-decisions.md` |
| Validator | Renamed to `scripts/Update-AttackMapping.ps1`; runs on PowerShell 5.1 and 7+; adds check 2 (each DET detects a technique cited alongside it), negative-tested |
| Independent review | 35 findings, all fixed. IAM events queried in `us-east-1`; GCP log scope fixed; ASG detach instead of group-wide suspend; NACL /32; NetworkPolicy caveat; probes corrected for MongoDB, SonarQube, SNMP, Cassandra, Elasticsearch 8.x, kubelet, MLflow, WinRM; Blob/GCS 404 and 403 no longer read as "not public"; Cloud Run 404s; GCP image sharing; Firebase regional URLs; IPv6 firewall rules; flexible-server firewalls; OIDC `repo:` prefix; guardrail names; storage-key rotation warning |
| Consistency | Skill examples validate against the schema; status and field names aligned; complete SOC-watch headers; A3 existence-check carve-out |
| Regions and authorship | London region examples; author d6falcon (LICENSE, schema `$id`, README) |

## 0.2.0 (2026-11-14): runbooks

| Area | Change |
|---|---|
| RB-01 | Exploited internet-facing software (Threat Horizons #1, 44.5%): four trigger modes, < 24h virtual patch / < 72h full patch, preserve-before-touch, hunts a–j, command appendix |
| RB-02 | Weak, leaked or stolen credentials (#2, 27.2%; identity 83%): four scenarios, attribute-without-use, reversible containment, exposure-time hunt, guardrails |
| Backlog and research | RB-S02 and RB-C04 superseded; build order re-ranked by Threat Horizons weight; primary report figures quoted |

## 0.1.0 (2026-11-12): initial draft

| Area | Change |
|---|---|
| Skills | `exposed-services`, `exposed-cloud-assets`, `exposure-triage` |
| Catalogs | 86 service and 43 cloud exposure classes mapped to MITRE ATT&CK Enterprise v20.1; `attack-enterprise.tsv` generated from MITRE STIX |
| Method | Exposure loop, rules of engagement, attribution A1–A3, evidence ladder E0–E4, EPS, verify-closed |
| Other | Finding schema, ticket and exec-brief templates, `RESEARCH.md`, `RUNBOOKS-BACKLOG.md` |
