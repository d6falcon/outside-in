# Changelog

## 0.3.0 (2026-11-14)

Release-readiness pass for publication at `github.com/d6falcon/outside-in`.

- **CTEM alignment.** The loop is now *Scope → Discover → Attribute → Validate → Prioritise → Mobilise →
  Verify-closed*, with a note on why validation precedes prioritisation in an EASM-led loop.
- **Mobilisation model.** Findings are mobilised as **remediation campaigns** with ITSM tickets, SLAs and an
  exception path that requires a Reach-reducing compensating control. Adds `templates/remediation-campaign.md`, plus
  `campaign_id` and `exception` fields in the finding schema.
- **Prioritisation-engine integration.** EPS now explicitly runs alongside an existing prioritisation engine and feeds
  it Reach, attribution and evidence rung.
- **New docs:** `docs/operating-model.md` (data sources, RACI, cadence, programme metrics, vendor-neutral) and
  `docs/architecture-decisions.md` (ADR-001 … ADR-008).
- **Fixes:**
  - The methodology referred to `class_weight`; the catalog field is `weight`.
  - Verify-closed status names now match the schema enum (`reopened-relocated`, `open-fix-not-effective`).
  - The "lift one band on regression" override is now documented in the methodology, matching the schema and the
    triage skill.
  - RB-02's PAT guardrail was in the wrong column.
- **Validator.** `scripts/Update-AttackSubset.ps1` is renamed to `scripts/Update-AttackMapping.ps1`. It now:
  - runs on Windows PowerShell 5.1 and PowerShell 7+;
  - adds **check 2**: every DET in each catalog entry and runbook must detect a technique cited alongside it
    (negative-tested).
- **Independent technical review (35 findings), all addressed:**
  - **RB-02:** IAM/STS events are now queried in `us-east-1` (they are global and missed in other regions). The GCP
    log query no longer relies on `--organization` (which skips child projects) and uses substring `methodName`
    matching.
  - **RB-01:**
    - ASG evidence preservation detaches the single instance instead of suspending group-wide processes.
    - The NACL deny is scoped to a /32.
    - Added a warning that NetworkPolicies are additive.
    - `kubectl` LoadBalancer listing now uses portable jsonpath.
  - **Service probes corrected:**
    - MongoDB (`mongodb-databases`; buildInfo alone is only E2).
    - SonarQube (`/api/components/search`).
    - SNMP (`snmp-sysdescr` for the RoE-gated community test).
    - Cassandra (`-sV`; `cassandra-info` is Thrift-only).
    - Elasticsearch 8.x TLS.
    - kubelet 403.
    - MLflow POST.
    - WinRM `/wsman`.
  - **Cloud checks corrected:**
    - Azure Blob and GCS: a 404/403 on list no longer reads as "not public".
    - Null `allowBlobPublicAccess`.
    - Cloud Run Google-front-end 404 vs app response.
    - GCP image-level sharing and the right guardrail.
    - Firebase regional URLs.
    - IPv6 and `sourceAddressPrefixes` in firewall checks.
    - PostgreSQL/MySQL flexible-server firewall checks.
    - RDS stranger command per region.
    - The GitHub OIDC `sub` needs its `repo:` prefix.
    - App Service and GKE guardrail names.
    - Storage-key rotation now warns which key, and who breaks.
  - **Consistency:**
    - Skill output examples now validate against the finding schema.
    - Worked example `svc-rdp` → `rdp`.
    - RB-02 RACI section reference.
    - Complete SOC-watch headers in both runbooks.
    - Explicit A3 existence-check carve-out in the rules of engagement.
    - UDP list wording.
- **Regions.** Concrete examples use London regions (AWS `eu-west-2`, Google Cloud `europe-west2`, Azure `uksouth`).
  Provider-fixed global endpoints are unchanged.
- Authorship set to d6falcon (LICENSE, schema `$id`, README). The README has been rewritten for a technical audience.

## 0.2.0 — 2026-11-14

- **Runbooks anchored on Google Cloud Threat Horizons H1 2026** (read from the primary PDF), cut down to its top two
  initial-access vectors:
  - `runbooks/RB-01-exploited-internet-facing-software.md`: software-based entry (44.5%). Four trigger modes,
    the report's < 24h virtual-patch / < 72h full-patch clock, preserve-before-touch (auto-scaling and self-healing
    awareness), compromise-assessment hunts a–j, and cloud and Kubernetes command appendix.
  - `runbooks/RB-02-weak-leaked-stolen-credentials.md`: weak or absent credentials (27.2%) and the identity theme
    (83%). Four scenarios (weak login, leaked secret, federation/OAuth abuse, human takeover), attribute-without-use,
    reversible containment per credential type, an exposure-time hunt mapped to the attacker sequence, and guardrails
    mapped to the report's recommendations.
- RB-S02 and RB-C04 are marked as superseded in `RUNBOOKS-BACKLOG.md`. The build order is re-ranked by Threat Horizons weight.
- `RESEARCH.md` and `README.md` now quote the primary Threat Horizons figures. Previously these were secondary summaries.
- `scripts/Update-AttackMapping.ps1` now also validates `runbooks/`, and all IDs are active in v20.1. The rule that
  each DET maps to a technique in the same runbook was checked manually here and automated in 0.3.0.

## 0.1.0 — 2026-11-12

Initial draft.

- Skills: `exposed-services`, `exposed-cloud-assets`, `exposure-triage`.
- Catalogs: `services.yaml` (86 service exposure classes), `cloud-assets.yaml` (43 cloud exposure classes), both
  mapped to MITRE ATT&CK Enterprise **v20.1** techniques, Detection Strategies and Mitigations.
- `catalog/attack-enterprise.tsv` generated from MITRE STIX `enterprise-attack-20.1.json`, with every referenced ID
  verified active.
- Methodology: exposure loop, rules of engagement, attribution A1–A3, evidence ladder E0–E4, EPS scoring and
  verify-closed.
- Finding JSON schema, owner-ticket and exec-brief templates.
- `RESEARCH.md` (problem validation with 2026 sources) and `RUNBOOKS-BACKLOG.md` (36 proposed runbooks, not yet written).
