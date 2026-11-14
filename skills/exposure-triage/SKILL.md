---
name: exposure-triage
description: CTEM prioritisation and mobilisation for external exposure findings (from exposed-services, exposed-cloud-assets, EASM, Shodan, Censys, Shadowserver, CNAPP/CSPM or VM tools). Resolves attribution (A1-A3) and the remediation owner, scores with the transparent Exposure Priority Score (EPS - Reach + Class + Pressure + Blast, 0-100, P1-P4) alongside the organisation's prioritisation engine, checks CISA KEV and EPSS, mobilises findings as remediation campaigns with ITSM tickets, SLAs and exceptions, writes an executive brief, hands the SOC the MITRE ATT&CK v20.1 Detection Strategies to watch while the exposure is open, and runs verify-closed re-tests and cycle-to-cycle diffs. Use when asked to prioritise or triage exposures, work out who owns an IP or bucket, build a remediation campaign, write tickets for remediation owners, brief leadership on the attack surface, tell the SOC what to watch, check whether a fix worked, or compare this week's exposure with last week's.
---

# Exposure triage: own it, rank it, mobilise it, close it

**Knowledge base location:** look for `docs/methodology.md`, `catalog/`, `schemas/finding.schema.json` and
`templates/` at the root of the `outside-in` repo. Otherwise look in `~/.claude/skills/outside-in-kb/`.
`docs/methodology.md` §3–§7 is the normative definition of everything below.

## Inputs accepted

- `outside-in` findings (YAML or JSON per `schemas/finding.schema.json`).
- Raw exports such as Shodan/Censys JSON, Shadowserver CSV reports, nmap XML, CSPM findings (Security Hub ASFF,
  Defender for Cloud, SCC) and ASM tool exports. **Normalise first:** map each row to a `catalog_id`. If no catalog
  entry fits, use `catalog_id: uncatalogued` and propose a new entry at the end.

## Step 1: normalise and de-duplicate

- Key: `(catalog_id, asset identity)`. Asset identity is the resource ID for cloud, or IP + port for services.
- Merge evidence from several sources and keep the **highest rung** and the **most recent timestamp**.
- **Root-cause roll-up:** group findings that share a cause (one security group, one firewall policy, one Terraform
  module, one golden image). The roll-up is what the owner fixes. Children stay for verification.

## Step 2: attribution and ownership

Apply methodology §3.

| Situation | Action |
|---|---|
| A1 with an owner | Assign to that remediation owner. |
| A1 without an owner | Assign to the platform owner of the account, subscription, project or netblock. Flag "ownership gap". |
| A2 | Assign to the most likely owner **and** raise `unmanaged-asset`. Lift one band (methodology §5). |
| A3 | **Attribution queue**: one owner (usually the ASM lead) has 5 business days to resolve it to A1/A2 or "not ours". Cap at P3. |

Ownership signals to try, in order: cloud resource tags (`owner`, `team`, `cost-center`), the account or subscription
to business-unit map, the CMDB, DNS zone owner, certificate requester, the IaC repo `CODEOWNERS`, and the last
deployer (CloudTrail, Activity Log, Audit Logs).

## Step 3: threat context (live, never from memory)

For every product and version identified:

1. **CISA KEV:** is any CVE listed? Record `dateAdded` and `knownRansomwareCampaignUse`.
2. **EPSS:** the current probability for each candidate CVE. Keep the max.
3. **Active exploitation signals:** vendor PSIRT "exploited in the wild", CISA/NCSC advisories, honeypot or
   mass-scan telemetry.
4. **Attacker evidence on the asset itself** (ransom notes, unknown accounts, miners) triggers the **incident
   override**: force P1 and notify IR now. Do not wait for scoring.

## Step 4: EPS scoring

`EPS = Reach + Class + Pressure + Blast` (each 0–25). See the methodology table. Rules of thumb:

- **Class** comes from the catalog `weight`: critical = 25, high = 20, medium = 10, low = 3.
- **Reach** drops when the owner shows an allow-list or SSO gateway. Re-score after containment.
- **Blast** needs the owner's input on data sensitivity and environment. Default to **15 (prod, unknown data)**
  until told otherwise, and say that you defaulted.
- Show the arithmetic in every ticket, e.g. `EPS 82 = Reach 25 + Class 20 + Pressure 15 + Blast 22`.

Then apply the overrides (force P1, cap at P3 for A3, lift a band for unmanaged or regressed) and map to a band:
**P1 ≥ 75 · P2 50–74 · P3 25–49 · P4 < 25**.

If the organisation runs a prioritisation engine, record its score next to EPS. Where the two differ by more than one
band, flag it for the weekly review (methodology §5, *EPS and your prioritisation engine*).

## Step 5: mobilise as remediation campaigns

Group roll-ups that share a **fix type and a remediation owner** into a campaign (methodology §6). For each campaign,
produce:

1. **Campaign brief**: fill in `templates/remediation-campaign.md`. Include the threat context, scope, standard fix,
   guardrail, SLA, exception rules and success measure.
2. **Owner tickets** for the ITSM: fill in `templates/owner-ticket.md`, one per remediation owner per roll-up. Plain
   language first, evidence second. Include the inside-out command, the fix, the guardrail, the SLA due date and the
   verification method.
3. **SOC hand-off**: list the `soc_watch` DET IDs with their names (from `catalog/attack-enterprise.tsv`) and the
   specific assets. Ask the SOC to confirm, for each DET, that it has (a) the log source and (b) an analytic running
   for those assets. Any "no" is a **detection gap** to record next to the exposure.
4. **Finding records**: JSON per the schema, for the prioritisation engine, data lake, SIEM or GRC.

For **P1**, also give a **24-hour containment** option that does not wait for the full fix: source allow-list,
disable the listener, pull the public IP, revoke the public grant, or deactivate the key.

**Exceptions:** an owner who cannot meet the SLA raises an ITSM exception with a Reach-reducing compensating control,
an expiry date and an accountable approver. Re-score EPS with that control in place.

## Step 6: executive brief

Fill in `templates/exec-brief.md`. Keep it to one page:

- Counts by band, plus a trend against the last cycle (new / closed / regressed).
- **Top 5 roll-ups** by EPS, each with one sentence of business impact.
- **Classes without a guardrail** (e.g. "public snapshots possible in 31 of 40 accounts").
- **Ownership gaps** and **detection gaps**.
- The time-to-close median for P1/P2 this cycle.

Avoid dollar-loss figures unless the organisation has its own loss model. EPS is a prioritisation tool, not a risk
quantification.

## Step 7: verify-closed

When an owner marks a ticket fixed:

1. Re-run the **original** proof command from the **same vantage point** (or an equivalent one). Add the
   inside-out check if available.
2. Set the status per the methodology §7 table: `closed-verified`, `closed-outside-only`, `reopened-relocated`,
   `open-fix-not-effective`, or spawn a new `dangling-dns-cloud` finding when the asset is gone but DNS remains.
3. Release the SOC watch only on `closed-verified`.

## Step 8: diff mode (every cycle)

Compare this cycle's normalised set with the previous one:

| Bucket | Meaning | Action |
|---|---|---|
| **New** | Exposure not seen before | Normal triage. Ask "which change created it?" (CloudTrail / change tickets) |
| **Closed** | Previously open, now failing the proof | Verify-closed flow |
| **Regressed** | Previously `closed-verified`, open again | Lift one band. The guardrail is missing or bypassed. Also check DET0424 (cloud firewall modification) in case it was reopened maliciously |
| **Persisting past SLA** | Open beyond its due date | Escalate per policy |

## Guardrails on your own behaviour

- Do not inflate. When evidence is E0 only, say so and score Pressure and Blast conservatively.
- Do not deflate an A2 or A3 just because nobody claims it. Unknown ownership is a risk, not a mitigation.
- Never include secrets, data samples or full banners containing personal data in tickets or briefs. Reference the
  evidence store instead.
