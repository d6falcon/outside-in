# Architecture decision records

The design choices behind `outside-in`, written so a reviewer can challenge the reasoning rather than the result.
Each record follows context → decision → consequences.

| ADR | Decision in one line |
|---|---|
| [001](#adr-001-defender-first-least-touch-validation) | Prove exposure with the least possible contact (E0–E4 ladder). No exploits, no data, no found credentials |
| [002](#adr-002-knowledge-as-versioned-data-not-prose) | Keep exposure knowledge in versioned YAML; keep the skills short |
| [003](#adr-003-a-transparent-score-eps-next-to-the-prioritisation-engine-not-instead-of-it) | Score transparently with EPS, alongside (not instead of) the prioritisation engine |
| [004](#adr-004-attribution-is-its-own-axis) | Track ownership confidence (A1–A3) separately from severity |
| [005](#adr-005-mitre-attck-v201-detection-strategies-as-the-soc-hand-off) | Hand the SOC ATT&CK v20.1 detection strategies to watch while an exposure is open |
| [006](#adr-006-close-the-instance-and-the-class) | Fix the instance and enforce an org-level guardrail for the class |
| [007](#adr-007-anchor-response-runbooks-on-observed-initial-access-data) | Build runbooks in order of observed attacker entry routes (Threat Horizons) |
| [008](#adr-008-vendor-neutral-by-design) | Name capabilities, not products |
| [009](#adr-009-count-missing-edr-on-exposed-hosts-as-risk-never-as-mitigation) | Missing EDR on an exposed host raises priority; a healthy agent never lowers it |

---

## ADR-001: Defender-first, least-touch validation

**Context.** External recon tooling is usually written for red teams: maximise findings, prove impact. An internal
exposure-management team has the opposite constraints. It must not disrupt production, read data it isn't entitled to,
or authenticate with secrets it finds, and every finding has to survive a debate with the asset owner.

**Decision.** Validation follows a five-rung **evidence ladder** (E0 reported → E4 owner-confirmed) and stops at the
lowest rung that answers the question. Proof is a status code, banner or key *name*. Never data, never exploits, never
found credentials. Default-credential and OT checks are explicitly RoE-gated.

**Consequences.** Findings are defensible and safe to run continuously. Some exposures stop at E2 and need the owner's
inside-out check (E4) to escalate. That is a deliberate trade, and the reason every cloud class ships an inside-out
command.

---

## ADR-002: Knowledge as versioned data, not prose

**Context.** Large prose skills are hard to review, diff, test or reuse outside the assistant that reads them.

**Decision.** Exposure knowledge lives in two YAML catalogs (`services.yaml`, `cloud-assets.yaml`) with a fixed shape:
ports, risk, passive query, least-touch proof, inside-out check, ATT&CK mapping, DET watch-list, mitigations, fix and
guardrail. Skills are short and procedural, and reason over the catalogs.

**Consequences.** A new exposure class is a reviewed pull request, not a rewrite. The same data can feed a scanner
port list, a SIEM enrichment table or a prioritisation engine. The cost is schema discipline: fields must stay
consistent, and the validation script enforces part of that.

---

## ADR-003: A transparent score (EPS) next to the prioritisation engine, not instead of it

**Context.** Enterprises already have a prioritisation engine. CVSS alone ignores reachability and exploitation, and
opaque vendor scores are hard to argue with. Owners disengage when they can't see why something is P1.

**Decision.** The **Exposure Priority Score** is four visible factors of 0–25 each (Reach, Class, Pressure, Blast),
plus explicit overrides. The outside-in facts (Reach, attribution, evidence rung) are fed *into* the engine as
attributes. Disagreements of more than one band are reviewed weekly.

**Consequences.** Every ticket shows its arithmetic, so owners argue with an input, not the outcome. EPS is a
prioritisation aid, not a loss model, and no dollar figures are produced without an organisational loss model.

---

## ADR-004: Attribution is its own axis

**Context.** In EASM, the most common false P1 is *someone else's* asset with a similar name, or a cloud IP that has
already been reassigned.

**Decision.** Every asset carries an attribution level (**A1** confirmed, **A2** probable, **A3** unattributed).
Active probing requires A2+. A3 is capped at P3 and goes to an attribution queue with a deadline. A2 not in inventory
raises an *unmanaged asset* finding and lifts one band.

**Consequences.** Fewer false alarms, and shadow IT becomes a first-class, measurable output instead of noise.

---

## ADR-005: MITRE ATT&CK v20.1 Detection Strategies as the SOC hand-off

**Context.** Exposure teams and SOCs often work in parallel. An open exposure is a window, and the SOC rarely knows
which windows are open.

**Decision.** Each catalog entry lists the ATT&CK techniques it enables and the **Detection Strategy IDs (DETxxxx)**,
introduced in ATT&CK v18, that the SOC must cover on those assets while the exposure is open. All IDs are generated
from and validated against MITRE's official STIX bundle, including the v19 Defense Evasion split and the revocation of
Impair Defenses. The validator fails the build on any stale ID and checks that every DET maps to a technique cited
alongside it.

**Consequences.** "We know it's open" becomes "we would see it being used". Unseen DETs become a measurable detection
backlog. The mapping must be refreshed after each April and October ATT&CK release, which takes one command.

---

## ADR-006: Close the instance *and* the class

**Context.** Fixing one public bucket a week is whack-a-mole. The same misconfiguration recurs because nothing
prevents it.

**Decision.** Every cloud class carries a **guardrail**: an org-level preventive control (SCPs and declarative
policies, Azure Policy at the management-group root, GCP organisation policy). Campaigns report guardrail coverage,
and a regression lifts a band.

**Consequences.** The inflow of findings shrinks over time. Guardrail rollout needs a sponsor and an exception path,
because it changes what engineers are allowed to do.

---

## ADR-007: Anchor response runbooks on observed initial-access data

**Context.** Runbook backlogs grow faster than teams can maintain them. Effort should follow how attackers actually
get in.

**Decision.** Runbooks are prioritised by Google Cloud Threat Horizons H1 2026, read from the primary report. The two
built first answer its top two cloud initial-access vectors: **software-based entry (44.5%)** → RB-01, and **weak or
absent credentials (27.2%)**, with identity behind 83% of cross-platform cases → RB-02. Both embed the report's
operational targets (virtual patch < 24h, full patch < 72h) and forensic-readiness lessons.

**Consequences.** Two deep runbooks cover roughly 72% of observed cloud initial access, instead of eleven shallow ones.
The ranking is revisited when the next Threat Horizons edition is published.

---

## ADR-008: Vendor-neutral by design

**Context.** Tool-specific guidance ages quickly, and publishing an organisation's actual security stack is itself an
information exposure.

**Decision.** The repo names *capabilities* (EASM, CNAPP, prioritisation engine, ITSM, SIEM), not a specific
organisation's products. Native cloud CLIs (`aws`, `az`, `gcloud`, `kubectl`) are used for inside-out checks because
every owner already has them.

**Consequences.** Any enterprise can adopt it. Teams map the capability names to their own tools in a private
operating-model addendum.

---

## ADR-009: Count missing EDR on exposed hosts as risk, never as mitigation

**Context.** An internet-exposed host without a working EDR agent is reachable *and* unseen. It also quietly breaks
the SOC hand-off (ADR-005), because most endpoint-based detection strategies need agent telemetry to fire. But many
exposed things can never run EDR (appliances, BMCs, hypervisors, OT, managed cloud services), so a blanket "no agent"
rule would drown teams in false positives.

**Decision.** Every catalog class carries `agent_expected` as a *class default* (true for general-purpose hosts and
container nodes, false otherwise), which can be overridden per asset when the real asset is an appliance or managed
service, or vice versa. Expected assets are joined to the EDR inventory on stable identifiers (resource ID and
hostname, not public IP). A **missing, stale or unknown** agent lifts the finding one band (not stacked with the
unmanaged-asset lift, since both share one root cause) and turns the endpoint-dependent DETs into recorded
`detection_gaps`. A **healthy** agent never lowers the band.

**Consequences.** Blind spots on the attack surface become a measured control-coverage metric (% of exposed hosts
with healthy EDR) instead of a surprise during an incident. Deploying an agent is an interim safety net only. It is
not the fix, and it doesn't qualify as an exception's compensating control, because it doesn't reduce Reach.
