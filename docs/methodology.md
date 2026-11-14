# Methodology

This document is the shared contract for all three skills and both runbooks. If a skill and this document disagree,
this document wins.

## Contents

1. [The exposure loop (CTEM-aligned)](#1-the-exposure-loop-ctem-aligned)
2. [Rules of engagement](#rules-of-engagement)
3. [Attribution: is it ours?](#3-attribution-is-it-ours)
4. [The evidence ladder](#4-the-evidence-ladder)
5. [Exposure Priority Score (EPS)](#5-exposure-priority-score-eps)
6. [Mobilisation: remediation campaigns, tickets, SLAs and exceptions](#6-mobilisation-remediation-campaigns-tickets-slas-and-exceptions)
7. [Verify-closed](#7-verify-closed)
8. [CTEM and framework alignment](#8-ctem-and-framework-alignment)

---

## 1. The exposure loop (CTEM-aligned)

| Stage | Question | Main inputs | Output |
|---|---|---|---|
| **Scope** | Which attack surface are we managing this cycle? | Legal entities, domains, ASNs, CIDRs, cloud accounts / subscriptions / projects, exclusions | Seed list and rules of engagement |
| **Discover** | What is reachable from the internet? | Passive sources first (EASM, internet-scan databases, CT, passive DNS), then authorised scanning of owned ranges | Candidate asset list |
| **Attribute** | Is it ours, and who is the remediation owner? | WHOIS/RDAP, cert subjects, cloud IP ranges, CMDB, cloud inventory, tags | Asset with an attribution level (A1–A3) and a remediation owner |
| **Validate** | Is it really exposed, and how badly? | Least-touch probes and inside-out read-only checks | Evidence at a rung on the ladder (E0–E4) |
| **Prioritise** | How urgent? | Catalog class, KEV/EPSS, blast radius, prioritisation-engine score | EPS score and P1–P4 band |
| **Mobilise** | Who fixes it, by when, and through which campaign? | Remediation-owner map, SLA table, ITSM | Remediation campaign, owner tickets, SLAs and exceptions, plus a SOC detection hand-off |
| **Verify-closed** | Is it actually gone? | Re-run the original proof from the outside | Closure evidence, or a reopened ticket |

The loop repeats. The second pass is a **diff**: new exposures, closed exposures and regressions. Over time, the diff is
the main deliverable.

> **Why "Validate" sits before "Prioritise".** CTEM lists prioritisation before validation because there, validation
> means attack-path testing of what has already been prioritised. In an EASM-led loop, an exposure must first be
> *proved real* (scan databases go stale). Otherwise the prioritisation engine ranks ghosts. Attack-path validation of
> P1s (for example a breach-and-attack-simulation or a red-team check) can still follow prioritisation as a
> CTEM-standard step.

---

## Rules of engagement

These apply to every skill, every time.

### Allowed without further authorisation (passive)

- Querying internet-scan databases (Shodan, Censys, FOFA, ZoomEye, Netlas, ONYPHE and similar) for **your own**
  ranges, domains and certificates.
- Certificate transparency (crt.sh), passive DNS, WHOIS/RDAP, RIR and ASN data, cloud providers' published IP ranges.
- Subscribing your own networks to **Shadowserver** free daily reports and, for eligible US organisations,
  **CISA Cyber Hygiene** scanning.
- Reading your own cloud inventory and configuration with **read-only** credentials (inside-out checks).

### Requires written authorisation (active)

Active work needs a document that names:

- the **IP ranges, hostnames and cloud accounts** in scope;
- the **rate limits** (packets per second, requests per second) and **time windows**;
- a **contact** who can stop the test;
- the **data-handling** rules for anything sensitive you see.

Active work includes port scanning, banner grabbing, HTTP probing, and unauthenticated API calls to storage or management
endpoints.

### Never, regardless of authorisation in this toolkit

- Running exploits or proof-of-concept code against production.
- Authenticating with credentials, keys or tokens you discover. Report them, and have the owner revoke and rotate.
- Downloading object bodies, database rows or file contents to "prove" sensitivity. Key *names*, counts and metadata
  are enough.
- Writing, deleting or modifying anything on an exposed asset, even to "test write access". Use the inside-out policy
  check instead.
- Probing assets you cannot attribute to the organisation at **A2 or higher** (see below). The one carve-out:
  **existence-only** checks (a DNS lookup, or an HTTP status on a storage endpoint name) of a *bounded*, explainable
  list of brand-name permutations are allowed at A3, to establish whether a candidate exists at all. No listing, no
  content and no service probes until the asset reaches A2.

> If you find something that is clearly someone else's (a supplier, a former subsidiary, a stranger's bucket), stop.
> Record the minimum needed to notify, and route it through your security leadership or legal team.

---

## 3. Attribution: is it ours?

Every asset carries an attribution level. Active probing requires **A2 or higher**.

| Level | Meaning | Typical evidence |
|---|---|---|
| **A1: Confirmed** | Inside our inventory. | IP or resource in our cloud account (inside-out query), in our CMDB, in our RIR allocation, or under our DNS zone with a matching record. |
| **A2: Probable** | Strong outside-in signals, not yet in inventory. | TLS cert for our domain, our hostname in reverse DNS, our org name in RDAP, a cloud IP that serves our content. Shadow IT usually sits here. |
| **A3: Unattributed** | Weak or conflicting signals. | Brand-like bucket name, a third-party-hosted page that mentions us, a shared-hosting IP. |

**A3 findings are not low severity. They are unresolved.** They go to the *attribution queue* (see
[exposure-triage](../skills/exposure-triage/SKILL.md)), not the remediation queue. A2 findings that cannot be found
in inventory are themselves a finding: **unmanaged asset** (shadow IT).

### Cloud IP attribution

Map an IP to a provider, region and service using the providers' published ranges:

- AWS: `https://ip-ranges.amazonaws.com/ip-ranges.json`
- Azure: Service Tags JSON (downloaded from Microsoft, refreshed weekly)
- Google Cloud: `https://www.gstatic.com/ipranges/cloud.json`
- Oracle Cloud: `https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json`

A cloud IP is **ephemeral**. It may belong to someone else tomorrow. Attribute cloud IPs by **resource** (an
inside-out lookup of the elastic IP, load balancer or public IP resource), not by address alone.

---

## 4. The evidence ladder

Prove exposure at the **lowest rung that answers the question**. Higher rungs mean more contact with the target and need
more justification.

| Rung | What you did | Example | Needs active authorisation? |
|---|---|---|---|
| **E0: Reported** | A third-party dataset says so. | Shodan shows 3389/tcp with an RDP banner last seen 3 days ago. | No |
| **E1: Reachable** | TCP handshake or TLS hello succeeded. | `nmap -Pn -p 3389` shows open. | Yes |
| **E2: Identified** | Protocol and product identified (banner, version, cert). | `rdp-ntlm-info` returns the AD domain name. | Yes |
| **E3: Unauthenticated access confirmed** | An unauthenticated request got a "success" status, with **no data read**. | `GET /` on Elasticsearch returns a cluster name. A bucket listing returns HTTP 200 with key names only. | Yes |
| **E4: Owner-confirmed** | The owner's inside-out read-only check agrees. | `aws s3api get-bucket-policy-status` shows `IsPublic: true`. | No (owner runs it) |

**Rules**

- E0 alone is enough to *open* a finding, but not to escalate it to P1. Scan databases go stale. Confirm with E1+ or E4.
- E3 must be **status-code or metadata only**. If the only way to go beyond E2 is to read data, stop at E2 and ask
  the owner for E4.
- Always record *when* and *from where* (source IP or vantage point) the evidence was collected. Exposure can be
  source-dependent (geo-blocking, allow-lists).

---

## 5. Exposure Priority Score (EPS)

EPS is a transparent 0–100 points model. It is deliberately simple, so that an owner can recompute it and argue with
a specific input rather than with the result.

```
EPS = Reach (0–25) + Class (0–25) + Pressure (0–25) + Blast (0–25)
```

| Factor | 25 | 15–20 | 5–10 | 0 |
|---|---|---|---|---|
| **Reach**: who can get to it? | Any internet source, no gateway | Internet, but behind SSO, VPN pre-auth or a geo/IP allow-list that is broad | Narrow allow-list (a handful of partner IPs) | Not actually reachable (E0 stale) |
| **Class**: how dangerous is this kind of exposure? | Catalog `weight: critical`: unauthenticated data plane, unauthenticated control plane, leaked credential | `high`: remote admin and login surfaces, edge appliances, management UIs | `medium`: info-leaking services, legacy protocols | `low`: expected public services (443 on a web front end) |
| **Pressure**: is it being exploited? | KEV-listed CVE matches the observed version, **or** a ransom note or attacker artefact is visible | EPSS ≥ 0.10, **or** active mass-scanning seen (GreyNoise, honeypot telemetry), **or** a public exploit exists | Known CVE with low EPSS, **or** brute-forceable login with no lockout evidence | Nothing known |
| **Blast**: what does it unlock? | Production data with regulated or sensitive content, identity or admin control plane, credentials | Production system without sensitive data | Non-production | Static or public content |

### Bands

| Band | EPS | Default SLA to remove the exposure* |
|---|---|---|
| **P1** | ≥ 75 | 72 hours (contain within 24 hours) |
| **P2** | 50–74 | 14 days |
| **P3** | 25–49 | 45 days |
| **P4** | < 25 | Next planned change, or accept the risk with a review date |

\* Adjust these to your policy. For KEV-listed CVEs, US federal agencies are bound by CISA BOD 22-01 timelines.

### Overrides (applied after scoring)

- **Force P1** when there is E3 unauthenticated access to an A1/A2 data store or control plane, when a valid secret is
  leaked publicly (even if unconfirmed: assume valid), or when there is attacker evidence (ransom note, web shell, unknown
  admin user, crypto-miner).
- **Cap at P3** while attribution is **A3**. Send it to the attribution queue.
- **Lift one band** when the asset is unmanaged (A2 and not in inventory). Nobody is patching it.
- **Lift one band** when the exposure has **regressed** (it was `closed-verified` and is open again). The guardrail is
  missing or was bypassed.
- **Lift one band** when the catalog class has `agent_expected: true` and the asset's EDR is **missing** or **stale**
  (see *Control coverage* below). It is reachable, and if it is hit, nobody will see it.

Each lift applies at most once per finding, and lifts never go above P1.

### Control coverage: EDR on exposed hosts

An exposed host without a working EDR agent is a blind spot, and it quietly breaks the SOC hand-off, because most
endpoint-based detection strategies (for example DET0384 shell execution, DET0394 web shells, DET0290 cron
persistence, DET0540 compute hijacking) need that telemetry to fire.

| State | Meaning |
|---|---|
| `healthy` | Agent present, checked in within 7 days, full prevention or detection mode |
| `stale` | Agent present but silent for more than 7 days, or in a reduced-functionality mode |
| `missing` | Not in the EDR console at all |
| `not-applicable` | Catalog class has `agent_expected: false` (appliance, BMC, hypervisor, IoT, OT, managed cloud service) |
| `unknown` | Not yet joined. Treat as `missing` for scoring until resolved |

Rules:

1. **Join on stable identifiers:** the cloud instance or resource ID and the hostname, never the public IP alone,
   because cloud IPs are reused.
2. **Missing or stale on an `agent_expected` class:** apply the override above, and record the endpoint-dependent
   `soc_watch` DETs for that asset as `detection_gaps`.
3. **A healthy agent never lowers the band.** EDR does not reduce Reach; it only improves the odds of seeing the
   attack. Removing the exposure is still the fix. Deploying the agent is the interim safety net, and a valid
   compensating control in an exception.

### EPS and your prioritisation engine

Most CTEM programmes already run a prioritisation engine: an exposure-management platform, the CNAPP's risk score, or
the VM tool's risk rating. EPS is **not** meant to replace it. It exists because an engine fed only by inside-out data
sources (agents, authenticated scans, cloud APIs) usually lacks three outside-in facts:

1. **Is it actually reachable from the internet right now?** That is EPS *Reach*, evidenced by an E1–E3 probe.
2. **Is it even ours?** That is the attribution level, A1–A3.
3. **Is it on a surface nobody manages?** That is the unmanaged / shadow-IT lift.

The recommended pattern is to **feed Reach, attribution and evidence rung into the engine as asset or finding
attributes**, and to let the engine's exploit intelligence inform EPS *Pressure*. Where the two disagree by more than
one band, that disagreement is itself a signal worth a 5-minute look in the weekly cycle.

---

## 6. Mobilisation: remediation campaigns, tickets, SLAs and exceptions

Findings are mobilised in **remediation campaigns**, not one ticket per IP. A campaign groups the roll-ups that share a
**fix type and a remediation owner** (for example, *"Remove internet-exposed RDP: 23 hosts, 4 owner teams, P1"*). The
VM / exposure-management team runs the campaign. The remediation owners do the fixing.

Each campaign produces four outputs:

1. **Campaign brief** ([templates/remediation-campaign.md](../templates/remediation-campaign.md)): the why (threat
   context and EPS), the scope, the standard fix and guardrail, the SLA, the exception rules and the success measure.
2. **Owner tickets** in your ITSM ([templates/owner-ticket.md](../templates/owner-ticket.md)), one per remediation
   owner per roll-up. Each carries the plain-language problem, evidence, the inside-out confirmation command, the fix,
   the SLA due date and how closure will be verified.
3. **SOC hand-off**: the ATT&CK techniques the exposure enables and their **Detection Strategy IDs (DETxxxx)**. While
   the exposure is open, the SOC should confirm it has telemetry and analytics for those strategies on those assets.
   This turns "we know it's open" into "we'd see it being used".
4. **Finding records** ([schemas/finding.schema.json](../schemas/finding.schema.json)): machine-readable, for the SIEM,
   data lake, prioritisation engine or GRC tool.

**Exceptions.** An owner who cannot meet the SLA raises an exception in the ITSM. An exception needs:

- a compensating control that **reduces Reach** (an allow-list, an IAP or a WAF virtual patch), re-scored with EPS;
- an expiry date;
- an accountable approver.

An exception never covers a **force-P1** override for more than 7 days without CISO sign-off.

---

## 7. Verify-closed

A finding closes only when the **original outside-in proof fails** from the same vantage point (or an equivalent one).
An owner saying "fixed" is not enough.

| Outcome | Status |
|---|---|
| Original probe now fails (filtered, closed, 401/403) **and** the inside-out check agrees | `closed-verified` |
| Probe fails, inside-out check unavailable | `closed-outside-only` (re-test at next cycle) |
| Service moved (new port or IP) with the same content | `reopened-relocated` |
| Probe succeeds | `open-fix-not-effective` |
| Asset decommissioned, but DNS still points at it | **New finding**: dangling DNS (takeover risk) |

---

## 8. CTEM and framework alignment

| This loop | Gartner CTEM stage | NIST CSF 2.0 | CIS Controls v8.1 |
|---|---|---|---|
| Scope | Scoping | GV.OC, ID.AM | 1, 2 |
| Discover + Attribute | Discovery | ID.AM-01/02/03 | 1, 12 |
| Validate | Validation | ID.RA | 7, 18 |
| Prioritise | Prioritisation | ID.RA-04/05/06 | 7 |
| Mobilise + Verify-closed | Mobilisation | PR.PS, RS.MI | 4, 7, 12 |
| SOC hand-off | (supports all) | DE.CM, DE.AE | 8, 13 |

How the loop plugs into an existing CTEM programme (data sources, prioritisation engine, ITSM, SOC) is described in
[operating-model.md](operating-model.md).

ATT&CK mapping conventions are described in [attack-mapping.md](attack-mapping.md).
