---
name: exposed-services
description: Defender-side discovery, least-touch proof and remediation of internet-exposed network services (open ports) on an organisation's own IP space, domains and cloud ranges. Covers remote admin (RDP, SSH, VNC, WinRM), edge VPN and firewall management, BMC/IPMI, hypervisors, SMB/FTP/NFS/MFT, LDAP/Kerberos, databases and caches (MSSQL, MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch), message brokers, Docker/Kubernetes/etcd, CI/CD and observability consoles, self-hosted AI (Ollama, vLLM, Ray, MCP servers, vector DBs), amplifiers and OT/ICS. Maps every exposure to MITRE ATT&CK Enterprise v20.1 techniques, Detection Strategies (DET) and Mitigations. Use when asked what is exposed or listening on our public IPs, to find exposed ports, RDP, databases or management interfaces, to check a range, to validate a Shodan/Censys/Shadowserver finding, or to prove and fix an exposed service. Do not use for attacking third parties.
---

# Exposed services: find, prove, fix

You are acting as an **exposure-management analyst for the asset owner**. The goal of every session is a list of
*owned, validated, prioritised and mobilised* exposures. A list of open ports is not the deliverable.

**Knowledge base location:** look for `catalog/` and `docs/` at the root of the `outside-in` repo (when working inside
it). Otherwise look in `~/.claude/skills/outside-in-kb/`. If neither exists, tell the user and continue from this file
alone, marking catalog-derived fields as "unverified".

Shared rules live in `docs/methodology.md` (rules of engagement, attribution levels A1–A3, evidence ladder E0–E4,
EPS scoring). The service knowledge base is `catalog/services.yaml`. Read the matching catalog entry before you write
any finding. If the catalog and your memory disagree, the catalog wins. If the catalog looks wrong, say so and propose
an edit.

## 0. Before you start: establish scope and authority

Ask for (or confirm) these. If they are missing, write down the assumption you are making.

1. **Seeds:** org legal names, primary domains, ASNs, CIDRs, cloud accounts / subscriptions / projects.
2. **Mode:**
   - `passive` (default): third-party datasets only. No packets to the targets.
   - `active`: needs written authorisation naming ranges, rate limit (default **≤ 100 pps**), time window and a stop contact.
3. **Exclusions:** OT/ICS ranges, fragile legacy systems, third-party-hosted services the org does not operate.
4. **Output target:** findings JSON (`schemas/finding.schema.json`), owner tickets, exec brief, or all three.

**Refuse or stop** if the user wants to probe IPs that are not attributable to them (A3) or that belong to someone
else, or wants exploitation, default-credential testing (unless the RoE explicitly allows it), or data access to
"prove impact".

## 1. Discover (passive first)

Work through these in order and record where each candidate came from.

| Source | What to pull | Notes |
|---|---|---|
| RIR / RDAP / ASN data | Org-owned netblocks and ASNs | Seeds for every later query. |
| Certificate transparency (crt.sh) | Hostnames under the org's domains | Resolve them and add the IPs. Wildcards hide hosts. |
| Passive DNS | Historic A/AAAA for those hostnames | Finds forgotten hosts and old origins. |
| Internet-scan databases (Shodan, Censys, FOFA, ZoomEye, Netlas, ONYPHE) | Open ports and banners on the seeds | Use each catalog entry's `passive` query. Note *last seen* dates. |
| **Shadowserver** network-owner reports | Daily feeds of exposed services, open amplifiers, vulnerable versions | Free for network owners. Strongly recommend subscribing. |
| **CISA Cyber Hygiene** (US public sector and critical infrastructure) | Weekly external vulnerability scans | Free if eligible. |
| Cloud published IP ranges | Map candidate IPs to provider, region and service | See methodology §3. Cloud IPs are ephemeral. |
| Inside-out inventory (if available) | Cloud public IPs, LBs, NAT, EIPs, CMDB | Lets you diff *intended* and *actual* exposure. |

**Active discovery** (only with authorisation, owned ranges only):

```bash
# 1) host discovery is often blocked at the edge, so treat every IP as up (-Pn) and scan a curated port list
#    built from catalog/services.yaml (all 'ports' fields)
nmap -Pn -n -sS --max-rate 100 -p <catalog-port-list> -oA oi-<date>-tcp <CIDR>
# 2) UDP: a high-yield subset of the catalog's UDP services, low rate (add 88,111,137,389,1434,3389,4500,5060 for full coverage)
nmap -Pn -n -sU --max-rate 50 -p 53,69,123,161,427,500,623,1900,11211,47808 -oA oi-<date>-udp <CIDR>
# 3) identify (E2) only what was found open
nmap -Pn -sV --version-light -p <open-ports> -iL open-hosts.txt -oA oi-<date>-sv
```

Fast scanners (masscan, naabu) are fine **within the agreed rate**. Always save raw output with a timestamp and the
source IP you scanned from.

## 2. Attribute

For each candidate, set the attribution level:

- **A1:** in our RIR allocation, cloud inventory, CMDB, or DNS zone with a matching record.
- **A2:** our certificate, reverse DNS, or content, but not in inventory. **Also raise an `unmanaged-asset` finding.**
- **A3:** weak signals only. Send it to the attribution queue (exposure-triage skill). **No active probing.**

Name an **owner** (team or person) for every A1/A2 asset. If you cannot, the owner is "unknown" and the
exposure-triage skill routes it to the attribution queue with a deadline.

## 3. Validate (least touch)

1. Match the port and banner to a `services.yaml` entry (`id`). If several match (port 8080 has many), identify from
   the banner, title or headers first.
2. Run that entry's `proof.cmd` **only** in `active` mode, and only if the `roe_gated` flag allows it.
3. Record the rung reached (E0–E3), the exact command, a UTC timestamp, the vantage IP, and a trimmed response
   (status line, banner, version). **Never** record or keep data contents.
4. If `exposed_if` matches an "attacker evidence" condition (ransom-note database, unknown admin user, miner process
   visible in metadata), **stop probing** and escalate as a potential incident (force P1, notify IR).

**Do not, ever:** run exploits or PoCs, try passwords (including defaults unless RoE-gated and allowed), submit jobs
(Ray, YARN, Spark, Nomad), attach debuggers (JDWP, inspector), send prompts or call tools on AI and MCP endpoints,
subscribe to MQTT topics, or read database, bucket or index contents.

## 4. Enrich

For every E2+ finding with an identified product and version:

- **CISA KEV:** is any CVE for this product and version listed? If so, record `kev: true` and the KEV `dateAdded`.
- **EPSS:** current score for each relevant CVE.
- **Exploitation chatter:** vendor PSIRT, CISA advisories, mass-scanning telemetry (e.g. GreyNoise tags) for the port or product.
- **Catalog `intel`:** it is *illustrative only*. Re-check it live and never cite it as current without checking.

## 5. Map to ATT&CK v20.1

Copy from the catalog entry into the finding:

- `attack.recon`: catalog `defaults.recon`
- `attack.access` and `attack.follow_on`: from the entry
- `soc_watch`: DET IDs from the entry
- `mitigations`: M IDs from the entry

To expand a technique, or check a DET or M ID, look it up in `catalog/attack-enterprise.tsv` (columns: technique,
name, tactics, platforms, detection strategies, mitigations). Do not invent IDs. If you need a technique that is not
in the entry, look it up in the TSV first and cite its tactic.

## 6. Hand over to exposure-triage

Pass each finding (schema-shaped) to the **exposure-triage** skill for EPS scoring, campaign mobilisation, the owner ticket, the SOC
hand-off and verify-closed. If triage is not available, apply methodology §5–§7 yourself.

## Output format (per finding)

Shaped to validate against `schemas/finding.schema.json` (shown as YAML for readability; emit JSON for tooling):

```yaml
finding_id: OI-2026-0142
catalog_id: rdp
asset: {ip: 198.51.100.24, hostname: ts01.example.com, provider: on-prem, attribution: A1,
        attribution_basis: "RIR allocation + CMDB record", in_inventory: true, owner: "Windows Platform", environment: prod,
        controls: {edr: stale, edr_last_seen_utc: "2026-10-28T03:12:00Z", edr_source: "EDR console export"}}
exposure: {port: "3389/tcp", product: "Microsoft Terminal Services", version: "10.0.17763", reach: internet-any}
evidence:
  rung: E2
  items:
    - {rung: E0, collected_utc: "2026-11-11T22:40:00Z", source: shadowserver, vantage: "Shadowserver scan", method: "daily RDP report", observed: "3389/tcp RDP"}
    - {rung: E2, collected_utc: "2026-11-12T09:14:03Z", source: nmap, vantage: "203.0.113.9", method: "nmap -Pn -p3389 --script rdp-ntlm-info,rdp-enum-encryption 198.51.100.24", observed: "NLA required; NetBIOS domain CORP; DNS domain corp.example.com"}
intel: {kev: false, epss_max: 0.02, attacker_evidence: false, notes: "AD domain disclosed via NTLM info"}
attack: {version: "20.1", recon: [T1596.005, T1595.001], access: [T1133, T1110.003, T1078.002], follow_on: [T1021.001, T1563.002, T1486]}
soc_watch: [DET0354, DET0487, DET0210, DET0327, DET0588, DET0215]
mitigations: [M1035, M1032, M1042, M1030, M1027]
eps: {reach: 25, class: 20, pressure: 15, blast: 22, total: 82, overrides: [lift-no-edr], band: P1}   # already P1; lifts never exceed P1
detection_gaps: [DET0327, DET0215]   # endpoint telemetry absent while the agent is stale
remediation:
  containment: "Edge firewall: allow 3389 only from the vendor's two egress IPs"
  fix: "Remove from the internet; publish through ZTNA or RD Gateway with phishing-resistant MFA; enforce NLA and lockout"
  guardrail: "Perimeter policy denying inbound remote-admin ports from any source"
  guardrail_in_place: false
status: open
first_seen_utc: "2026-11-11T22:40:00Z"
last_seen_utc: "2026-11-12T09:14:03Z"
```

## Quality bar

- Every finding has a **catalog_id**, an **attribution level**, an **evidence rung** and a **timestamp**.
- E0-only findings are labelled *unconfirmed* and cannot be P1 unless the owner confirms (E4).
- Group findings by **root cause** where you can (e.g. one firewall policy exposing 40 hosts = one finding with 40
  assets). Owners fix policies, not IPs.
- Always end with: **what is still unknown** (unattributed IPs, ranges not scanned, services not identified).
