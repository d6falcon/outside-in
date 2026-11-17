# MITRE ATT&CK® mapping (Enterprise v20.1)

This document explains how `outside-in` uses ATT&CK, and gives the exposure-to-attack-chain matrix the skills reason from.

- **Version:** Enterprise ATT&CK **v20.1** (STIX data modified 5 Nov 2026). It has 15 tactics, 227 techniques,
  479 sub-techniques, 703 detection strategies and 1,770 analytics.
- **Source of truth:** [`catalog/attack-enterprise.tsv`](../catalog/attack-enterprise.tsv), generated from MITRE's
  official STIX bundle by [`scripts/update_attack_mapping.py`](../scripts/update_attack_mapping.py). The script also fails
  if any T, DET or M ID in the catalogs or docs is revoked, deprecated or mistyped.

## 1. Conventions

| Field in catalog | ATT&CK object | Why we use it |
|---|---|---|
| `defaults.recon` | Reconnaissance techniques (TA0043) | How attackers *find* the exposure. These are mostly pre-compromise and invisible to you, so their main use is threat modelling. |
| `attack.access` | Initial Access (TA0001) or Credential Access techniques | What the exposure directly enables. |
| `attack.follow_on` | Later-stage techniques | What happens next, which sets the "Blast" factor in EPS. |
| `soc_watch` | **Detection Strategies (DETxxxx)** | The detection coverage the SOC should confirm while the exposure is open. This is the hand-off. |
| `mitigations` | **Mitigations (Mxxxx)** | Lets GRC tooling tie the fix back to ATT&CK mitigations. |

Since **v18**, ATT&CK models detection as **Detection Strategy → Analytic → Log Source / Data Component**. A DET ID is
stable and platform-agnostic. Each DET has platform-specific analytics (ANxxxx) underneath it. That makes DET IDs the
right granularity for a hand-off: *"confirm you have analytics for DET0354 on these 4 hosts"*.

### Framework changes to be aware of

| Change | Version | Effect on this repo |
|---|---|---|
| Defense Evasion (TA0005) split into **Stealth (TA0005)** and **Defense Impairment (TA0112)** | v19 | Cloud tampering techniques (T1578, T1666, T1685, T1686) are now under Defense Impairment. |
| **T1562 Impair Defenses revoked** → **T1685 Disable or Modify Tools**, **T1686 Disable or Modify System Firewall** | v19 | Older mappings that cite T1562.007 / T1562.008 are stale. Use **T1686.001 Cloud Firewall** and **T1685.002 Disable or Modify Cloud Log**. <!-- attack-lint: historical --> |
| T1078 Valid Accounts major version bump; now listed under Stealth, Persistence, Privilege Escalation and Initial Access | v19 | No ID change. |
| New AI techniques: **T1698 Indirect Prompt Injection, T1699 Direct Prompt Injection, T1700 AI-Enabled Exfiltration, T1608.007 AI Result Poisoning, T1685.007 Impair Autonomous Defenses** | v20 | Used for exposed AI, MCP and agent endpoints. |
| **T1496.004 Cloud Service Hijacking** (e.g. LLMjacking) and **T1485.001 Lifecycle-Triggered Deletion** | recent releases (v16+) | Used for leaked keys and cloud storage. |

ICS assets (the `ot-ics` family) should also be mapped with **ATT&CK for ICS** (for example T0883 *Internet Accessible
Device*, T0822 *External Remote Services*, T0886 *Remote Services*). The Enterprise mappings in the catalog cover only
the IT-side entry path.

---

## 2. Exposure-to-attack-chain matrix

Each row is an exposure **family**. The individual catalog entries refine it.

### 2.1 Exposed services (`catalog/services.yaml`)

| Family | Recon | Initial access | Typical follow-on | SOC watch (core) |
|---|---|---|---|---|
| Remote admin (RDP, SSH, VNC, WinRM) | T1596.005, T1595.001 | **T1133**, T1110.003, T1078.002 | T1021.001/.004/.005/.006, T1563.002, T1486 | DET0354, DET0487, DET0327 |
| Edge appliances (VPN, firewall management) | T1590.006, T1596.005 | **T1190**, T1133, T1078.002 | T1505.003, T1003.003, T1686.002 | DET0080, DET0354, DET0394 |
| Infra management (BMC, vSphere, backup, NAS) | T1596.005 | T1190, T1078.001 | T1486, T1490, T1485 | DET0080, DET0465, DET0215 |
| File transfer and sharing (SMB, FTP, NFS, MFT) | T1595.001 | T1190, T1210 | T1021.002, T1557.001, T1567 | DET0080, DET0118, DET0530 |
| Directory (LDAP, Kerberos, RPC) | T1590.002 | T1110.003 | T1087.002, T1482, T1558.004 | DET0487 |
| Databases and caches | T1596.005 | T1190, T1078.001, T1110.001 | **T1213.006**, T1485, T1486, T1496.001 | DET0242, DET0146, DET0540 |
| Containers and orchestration | T1595.002 | T1190, T1078.004 | T1609, T1610, T1611, T1613, T1552.007 | DET0065, DET0249, DET0219, DET0198 |
| DevOps and observability | T1593.003 | T1190, T1078.001 | T1552.001, T1072, T1195.002 | DET0307, DET0309 |
| AI / ML (Ollama, vLLM, Ray, MCP, vector DBs) | T1596.005 | T1190, T1133 | **T1496.004**, T1698, T1699, T1700 | DET0941, DET0942, DET0927 |
| Amplifiers (DNS, NTP, SSDP, memcached, CLDAP, SLP) | T1595.001 | n/a (you are the weapon) | T1498.002 | DET0408 |
| OT / ICS | T1596.005 | T1190, T1133 (+ ICS T0883) | T1565 | DET0080, DET0354 |

### 2.2 Exposed cloud assets (`catalog/cloud-assets.yaml`)

| Family | Recon | Initial access / collection | Typical follow-on | SOC watch (core) |
|---|---|---|---|---|
| Object storage (S3, Blob, GCS, R2, OCI) | T1593.002, T1619 | **T1530** | T1567.002, T1552.001, T1485, T1486 | DET0484, DET0578, DET0570 |
| Writable storage | T1593.002 | T1608.001, **T1195.002** | T1189, T1485 | DET0824, DET0309, DET0176 |
| Snapshots and images (EBS, RDS, AMI, disks) | T1580 | **T1537** (copy to attacker account) | T1552.001, T1552.004, T1078.004 | DET0573, DET0307 |
| Managed DBs and BaaS (RDS, Azure SQL, Cloud SQL, Firebase, Supabase) | T1596.005 | T1190, T1530 | T1213.006, T1565.001 | DET0242, DET0193 |
| Serverless and APIs | T1593.003 | T1190 | **T1648**, T1499.003 | DET0374, DET0415 |
| Managed Kubernetes endpoints | T1596.003 | T1078.004, T1190 | T1609, T1610, T1613, T1552.007 | DET0546, DET0065, DET0490 |
| Cloud firewall drift | (none) | T1133, T1190 | **T1686.001** (attacker re-opens), T1021.008 | DET0424, DET0211 |
| Dangling DNS / IPs | T1596.001 | **T1584.001**, T1583.003 | T1189, T1539 | DET0863, DET0176, DET0509 |
| Leaked non-human credentials | T1593.003 | **T1552.001 → T1078.004** | T1580, T1526, T1098.001, T1136.003, T1496.004, T1535 | DET0546, DET0531, DET0319, DET0147 |
| Federation and trust (OIDC, cross-account, Cognito) | T1593.003 | T1550.001, T1199, T1078.004 | T1098.003, T1530 | DET0185, DET0488, DET0277 |
| SaaS public links | T1593.002 | (direct collection) | T1213, T1213.002, T1552.001 | DET0413, DET0500 |
| Cloud AI (notebooks, agents, LLM keys) | T1593.003 | T1190, T1078.004 | T1496.004, T1698, T1699, T1700, T1552.005 | DET0147, DET0941, DET0942, DET0927, DET0001 |

---

## 3. The SOC hand-off, worked example

> **Finding:** `rdp` on `198.51.100.24` (A1, E2, EPS 82 → P1). The owner says removing exposure takes 5 days
> (vendor support dependency).

1. **Contain now:** source allow-list on the edge firewall for the vendor's IPs. Reach drops from 25 to 10 and the
   EPS is recomputed.
2. **Hand-off to the SOC:** "Until finding OI-2026-0142 closes, confirm analytics for:
   - **DET0354** (External Remote Services behaviour chain): logons to 198.51.100.24 from non-allow-listed sources;
   - **DET0487** (Password spraying): distributed 4625 failures across accounts on that host;
   - **DET0327** (RDP logins and post-access activity): new interactive sessions followed by discovery commands;
   - **DET0215** (File encryption for impact): mass file rename or write on that host and its shares."
3. **Close:** the outside-in re-test from the same vantage point shows `3389/tcp filtered`. The finding becomes
   `closed-verified` and the SOC watch is released.

---

## 4. ATT&CK Navigator layer (backlog)

A generated Navigator layer (`.json`) that colours techniques by the number of open findings that enable them is
listed in [RUNBOOKS-BACKLOG.md](../RUNBOOKS-BACKLOG.md#tooling-backlog).

---

*MITRE ATT&CK® is a registered trademark of The MITRE Corporation. ATT&CK content © The MITRE Corporation, used under
the ATT&CK Terms of Use.*
