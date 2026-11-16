# Problem validation: are these really the burning issues?

*Research date: 12 November 2026. Scope: public 2026 reporting on enterprise initial access and internet exposure.*

**Bottom line:** yes, both problems are well supported. They are also two halves of the same problem.
In 2026 reporting, **exploitation of internet-facing software** and **abuse of exposed remote access** are the top
ways attackers get in. **Exposed cloud assets** (public storage, open managed services, leaked non-human credentials,
and now self-hosted AI endpoints) are a leading cause of cloud compromise and data-extortion events. If you are
seeing both in your organisation, the data says you are typical, not unlucky.

> **How to read the numbers.** Vendors measure different populations (IR caseloads, surveys, internet scans) with
> different definitions, so their percentages do not line up neatly. Where a figure comes from a secondary summary
> rather than the primary report, it is marked **(secondary)**. Check it against the primary source before you put
> it in a board paper.

---

## 1. Exposed common ports and services

### 1.1 Initial-access data

| Source | Finding | Notes |
|---|---|---|
| **Verizon DBIR 2026** | Exploitation of vulnerabilities is the **#1 initial-access vector at ~31%** (up from 20%), and credential abuse fell to ~13%. | Secondary summaries also cite **edge/VPN devices rising from 3% → 22%** of exploitation breaches **(secondary)**. |
| **Verizon DBIR 2026** | Among **initial-access-broker** listings, **44%** of known connection types were **VPN** and **35%** were **remote-desktop** applications. | This is what is sold on the market: exposed remote access. |
| **Mandiant M-Trends 2026** | Exploits were the most common initial infection vector for the **6th consecutive year (32%)**. Mean time-to-exploit was about **-7 days**, and the median access hand-off to a second group took **22 seconds**. | The patch window has effectively closed for exposed services. Removing the exposure is the control. |
| **Arctic Wolf Threat Report 2026** | **65%** of non-BEC IR cases came from abuse of **external remote-access** products (RDP, VPN, RMM). | Described as a sharp rise over two years. |
| **Sophos Active Adversary Report 2026** | Identity-led access dominates. **Brute force (15.6%)** is almost level with **exploitation (16%)**. | Brute force needs an exposed login surface (RDP, SSH, VPN, OWA). |
| **Sophos State of Ransomware 2026** | Where the compromise point was known, **firewalls accounted for 21%** and **VPNs 8%**. Firewall-exploit cases more often led to demands of **$1M+ (59%)**. | Survey-based. |
| **Rapid7 Threat Landscape 2026** | The access types most often advertised on underground forums were **RDP (21.2%)**, **VPN (12.8%)** and **RDWeb (11.2%)**. | |

### 1.2 Internet-scan data (how much is exposed)

| Source | Finding |
|---|---|
| Forescout Vedere Labs (May 2026, **secondary**) | About **1.8M RDP** and **1.6M VNC** servers exposed on the internet. |
| Shodan-based EU study (2026) | **416,856 RDP** and **210,306 SMB** endpoints exposed across the EU. Also counts exposed MySQL, PostgreSQL, MongoDB, Redis and Elasticsearch by country. |
| Flare (2026) | **208,500+** internet-exposed **MongoDB** servers. About 3,100 needed no authentication, and about 100,000 leaked operational information. |
| Ransomnews five-year study | **46.3%** of 65,907 exposed database and admin-panel systems already carried a ransom or wipe note. Nearly all exposed Elasticsearch instances in the set (6,055 of 6,185) did. |
| 2026 attack-surface write-ups (**secondary**) | Around **49%** of assessed organisations had a risky port or service exposed, and **42%** had a directly reachable database. Methodology not verified. |

### 1.3 What this means for the repo

| Family | Why it matters |
|---|---|
| **Remote access and admin interfaces** (RDP, SSH, VNC, WinRM, VPN/firewall portals, iLO/iDRAC/IPMI, hypervisors) | Carry the most weight. CISA **BOD 23-02** already makes US federal agencies remove internet-exposed management interfaces, which is a sensible baseline for any enterprise |
| **Unauthenticated data planes** (databases, caches, search clusters, object stores, brokers) | Turn exposure into data extortion with no exploit at all |
| **Edge appliances** | Both an exposed service and a frequent KEV entry, so exposure and patch status are scored together |
| **Newer classes** | Container and orchestration APIs, CI/CD and observability consoles, **self-hosted AI inference and MCP servers** |

---

## 2. Exposed cloud assets

| Source | Finding | Notes |
|---|---|---|
| **Google Cloud Threat Horizons H1 2026** (H2 2025 data). **Primary source, read in full.** | **Google Cloud initial access:** software-based entry **44.5%** (known software vulnerability 30.9% + RCE 13.6%; it was 2.9% in H1 2025), weak or absent credentials **27.2%** (from 47.1%), misconfiguration **21.0%** (from 29.4%), exposed sensitive UI/API **4.9%** (from 11.8%), other 2.5%. **Cross-platform (Mandiant IR):** identity **83%** (phishing 31%, of which vishing 17%; third-party 21%; stolen credentials 21%; insider 7%; supply chain 3%), misconfiguration 7%, vulnerability exploitation 2%. **Objectives:** data theft 73% (45% silent, 28% with extortion), ransomware 3%, resource co-opting 5%. Disclosure-to-exploitation went from weeks to days (XMRig ~48h after CVE-2025-55182). Recommended patch targets: **< 24h virtual patch, < 72h full patch**. | The report notes its Google Cloud data is a subset of observed activity. **This repo's runbooks are anchored on it** (see `runbooks/README.md`). |
| **Wiz State of Cloud Risk 2026** (**secondary**) | Misconfigurations account for **~19%** of initial access in documented cloud intrusions. **Credential and secret exposure** is the second-largest class of exploitable high or critical findings (~23%). | |
| **Unit 42 Global IR Report 2026** | Previously compromised credentials accounted for **13%** of initial access. Includes cases of **cloud credentials exposed in public code repositories**. | Enterprise-wide, not cloud-only. |
| Cloud Exposure Index 2026 (**secondary**) | **484,142** publicly accessible cloud storage buckets across major providers. Two-thirds of exposed `.env` files were created in 2026. | Treat as indicative. |
| Censys (Apr 2026) | **12,520** internet-accessible **MCP** services across 8,758 IPs (later updates: 21k+). The MCP specification does not require authentication. | Agentic-AI tooling is a new cloud exposure class. |
| CSA research note (Sep 2026) / Intruder | **36,769** self-hosted AI endpoints exposed, and about **2%** sat behind an HTTP authentication gate. Intruder found **31%** of 5,200+ Ollama servers answered prompts without authentication. | The CSA note is AI-assisted and not formally reviewed. |
| Industry roundups | Misconfiguration's share of cloud breaches is variously quoted from **15% to 95%**. | The spread comes from definitions. Do not quote a single "X% of breaches" figure without its source. |

### 2.1 What this means for the repo

"Exposed cloud assets" is wider than public buckets. The catalog covers:

| Exposure type | Examples |
|---|---|
| **Data** | Object storage, public snapshots and images, managed databases and search, Firebase/Supabase back ends, SaaS share links |
| **Compute and control plane** | Public Kubernetes API endpoints, unauthenticated serverless, security groups open to `0.0.0.0/0`, container registries |
| **Identity** | Leaked access keys, tokens, service-account JSON. The non-human identity problem, and the fastest-growing slice |
| **DNS** | Dangling records pointing at deprovisioned cloud resources (subdomain takeover) |
| **AI** | Inference servers, notebooks, vector databases, MCP endpoints |

---

## 3. Why MITRE ATT&CK v20.1?

ATT&CK **v20.1** (released 13 Oct 2026, data updated 5 Nov 2026) is current. The recent changes that matter here:

| Version | Change | Why it matters here |
|---|---|---|
| **v18** (Oct 2025) | **Detection Strategies (DETxxxx)** and **Analytics (ANxxxx)** become first-class objects | Each finding can name the detection coverage the SOC needs while the fix is in flight |
| **v19** (Apr 2026) | Defense Evasion split into **Stealth (TA0005)** and **Defense Impairment (TA0112)**. *Impair Defenses (T1562)* revoked in favour of **T1685** and **T1686** <!-- attack-lint: historical --> | **T1686.001 Cloud Firewall** covers an attacker *opening* a security group, which is how exposures get created after compromise |
| **v20** (Oct 2026) | AI techniques: **Direct/Indirect Prompt Injection (T1699/T1698)**, **AI-Enabled Exfiltration (T1700)**, **AI Result Poisoning (T1608.007)** | Used for exposed AI and MCP endpoints |

All technique, DET and mitigation IDs in this repo were checked against MITRE's official STIX bundle
(`enterprise-attack-20.1.json`) on 12 Nov 2026. See [scripts/Update-AttackMapping.ps1](scripts/Update-AttackMapping.ps1).

---

## Sources

| Topic | Source |
|---|---|
| Verizon 2026 DBIR | <https://www.verizon.com/business/resources/T343/reports/2026-dbir-data-breach-investigations-report.pdf> |
| Commentary on DBIR 2026 | <https://watchtowr.com/resources/verizon-dbir-2026-vulnerability-exploitation/>, <https://eclypsium.com/blog/verizon-dbir-2026/>, <https://blog.cybelesoft.com/dbir-2026-edge-device-exploitation/> |
| Mandiant M-Trends 2026 | <https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026> |
| Arctic Wolf 2026 Threat Report | <https://arcticwolf.com/resources/press-releases/arctic-wolf-threat-report-highlights-11x-growth-in-data-extortion-incidents-and-continued-dominance-of-ransomware/> |
| Sophos Active Adversary Report 2026 | <https://www.sophos.com/en-us/blog/2026-sophos-active-adversary-report> |
| Sophos State of Ransomware 2026 | <https://www.sophos.com/en-us/blog/sophos-state-of-ransomware-2026> |
| Rapid7 Threat Landscape Report 2026 | <https://www.rapid7.com/cdn/assets/bltc1ddd6561ab54a26/69ba67de50ca691edcd3f5b7/rapid7-threat-landscape-report-2026.pdf> |
| RDP exposure | <https://dev.to/stark_zhuang_df5076f35c68/156-million-exposed-rdp-endpoints-why-remote-desktop-remains-the-favourite-initial-access-vector-48ff> |
| EU exposure study | <https://cyberleveling.com/blog/eu-internet-exposure-research-2026> |
| Open-port statistics roundup | <https://scantitan.com/research/open-ports-statistics/> |
| MongoDB exposure (Flare) | <https://flare.io/?p=32759>, <https://securityaffairs.com/187548/security/hackers-exploit-unsecured-mongodb-instances-to-wipe-data-and-demand-ransom.html> |
| Ransomed databases | <https://www.securityscientist.net/blog/exposed-databases-ransomed/>, <https://securityaffairs.com/192711/cyber-crime/the-hidden-ransomware-economy-running-on-exposed-databases.html> |
| Google Cloud Threat Horizons H1 2026 | <https://cloud.google.com/security/report/resources/cloud-threat-horizons-report-h1-2026> |
| Unit 42 2026 IR Report | <https://www.paloaltonetworks.com/resources/research/unit-42-incident-response-report> |
| Wiz 2026 summary (secondary) | <https://stats.conversationalgeek.com/analysis/wiz-2026-cloud-security> |
| Cloud misconfiguration roundups | <https://securityboulevard.com/2026/08/why-cloud-misconfigurations-continue-to-cause-data-breaches-in-2026/>, <https://www.sentinelone.com/cybersecurity-101/cloud-security/cloud-security-statistics/> |
| Exposed AI / MCP | <https://censys.com/?p=9062>, <https://labs.cloudsecurityalliance.org/research/csa-research-note-exposed-ai-endpoints-20260915-csa-styled/>, <https://securityaffairs.com/198898/ai/the-ai-supply-chain-has-a-security-problem-and-much-of-it-is-sitting-on-the-open-internet.html> |
| MITRE ATT&CK versions and release notes | <https://attack.mitre.org/resources/versions/>, <https://attack.mitre.org/resources/updates/updates-october-2026/>, <https://attack.mitre.org/resources/updates/updates-april-2026/> |
| MITRE STIX data | <https://github.com/mitre-attack/attack-stix-data> |
| CISA BOD 23-02 (internet-exposed management interfaces) | <https://www.cisa.gov/news-events/directives/bod-23-02-mitigating-risk-internet-exposed-management-interfaces> |
