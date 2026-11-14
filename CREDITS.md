# Credits and prior art

## Inspiration

**[elementalsouls/Claude-OSINT](https://github.com/elementalsouls/Claude-OSINT)** by **Sachin Sharma** showed that a
library of `SKILL.md` files can carry serious external-recon tradecraft. That project is licensed **MIT (code)**
and **CC BY 4.0 (content)**. Thank you.

`outside-in` borrows the **idea** of packaging security methodology as assistant skills, and the general practice of
grading confidence and gating severity on ownership. **No text, data, code, regexes, wordlists or structure was
copied.** Everything here was written from scratch for a different audience and purpose. If you notice anything that
looks like it was carried over, please open an issue and we will fix or attribute it.

### How this project differs

| | Claude-OSINT | outside-in |
|---|---|---|
| **Primary user** | Red-teamers and bug-bounty hunters (authorised offensive recon) | In-house defenders and exposure-management / ASM teams |
| **Scope** | Broad recon: identity, email, web apps, secrets, HUMINT, sector-specific | Deliberately narrow: **exposed services** and **exposed cloud assets** only |
| **End product** | Recon findings and attack paths | **Owned, validated, prioritised, mobilised and verified-closed** exposures, plus guardrails |
| **Knowledge format** | Long prose skills (one is ~4.7k lines) | Short skills that reason over **versioned YAML catalogs** (86 service classes, 43 cloud classes) |
| **Proof model** | Confidence levels per finding | **Evidence ladder E0–E4**, ending in the owner's **inside-out** read-only confirmation and a "stranger account" view for public sharing |
| **Prioritisation** | FAIR-style $ risk quantification | **EPS**: a transparent 4-factor points model with explicit overrides, tied to SLAs |
| **ATT&CK** | Occasional references | Every class is mapped to **v20.1** techniques, **Detection Strategies (DET)** and **Mitigations**, generated from MITRE STIX and machine-checked |
| **Defensive hand-off** | Not a focus | **SOC watch list** of DET IDs while an exposure is open, plus **org-level guardrails** per class |
| **Post-fix** | Re-scan and diff | **Verify-closed** state machine and regression detection (including attacker re-opening via T1686.001) |

## Data and frameworks

- **MITRE ATT&CK®** Enterprise v20.1: © The MITRE Corporation. Reproduced and derived under the
  [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
  `catalog/attack-enterprise.tsv` is derived from [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data).
- **CISA** Known Exploited Vulnerabilities catalog, BOD 22-01 and BOD 23-02 are referenced for prioritisation and policy.
- **Shadowserver Foundation** and **CISA Cyber Hygiene** are recommended as free data sources for network owners.
- **Gartner CTEM**, **NIST CSF 2.0** and **CIS Controls v8.1** are referenced for alignment only.
- Industry reports cited in [RESEARCH.md](RESEARCH.md) belong to their respective publishers.
- Nmap NSE script names, cloud CLI commands and product names are referenced for interoperability. All trademarks
  belong to their owners.
