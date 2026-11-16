# Runbooks

Runbooks tell **people** what to do once an exposure or event is confirmed. The skills find and prove exposures; the
runbooks own the response.

## Why only two (for now)

The runbook set is anchored on **Google Cloud Threat Horizons Report H1 2026** (Google Cloud Office of the CISO, March
2026, covering H2 2025). Its headline finding is that, for the first time, **software exploitation overtook
credentials** as the top way into cloud environments. We build the two runbooks that answer its top two
initial-access vectors first:

| # | Runbook | Threat Horizons vector it answers | Share (H2 2025) |
|---|---|---|---|
| **RB-01** | [Exploited internet-facing software](RB-01-exploited-internet-facing-software.md) | **Software-based entry**: known-CVE exploitation (30.9%) plus remote code execution (13.6%) of user-managed apps on cloud compute and Kubernetes, behind permissive firewall rules | **44.5%** |
| **RB-02** | [Weak, leaked or stolen cloud credentials](RB-02-weak-leaked-stolen-credentials.md) | **Weak or absent credentials** (27.2% in Google Cloud). Across all platforms, identity underpinned **83%** of cloud/SaaS intrusions, with **stolen human and non-human credentials at 21%** | **27.2%** (83% identity, cross-platform) |

Together they cover **~72%** of observed initial access in Google Cloud, and the identity theme behind 83% of
Mandiant's cross-platform cloud cases. Misconfiguration (21%) and exposed sensitive UI/API (4.9%) are handled by the
exposure loop and skills themselves. They come next in the [backlog](../RUNBOOKS-BACKLOG.md).

### Threat Horizons themes built into both runbooks

| Theme from the report | Where it shows up |
|---|---|
| Disclosure-to-exploitation collapsed **from weeks to days**. XMRig deployed ~48h after React2Shell disclosure, and misconfigured apps compromised **< 1 hour** after creation. | RB-01 clock: **virtual patch < 24h, full patch < 72h** (the report's targets) |
| Identity-centric proxies instead of permissive firewall rules. Org policy blocking `0.0.0.0/0` ingress. | RB-01 §4 and the guardrails in both runbooks |
| CI/CD → cloud compromise via **over-permissive OIDC trust** in < 72h (UNC6426). Leaked keys **from 2022** reused in late 2025. | RB-02 scenario C (federation) and scenario B (look-back that ignores key age) |
| **Data theft is the goal in 73%** of cloud cases, much of it *silent* (45%) via legitimate bulk APIs. | RB-02 §3: hunt bulk API and egress, not only logins |
| Attackers **delete logs, snapshots and backups** before extortion. | Both: "preserve before you touch" and four-eyes on destructive actions |
| **Forensic readiness**: pre-provisioned IR access, snapshot at detection, environment labels, and awareness that auto-scaling or self-healing can undo containment. | Both §2 (first 60 minutes) and the readiness checklists |

## Conventions

| Convention | Meaning |
|---|---|
| **Header table** | Trigger, catalog IDs, MITRE ATT&CK® Enterprise v20.1 techniques and detection strategies (DET), priority |
| **Sections** | 0 Trigger · 1 Roles · 2 First 60 minutes · 3 Investigation · 4 Remediation and guardrail · 5 Verification · 6 Exit criteria · 7 Metrics · Appendix: commands |
| **(read) / (change)** | Read-only command / state-changing command that needs an emergency-change record. Both run with the owner's or IR's least-privileged credentials |
| **Regions** | London examples: AWS `eu-west-2`, Google Cloud `europe-west2`, Azure `uksouth`. Provider-fixed global endpoints (e.g. AWS IAM events in `us-east-1`) stay as-is |
| **Preserve → contain → fix** | Reversible containment (deactivate, isolate, restrict) before destructive actions (delete, terminate, rebuild) |
| **Look-back** | From the start of the exposure window, never "since we noticed" |
| **Hygiene** | No secrets, data samples or personal data in tickets, chat or this repository |

| Role | Who it usually is |
|---|---|
| **ASM lead** | Owns the exposure programme. Runs the runbook until IR takes command |
| **Asset owner** | Team that runs the system. Makes the change |
| **SOC** | Monitoring, hunting, detection-gap confirmation |
| **IR lead** | Takes command once there is evidence of compromise |
| **Privacy / Legal** | Breach assessment and regulatory clocks |
| **Change authority** | Approves emergency changes |

## Source

Google Cloud, *Cloud Threat Horizons Report H1 2026*, Office of the CISO:
<https://cloud.google.com/security/report/resources/cloud-threat-horizons-report-h1-2026>.
Figures are quoted from the report. Google notes that its Google Cloud data "reflects a subset of observed activity
and may not represent all customers".
