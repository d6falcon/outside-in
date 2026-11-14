<!-- outside-in executive brief: one page. Replace {{placeholders}}. -->

# External exposure brief: {{period}}

**Bottom line:** {{one sentence. Example: "Two internet-exposed admin services and one public database snapshot need
action this week; no evidence of misuse so far."}}

## Where we stand

| Band | Open | New this cycle | Closed (verified) | Regressed | Past SLA |
|---|---|---|---|---|---|
| P1 | {{}} | {{}} | {{}} | {{}} | {{}} |
| P2 | {{}} | {{}} | {{}} | {{}} | {{}} |
| P3 | {{}} | {{}} | {{}} | {{}} | {{}} |
| P4 | {{}} | {{}} | {{}} | {{}} | {{}} |

Median time to close: P1 {{x}} days (target 3) · P2 {{y}} days (target 14)

## Top 5 by priority

| # | Exposure | Business impact if abused | Owner | Due |
|---|---|---|---|---|
| 1 | {{e.g. RDP open on 4 finance servers}} | {{ransomware entry to finance systems}} | {{}} | {{}} |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |

## Classes with no preventive guardrail

{{e.g. "Public EBS snapshots can still be created in 31 of 40 AWS accounts (no org-wide block)." One line each, with the
recommended guardrail.}}

## Gaps

- **Ownership:** {{n}} exposed assets have no identified owner ({{n}} of them not in any inventory).
- **Detection:** the SOC lacks coverage for {{DET IDs / plain names}} on {{n}} exposed assets.
- **Endpoint coverage:** {{n}} of {{n}} internet-exposed hosts that should run EDR have a healthy agent ({{%}}).
  {{n}} missing, {{n}} stale.

## Decisions needed

{{e.g. "Approve an emergency change to remove internet access for the vendor-managed RDP (business owner: …)."}}

<sub>Method: outside-in exposure loop (scope → discover → attribute → validate → prioritise → mobilise → verify-closed). Priority uses
EPS (reach, class, exploitation pressure, blast radius). Techniques reference MITRE ATT&CK® Enterprise v20.1.</sub>
