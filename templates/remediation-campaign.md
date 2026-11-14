<!-- outside-in remediation campaign brief. One campaign = one fix type, many assets, a handful of remediation owners. -->

# Campaign {{campaign_id}}: {{verb-first title, e.g. "Remove internet-exposed RDP"}}

| | |
|---|---|
| **Band / SLA** | {{P1–P4}} · due {{date}} (exceptions: see below) |
| **Scope** | {{n}} roll-ups · {{n}} assets · {{n}} remediation owners · catalog `{{catalog_id}}` |
| **Campaign lead** | {{VM / exposure-management analyst}} |
| **Success measure** | {{e.g. "0 internet-reachable RDP endpoints, verified from two vantage points"}} |

## Why now

{{Two or three sentences of threat context in business language. Cite live intel (KEV entry, vendor advisory, sector
alert) and the EPS arithmetic of the highest roll-up. Example: "Exposed remote desktop is the most-advertised access
type on criminal forums, and ransomware crews buy it. 23 of our servers accept RDP from anywhere on the internet."}}

## What we're asking every remediation owner to do

1. **Standard fix:** {{one fix that works for most assets, e.g. "close 3389 at the edge; publish via ZTNA with
   phishing-resistant MFA"}}
2. **Confirm from your side** (read-only): `{{inside-out command}}`
3. **If you can't make the date:** raise an ITSM exception with a compensating control that reduces reachability
   (source allow-list, identity-aware proxy or WAF virtual patch), an expiry date and an accountable approver.

## Owners and progress

| Remediation owner | Roll-ups | Assets | Ticket | Status | Exception |
|---|---|---|---|---|---|
| {{team}} | {{n}} | {{n}} | {{ITSM ref}} | {{open / contained / closed-verified}} | {{ref or –}} |

## Guardrail (stop the class coming back)

{{Org-level control from the catalog `guardrail` field, its current coverage, and the owner of the rollout.}}

## While it's open (SOC)

The SOC is watching {{DET IDs + names}} on in-scope assets. Detection gaps: {{none / list}}.

## Close-out

The campaign closes when every roll-up is `closed-verified` (outside-in re-test failed from the original vantage
point) or covered by an unexpired exception. Report: assets closed, median time to close, exceptions raised, guardrail
coverage before and after.
