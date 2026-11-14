<!-- outside-in owner ticket template. Fill every {{placeholder}}. Delete sections marked (optional) if unused. -->

# [{{band}}] {{one-line plain-language title}}

**Finding:** {{finding_id}} · **Catalog:** `{{catalog_id}}` · **Due:** {{due_date}} ({{band}} SLA) · **Owner:** {{owner}}

## What's wrong (plain language)

{{Two or three sentences a non-specialist can read. Example: "The remote-desktop service on ts01.example.com can be
reached by anyone on the internet. Attackers routinely guess passwords on this kind of service, and it is one of the
most common ways ransomware gets in."}}

## Why it matters now

- **EPS {{total}}** = Reach {{reach}} + Class {{class}} + Pressure {{pressure}} + Blast {{blast}} {{"(defaults used: …)" if any}}
- **Exploitation context:** {{KEV yes/no (date added) · EPSS max · active scanning or advisories}}
- **What an attacker does next (ATT&CK v20.1):** {{access techniques}} → {{follow-on techniques}}

## Evidence

| When (UTC) | From | Method | What we saw |
|---|---|---|---|
| {{collected_utc}} | {{vantage}} | `{{method}}` | {{observed}} |

**Please confirm from your side** (read-only):

```bash
{{inside_out_check}}
```

## What to do

1. **Contain within 24h** (P1 only): {{containment}}
2. **Fix:** {{fix}}
3. **Stop it recurring (guardrail):** {{guardrail}}. Currently in place: {{yes/no}}

## How we'll verify

We will re-run the original check from the same vantage point after you mark this fixed. The ticket closes only when
that check fails (for example port filtered, HTTP 401/403, or the snapshot no longer listed) {{and the inside-out check agrees}}.

## Security operations (FYI)

While this is open, the SOC is watching: {{DET IDs + names}}. Detection gaps found: {{none / list}}.

<!-- Do not paste secrets, data samples or personal data into this ticket. Reference the evidence store: {{artifact_ref}} -->
