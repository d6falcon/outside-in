# Worked example: a public GCS bucket with sensitive data

**Scenario.** `acme-prod-exports` (Google Cloud, `europe-west2`) was granted to `allUsers` during a rushed data-sharing
change. It holds nightly customer exports. Nobody noticed.

This walks the finding through the whole loop using the repo's catalog entry
[`gcs-allusers`](../../catalog/cloud-assets.yaml), the [methodology](../methodology.md) and the
[`exposure-triage`](../../skills/exposure-triage/SKILL.md) skill. Names, IDs and IPs are fictitious.

| Step | Who | Output |
|---|---|---|
| 1 Scope | Exposure management | Seeds |
| 2 Discover | Exposure management | Candidate bucket |
| 3 Attribute | Exposure management | A1 |
| 4 Validate (outside-in) | Exposure management | E3 evidence |
| 5 Validate (inside-out) | Bucket owner | E4 evidence |
| 6 Prioritise | Exposure management | EPS 85, P1 |
| 7 Mobilise | Exposure management → owner, SOC | Ticket, SOC watch-list |
| 8 Contain and fix | Owner (+ IR, Privacy) | Bucket private, exposure window known |
| 9 Close the class | Cloud security | Org guardrails |
| 10 Verify-closed | Exposure management | `closed-verified` |

---

## 1. Scope

Seeds: `acme.example`, GCP organisation `123456789012`, brand tokens `acme`, `acme-prod`.

## 2. Discover

> *"Using outside-in, find exposed cloud storage for acme.example. Passive only."*

The `exposed-cloud-assets` skill looks for bucket names the organisation already leaks, then checks a small,
explainable set of permutations for existence only:

- `https://storage.googleapis.com/acme-prod-exports/...` referenced in the website's JavaScript bundle ← **hit**
- Firebase buckets (`<project>.appspot.com`, `<project>.firebasestorage.app`)
- `acme-backup`, `acme-exports`, `acme-prod-logs` … existence-only

## 3. Attribute

The bucket is referenced by our own website, so it is **A2**. The owner's inventory confirms it in project
`acme-data-prod`, so it is **A1**. *(A lookalike `acme-exports` with no link to us would stay A3: existence check
only, and never reported as "your bucket is public".)*

## 4. Validate, outside-in (E3, metadata only)

```bash
curl -s -o /dev/null -w '%{http_code}' 'https://storage.googleapis.com/storage/v1/b/acme-prod-exports/o?maxResults=1'
# 200
```

**200 = anyone on the internet can list it.** For evidence, rerun without `-o /dev/null` and keep only the first key
*name* returned (here `exports/2026-11-13/customers.csv`). Don't page through the listing to count objects; the owner
gets the count inside-out in step 5. **Never download objects** to "prove" sensitivity; a file name plus the owner's
confirmation is enough.

> A 401/403 would *not* clear it: individual objects can still be public through an object-level `allUsers` grant,
> so step 5 is always run.

## 5. Validate, inside-out (E4, owner, read-only)

```bash
gcloud storage buckets get-iam-policy gs://acme-prod-exports --format=json
#   { "members": ["allUsers"], "role": "roles/storage.objectViewer" }
gcloud storage buckets describe gs://acme-prod-exports --format='value(public_access_prevention)'
#   inherited          ← not set on the bucket; follows org policy
gcloud resource-manager org-policies describe storage.publicAccessPrevention --project=acme-data-prod --effective
#   (no enforcement)   ← so nothing is blocking public access
gcloud storage ls 'gs://acme-prod-exports/**' | wc -l
#   412                ← object count, taken inside-out
```

> `allAuthenticatedUsers` would be just as bad: it means *any* Google account, not just staff.

## 6. Prioritise

```
EPS 85 = Reach 25 (any internet source)
       + Class 25 (catalog weight: critical)
       + Pressure 10 (public buckets are indexed by bucket hunters within hours)
       + Blast 25 (production customer data)
→ P1. Also a force-P1 override: unauthenticated access to a sensitive A1 data store.
```

SLA: **contain within 24 hours, fix within 72 hours.**

## 7. Mobilise

**Owner ticket** ([template](../../templates/owner-ticket.md)), in plain language:

> *"Anyone on the internet can list and download the nightly customer exports in `acme-prod-exports`. Please remove
> public access today, confirm with the command below, and keep the bucket private going forward."*

**SOC watch-list** while the bucket is public (MITRE ATT&CK v20.1):

| Detection strategy | Watches for | Technique |
|---|---|---|
| DET0484 | Data pulled from cloud storage | T1530 Data from Cloud Storage |
| DET0578 | Bucket and object enumeration | T1619 Cloud Storage Object Discovery |
| DET0570 | Data moved out to other cloud storage | T1567.002 Exfiltration to Cloud Storage |

**Finding record** ([schema](../../schemas/finding.schema.json)), for the prioritisation engine, SIEM or ITSM:

```json
{
  "finding_id": "OI-2026-0201",
  "catalog_id": "gcs-allusers",
  "asset": {
    "provider": "gcp", "account": "acme-data-prod", "region": "europe-west2",
    "resource": "gs://acme-prod-exports", "attribution": "A1",
    "attribution_basis": "referenced by acme.example JS; present in org inventory",
    "in_inventory": true, "owner": "Data Platform", "environment": "prod",
    "controls": { "edr": "not-applicable" }
  },
  "exposure": { "reach": "internet-any" },
  "evidence": {
    "rung": "E4",
    "items": [
      { "rung": "E3", "collected_utc": "2026-11-14T09:02:00Z", "source": "curl", "vantage": "203.0.113.9",
        "method": "GET storage/v1/b/acme-prod-exports/o?maxResults=1", "observed": "200; listing permitted; first key name recorded" },
      { "rung": "E4", "collected_utc": "2026-11-14T09:40:00Z", "source": "owner-cli", "vantage": "data-platform on-call",
        "method": "gcloud storage buckets get-iam-policy gs://acme-prod-exports", "observed": "allUsers: roles/storage.objectViewer" }
    ]
  },
  "attack": { "version": "20.1", "access": ["T1530"], "follow_on": ["T1619", "T1567.002"] },
  "soc_watch": ["DET0484", "DET0578", "DET0570"],
  "mitigations": ["M1022", "M1041", "M1047"],
  "eps": { "reach": 25, "class": 25, "pressure": 10, "blast": 25, "total": 85,
           "overrides": ["force-p1-unauth-data"], "band": "P1" },
  "remediation": {
    "containment": "Remove the allUsers binding",
    "fix": "Enforce public access prevention and uniform bucket-level access",
    "guardrail": "Org policies storage.publicAccessPrevention and iam.allowedPolicyMemberDomains",
    "guardrail_in_place": false,
    "inside_out_check": "gcloud storage buckets get-iam-policy gs://acme-prod-exports"
  },
  "status": "open",
  "first_seen_utc": "2026-11-14T09:02:00Z",
  "last_seen_utc": "2026-11-14T09:40:00Z"
}
```

## 8. Contain and fix (owner, emergency-change record)

```bash
gcloud storage buckets remove-iam-policy-binding gs://acme-prod-exports \
  --member=allUsers --role=roles/storage.objectViewer
gcloud storage buckets update gs://acme-prod-exports --public-access-prevention
```

Public access prevention alone contains it. Add `--uniform-bucket-level-access` later, as a separate change: it
disables **all** object ACLs, including legitimate non-public grants that apps may rely on, and is reversible for 90
days only. Check for ACL-dependent consumers first.

Sensitive data was exposed, so this is also an **incident question**:

| Question | How to answer it |
|---|---|
| **Exposure window** | When was `allUsers` added? Cloud Storage logs bucket IAM changes as `storage.setIamPermissions`: `gcloud logging read 'resource.type="gcs_bucket" AND resource.labels.bucket_name="acme-prod-exports" AND protoPayload.methodName="storage.setIamPermissions"' --project=acme-data-prod --freshness=400d` |
| **Was it read?** | Cloud Audit Logs do **not** record access granted through `allUsers` / `allAuthenticatedUsers`, even with Data Access logs on. Only the bucket's usage logs (if enabled) show reads, so their absence is *inconclusive*, not "no access" |
| **Breach decision** | If access can't be ruled out, Privacy and Legal decide on notification. Regulatory clocks may start at awareness |
| **Secrets in the exports?** | Rotate them (see [RB-02](../../runbooks/RB-02-weak-leaked-stolen-credentials.md)) |

## 9. Close the class

Enforce at the organisation, so no project can repeat it. **Read the caution first.**

> **Caution:** enforcing public access prevention at the organisation applies to **existing** buckets within about
> 10 minutes. Any *intentionally* public bucket (static sites, public downloads) stops serving immediately. Before you
> enforce, list those buckets (Cloud Asset Inventory or SCC) and exempt their projects, or move them behind a CDN with
> a private origin.

```bash
gcloud resource-manager org-policies enable-enforce constraints/storage.publicAccessPrevention --organization=123456789012
```

Add `constraints/iam.allowedPolicyMemberDomains` (domain-restricted sharing) to block **new** `allUsers` and
`allAuthenticatedUsers` bindings everywhere. It isn't retroactive, so existing public bindings must be removed
separately.

## 10. Verify-closed

```bash
curl -s -o /dev/null -w '%{http_code}' 'https://storage.googleapis.com/storage/v1/b/acme-prod-exports/o?maxResults=1'
# 401
```

The outside-in check fails from the same vantage point, and the inside-out IAM policy has no public members, so the
finding is **`closed-verified`** and the SOC watch-list is released. If the bucket goes public again, the weekly diff
flags it as **regressed** and lifts it one band. With the org policy in place, it can't.

---

**What the repo added:**

| Without it | With it |
|---|---|
| "Found an open bucket", a vague ticket, and an argument about whose it is | Proof that never touched the data, confirmed ownership, a defensible P1 |
| The SOC finds out from the news | The SOC watches three named detection strategies while it's open |
| The same mistake recurs in another project next month | An org-wide guardrail, and a re-test that proves it's closed |
