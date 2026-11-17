# Install

Working from the repo root needs no install: skills, catalogs and docs resolve relative to it.

To make the skills available in every project of an AI coding assistant that reads `SKILL.md` (for example Claude
Code's user skills folder), copy the skills and the knowledge base:

```bash
mkdir -p ~/.claude/skills ~/.claude/skills/outside-in-kb
cp -r skills/* ~/.claude/skills/
cp -r catalog docs schemas templates runbooks ~/.claude/skills/outside-in-kb/
```

```powershell
New-Item -ItemType Directory -Force "$HOME\.claude\skills", "$HOME\.claude\skills\outside-in-kb" | Out-Null
Copy-Item -Recurse skills\* "$HOME\.claude\skills\"
Copy-Item -Recurse catalog, docs, schemas, templates, runbooks "$HOME\.claude\skills\outside-in-kb\"
```

## Refresh ATT&CK

After each MITRE release (April and October), run this (Python 3.9+, standard library only):

```bash
python3 scripts/update_attack_mapping.py
```

| Check | Fails when |
|---|---|
| 1 | Any cited technique, detection strategy or mitigation ID is revoked, deprecated or mistyped |
| 2 | A detection strategy is cited without a technique it detects (per catalog entry and per runbook) |

It also regenerates `catalog/attack-enterprise.tsv`. Add `--version 20.1` to pin a release, or `--check-only` to validate without rewriting the file.

The [attack-lint](../.github/workflows/attack-lint.yml) workflow runs both checks on every push and pull request (pinned to v20.1), and monthly against the latest ATT&CK release so a new release that revokes a cited ID shows up as a failed run.
