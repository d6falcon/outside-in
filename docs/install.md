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

After each MITRE release (April and October), run this on Windows PowerShell 5.1 or PowerShell 7+:

```powershell
./scripts/Update-AttackMapping.ps1
```

| Check | Fails when |
|---|---|
| 1 | Any cited technique, detection strategy or mitigation ID is revoked, deprecated or mistyped |
| 2 | A detection strategy is cited without a technique it detects (per catalog entry and per runbook) |

It also regenerates `catalog/attack-enterprise.tsv`.
