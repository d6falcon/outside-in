# Install

Working from the repo root needs no install: skills, catalogs and docs resolve relative to it.

To make the skills available in every project of an AI coding assistant that reads `SKILL.md` (for example Claude
Code's user skills folder), copy the skills and the knowledge base:

```bash
cp -r skills/* ~/.claude/skills/
mkdir -p ~/.claude/skills/outside-in-kb && cp -r catalog docs schemas templates runbooks ~/.claude/skills/outside-in-kb/
```

```powershell
Copy-Item -Recurse skills\* "$HOME\.claude\skills\"
New-Item -ItemType Directory -Force "$HOME\.claude\skills\outside-in-kb" | Out-Null
Copy-Item -Recurse catalog, docs, schemas, templates, runbooks "$HOME\.claude\skills\outside-in-kb\"
```

## Refresh ATT&CK

After each MITRE release (April and October), run this on Windows PowerShell 5.1 or PowerShell 7+:

```powershell
./scripts/Update-AttackMapping.ps1
```

It regenerates `catalog/attack-enterprise.tsv` and fails if any cited ID is revoked, deprecated or mistyped, or if a
detection strategy is cited without a technique it detects.
