#!/usr/bin/env python3
"""Regenerate catalog/attack-enterprise.tsv from MITRE's ATT&CK STIX bundle and validate every ATT&CK
reference in the repository.

1. Downloads (or reads) enterprise-attack-<version>.json from github.com/mitre-attack/attack-stix-data and
   writes one row per active (non-revoked, non-deprecated) Enterprise technique or sub-technique:

       technique_id  name  tactics  platforms  detection_strategies  mitigations

   detection_strategies = DET IDs linked by a "detects" relationship (ATT&CK v18+ data model)
   mitigations          = M IDs linked by a "mitigates" relationship

2. ID check: every T1xxx / DETxxxx / M1xxx cited in catalog/, docs/, skills/, templates/, runbooks/ and root
   *.md must be active in the chosen version. Lines that deliberately cite revoked IDs carry
   "attack-lint: historical".

3. Consistency check: every DET cited in a catalog entry (services.yaml / cloud-assets.yaml "- id:" block) or
   in a runbook (runbooks/RB-*.md) must detect at least one technique cited in that same entry or runbook.

Exit code 1 if either check fails. Standard library only, Python 3.9+.

    python3 scripts/update_attack_mapping.py                  # latest
    python3 scripts/update_attack_mapping.py --version 20.1   # pinned
    python3 scripts/update_attack_mapping.py --version 20.1 --check-only   # validate, don't rewrite the TSV
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import urllib.request
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT_FILE = REPO / "catalog" / "attack-enterprise.tsv"
INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
HISTORICAL = re.compile(r"attack-lint:\s*historical", re.IGNORECASE)
ID_RE = re.compile(r"\b(T1\d{3}(?:\.\d{3})?|DET\d{4}|M1\d{3})\b")  # Enterprise only; ICS (T0xxx) not checked
T_RE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")
DET_RE = re.compile(r"\bDET\d{4}\b")


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "outside-in attack-lint"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def load_bundle(version: str | None, stix_path: str | None) -> tuple[dict, str]:
    if stix_path:
        return json.loads(Path(stix_path).read_text(encoding="utf-8-sig")), version or "local"
    index = json.loads(fetch(INDEX_URL))
    coll = next(c for c in index["collections"] if c["name"] == "Enterprise ATT&CK")
    ver = next((v for v in coll["versions"] if v["version"] == version), None) if version else coll["versions"][0]
    if not ver:
        sys.exit(f"ATT&CK version '{version}' not found in STIX index.")
    cache = Path(tempfile.gettempdir()) / f"enterprise-attack-{ver['version']}.json"
    if not cache.exists():
        print(f"Downloading ATT&CK Enterprise {ver['version']} ...")
        cache.write_bytes(fetch(ver["url"]))
    return json.loads(cache.read_text(encoding="utf-8")), ver["version"]


def main() -> int:
    ap = argparse.ArgumentParser(description="Regenerate the ATT&CK catalogue and validate ATT&CK IDs.")
    ap.add_argument("--version", help='ATT&CK version, e.g. "20.1" (default: latest in the STIX index)')
    ap.add_argument("--stix-path", help="use a local STIX JSON instead of downloading")
    ap.add_argument("--check-only", action="store_true", help="run the checks without rewriting the TSV")
    args = ap.parse_args()

    bundle, version = load_bundle(args.version, args.stix_path)
    objects = bundle["objects"]

    # STIX id -> {ext, name, type, active, obj}
    by_stix: dict[str, dict] = {}
    for o in objects:
        ref = next((r for r in o.get("external_references") or [] if r.get("source_name") == "mitre-attack"), None)
        if not ref:
            continue
        by_stix[o["id"]] = {"ext": ref.get("external_id"), "name": o.get("name"), "type": o.get("type"),
                            "active": not (o.get("revoked") or o.get("x_mitre_deprecated")), "obj": o}

    # technique -> DETs / Ms ; DET -> techniques
    det: dict[str, list[str]] = {}
    mit: dict[str, list[str]] = {}
    det_to_t: dict[str, list[str]] = {}
    for o in objects:
        if o.get("type") != "relationship" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        rt = o.get("relationship_type")
        if rt not in ("detects", "mitigates"):
            continue
        s, t = by_stix.get(o.get("source_ref")), by_stix.get(o.get("target_ref"))
        if not s or not t or not s["active"] or not t["active"]:
            continue
        if not re.match(r"^(DET|M)\d+$", s["ext"] or "", re.IGNORECASE):
            continue
        bucket = det if rt == "detects" else mit
        if s["ext"] not in bucket.setdefault(t["ext"], []):
            bucket[t["ext"]].append(s["ext"])
        if rt == "detects" and t["ext"] not in det_to_t.setdefault(s["ext"], []):
            det_to_t[s["ext"]].append(t["ext"])

    rows = []
    for e in by_stix.values():
        if e["type"] != "attack-pattern" or not e["active"]:
            continue
        o = e["obj"]
        tactics = ",".join(p["phase_name"] for p in o.get("kill_chain_phases") or [])
        plats = ",".join(o.get("x_mitre_platforms") or [])
        rows.append("\t".join([e["ext"], e["name"], tactics, plats,
                               ",".join(sorted(det.get(e["ext"], []))), ",".join(sorted(mit.get(e["ext"], [])))]))

    if not args.check_only:
        header = (f"# ATT&CK Enterprise {version} - generated {date.today():%Y-%m-%d} by "
                  "scripts/update_attack_mapping.py - (c) The MITRE Corporation, ATT&CK Terms of Use apply\n"
                  "technique_id\tname\ttactics\tplatforms\tdetection_strategies\tmitigations")
        OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        OUT_FILE.write_text(header + "\n" + "\n".join(sorted(rows)) + "\n", encoding="utf-8", newline="\n")
        print(f"Wrote {len(rows)} techniques to {OUT_FILE.relative_to(REPO)}")

    # ---- check 1: every cited ID is active ----
    active_t, active_det, active_m = set(), set(), set()
    for e in by_stix.values():
        ext = e["ext"] or ""
        if not e["active"]:
            continue
        if re.match(r"^T\d{4}(\.\d{3})?$", ext) and e["type"] == "attack-pattern":
            active_t.add(ext)
        elif re.match(r"^DET\d+$", ext):
            active_det.add(ext)
        elif re.match(r"^M\d{4}$", ext) and e["type"] == "course-of-action":
            active_m.add(ext)

    files = [p for d in ("catalog", "docs", "skills", "templates", "runbooks") if (REPO / d).is_dir()
             for p in sorted((REPO / d).rglob("*")) if p.is_file() and p.suffix in (".yaml", ".md")]
    files += sorted(REPO.glob("*.md"))
    bad = set()
    for f in files:
        for n, line in enumerate(f.read_text(encoding="utf-8-sig").splitlines(), 1):
            if HISTORICAL.search(line):
                continue
            for m in ID_RE.finditer(line):
                i = m.group(0)
                ok = (i in active_t) if i.startswith("T") else (i in active_det) if i.startswith("DET") else (i in active_m)
                if not ok:
                    bad.add(f"{f.name}:{n} {i}")

    # ---- check 2: each cited DET detects a technique cited in the same unit ----
    def det_consistency(unit: str, lines: list[str]) -> list[str]:
        ts, ds = set(), {}
        for line in lines:
            if HISTORICAL.search(line):
                continue
            ts.update(T_RE.findall(line))
            ds.update(dict.fromkeys(DET_RE.findall(line)))
        return [f"{unit} -> {d} (detects: {','.join(det_to_t.get(d, []))}) has no matching technique cited alongside it"
                for d in ds if not any(t in ts for t in det_to_t.get(d, []))]

    incons: list[str] = []
    for cat in ("services.yaml", "cloud-assets.yaml"):
        p = REPO / "catalog" / cat
        if not p.exists():
            continue
        block: list[str] = []
        cur = None
        for line in p.read_text(encoding="utf-8-sig").splitlines():
            m = re.match(r"^- id:\s*(\S+)", line)
            if m:
                if cur:
                    incons += det_consistency(f"{cat}#{cur}", block)
                cur, block = m.group(1), []
            elif cur:
                block.append(line)
        if cur:
            incons += det_consistency(f"{cat}#{cur}", block)
    for rb in sorted((REPO / "runbooks").glob("RB-*.md")) if (REPO / "runbooks").is_dir() else []:
        incons += det_consistency(rb.name, rb.read_text(encoding="utf-8-sig").splitlines())

    # ---- report ----
    if bad:
        print(f"IDs not active in ATT&CK {version} (revoked, deprecated or mistyped):", file=sys.stderr)
        for b in sorted(bad):
            print(f"  {b}", file=sys.stderr)
    if incons:
        print("Detection strategies cited without any technique they detect:", file=sys.stderr)
        for i in incons:
            print(f"  {i}", file=sys.stderr)
    if bad or incons:
        return 1
    print(f"Check 1: all ATT&CK IDs cited in catalog/, docs/, skills/, templates/, runbooks/ and root *.md are active in {version}.")
    print("Check 2: every DET in each catalog entry and runbook detects a technique cited alongside it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
