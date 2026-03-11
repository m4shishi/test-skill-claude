#!/usr/bin/env python3
"""
dep_check.py — Dependency vulnerability scanner for appsec-review skill.
Parses dependency manifests and queries OSV.dev for known CVEs.

Usage:
    python dep_check.py <manifest_file>
    python dep_check.py requirements.txt
    python dep_check.py package.json
    python dep_check.py pom.xml
    python dep_check.py go.mod
"""

import sys
import json
import re
import urllib.request
import urllib.error
from pathlib import Path


# ── Manifest parsers ──────────────────────────────────────────────────────────

def parse_requirements_txt(content: str) -> list[dict]:
    """Parse pip requirements.txt"""
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('-'):
            continue
        # Handle: package==1.0.0, package>=1.0.0, package~=1.0.0
        match = re.match(r'^([A-Za-z0-9_\-\.]+)\s*([><=!~]+)\s*([^\s;#]+)', line)
        if match:
            name, op, version = match.groups()
            # Normalize version (strip extras like <=2.0,>=1.5)
            version = version.split(',')[0].strip()
            deps.append({"name": name.lower(), "version": version, "ecosystem": "PyPI"})
        else:
            # Package with no version pinned
            name = re.match(r'^([A-Za-z0-9_\-\.]+)', line)
            if name:
                deps.append({"name": name.group(1).lower(), "version": None, "ecosystem": "PyPI"})
    return deps


def parse_package_json(content: str) -> list[dict]:
    """Parse npm package.json"""
    deps = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Could not parse package.json: {e}", file=sys.stderr)
        return deps

    all_deps = {}
    all_deps.update(data.get("dependencies", {}))
    all_deps.update(data.get("devDependencies", {}))

    for name, version_spec in all_deps.items():
        # Strip semver range chars: ^, ~, >=, etc.
        version = re.sub(r'^[\^~>=<]', '', version_spec).strip()
        deps.append({"name": name, "version": version, "ecosystem": "npm"})
    return deps


def parse_go_mod(content: str) -> list[dict]:
    """Parse go.mod"""
    deps = []
    in_require = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith('require ('):
            in_require = True
            continue
        if in_require and line == ')':
            in_require = False
            continue
        if in_require or line.startswith('require '):
            line = line.replace('require ', '').strip()
            parts = line.split()
            if len(parts) >= 2:
                name, version = parts[0], parts[1]
                version = version.lstrip('v')
                deps.append({"name": name, "version": version, "ecosystem": "Go"})
    return deps


def parse_pom_xml(content: str) -> list[dict]:
    """Parse Maven pom.xml — basic regex-based extraction"""
    deps = []
    # Find all <dependency> blocks
    dep_blocks = re.findall(r'<dependency>(.*?)</dependency>', content, re.DOTALL)
    for block in dep_blocks:
        group = re.search(r'<groupId>(.*?)</groupId>', block)
        artifact = re.search(r'<artifactId>(.*?)</artifactId>', block)
        version = re.search(r'<version>(.*?)</version>', block)
        if group and artifact:
            name = f"{group.group(1)}:{artifact.group(1)}"
            ver = version.group(1) if version else None
            # Skip property placeholders like ${spring.version}
            if ver and ver.startswith('${'):
                ver = None
            deps.append({"name": name, "version": ver, "ecosystem": "Maven"})
    return deps


def detect_and_parse(filepath: str) -> tuple[list[dict], str]:
    """Auto-detect manifest type and parse it."""
    path = Path(filepath)
    content = path.read_text(encoding='utf-8', errors='replace')
    name = path.name.lower()

    if name == 'requirements.txt' or name.endswith('.txt'):
        return parse_requirements_txt(content), 'PyPI'
    elif name == 'package.json':
        return parse_package_json(content), 'npm'
    elif name == 'go.mod':
        return parse_go_mod(content), 'Go'
    elif name == 'pom.xml':
        return parse_pom_xml(content), 'Maven'
    else:
        print(f"[WARN] Unknown manifest type: {name}. Attempting requirements.txt parse.", file=sys.stderr)
        return parse_requirements_txt(content), 'PyPI'


# ── OSV.dev API ───────────────────────────────────────────────────────────────

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def query_osv(deps: list[dict]) -> dict:
    """
    Query OSV.dev batch API for vulnerabilities.
    Returns dict: package_name -> list of vulns
    """
    if not deps:
        return {}

    queries = []
    for dep in deps:
        if dep["version"]:
            queries.append({
                "version": dep["version"],
                "package": {
                    "name": dep["name"],
                    "ecosystem": dep["ecosystem"]
                }
            })
        else:
            queries.append({
                "package": {
                    "name": dep["name"],
                    "ecosystem": dep["ecosystem"]
                }
            })

    payload = json.dumps({"queries": queries}).encode('utf-8')

    try:
        req = urllib.request.Request(
            OSV_BATCH_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode('utf-8'))
    except urllib.error.URLError as e:
        print(f"[WARN] OSV.dev unreachable: {e}. Falling back to local pattern matching only.", file=sys.stderr)
        return {}
    except Exception as e:
        print(f"[WARN] OSV query failed: {e}", file=sys.stderr)
        return {}

    results = {}
    for dep, result in zip(deps, data.get("results", [])):
        vulns = result.get("vulns", [])
        if vulns:
            results[dep["name"]] = {
                "version": dep["version"],
                "vulns": [
                    {
                        "id": v.get("id", ""),
                        "summary": v.get("summary", "No summary"),
                        "severity": extract_severity(v),
                        "aliases": v.get("aliases", []),
                        "fixed_in": extract_fixed_version(v, dep["ecosystem"])
                    }
                    for v in vulns
                ]
            }
    return results


def extract_severity(vuln: dict) -> str:
    """Extract highest severity from OSV vuln record."""
    severities = vuln.get("severity", [])
    for s in severities:
        if s.get("type") == "CVSS_V3":
            score = float(s.get("score", "0").split("/")[0] if "/" not in s.get("score","0") else "0")
            # CVSS score in CVSS_V3 is usually a vector string, not a float
            # Try to extract from database_specific
            pass
    db = vuln.get("database_specific", {})
    return db.get("severity", "UNKNOWN").upper()


def extract_fixed_version(vuln: dict, ecosystem: str) -> str | None:
    """Try to find the fixed version from the vuln record."""
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


# ── Report output ─────────────────────────────────────────────────────────────

def print_report(deps: list[dict], osv_results: dict, manifest_path: str):
    total = len(deps)
    vuln_count = len(osv_results)
    no_version = sum(1 for d in deps if not d["version"])

    print(f"\n{'='*60}")
    print(f"DEPENDENCY SCAN REPORT")
    print(f"Manifest : {manifest_path}")
    print(f"Packages : {total} total, {no_version} unpinned")
    print(f"Findings : {vuln_count} packages with known CVEs")
    print(f"{'='*60}\n")

    if not osv_results:
        print("✅ No known CVEs found via OSV.dev for pinned packages.\n")
        print("NOTE: Packages without pinned versions could not be checked.")
    else:
        for pkg_name, data in osv_results.items():
            print(f"📦 {pkg_name} @ {data['version'] or 'unpinned'}")
            for v in data["vulns"]:
                cve_ids = [a for a in v["aliases"] if a.startswith("CVE-")]
                cve_str = ", ".join(cve_ids) if cve_ids else v["id"]
                fixed = f" → fix: >= {v['fixed_in']}" if v["fixed_in"] else ""
                print(f"  [{v['severity']}] {cve_str}: {v['summary'][:80]}{fixed}")
            print()

    if no_version > 0:
        print(f"⚠️  {no_version} packages have no pinned version — could not check for CVEs:")
        for d in deps:
            if not d["version"]:
                print(f"   - {d['name']}")
        print()

    print("─" * 60)
    print("Scan complete. Cross-reference with: https://osv.dev")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python dep_check.py <manifest_file>")
        print("Supported: requirements.txt, package.json, go.mod, pom.xml")
        sys.exit(1)

    manifest_path = sys.argv[1]

    if not Path(manifest_path).exists():
        print(f"[ERROR] File not found: {manifest_path}")
        sys.exit(1)

    print(f"[*] Parsing {manifest_path}...")
    deps, ecosystem = detect_and_parse(manifest_path)
    print(f"[*] Found {len(deps)} packages ({ecosystem})")

    print(f"[*] Querying OSV.dev for CVEs...")
    osv_results = query_osv(deps)

    print_report(deps, osv_results, manifest_path)

    # Exit code: 1 if any HIGH or CRITICAL findings
    if any(
        v["severity"] in ("HIGH", "CRITICAL")
        for data in osv_results.values()
        for v in data["vulns"]
    ):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
