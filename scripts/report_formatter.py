#!/usr/bin/env python3
"""
report_formatter.py — Format raw findings into a structured AppSec report.

Usage:
    python report_formatter.py --sast sast_results.json --deps dep_results.json --output report.md
    python report_formatter.py --sast sast_results.json  # deps optional
"""

import sys
import json
import argparse
from datetime import datetime
from pathlib import Path


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4, "UNKNOWN": 5}
SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFORMATIONAL": "ℹ️"
}

OVERALL_RISK_RULES = [
    ("CRITICAL", "🔴 Critical Risk — immediate action required"),
    ("HIGH",     "🟠 High Risk — remediate before next release"),
    ("MEDIUM",   "🟡 Medium Risk — remediate in current sprint"),
    ("LOW",      "🔵 Low Risk — address in future hardening work"),
]


def overall_risk(sast_findings: list, dep_findings: list) -> str:
    all_severities = set()
    for f in sast_findings:
        all_severities.add(f.get("severity", "").upper())
    for f in dep_findings:
        for v in f.get("vulns", []):
            all_severities.add(v.get("severity", "").upper())

    for sev, label in OVERALL_RISK_RULES:
        if sev in all_severities:
            return label
    return "✅ Minimal Risk — no significant findings"


def count_by_severity(findings_flat: list) -> dict:
    counts = {}
    for f in findings_flat:
        sev = f.get("severity", "UNKNOWN").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def format_report(sast_findings: list, dep_findings: list, target: str = "Unknown") -> str:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # Flatten dep findings for counting
    dep_flat = [
        {**v, "package": pkg["name"], "version": pkg.get("version")}
        for pkg in dep_findings
        for v in pkg.get("vulns", [])
    ]

    all_flat = sast_findings + dep_flat
    sast_counts = count_by_severity(sast_findings)
    dep_counts = count_by_severity(dep_flat)
    risk = overall_risk(sast_findings, dep_findings)

    lines = []

    # ── Header ────────────────────────────────────────────────────────────────
    lines += [
        "# AppSec Review Report",
        "",
        f"**Target**: {target}  ",
        f"**Date**: {now}  ",
        f"**Overall Risk**: {risk}",
        "",
        "---",
        "",
    ]

    # ── Executive Summary ─────────────────────────────────────────────────────
    lines += [
        "## Executive Summary",
        "",
        "| Phase | Critical | High | Medium | Low | Total |",
        "|---|---|---|---|---|---|",
    ]

    def row(label, counts, total):
        return (f"| {label} "
                f"| {counts.get('CRITICAL', 0)} "
                f"| {counts.get('HIGH', 0)} "
                f"| {counts.get('MEDIUM', 0)} "
                f"| {counts.get('LOW', 0)} "
                f"| {total} |")

    lines.append(row("Static Code Review (SAST)", sast_counts, len(sast_findings)))
    lines.append(row("Dependency Analysis", dep_counts, len(dep_flat)))
    lines.append(row("**Total**", count_by_severity(all_flat), len(all_flat)))
    lines += ["", "---", ""]

    # ── Phase 1: SAST Findings ─────────────────────────────────────────────────
    lines += ["## Phase 1 — Static Code Review (SAST)", ""]

    if not sast_findings:
        lines += ["✅ No pattern-based findings detected.", ""]
    else:
        sast_sorted = sorted(sast_findings, key=lambda f: (SEVERITY_ORDER.get(f.get("severity","").upper(), 9), f.get("file",""), f.get("line", 0)))
        current_file = None
        for f in sast_sorted:
            if f.get("file") != current_file:
                current_file = f.get("file")
                lines += [f"### 📄 `{current_file}`", ""]

            icon = SEVERITY_ICONS.get(f.get("severity","").upper(), "ℹ️")
            lines += [
                f"#### {icon} [{f.get('severity','?')}] {f.get('description', '')}",
                "",
                f"- **Line**: {f.get('line', '?')}",
                f"- **Category**: {f.get('category', '?')}",
                f"- **Code**: `{f.get('snippet', '')}`",
                f"- **Remediation**: {f.get('remediation', '')}",
                "",
            ]

    lines += ["---", ""]

    # ── Phase 2: Dependency Findings ──────────────────────────────────────────
    lines += ["## Phase 2 — Dependency Analysis", ""]

    if not dep_flat:
        lines += ["✅ No known CVEs found for pinned dependencies.", ""]
    else:
        dep_sorted = sorted(dep_flat, key=lambda f: SEVERITY_ORDER.get(f.get("severity","").upper(), 9))
        for f in dep_sorted:
            icon = SEVERITY_ICONS.get(f.get("severity","").upper(), "ℹ️")
            aliases = f.get("aliases", [])
            cve_ids = [a for a in aliases if a.startswith("CVE-")]
            cve_str = ", ".join(cve_ids) if cve_ids else f.get("id", "")
            fixed = f.get("fixed_in")
            lines += [
                f"#### {icon} [{f.get('severity','?')}] `{f.get('package', '?')}` @ {f.get('version', 'unpinned')}",
                "",
                f"- **CVE**: {cve_str or 'See OSV ID: ' + f.get('id', '?')}",
                f"- **Summary**: {f.get('summary', '')}",
            ]
            if fixed:
                lines.append(f"- **Fix**: Upgrade to >= `{fixed}`")
            lines.append("")

    lines += ["---", ""]

    # ── Recommendations ────────────────────────────────────────────────────────
    lines += [
        "## Recommendations",
        "",
        "### Immediate (Critical & High)",
    ]

    immediate = [f for f in sast_findings if f.get("severity","").upper() in ("CRITICAL","HIGH")]
    immediate += [f for f in dep_flat if f.get("severity","").upper() in ("CRITICAL","HIGH")]

    if immediate:
        for f in immediate:
            label = f.get("description") or f.get("summary", "Finding")
            pkg = f.get("package")
            ref = f" in `{pkg}`" if pkg else f" — `{f.get('file','')}:{f.get('line','')}`"
            lines.append(f"- [ ] {label}{ref}")
    else:
        lines.append("- No immediate critical/high findings.")

    lines += [
        "",
        "### Short-term (Medium)",
    ]

    medium = [f for f in all_flat if f.get("severity","").upper() == "MEDIUM"]
    if medium:
        for f in medium[:10]:  # Cap at 10 to avoid noise
            label = f.get("description") or f.get("summary", "Finding")
            lines.append(f"- [ ] {label}")
        if len(medium) > 10:
            lines.append(f"- [ ] ...and {len(medium)-10} more medium findings")
    else:
        lines.append("- No medium-severity findings.")

    lines += [
        "",
        "---",
        "",
        "*Report generated by appsec-review skill. Pattern matching only — manual review recommended for full coverage.*",
    ]

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Format AppSec findings into a Markdown report")
    parser.add_argument("--sast", help="JSON file with SAST findings", default=None)
    parser.add_argument("--deps", help="JSON file with dependency findings", default=None)
    parser.add_argument("--target", help="Target name/path", default="Code Review")
    parser.add_argument("--output", help="Output file (default: stdout)", default=None)
    args = parser.parse_args()

    sast_findings = []
    dep_findings = []

    if args.sast and Path(args.sast).exists():
        with open(args.sast) as f:
            sast_findings = json.load(f)

    if args.deps and Path(args.deps).exists():
        with open(args.deps) as f:
            dep_findings = json.load(f)

    report = format_report(sast_findings, dep_findings, target=args.target)

    if args.output:
        Path(args.output).write_text(report, encoding='utf-8')
        print(f"[*] Report written to {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
