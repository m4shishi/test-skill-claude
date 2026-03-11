---
name: appsec-review
description: Performs application security analysis including static code review (SAST) and dependency vulnerability scanning. Use when user uploads source code, asks for "security review", "SAST", "vuln scan", "check for vulnerabilities", "dependency audit", "CVE check", or uploads manifest files (requirements.txt, package.json, pom.xml, go.mod). Do NOT use for general code quality, style reviews, or refactoring.
---

# AppSec Review Skill

## Before Starting
- Read `references/owasp-top10.md` for language-specific vulnerability patterns
- Read `references/severity-guide.md` for consistent severity classification
- Read `references/remediation-playbook.md` for standard fix guidance

## CRITICAL: Complete both phases fully before producing the final report.

---

## Phase 1 — Static Code Review (SAST)

1. Identify language from file extension
2. Run `scripts/sast_helpers.py <file>` for automated pattern detection
3. Apply OWASP Top 10 checks manually for anything the script may miss
4. Flag: injection flaws, broken auth, insecure deserialization, XXE, SSRF
5. For each finding: file path, line number, severity, OWASP category, remediation

## Phase 2 — Dependency Analysis

1. Detect manifest type (requirements.txt, package.json, pom.xml, go.mod, Gemfile.lock)
2. Run `scripts/dep_check.py <manifest>` to query OSV.dev for CVEs
3. If network unavailable, fall back to `references/cve-patterns.md`
4. Flag packages with known CVEs or no active maintenance
5. For each finding: package name, current version, CVE ID, fixed version

---

## Report Format

Use `assets/report-template.md` as the structure. Always:
- Lead with overall risk rating (from `references/severity-guide.md`)
- Group findings by phase
- Sort within each phase: Critical → High → Medium → Low
- Include CVSS score where available
- End with a prioritized remediation checklist
