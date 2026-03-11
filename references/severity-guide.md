# Severity Classification Guide

Use this rubric consistently across all findings. When in doubt, rate higher and explain your reasoning.

---

## Severity Levels

### 🔴 Critical
**Definition**: Directly exploitable with no authentication required, or exploitable with low-privilege access, leading to full system compromise, data breach, or remote code execution.

**Criteria (any one is sufficient):**
- Remote Code Execution (RCE)
- SQL Injection on unauthenticated endpoints
- Authentication bypass
- Hardcoded credentials / secrets that are active
- Deserialization of untrusted data leading to RCE
- SSRF accessing internal cloud metadata

**CVSS range**: 9.0 – 10.0

**Report language**: "Immediate remediation required. This finding represents a direct path to system compromise."

---

### 🟠 High
**Definition**: Exploitable with some conditions (e.g., authenticated user, specific config), leading to significant data exposure, privilege escalation, or service disruption.

**Criteria (any one is sufficient):**
- SQL Injection requiring authentication
- Broken Access Control / IDOR exposing sensitive data
- Stored XSS
- JWT with no signature verification
- Command injection with limited impact
- Cryptographic failures (weak hashing of passwords)
- Secrets in code (environment-specific, possibly inactive)

**CVSS range**: 7.0 – 8.9

**Report language**: "Remediation strongly recommended before next release."

---

### 🟡 Medium
**Definition**: Exploitable under specific conditions, limited blast radius, or requires chaining with other issues for significant impact.

**Criteria:**
- Reflected XSS
- CSRF on state-changing actions
- Verbose error messages exposing stack traces
- Missing rate limiting on sensitive endpoints
- Insecure random for non-cryptographic security use
- Outdated dependencies with known CVEs (no active exploit)
- Missing security headers (CSP, HSTS, etc.)
- Overly permissive CORS

**CVSS range**: 4.0 – 6.9

**Report language**: "Remediation recommended in the current sprint or next release."

---

### 🔵 Low
**Definition**: Minimal exploitability or impact. Defense-in-depth issues, informational leakage, or best-practice deviations.

**Criteria:**
- Information disclosure (version numbers, internal paths)
- Missing `HttpOnly` / `Secure` cookie flags
- Outdated dependencies (no known CVE)
- Verbose logging (non-sensitive)
- Missing Content-Type header
- Use of deprecated but not broken algorithms

**CVSS range**: 0.1 – 3.9

**Report language**: "Consider addressing in future hardening work."

---

### ℹ️ Informational
**Definition**: Not a vulnerability. Observation, best-practice suggestion, or positive finding worth noting.

**Examples:**
- Code uses parameterized queries correctly (positive note)
- Consider adding audit logging
- Suggest migrating to newer library version for maintenance reasons

---

## Dependency-Specific Severity Mapping

When a CVE is found in a dependency, use this table to determine effective severity:

| CVE CVSS Score | Package is transitive? | Reachable from user input? | Effective Severity |
|---|---|---|---|
| 9.0+ | No | Yes | Critical |
| 9.0+ | No | Unknown | High |
| 9.0+ | Yes | Any | High |
| 7.0–8.9 | No | Yes | High |
| 7.0–8.9 | No/Yes | Unknown | Medium |
| 4.0–6.9 | Any | Any | Medium |
| < 4.0 | Any | Any | Low |

**Transitive dependency**: A dependency of a dependency (indirect). Flag it but note it as transitive.

---

## Multi-Finding Risk Rating

After listing all findings, produce an overall risk rating for the codebase:

| Overall Rating | Criteria |
|---|---|
| **Critical Risk** | Any Critical finding present |
| **High Risk** | Any High finding, no Critical |
| **Medium Risk** | Only Medium and below |
| **Low Risk** | Only Low / Informational |
| **Minimal Risk** | Informational only |
