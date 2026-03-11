#!/usr/bin/env python3
"""
sast_helpers.py — Static analysis helper for appsec-review skill.
Scans source code files for common vulnerability patterns using regex.

Usage:
    python sast_helpers.py <file_or_directory>
    python sast_helpers.py app.py
    python sast_helpers.py ./src/
"""

import sys
import re
import os
from pathlib import Path
from dataclasses import dataclass


@dataclass
class Finding:
    file: str
    line: int
    severity: str
    category: str
    description: str
    snippet: str
    remediation: str


# ── Pattern definitions ───────────────────────────────────────────────────────

PATTERNS = {
    # ── Secrets / Hardcoded credentials ──────────────────────────────────────
    "hardcoded_password": {
        "regex": r'(?i)(password|passwd|pwd|secret|api_key|apikey|auth_token|access_token)\s*[=:]\s*["\'][^"\']{4,}["\']',
        "severity": "HIGH",
        "category": "A02 – Cryptographic Failure",
        "description": "Possible hardcoded credential or secret",
        "remediation": "Move to environment variable or secrets manager. Rotate the exposed value immediately."
    },
    "aws_key": {
        "regex": r'AKIA[0-9A-Z]{16}',
        "severity": "CRITICAL",
        "category": "A02 – Cryptographic Failure",
        "description": "Possible AWS Access Key ID found in source",
        "remediation": "Revoke this AWS key immediately and rotate. Move to IAM roles or AWS Secrets Manager."
    },
    "private_key_header": {
        "regex": r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
        "severity": "CRITICAL",
        "category": "A02 – Cryptographic Failure",
        "description": "Private key material found in source file",
        "remediation": "Remove key from source immediately. Treat key as compromised and rotate."
    },

    # ── Weak cryptography ─────────────────────────────────────────────────────
    "weak_hash_md5": {
        "regex": r'\bmd5\s*\(|hashlib\.md5\b|MessageDigest\.getInstance\(["\']MD5["\']\)',
        "severity": "HIGH",
        "category": "A02 – Cryptographic Failure",
        "description": "MD5 is a cryptographically broken hash function",
        "remediation": "Replace with SHA-256 or stronger. For passwords, use bcrypt/Argon2."
    },
    "weak_hash_sha1": {
        "regex": r'\bsha1\s*\(|hashlib\.sha1\b|MessageDigest\.getInstance\(["\']SHA-?1["\']\)',
        "severity": "MEDIUM",
        "category": "A02 – Cryptographic Failure",
        "description": "SHA-1 is weak for security-sensitive use cases",
        "remediation": "Replace with SHA-256 or stronger for security purposes."
    },
    "insecure_random": {
        "regex": r'\brandom\.random\(\)|\bMath\.random\(\)|\bnew Random\(\)',
        "severity": "MEDIUM",
        "category": "A02 – Cryptographic Failure",
        "description": "Non-cryptographic random number generator used — may be predictable",
        "remediation": "Use secrets.token_hex() (Python), crypto.randomBytes() (Node), or SecureRandom (Java) for security-sensitive values."
    },

    # ── Injection ─────────────────────────────────────────────────────────────
    "sql_injection_concat": {
        "regex": r'(execute|query|cursor\.execute)\s*\(\s*["\'].*\+|f["\'].*SELECT.*\{|f["\'].*INSERT.*\{|f["\'].*UPDATE.*\{|f["\'].*DELETE.*\{',
        "severity": "CRITICAL",
        "category": "A03 – Injection",
        "description": "Possible SQL injection via string concatenation or f-string",
        "remediation": "Use parameterized queries / prepared statements. Never build SQL from user input."
    },
    "command_injection_shell": {
        "regex": r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True|os\.system\s*\(|os\.popen\s*\(',
        "severity": "HIGH",
        "category": "A03 – Injection",
        "description": "Possible command injection via shell=True or os.system",
        "remediation": "Use subprocess with list arguments and shell=False. Avoid os.system entirely."
    },
    "eval_injection": {
        "regex": r'\beval\s*\(|\bexec\s*\(|\bnew Function\s*\(',
        "severity": "CRITICAL",
        "category": "A03 – Injection",
        "description": "eval()/exec()/new Function() can execute arbitrary code if called with user input",
        "remediation": "Remove eval/exec. If required, validate input strictly against an allowlist."
    },

    # ── Deserialization ───────────────────────────────────────────────────────
    "pickle_load": {
        "regex": r'\bpickle\.(loads?|Unpickler)',
        "severity": "HIGH",
        "category": "A08 – Deserialization",
        "description": "pickle.load/loads deserializes arbitrary Python objects — dangerous with untrusted input",
        "remediation": "Never deserialize pickle data from untrusted sources. Use JSON or a schema-validated format."
    },
    "yaml_load_unsafe": {
        "regex": r'\byaml\.load\s*\([^)]*\)',
        "severity": "CRITICAL",
        "category": "A08 – Deserialization",
        "description": "yaml.load() with default Loader can execute arbitrary Python code",
        "remediation": "Replace with yaml.safe_load() which only deserializes basic data types."
    },

    # ── Path traversal ────────────────────────────────────────────────────────
    "path_traversal": {
        "regex": r'open\s*\(\s*[^"\']*\+|os\.path\.join\s*\([^)]*request\.',
        "severity": "HIGH",
        "category": "A01 – Broken Access Control",
        "description": "Possible path traversal — user input used in file path construction",
        "remediation": "Validate and sanitize file paths. Use os.path.abspath() and verify the result starts with the expected base directory."
    },

    # ── Sensitive data exposure ───────────────────────────────────────────────
    "debug_mode": {
        "regex": r'(?i)(debug\s*=\s*True|app\.run\([^)]*debug\s*=\s*True)',
        "severity": "MEDIUM",
        "category": "A05 – Security Misconfiguration",
        "description": "Debug mode enabled — must not reach production",
        "remediation": "Set debug mode via environment variable: DEBUG=os.environ.get('DEBUG', False)"
    },
    "sensitive_in_log": {
        "regex": r'(?i)(log(ger)?\.(info|debug|warning|error|critical).*?(password|passwd|token|secret|api_key|credit_card|ssn|cvv))',
        "severity": "MEDIUM",
        "category": "A09 – Security Logging Failure",
        "description": "Possible sensitive data being written to logs",
        "remediation": "Remove sensitive fields from log statements. Use structured logging with field-level filtering."
    },

    # ── SSRF ──────────────────────────────────────────────────────────────────
    "ssrf_requests": {
        "regex": r'requests\.(get|post|put|delete)\s*\(\s*(request\.|req\.|params|args|data|body)',
        "severity": "HIGH",
        "category": "A10 – SSRF",
        "description": "Possible SSRF — URL appears to come from user-controlled request data",
        "remediation": "Validate URLs against an allowlist of domains before making server-side requests."
    },

    # ── JWT ───────────────────────────────────────────────────────────────────
    "jwt_no_verify": {
        "regex": r'jwt\.decode.*verify_signature\s*=\s*False|algorithms\s*=\s*\[["\']none["\']\]',
        "severity": "CRITICAL",
        "category": "A07 – Auth Failure",
        "description": "JWT signature verification disabled — tokens can be forged",
        "remediation": "Always verify JWT signatures. Never use algorithms=['none']."
    },
}

# ── File type mappings ────────────────────────────────────────────────────────

SUPPORTED_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx',
    '.java', '.go', '.rb', '.php',
    '.cs', '.cpp', '.c', '.swift', '.kt'
}

# Patterns that apply only to specific languages
LANGUAGE_FILTER = {
    "pickle_load": {'.py'},
    "yaml_load_unsafe": {'.py'},
    "insecure_random": {'.py', '.js', '.ts', '.java'},
}


# ── Scanner ───────────────────────────────────────────────────────────────────

def scan_file(filepath: str) -> list[Finding]:
    path = Path(filepath)
    if path.suffix not in SUPPORTED_EXTENSIONS:
        return []

    try:
        lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    except Exception as e:
        print(f"[WARN] Could not read {filepath}: {e}", file=sys.stderr)
        return []

    findings = []
    for pattern_name, rule in PATTERNS.items():
        # Language filter
        allowed_exts = LANGUAGE_FILTER.get(pattern_name)
        if allowed_exts and path.suffix not in allowed_exts:
            continue

        regex = re.compile(rule["regex"], re.IGNORECASE)
        for i, line in enumerate(lines, start=1):
            # Skip comment lines
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('*'):
                continue
            if regex.search(line):
                findings.append(Finding(
                    file=str(filepath),
                    line=i,
                    severity=rule["severity"],
                    category=rule["category"],
                    description=rule["description"],
                    snippet=line.strip()[:120],
                    remediation=rule["remediation"]
                ))
    return findings


def scan_path(target: str) -> list[Finding]:
    path = Path(target)
    all_findings = []

    if path.is_file():
        all_findings = scan_file(str(path))
    elif path.is_dir():
        for root, dirs, files in os.walk(path):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in {
                'node_modules', '.git', '__pycache__', 'venv', '.venv',
                'dist', 'build', 'target', '.tox', 'vendor'
            }]
            for filename in files:
                filepath = os.path.join(root, filename)
                all_findings.extend(scan_file(filepath))
    else:
        print(f"[ERROR] Path not found: {target}")
        sys.exit(1)

    return all_findings


# ── Report ────────────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def print_report(findings: list[Finding], target: str):
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 5), f.file, f.line))

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"\n{'='*60}")
    print("SAST SCAN REPORT")
    print(f"Target  : {target}")
    print(f"Findings: {len(findings)} total — " +
          " | ".join(f"{s}: {n}" for s, n in sorted(counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 9))))
    print(f"{'='*60}\n")

    if not findings:
        print("✅ No pattern-based findings detected.\n")
        print("NOTE: This is pattern-matching only. Manual review is still required.")
        return

    current_file = None
    for f in findings:
        if f.file != current_file:
            current_file = f.file
            print(f"\n📄 {f.file}")
            print("─" * 50)
        severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(f.severity, "ℹ️")
        print(f"  {severity_icon} Line {f.line:4d} [{f.severity}] {f.category}")
        print(f"           {f.description}")
        print(f"           Code: {f.snippet}")
        print(f"           Fix : {f.remediation[:100]}")
        print()

    print("─" * 60)
    print("Scan complete. This tool aids review — not a replacement for manual analysis.")
    if counts.get("CRITICAL", 0) + counts.get("HIGH", 0) > 0:
        print(f"⚠️  {counts.get('CRITICAL', 0)} Critical and {counts.get('HIGH', 0)} High findings require immediate attention.")


def main():
    if len(sys.argv) < 2:
        print("Usage: python sast_helpers.py <file_or_directory>")
        sys.exit(1)

    target = sys.argv[1]
    findings = scan_path(target)
    print_report(findings, target)

    # Exit code: 1 if critical/high findings
    has_critical = any(f.severity in ("CRITICAL", "HIGH") for f in findings)
    sys.exit(1 if has_critical else 0)


if __name__ == "__main__":
    main()
