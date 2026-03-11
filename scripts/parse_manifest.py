#!/usr/bin/env python3
"""
parse_manifest.py — Normalize dependency manifests to a standard structure.
Used by dep_check.py and directly by Claude to understand dependency scope.

Usage:
    python parse_manifest.py <manifest_file>

Output: JSON array of normalized dependency objects:
    [{"name": "...", "version": "...", "ecosystem": "...", "direct": true/false}]
"""

import sys
import json
import re
from pathlib import Path


def parse_requirements_txt(content: str) -> list[dict]:
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('-r'):
            continue
        # Handle extras: package[extra]==1.0
        line = re.sub(r'\[.*?\]', '', line)
        match = re.match(r'^([A-Za-z0-9_\-\.]+)\s*([><=!~]+)\s*([^\s;#,]+)', line)
        if match:
            name, op, version = match.groups()
            pinned = '==' in op
            deps.append({
                "name": name.lower().replace('_', '-'),
                "version": version,
                "version_constraint": op + version,
                "ecosystem": "PyPI",
                "pinned": pinned,
                "direct": True
            })
        else:
            name_match = re.match(r'^([A-Za-z0-9_\-\.]+)', line)
            if name_match:
                deps.append({
                    "name": name_match.group(1).lower().replace('_', '-'),
                    "version": None,
                    "version_constraint": None,
                    "ecosystem": "PyPI",
                    "pinned": False,
                    "direct": True
                })
    return deps


def parse_package_json(content: str) -> list[dict]:
    deps = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON in package.json: {e}", file=sys.stderr)
        return deps

    def process_deps(dep_dict: dict, is_dev: bool = False) -> list[dict]:
        result = []
        for name, version_spec in dep_dict.items():
            clean_version = re.sub(r'^[\^~>=<]', '', str(version_spec)).strip()
            # Handle "latest", "next", etc.
            if not re.match(r'^\d', clean_version):
                clean_version = None
            result.append({
                "name": name,
                "version": clean_version,
                "version_constraint": version_spec,
                "ecosystem": "npm",
                "pinned": version_spec.startswith('') and '.' in version_spec and not version_spec.startswith('^') and not version_spec.startswith('~'),
                "direct": True,
                "dev": is_dev
            })
        return result

    deps.extend(process_deps(data.get("dependencies", {}), is_dev=False))
    deps.extend(process_deps(data.get("devDependencies", {}), is_dev=True))
    return deps


def parse_go_mod(content: str) -> list[dict]:
    deps = []
    in_require = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith('require ('):
            in_require = True
            continue
        if in_require and stripped == ')':
            in_require = False
            continue

        target = None
        if in_require:
            target = stripped
        elif stripped.startswith('require '):
            target = stripped[8:].strip()

        if target:
            # Handle indirect marker: github.com/pkg v1.0.0 // indirect
            indirect = '// indirect' in target
            target = target.split('//')[0].strip()
            parts = target.split()
            if len(parts) >= 2:
                name, version = parts[0], parts[1].lstrip('v')
                deps.append({
                    "name": name,
                    "version": version,
                    "version_constraint": "==" + version,
                    "ecosystem": "Go",
                    "pinned": True,
                    "direct": not indirect
                })
    return deps


def parse_pom_xml(content: str) -> list[dict]:
    deps = []
    dep_blocks = re.findall(r'<dependency>(.*?)</dependency>', content, re.DOTALL)
    for block in dep_blocks:
        group = re.search(r'<groupId>(.*?)</groupId>', block)
        artifact = re.search(r'<artifactId>(.*?)</artifactId>', block)
        version = re.search(r'<version>(.*?)</version>', block)
        scope = re.search(r'<scope>(.*?)</scope>', block)

        if group and artifact:
            ver = version.group(1).strip() if version else None
            # Skip Maven property placeholders
            if ver and ver.startswith('${'):
                ver = None
            scope_val = scope.group(1).strip() if scope else "compile"
            deps.append({
                "name": f"{group.group(1).strip()}:{artifact.group(1).strip()}",
                "version": ver,
                "version_constraint": f"=={ver}" if ver else None,
                "ecosystem": "Maven",
                "pinned": ver is not None and not ver.startswith('$'),
                "direct": scope_val not in ("test",),
                "scope": scope_val
            })
    return deps


def parse_gemfile_lock(content: str) -> list[dict]:
    """Parse Gemfile.lock for pinned Ruby gem versions."""
    deps = []
    in_gems = False
    for line in content.splitlines():
        if line.strip() == 'GEM':
            continue
        if line.strip() == 'specs:':
            in_gems = True
            continue
        if in_gems and line and not line.startswith(' '):
            in_gems = False
            continue
        if in_gems and line.startswith('    ') and not line.startswith('      '):
            match = re.match(r'\s+([A-Za-z0-9_\-\.]+)\s+\(([^)]+)\)', line)
            if match:
                name, version = match.groups()
                deps.append({
                    "name": name,
                    "version": version,
                    "version_constraint": f"=={version}",
                    "ecosystem": "RubyGems",
                    "pinned": True,
                    "direct": True
                })
    return deps


def detect_and_parse(filepath: str) -> list[dict]:
    path = Path(filepath)
    content = path.read_text(encoding='utf-8', errors='replace')
    name = path.name.lower()

    if name in ('requirements.txt',) or name.endswith('.txt'):
        return parse_requirements_txt(content)
    elif name == 'package.json':
        return parse_package_json(content)
    elif name == 'go.mod':
        return parse_go_mod(content)
    elif name == 'pom.xml':
        return parse_pom_xml(content)
    elif name == 'gemfile.lock':
        return parse_gemfile_lock(content)
    else:
        print(f"[WARN] Unrecognized manifest: {name}. Trying requirements.txt format.", file=sys.stderr)
        return parse_requirements_txt(content)


def main():
    if len(sys.argv) < 2:
        print("Usage: python parse_manifest.py <manifest_file>")
        sys.exit(1)

    filepath = sys.argv[1]
    if not Path(filepath).exists():
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    deps = detect_and_parse(filepath)

    # Output as JSON for consumption by other scripts
    print(json.dumps(deps, indent=2))

    # Summary to stderr
    pinned = sum(1 for d in deps if d.get("pinned"))
    print(f"\n[Summary] {len(deps)} packages ({pinned} pinned, {len(deps)-pinned} unpinned)", file=sys.stderr)


if __name__ == "__main__":
    main()
