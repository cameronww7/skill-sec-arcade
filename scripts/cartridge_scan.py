#!/usr/bin/env python3
"""Cartridge Scanner: repo inventory for cartridge-scanner skill.

Walks a repo, runs `scc` for language/LOC stats (falls back to a rough
manual count if `scc` isn't installed), inventories package manager
manifests/lockfiles with approximate dependency counts, flags any
non-default (private/internal) package registries, and finds
Dockerfiles/compose files and common IaC file types.

Prints one JSON object to stdout. No prose, no markdown: interpretation
is the calling skill's job, not this script's.
"""

import json
import os
import re
import subprocess
import sys
from urllib.parse import urlparse

EXCLUDE_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "env",
    "site-packages", "dist", "build", "target", ".tox",
    ".mypy_cache", "__pycache__", "bower_components", ".terraform",
    ".serverless",
}

FALLBACK_EXT_LANG = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go",
    ".java": "Java", ".kt": "Kotlin", ".rb": "Ruby", ".php": "PHP",
    ".rs": "Rust", ".cs": "C#", ".c": "C", ".h": "C", ".cpp": "C++",
    ".hpp": "C++", ".swift": "Swift", ".dart": "Dart",
    ".sh": "Shell", ".yaml": "YAML", ".yml": "YAML", ".tf": "Terraform",
    ".sql": "SQL", ".rb": "Ruby", ".scala": "Scala", ".m": "Objective-C",
    ".html": "HTML", ".css": "CSS", ".scss": "SCSS",
}

DEFAULT_REGISTRY_HOSTS = {
    "npm": {"registry.npmjs.org"},
    "pip": {"pypi.org", "files.pythonhosted.org"},
    "maven": {"repo.maven.apache.org", "repo1.maven.org", "central.sonatype.com"},
    "gem": {"rubygems.org"},
    "composer": {"repo.packagist.org"},
    "cargo": {"crates.io", "static.crates.io"},
    "nuget": {"api.nuget.org", "www.nuget.org"},
}


def read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


def read_json(path):
    try:
        return json.loads(read_text(path))
    except (ValueError, TypeError):
        return None


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        yield dirpath, dirnames, filenames


def find_files(root, names=None, suffixes=None):
    names = set(names or [])
    suffixes = tuple(suffixes or ())
    hits = []
    for dirpath, _dirnames, filenames in walk(root):
        for fn in filenames:
            if fn in names or (suffixes and fn.endswith(suffixes)):
                hits.append(os.path.join(dirpath, fn))
    return hits


# --- scc / fallback LOC -----------------------------------------------

def run_scc(root):
    try:
        proc = subprocess.run(
            ["scc", "--format", "json", root],
            capture_output=True, text=True, timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        raw = json.loads(proc.stdout)
    except ValueError:
        return None
    languages = []
    for entry in raw:
        languages.append({
            "name": entry.get("Name"),
            "files": entry.get("Count", 0),
            "lines": entry.get("Lines", 0),
            "code": entry.get("Code", 0),
            "comment": entry.get("Comment", 0),
            "blank": entry.get("Blank", 0),
            "complexity": entry.get("Complexity", 0),
        })
    return languages


def fallback_loc_scan(root):
    totals = {}
    for dirpath, _dirnames, filenames in walk(root):
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            lang = FALLBACK_EXT_LANG.get(ext)
            if not lang:
                continue
            path = os.path.join(dirpath, fn)
            text = read_text(path)
            if not text and os.path.getsize(path) > 0:
                continue  # unreadable/binary
            entry = totals.setdefault(lang, {"name": lang, "files": 0, "lines": 0,
                                              "code": 0, "comment": 0, "blank": 0,
                                              "complexity": 0})
            entry["files"] += 1
            entry["lines"] += text.count("\n") + (1 if text and not text.endswith("\n") else 0)
    return list(totals.values())


def totals_of(languages):
    totals = {"files": 0, "lines": 0, "code": 0, "comment": 0, "blank": 0}
    for lang in languages:
        for key in totals:
            totals[key] += lang.get(key, 0)
    return totals


# --- generic helpers for manifest/lockfile parsing ---------------------

def toml_section_lines(text, header):
    lines = text.splitlines()
    out = []
    in_section = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("["):
            in_section = stripped == f"[{header}]"
            continue
        if in_section:
            out.append(line)
    return out


def count_key_value_lines(lines, exclude_keys=()):
    count = 0
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r'^["\']?([\w.\-/@]+)["\']?\s*=', s)
        if m and m.group(1) not in exclude_keys:
            count += 1
    return count


def host_of(url):
    try:
        return urlparse(url).hostname
    except ValueError:
        return None


def add_if_private(results, ecosystem, url, source_file, default_hosts):
    host = host_of(url)
    if not host or host in default_hosts:
        return
    results.append({"ecosystem": ecosystem, "host": host, "url": url, "source_file": source_file})


# --- per-ecosystem package manager inventory ----------------------------

def scan_npm(root, pm, registries):
    manifests = find_files(root, names={"package.json"})
    lockfiles = find_files(root, names={"package-lock.json", "yarn.lock", "pnpm-lock.yaml"})
    if not manifests and not lockfiles:
        return
    declared = None
    for manifest in manifests:
        data = read_json(manifest)
        if not isinstance(data, dict):
            continue
        declared = sum(len(data.get(k) or {}) for k in
                        ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"))
        publish_registry = (data.get("publishConfig") or {}).get("registry")
        if publish_registry:
            add_if_private(registries, "npm", publish_registry, manifest, DEFAULT_REGISTRY_HOSTS["npm"])
        break
    resolved = None
    for lock in lockfiles:
        name = os.path.basename(lock)
        text = read_text(lock)
        if name == "package-lock.json":
            data = read_json(lock)
            if isinstance(data, dict) and isinstance(data.get("packages"), dict):
                resolved = len(data["packages"]) - (1 if "" in data["packages"] else 0)
            elif isinstance(data, dict) and isinstance(data.get("dependencies"), dict):
                def recurse(deps):
                    n = 0
                    for v in deps.values():
                        n += 1
                        if isinstance(v, dict) and isinstance(v.get("dependencies"), dict):
                            n += recurse(v["dependencies"])
                    return n
                resolved = recurse(data["dependencies"])
        elif name == "yarn.lock":
            resolved = sum(1 for line in text.splitlines()
                            if line and not line[0].isspace() and line.rstrip().endswith(":")
                            and not line.startswith("#")) or None
        elif name == "pnpm-lock.yaml":
            resolved = len(re.findall(r"^\s{2}[^\s#][^:]*:\s*$", text, re.MULTILINE)) or None
        if resolved is not None:
            break
    for rc_name in (".npmrc",):
        for rc in find_files(root, names={rc_name}):
            text = read_text(rc)
            for m in re.finditer(r"^(?:@[\w-]+:)?registry\s*=\s*(\S+)", text, re.MULTILINE):
                add_if_private(registries, "npm", m.group(1), rc, DEFAULT_REGISTRY_HOSTS["npm"])
    pm.append({"ecosystem": "npm", "manifest_files": manifests, "lockfile_files": lockfiles,
               "declared_dependencies": declared, "resolved_dependencies": resolved})


def scan_python(root, pm, registries):
    req_files = find_files(root, suffixes=("requirements.txt",)) + \
        [f for f in find_files(root, suffixes=(".txt",)) if os.path.basename(f).startswith("requirements")]
    req_files = sorted(set(req_files))
    pyproject = find_files(root, names={"pyproject.toml"})
    pipfile = find_files(root, names={"Pipfile"})
    pipfile_lock = find_files(root, names={"Pipfile.lock"})
    poetry_lock = find_files(root, names={"poetry.lock"})
    manifests = req_files + pyproject + pipfile
    lockfiles = pipfile_lock + poetry_lock
    if not manifests and not lockfiles:
        return
    declared = None
    for req in req_files:
        text = read_text(req)
        count = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-"):
                m = re.match(r"--(?:extra-)?index-url\s+(\S+)", line)
                if m:
                    add_if_private(registries, "pip", m.group(1), req, DEFAULT_REGISTRY_HOSTS["pip"])
                continue
            count += 1
        declared = (declared or 0) + count
    for pp in pyproject:
        text = read_text(pp)
        m = re.search(r"dependencies\s*=\s*\[(.*?)\]", text, re.DOTALL)
        if m:
            declared = (declared or 0) + len(re.findall(r'["\']([^"\']+)["\']', m.group(1)))
        poetry_deps = toml_section_lines(text, "tool.poetry.dependencies")
        if poetry_deps:
            declared = (declared or 0) + count_key_value_lines(poetry_deps, exclude_keys={"python"})
        for src_m in re.finditer(r'\[\[tool\.poetry\.source\]\].*?url\s*=\s*["\']([^"\']+)["\']', text, re.DOTALL):
            add_if_private(registries, "pip", src_m.group(1), pp, DEFAULT_REGISTRY_HOSTS["pip"])
    for pf in pipfile:
        text = read_text(pf)
        for section in ("packages", "dev-packages"):
            lines = toml_section_lines(text, section)
            declared = (declared or 0) + count_key_value_lines(lines)
    resolved = None
    for lock in pipfile_lock:
        data = read_json(lock)
        if isinstance(data, dict):
            resolved = (resolved or 0) + len(data.get("default") or {}) + len(data.get("develop") or {})
    for lock in poetry_lock:
        text = read_text(lock)
        n = len(re.findall(r"^\[\[package\]\]\s*$", text, re.MULTILINE))
        if n:
            resolved = (resolved or 0) + n
    for pip_conf in find_files(root, names={"pip.conf", "pip.ini"}):
        text = read_text(pip_conf)
        m = re.search(r"index-url\s*=\s*(\S+)", text)
        if m:
            add_if_private(registries, "pip", m.group(1), pip_conf, DEFAULT_REGISTRY_HOSTS["pip"])
    pm.append({"ecosystem": "python", "manifest_files": manifests, "lockfile_files": lockfiles,
               "declared_dependencies": declared, "resolved_dependencies": resolved})


def scan_go(root, pm, registries):
    manifests = find_files(root, names={"go.mod"})
    lockfiles = find_files(root, names={"go.sum"})
    if not manifests and not lockfiles:
        return
    declared = None
    for mod in manifests:
        text = read_text(mod)
        count = 0
        in_block = False
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("require ("):
                in_block = True
                continue
            if in_block:
                if s == ")":
                    in_block = False
                    continue
                if s and not s.startswith("//"):
                    count += 1
                continue
            if s.startswith("require ") and "(" not in s:
                count += 1
        declared = (declared or 0) + count
        for m in re.finditer(r"^replace\s+\S+\s*=>\s*(\S+)", text, re.MULTILINE):
            target = m.group(1)
            if "://" in target or (re.match(r"^[\w.-]+\.[a-z]{2,}/", target)):
                url = target if "://" in target else f"https://{target}"
                add_if_private(registries, "go", url, mod, set())
    resolved = None
    for sm in lockfiles:
        text = read_text(sm)
        mods = {line.split()[0] for line in text.splitlines() if line.split()}
        if mods:
            resolved = (resolved or 0) + len(mods)
    pm.append({"ecosystem": "go", "manifest_files": manifests, "lockfile_files": lockfiles,
               "declared_dependencies": declared, "resolved_dependencies": resolved})


def scan_java(root, pm, registries):
    manifests = find_files(root, names={"pom.xml", "build.gradle", "build.gradle.kts"})
    if not manifests:
        return
    declared = None
    for m_path in manifests:
        text = read_text(m_path)
        if m_path.endswith("pom.xml"):
            declared = (declared or 0) + len(re.findall(r"<dependency>", text))
            repos = re.search(r"<repositories>(.*?)</repositories>", text, re.DOTALL)
            if repos:
                for url_m in re.finditer(r"<url>([^<]+)</url>", repos.group(1)):
                    add_if_private(registries, "maven", url_m.group(1), m_path, DEFAULT_REGISTRY_HOSTS["maven"])
        else:
            declared = (declared or 0) + len(re.findall(
                r"\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly)\s*[\(\'\"]", text))
            for url_m in re.finditer(r"maven\s*\{\s*url\s*[=]?\s*[\'\"]([^\'\"]+)[\'\"]", text):
                add_if_private(registries, "maven", url_m.group(1), m_path, DEFAULT_REGISTRY_HOSTS["maven"])
    pm.append({"ecosystem": "java", "manifest_files": manifests, "lockfile_files": [],
               "declared_dependencies": declared, "resolved_dependencies": None})


def scan_ruby(root, pm, registries):
    manifests = find_files(root, names={"Gemfile"})
    lockfiles = find_files(root, names={"Gemfile.lock"})
    if not manifests and not lockfiles:
        return
    declared = None
    for gf in manifests:
        text = read_text(gf)
        declared = (declared or 0) + len(re.findall(r"^\s*gem\s+['\"]", text, re.MULTILINE))
        for m in re.finditer(r"^\s*source\s+['\"]([^'\"]+)['\"]", text, re.MULTILINE):
            add_if_private(registries, "gem", m.group(1), gf, DEFAULT_REGISTRY_HOSTS["gem"])
    resolved = None
    for lock in lockfiles:
        text = read_text(lock)
        count = 0
        in_specs = False
        for line in text.splitlines():
            if line.strip() == "specs:":
                in_specs = True
                continue
            if in_specs:
                if line.startswith("    ") and not line.startswith("      "):
                    count += 1
                elif line and not line.startswith(" "):
                    in_specs = False
        if count:
            resolved = (resolved or 0) + count
    pm.append({"ecosystem": "ruby", "manifest_files": manifests, "lockfile_files": lockfiles,
               "declared_dependencies": declared, "resolved_dependencies": resolved})


def scan_php(root, pm, registries):
    manifests = find_files(root, names={"composer.json"})
    lockfiles = find_files(root, names={"composer.lock"})
    if not manifests and not lockfiles:
        return
    declared = None
    for cj in manifests:
        data = read_json(cj)
        if isinstance(data, dict):
            req = {k: v for k, v in (data.get("require") or {}).items() if k != "php"}
            req_dev = data.get("require-dev") or {}
            declared = (declared or 0) + len(req) + len(req_dev)
            repos = data.get("repositories")
            if isinstance(repos, list):
                for r in repos:
                    if isinstance(r, dict) and r.get("url"):
                        add_if_private(registries, "composer", r["url"], cj, DEFAULT_REGISTRY_HOSTS["composer"])
            elif isinstance(repos, dict):
                for r in repos.values():
                    if isinstance(r, dict) and r.get("url"):
                        add_if_private(registries, "composer", r["url"], cj, DEFAULT_REGISTRY_HOSTS["composer"])
    resolved = None
    for lock in lockfiles:
        data = read_json(lock)
        if isinstance(data, dict):
            resolved = (resolved or 0) + len(data.get("packages") or []) + len(data.get("packages-dev") or [])
    pm.append({"ecosystem": "php", "manifest_files": manifests, "lockfile_files": lockfiles,
               "declared_dependencies": declared, "resolved_dependencies": resolved})


def scan_rust(root, pm, registries):
    manifests = find_files(root, names={"Cargo.toml"})
    lockfiles = find_files(root, names={"Cargo.lock"})
    if not manifests and not lockfiles:
        return
    declared = None
    for ct in manifests:
        text = read_text(ct)
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            declared = (declared or 0) + count_key_value_lines(toml_section_lines(text, section))
    for cfg in find_files(root, names={"config.toml"}):
        if os.path.basename(os.path.dirname(cfg)) != ".cargo":
            continue
        text = read_text(cfg)
        for m in re.finditer(r"registry\s*=\s*['\"]([^'\"]+)['\"]", text):
            add_if_private(registries, "cargo", m.group(1), cfg, DEFAULT_REGISTRY_HOSTS["cargo"])
    resolved = None
    for lock in lockfiles:
        text = read_text(lock)
        n = len(re.findall(r"^\[\[package\]\]\s*$", text, re.MULTILINE))
        if n:
            resolved = (resolved or 0) + n
    pm.append({"ecosystem": "rust", "manifest_files": manifests, "lockfile_files": lockfiles,
               "declared_dependencies": declared, "resolved_dependencies": resolved})


def scan_dotnet(root, pm, registries):
    manifests = find_files(root, suffixes=(".csproj",))
    lockfiles = find_files(root, names={"packages.lock.json"})
    if not manifests and not lockfiles:
        return
    declared = None
    for cs in manifests:
        text = read_text(cs)
        declared = (declared or 0) + len(re.findall(r"<PackageReference\b", text))
    resolved = None
    for lock in lockfiles:
        data = read_json(lock)
        if isinstance(data, dict) and isinstance(data.get("dependencies"), dict):
            total = 0
            for framework_deps in data["dependencies"].values():
                if isinstance(framework_deps, dict):
                    total += len(framework_deps)
            if total:
                resolved = (resolved or 0) + total
    for nc in find_files(root, names={"nuget.config", "NuGet.Config"}):
        text = read_text(nc)
        for m in re.finditer(r'<add\s+key="[^"]*"\s+value="([^"]+)"', text):
            if m.group(1).startswith("http"):
                add_if_private(registries, "nuget", m.group(1), nc, DEFAULT_REGISTRY_HOSTS["nuget"])
    pm.append({"ecosystem": "dotnet", "manifest_files": manifests, "lockfile_files": lockfiles,
               "declared_dependencies": declared, "resolved_dependencies": resolved})


def scan_dart(root, pm, _registries):
    manifests = find_files(root, names={"pubspec.yaml"})
    lockfiles = find_files(root, names={"pubspec.lock"})
    if not manifests and not lockfiles:
        return
    declared = None
    for pf in manifests:
        text = read_text(pf)
        in_deps = False
        count = 0
        for line in text.splitlines():
            if re.match(r"^(dependencies|dev_dependencies):\s*$", line):
                in_deps = True
                continue
            if in_deps:
                if re.match(r"^\S", line):
                    in_deps = False
                    continue
                if re.match(r"^  \S[^:]*:", line):
                    count += 1
        declared = (declared or 0) + count
    resolved = None
    for lock in lockfiles:
        text = read_text(lock)
        n = len(re.findall(r"^  \S[^:]*:\s*$", text, re.MULTILINE))
        if n:
            resolved = (resolved or 0) + n
    pm.append({"ecosystem": "dart", "manifest_files": manifests, "lockfile_files": lockfiles,
               "declared_dependencies": declared, "resolved_dependencies": resolved})


def scan_package_managers(root):
    pm = []
    registries = []
    for fn in (scan_npm, scan_python, scan_go, scan_java, scan_ruby, scan_php, scan_rust, scan_dotnet, scan_dart):
        fn(root, pm, registries)
    return pm, registries


# --- containers ----------------------------------------------------------

def scan_containers(root):
    dockerfiles = []
    for path in find_files(root, names={"Dockerfile"}):
        dockerfiles.append(path)
    for dirpath, _dirnames, filenames in walk(root):
        for fn in filenames:
            if fn.startswith("Dockerfile") and fn != "Dockerfile":
                dockerfiles.append(os.path.join(dirpath, fn))
    entries = []
    for path in sorted(set(dockerfiles)):
        text = read_text(path)
        bases = re.findall(r"^FROM\s+(\S+)", text, re.MULTILINE)
        entries.append({"path": path, "base_images": bases})
    compose_files = []
    for dirpath, _dirnames, filenames in walk(root):
        for fn in filenames:
            if re.match(r"^docker-compose.*\.ya?ml$", fn):
                compose_files.append(os.path.join(dirpath, fn))
    return {"dockerfiles": entries, "compose_files": sorted(compose_files)}


# --- IaC -------------------------------------------------------------------

def scan_iac(root):
    result = {"terraform": [], "cloudformation": [], "kubernetes": [], "helm": [],
              "ansible": [], "pulumi": [], "serverless": [], "cdk": []}
    result["terraform"] = sorted(find_files(root, suffixes=(".tf", ".tfvars")))
    result["helm"] = sorted(find_files(root, names={"Chart.yaml"}))
    result["pulumi"] = sorted(find_files(root, names={"Pulumi.yaml"}))
    result["serverless"] = sorted(find_files(root, names={"serverless.yml", "serverless.yaml"}))
    result["cdk"] = sorted(find_files(root, names={"cdk.json"}))

    for dirpath, _dirnames, filenames in walk(root):
        for fn in filenames:
            if not fn.endswith((".yml", ".yaml", ".json")):
                continue
            path = os.path.join(dirpath, fn)
            text = read_text(path)
            if not text:
                continue
            if "AWSTemplateFormatVersion" in text or re.search(r"Type:\s*['\"]?AWS::", text):
                result["cloudformation"].append(path)
                continue
            if fn.endswith((".yml", ".yaml")) and "apiVersion:" in text and "kind:" in text:
                result["kubernetes"].append(path)
                continue
            if fn.endswith((".yml", ".yaml")) and "hosts:" in text and "tasks:" in text:
                result["ansible"].append(path)

    for key in result:
        result[key] = sorted(set(result[key]))
    return result


# --- main ------------------------------------------------------------------

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    root = os.path.abspath(root)

    languages = run_scc(root)
    scc_available = languages is not None
    if languages is None:
        languages = fallback_loc_scan(root)

    package_managers, private_registries = scan_package_managers(root)
    containers = scan_containers(root)
    iac = scan_iac(root)

    output = {
        "scc_available": scc_available,
        "languages": languages,
        "totals": totals_of(languages),
        "package_managers": package_managers,
        "private_registries": private_registries,
        "containers": containers,
        "iac": iac,
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
