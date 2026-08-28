#!/usr/bin/env python3
"""Dead Weight Detector: dependency usage + health scan for dead-weight-detector skill.

Two independent modes:

  usage <path>
      Local only, no network. Lists direct dependencies per ecosystem
      (reusing cartridge_scan.py's manifest discovery) and sweeps
      first-party source files for import/require sites, computing an
      approximate usage tier per dependency.

  health <ecosystem> <repo_path> <name> [<name> ...]
      Live network calls. <repo_path> is used only to resolve each
      name's pinned version from the local lockfile (so the OSV.dev
      vulnerability check is scoped to the version actually installed,
      not every version ever published), no other local file access
      happens in this mode. Queries each ecosystem's own public
      registry API (plus OSV.dev for every ecosystem) for release
      recency, maintainer count, download volume, and known unpatched
      vulnerabilities in the pinned version. When a version can't be
      resolved, the OSV result is unscoped and is reported for
      awareness only, it cannot by itself push the health tier to "at
      risk." Only ever call this with names already triaged as worth a
      deep dive, this is what keeps the number of outbound calls
      bounded.

Prints one JSON object to stdout per invocation. No prose, no markdown.
"""

import json
import os
import re
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cartridge_scan import walk, find_files, read_text, read_json, EXCLUDE_DIRS  # noqa: E402

USER_AGENT = "dead-weight-detector/1.0 (github.com/cameronww7/skill-sec-arcade)"

SOURCE_EXTENSIONS = {
    "npm": (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
    "python": (".py",),
    "go": (".go",),
    "java": (".java",),
    "ruby": (".rb",),
    "php": (".php",),
    "rust": (".rs",),
    "dotnet": (".cs",),
    "dart": (".dart",),
}

# Ecosystems where a real symbol/call-site count is attempted vs. where
# only the import/require/use statement itself can be counted reliably.
WEAK_ECOSYSTEMS = {"ruby", "php"}


# --- dependency name extraction (new logic, not in cartridge_scan.py) ------

def list_npm_deps(root):
    out = []
    for manifest in find_files(root, names={"package.json"}):
        data = read_json(manifest)
        if not isinstance(data, dict):
            continue
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for name in (data.get(key) or {}):
                out.append((name, manifest))
        break
    return out


def list_python_deps(root):
    out = []
    for req in find_files(root, suffixes=("requirements.txt",)):
        for line in read_text(req).splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            name = re.split(r"[<>=!~;\[\s]", line, maxsplit=1)[0].strip()
            if name:
                out.append((name, req))
    for pp in find_files(root, names={"pyproject.toml"}):
        text = read_text(pp)
        m = re.search(r"dependencies\s*=\s*\[(.*?)\]", text, re.DOTALL)
        if m:
            for spec in re.findall(r'["\']([^"\']+)["\']', m.group(1)):
                name = re.split(r"[<>=!~;\[\s]", spec, 1)[0].strip()
                if name:
                    out.append((name, pp))
        in_section = False
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("["):
                in_section = s == "[tool.poetry.dependencies]"
                continue
            if in_section and "=" in s and not s.startswith("#"):
                name = s.split("=", 1)[0].strip().strip('"\'')
                if name and name != "python":
                    out.append((name, pp))
    for pf in find_files(root, names={"Pipfile"}):
        text = read_text(pf)
        in_section = False
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("["):
                in_section = s in ("[packages]", "[dev-packages]")
                continue
            if in_section and "=" in s and not s.startswith("#"):
                name = s.split("=", 1)[0].strip().strip('"\'')
                if name:
                    out.append((name, pf))
    return out


def list_go_deps(root):
    out = []
    for mod in find_files(root, names={"go.mod"}):
        text = read_text(mod)
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
                m = re.match(r"^(\S+)\s+v\S+", s)
                if m:
                    out.append((m.group(1), mod))
                continue
            m = re.match(r"^require\s+(\S+)\s+v\S+", s)
            if m:
                out.append((m.group(1), mod))
    return out


def list_java_deps(root):
    """Returns (matching_prefix, manifest) pairs. Prefix is groupId for
    Maven (imports conventionally start with the groupId), or the raw
    group:artifact string for Gradle, both best-effort."""
    out = []
    for pom in find_files(root, names={"pom.xml"}):
        text = read_text(pom)
        for m in re.finditer(r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>", text):
            out.append((m.group(1), pom, f"{m.group(1)}:{m.group(2)}"))
    for gradle in find_files(root, names={"build.gradle", "build.gradle.kts"}):
        text = read_text(gradle)
        for m in re.finditer(r"[\'\"]([\w.\-]+):([\w.\-]+):[\w.\-\[\],+]+[\'\"]", text):
            out.append((m.group(1), gradle, f"{m.group(1)}:{m.group(2)}"))
    return out


def list_ruby_deps(root):
    out = []
    for gf in find_files(root, names={"Gemfile"}):
        for m in re.finditer(r"^\s*gem\s+['\"]([^'\"]+)['\"]", read_text(gf), re.MULTILINE):
            out.append((m.group(1), gf))
    return out


def list_php_deps(root):
    out = []
    for cj in find_files(root, names={"composer.json"}):
        data = read_json(cj)
        if not isinstance(data, dict):
            continue
        for key in ("require", "require-dev"):
            for name in (data.get(key) or {}):
                if name != "php" and "/" in name:
                    out.append((name, cj))
    return out


def list_rust_deps(root):
    out = []
    for ct in find_files(root, names={"Cargo.toml"}):
        text = read_text(ct)
        in_section = False
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("["):
                in_section = s in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]")
                continue
            if in_section and "=" in s and not s.startswith("#"):
                name = s.split("=", 1)[0].strip().strip('"\'')
                if name:
                    out.append((name, ct))
    return out


def list_dotnet_deps(root):
    out = []
    for cs in find_files(root, suffixes=(".csproj",)):
        for m in re.finditer(r'<PackageReference\s+Include="([^"]+)"', read_text(cs)):
            out.append((m.group(1), cs))
    return out


def list_dart_deps(root):
    out = []
    for pf in find_files(root, names={"pubspec.yaml"}):
        text = read_text(pf)
        in_deps = False
        for line in text.splitlines():
            if re.match(r"^dependencies:\s*$", line):
                in_deps = True
                continue
            if in_deps:
                if re.match(r"^\S", line):
                    in_deps = False
                    continue
                m = re.match(r"^  (\S[^:]*):", line)
                if m:
                    out.append((m.group(1), pf))
    return out


LIST_DEPS = {
    "npm": list_npm_deps,
    "python": list_python_deps,
    "go": list_go_deps,
    "java": list_java_deps,
    "ruby": list_ruby_deps,
    "php": list_php_deps,
    "rust": list_rust_deps,
    "dotnet": list_dotnet_deps,
    "dart": list_dart_deps,
}


# --- per-ecosystem import-line extraction ------------------------------
# Each extractor takes a source line and returns (module_key, bound_names)
# or None. module_key is what gets matched against the dependency name
# (or, for java, the matching prefix); bound_names is the list of
# identifiers a call-site sweep should look for elsewhere in the file.

def extract_js(line):
    m = re.match(r"^\s*import\s+(\w+)\s*,?\s*from\s+['\"]([^'\"]+)['\"]", line)
    if m:
        return m.group(2), [m.group(1)]
    m = re.match(r"^\s*import\s+\*\s+as\s+(\w+)\s+from\s+['\"]([^'\"]+)['\"]", line)
    if m:
        return m.group(2), [m.group(1)]
    m = re.match(r"^\s*import\s+\{([^}]+)\}\s+from\s+['\"]([^'\"]+)['\"]", line)
    if m:
        names = []
        for part in m.group(1).split(","):
            part = part.strip()
            if not part:
                continue
            names.append(part.split(" as ")[-1].strip())
        return m.group(2), names
    m = re.match(r"^\s*(?:const|let|var)\s+\{([^}]+)\}\s*=\s*require\(['\"]([^'\"]+)['\"]\)", line)
    if m:
        names = [p.strip().split(":")[-1].strip() for p in m.group(1).split(",") if p.strip()]
        return m.group(2), names
    m = re.match(r"^\s*(?:const|let|var)\s+(\w+)\s*=\s*require\(['\"]([^'\"]+)['\"]\)", line)
    if m:
        return m.group(2), [m.group(1)]
    m = re.match(r"^\s*import\s+['\"]([^'\"]+)['\"]", line) or re.match(r"^\s*require\(['\"]([^'\"]+)['\"]\)", line)
    if m:
        return m.group(1), []
    return None


def extract_python(line):
    m = re.match(r"^\s*from\s+([\w.]+)\s+import\s+(.+)", line)
    if m:
        module = m.group(1).split(".")[0]
        names = []
        for part in m.group(2).split(","):
            part = part.strip().strip("()")
            if not part:
                continue
            names.append(part.split(" as ")[-1].strip())
        return module, names
    m = re.match(r"^\s*import\s+([\w.]+)(?:\s+as\s+(\w+))?", line)
    if m:
        module = m.group(1).split(".")[0]
        bound = m.group(2) or module
        return module, [bound]
    return None


def extract_go(line):
    m = re.match(r'^\s*import\s+(?:(\w+)\s+)?"([^"]+)"\s*$', line)
    if not m:
        m = re.match(r'^\s*(?:(\w+)\s+)?"([^"]+)"\s*$', line)
    if m:
        alias = m.group(1)
        path = m.group(2)
        bound = alias or path.rstrip("/").split("/")[-1]
        return path, [bound]
    return None


def extract_java(line):
    m = re.match(r"^\s*import\s+(?:static\s+)?([\w.]+)(\.\*)?;", line)
    if m:
        dotted = m.group(1)
        bound = dotted.split(".")[-1]
        return dotted, [bound]
    return None


def extract_rust(line):
    m = re.match(r"^\s*use\s+([\w:]+)(?:::\{[^}]*\})?(?:::(\w+))?", line)
    if m:
        module = m.group(1).split("::")[0]
        bound = m.group(2) or module
        return module, [bound]
    return None


def extract_dotnet(line):
    m = re.match(r"^\s*using\s+([\w.]+)\s*;", line)
    if m:
        dotted = m.group(1)
        return dotted, [dotted.split(".")[-1]]
    return None


def extract_dart(line):
    m = re.match(r"^\s*import\s+['\"]package:([\w.\-]+)/[^'\"]*['\"](?:\s+as\s+(\w+))?", line)
    if m:
        pkg = m.group(1)
        bound = m.group(2) or pkg.replace("-", "_")
        return pkg, [bound]
    return None


def extract_weak(pattern):
    def fn(line):
        m = pattern.match(line)
        if m:
            return m.group(1), []
        return None
    return fn


EXTRACTORS = {
    "npm": extract_js,
    "python": extract_python,
    "go": extract_go,
    "java": extract_java,
    "ruby": extract_weak(re.compile(r"^\s*require(?:_relative)?\s+['\"]([^'\"]+)['\"]")),
    "php": extract_weak(re.compile(r"^\s*use\s+([\w\\]+)")),
    "rust": extract_rust,
    "dotnet": extract_dotnet,
    "dart": extract_dart,
}


def module_matches(ecosystem, module_key, dep_name, dep_match_key=None):
    if ecosystem == "npm":
        if module_key.startswith("@"):
            parts = module_key.split("/")
            module_key = "/".join(parts[:2]) if len(parts) > 1 else module_key
        else:
            module_key = module_key.split("/")[0]
        return module_key == dep_name
    if ecosystem == "python":
        return module_key == dep_name or module_key.replace("-", "_") == dep_name.replace("-", "_")
    if ecosystem == "go":
        return module_key == dep_name
    if ecosystem == "java":
        prefix = dep_match_key or dep_name
        return module_key == prefix or module_key.startswith(prefix + ".")
    if ecosystem == "rust":
        return module_key == dep_name.replace("-", "_")
    if ecosystem == "dotnet":
        return module_key == dep_name or module_key.startswith(dep_name + ".")
    if ecosystem == "dart":
        return module_key == dep_name
    if ecosystem == "ruby":
        return module_key == dep_name or module_key.startswith(dep_name + "/")
    if ecosystem == "php":
        vendor, _, pkg = dep_name.partition("/")
        guess = "".join(p.capitalize() for p in re.split(r"[-_]", vendor)) + "\\" + \
            "".join(p.capitalize() for p in re.split(r"[-_]", pkg))
        return module_key.startswith(guess.split("\\")[0])
    return False


def usage_tier(files_importing, call_site_count):
    if call_site_count is None:
        call_site_count = files_importing
    if files_importing >= 5 or call_site_count > 20:
        return "heavy"
    if files_importing >= 3:
        return "moderate"
    if call_site_count <= 2 and files_importing <= 1:
        return "minimal"
    if call_site_count <= 6:
        return "light"
    return "moderate"


def scan_usage_for_ecosystem(root, ecosystem, deps):
    """deps: list of (name, manifest_file) or (matching_key, manifest_file, display_name) for java."""
    if not deps:
        return []
    extensions = SOURCE_EXTENSIONS[ecosystem]
    extractor = EXTRACTORS[ecosystem]
    weak = ecosystem in WEAK_ECOSYSTEMS

    if ecosystem == "java":
        dep_index = {}
        for match_key, manifest, display in deps:
            dep_index.setdefault(display, {"match_key": match_key, "manifest": manifest})
        dep_entries = [(display, v["match_key"], v["manifest"]) for display, v in dep_index.items()]
    else:
        dep_names = sorted({name for name, _m in deps})
        dep_entries = [(name, None, None) for name in dep_names]

    stats = {name: {"files_importing": 0, "call_site_count": 0, "symbols": set()} for name, _, _ in dep_entries}

    source_files = find_files(root, suffixes=extensions)
    for path in source_files:
        text = read_text(path)
        if not text:
            continue
        lines = text.splitlines()
        file_hits = {}
        for i, line in enumerate(lines):
            extracted = extractor(line)
            if not extracted:
                continue
            module_key, bound_names = extracted
            for name, match_key, _manifest in dep_entries:
                if module_matches(ecosystem, module_key, name, match_key):
                    file_hits.setdefault(name, {"bound": set(), "import_lines": set()})
                    file_hits[name]["bound"].update(bound_names)
                    file_hits[name]["import_lines"].add(i)

        if not file_hits:
            continue
        body = "\n".join(lines)
        for name, info in file_hits.items():
            stats[name]["files_importing"] += 1
            stats[name]["symbols"].update(info["bound"])
            if weak or not info["bound"]:
                stats[name]["call_site_count"] += len(info["import_lines"])
                continue
            count = 0
            for sym in info["bound"]:
                if not sym or not re.match(r"^\w+$", sym):
                    continue
                count += len(re.findall(r"\b" + re.escape(sym) + r"\b", body)) - len(
                    [i for i in info["import_lines"]]
                )
            stats[name]["call_site_count"] += max(count, 0)

    out = []
    for name, s in stats.items():
        call_sites = s["call_site_count"] if (s["symbols"] or weak) else None
        out.append({
            "name": name,
            "files_importing": s["files_importing"],
            "call_site_count": call_sites,
            "distinct_symbols_used": sorted(s["symbols"]) if s["symbols"] else [],
            "usage_tier": usage_tier(s["files_importing"], call_sites) if s["files_importing"] else "unused",
            "usage_signal": "weak" if weak else "standard",
        })
    return sorted(out, key=lambda d: d["name"])


def run_usage(root):
    result = {}
    listers = {
        "npm": list_npm_deps, "python": list_python_deps, "go": list_go_deps,
        "java": list_java_deps, "ruby": list_ruby_deps, "php": list_php_deps,
        "rust": list_rust_deps, "dotnet": list_dotnet_deps, "dart": list_dart_deps,
    }
    for ecosystem, lister in listers.items():
        deps = lister(root)
        if not deps:
            continue
        result[ecosystem] = scan_usage_for_ecosystem(root, ecosystem, deps)
    return result


# --- pinned-version resolution (needed to scope OSV queries correctly) -----
# Without a version, an OSV lookup returns every vulnerability ever
# reported against the package, not just ones affecting what's actually
# installed. Best-effort per ecosystem; None means "couldn't resolve,"
# not "no version."

def resolve_version_npm(root, name):
    for lock in find_files(root, names={"package-lock.json"}):
        data = read_json(lock)
        if not isinstance(data, dict):
            continue
        packages = data.get("packages")
        if isinstance(packages, dict):
            entry = packages.get(f"node_modules/{name}")
            if isinstance(entry, dict) and entry.get("version"):
                return entry["version"]
        deps = data.get("dependencies")
        if isinstance(deps, dict) and isinstance(deps.get(name), dict):
            v = deps[name].get("version")
            if v:
                return v
    return None


def resolve_version_python(root, name):
    for req in find_files(root, suffixes=("requirements.txt",)):
        for line in read_text(req).splitlines():
            m = re.match(r"^\s*" + re.escape(name) + r"\s*==\s*(\S+)", line, re.IGNORECASE)
            if m:
                return m.group(1)
    for lock in find_files(root, names={"poetry.lock"}):
        text = read_text(lock)
        for block in re.split(r"^\[\[package\]\]\s*$", text, flags=re.MULTILINE):
            nm = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
            vs = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
            if nm and vs and nm.group(1).lower() == name.lower():
                return vs.group(1)
    for lock in find_files(root, names={"Pipfile.lock"}):
        data = read_json(lock)
        if isinstance(data, dict):
            for section in ("default", "develop"):
                entry = (data.get(section) or {}).get(name)
                if isinstance(entry, dict) and entry.get("version"):
                    return entry["version"].lstrip("=")
    return None


def resolve_version_go(root, name):
    for mod in find_files(root, names={"go.mod"}):
        for line in read_text(mod).splitlines():
            m = re.match(r"^\s*" + re.escape(name) + r"\s+(v\S+)", line.strip())
            if m:
                return m.group(1)
    return None


def resolve_version_rust(root, name):
    for lock in find_files(root, names={"Cargo.lock"}):
        text = read_text(lock)
        for block in re.split(r"^\[\[package\]\]\s*$", text, flags=re.MULTILINE):
            nm = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
            vs = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
            if nm and vs and nm.group(1) == name:
                return vs.group(1)
    return None


def resolve_version_ruby(root, name):
    for lock in find_files(root, names={"Gemfile.lock"}):
        m = re.search(r"^\s{4}" + re.escape(name) + r"\s+\(([^)]+)\)", read_text(lock), re.MULTILINE)
        if m:
            return m.group(1)
    return None


def resolve_version_php(root, name):
    for lock in find_files(root, names={"composer.lock"}):
        data = read_json(lock)
        if not isinstance(data, dict):
            continue
        for section in ("packages", "packages-dev"):
            for pkg in (data.get(section) or []):
                if isinstance(pkg, dict) and pkg.get("name") == name and pkg.get("version"):
                    return pkg["version"]
    return None


def resolve_version_dart(root, name):
    for lock in find_files(root, names={"pubspec.lock"}):
        text = read_text(lock)
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if re.match(r"^  " + re.escape(name) + r":\s*$", line):
                for j in range(i + 1, min(i + 8, len(lines))):
                    m = re.match(r'^\s+version:\s*"([^"]+)"', lines[j])
                    if m:
                        return m.group(1)
                    if re.match(r"^  \S", lines[j]):
                        break
    return None


def resolve_version_java(root, group_artifact):
    group, _, artifact = group_artifact.partition(":")
    for pom in find_files(root, names={"pom.xml"}):
        text = read_text(pom)
        m = re.search(
            r"<dependency>\s*<groupId>" + re.escape(group) + r"</groupId>\s*<artifactId>" +
            re.escape(artifact) + r"</artifactId>\s*<version>([^<]+)</version>", text)
        if m:
            return m.group(1)
    for gradle in find_files(root, names={"build.gradle", "build.gradle.kts"}):
        m = re.search(
            r"[\'\"]" + re.escape(group) + r":" + re.escape(artifact) + r":([\w.\-]+)[\'\"]",
            read_text(gradle))
        if m:
            return m.group(1)
    return None


def resolve_version_dotnet(root, name):
    for cs in find_files(root, suffixes=(".csproj",)):
        m = re.search(
            r'<PackageReference\s+Include="' + re.escape(name) + r'"\s+Version="([^"]+)"',
            read_text(cs))
        if m:
            return m.group(1)
    return None


RESOLVE_VERSION = {
    "npm": resolve_version_npm, "python": resolve_version_python, "go": resolve_version_go,
    "rust": resolve_version_rust, "ruby": resolve_version_ruby, "php": resolve_version_php,
    "dart": resolve_version_dart, "java": resolve_version_java, "dotnet": resolve_version_dotnet,
}


def resolve_version(root, ecosystem, name):
    fn = RESOLVE_VERSION.get(ecosystem)
    if not fn:
        return None
    try:
        return fn(root, name)
    except (OSError, re.error):
        return None


# --- health mode: live registry lookups ---------------------------------

def http_json(url, method="GET", data=None, headers=None, timeout=10):
    req_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    req_headers.update(headers or {})
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        req_headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, TimeoutError):
        return None


OSV_ECOSYSTEM = {
    "npm": "npm", "python": "PyPI", "go": "Go", "rust": "crates.io",
    "ruby": "RubyGems", "php": "Packagist", "java": "Maven", "dotnet": "NuGet",
    "dart": "Pub",
}


def check_osv(ecosystem, name, version=None):
    osv_eco = OSV_ECOSYSTEM.get(ecosystem)
    if not osv_eco:
        return {"status": "unavailable", "vulnerabilities": [], "version_scoped": False}
    package = {"name": name, "ecosystem": osv_eco}
    query = {"version": version, "package": package} if version else {"package": package}
    data = http_json("https://api.osv.dev/v1/query", method="POST", data=query)
    if data is None:
        return {"status": "unknown", "vulnerabilities": [], "version_scoped": bool(version)}
    vulns = [v.get("id") for v in (data.get("vulns") or [])]
    return {"status": "ok", "vulnerabilities": vulns, "version_scoped": bool(version)}


def health_npm(name):
    meta = http_json(f"https://registry.npmjs.org/{name}")
    downloads = http_json(f"https://api.npmjs.org/downloads/point/last-month/{name}")
    if meta is None:
        return {"recency": None, "maintainers": None, "downloads": None}
    latest = (meta.get("dist-tags") or {}).get("latest")
    time_map = meta.get("time") or {}
    return {
        "recency": time_map.get(latest),
        "maintainers": len(meta.get("maintainers") or []),
        "downloads": (downloads or {}).get("downloads"),
    }


def health_python(name):
    meta = http_json(f"https://pypi.org/pypi/{name}/json")
    if meta is None:
        return {"recency": None, "maintainers": "n/a", "downloads": None}
    releases = meta.get("releases") or {}
    latest_version = (meta.get("info") or {}).get("version")
    upload_time = None
    for r in (releases.get(latest_version) or []):
        upload_time = r.get("upload_time_iso_8601") or r.get("upload_time")
        break
    downloads_data = http_json(f"https://pypistats.org/api/packages/{name}/recent")
    downloads = None
    if downloads_data:
        downloads = (downloads_data.get("data") or {}).get("last_month")
    return {"recency": upload_time, "maintainers": "n/a", "downloads": downloads}


def health_go(name):
    module = name.lower()
    meta = http_json(f"https://proxy.golang.org/{module}/@latest")
    if meta is None:
        return {"recency": None, "maintainers": "n/a", "downloads": "n/a"}
    return {"recency": meta.get("Time"), "maintainers": "n/a", "downloads": "n/a"}


def health_rust(name):
    meta = http_json(f"https://crates.io/api/v1/crates/{name}")
    if meta is None:
        return {"recency": None, "maintainers": None, "downloads": None}
    crate = meta.get("crate") or {}
    owners = http_json(f"https://crates.io/api/v1/crates/{name}/owners")
    maintainers = len((owners or {}).get("users") or []) if owners else None
    return {
        "recency": crate.get("updated_at"),
        "maintainers": maintainers,
        "downloads": crate.get("downloads"),
    }


def health_ruby(name):
    meta = http_json(f"https://rubygems.org/api/v1/gems/{name}.json")
    if meta is None:
        return {"recency": None, "maintainers": "n/a (authors string, not a count)", "downloads": None}
    return {
        "recency": meta.get("version_created_at"),
        "maintainers": meta.get("authors", "n/a"),
        "downloads": meta.get("downloads"),
    }


def health_php(vendor_pkg):
    meta = http_json(f"https://repo.packagist.org/p2/{vendor_pkg}.json")
    if meta is None:
        return {"recency": None, "maintainers": None, "downloads": "n/a"}
    versions = ((meta.get("packages") or {}).get(vendor_pkg) or [])
    recency = versions[0].get("time") if versions else None
    maintainers_meta = http_json(f"https://packagist.org/packages/{vendor_pkg}.json")
    maintainers = None
    if maintainers_meta:
        maintainers = len((maintainers_meta.get("package") or {}).get("maintainers") or [])
    return {"recency": recency, "maintainers": maintainers, "downloads": "n/a"}


def health_java(group_artifact):
    group, _, artifact = group_artifact.partition(":")
    q = f"g:{group}+AND+a:{artifact}" if artifact else f"a:{group}"
    meta = http_json(f"https://search.maven.org/solrsearch/select?q={q}&core=gav&rows=1&wt=json")
    if not meta:
        return {"recency": None, "maintainers": "n/a", "downloads": "n/a"}
    docs = ((meta.get("response") or {}).get("docs") or [])
    recency = docs[0].get("timestamp") if docs else None
    return {"recency": recency, "maintainers": "n/a", "downloads": "n/a"}


def health_dotnet(name):
    meta = http_json(f"https://api.nuget.org/v3/registration5-semver1/{name.lower()}/index.json")
    if not meta:
        return {"recency": None, "maintainers": "n/a", "downloads": "n/a"}
    try:
        pages = meta.get("items") or []
        last_page = pages[-1]
        items = last_page.get("items") or []
        recency = items[-1]["catalogEntry"]["published"] if items else None
    except (IndexError, KeyError, TypeError):
        recency = None
    return {"recency": recency, "maintainers": "n/a", "downloads": "n/a"}


def health_dart(name):
    meta = http_json(f"https://pub.dev/api/packages/{name}")
    if not meta:
        return {"recency": None, "maintainers": "n/a", "downloads": "n/a"}
    return {
        "recency": (meta.get("latest") or {}).get("published"),
        "maintainers": meta.get("publisher") or "n/a",
        "downloads": "n/a",
    }


HEALTH_FN = {
    "npm": health_npm, "python": health_python, "go": health_go,
    "rust": health_rust, "ruby": health_ruby, "php": health_php,
    "java": health_java, "dotnet": health_dotnet, "dart": health_dart,
}


def health_tier(recency, maintainers, downloads, vuln_status):
    if vuln_status.get("vulnerabilities") and vuln_status.get("version_scoped"):
        return "at_risk"

    def months_old(iso):
        if not iso:
            return None
        try:
            from datetime import datetime, timezone
            iso_clean = iso.replace("Z", "+00:00")
            dt = datetime.fromisoformat(iso_clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            delta = datetime.now(timezone.utc) - dt
            return delta.days / 30.0
        except (ValueError, TypeError):
            return None

    age = months_old(recency) if isinstance(recency, str) else None
    maint_n = maintainers if isinstance(maintainers, int) else None
    dl_n = downloads if isinstance(downloads, int) else None

    if age is None and maint_n is None and dl_n is None:
        return "unknown"

    if age is not None and age > 12:
        return "at_risk"
    if maint_n is not None and maint_n == 0:
        return "at_risk"

    if age is not None and age < 3 and (maint_n is None or maint_n >= 2 or (dl_n is not None and dl_n >= 10000)):
        return "healthy"

    return "slowing"


def run_health(ecosystem, names, root=None):
    fn = HEALTH_FN.get(ecosystem)
    out = {}
    for name in names:
        data = fn(name) if fn else {"recency": None, "maintainers": "n/a", "downloads": "n/a"}
        version = resolve_version(root, ecosystem, name) if root else None
        vuln = check_osv(ecosystem, name, version)
        out[name] = {
            "pinned_version": version,
            "recency": data.get("recency"),
            "maintainers": data.get("maintainers"),
            "downloads": data.get("downloads"),
            "vulnerabilities": vuln,
            "health_tier": health_tier(data.get("recency"), data.get("maintainers"),
                                        data.get("downloads"), vuln),
        }
    return out


# --- main ------------------------------------------------------------------

def main():
    usage_msg = ("usage: dead_weight_scan.py usage <path> | "
                 "health <ecosystem> <repo_path> <name> [<name> ...]")
    if len(sys.argv) < 2:
        print(json.dumps({"error": usage_msg}))
        sys.exit(1)

    mode = sys.argv[1]
    if mode == "usage":
        root = sys.argv[2] if len(sys.argv) > 2 else "."
        root = os.path.abspath(root)
        print(json.dumps(run_usage(root), indent=2))
    elif mode == "health":
        if len(sys.argv) < 5:
            print(json.dumps({"error": usage_msg}))
            sys.exit(1)
        ecosystem = sys.argv[2]
        root = os.path.abspath(sys.argv[3])
        names = sys.argv[4:]
        print(json.dumps(run_health(ecosystem, names, root=root), indent=2))
    else:
        print(json.dumps({"error": f"unknown mode {mode!r}, expected 'usage' or 'health'"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
