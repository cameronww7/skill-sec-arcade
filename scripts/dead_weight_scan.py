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

# Ruby and PHP can't be matched reliably by static regex: Ruby's `require`
# doesn't bind a symbol name at all (whatever the gem defines just becomes
# globally available), and PHP namespaces are PSR-4-mapped by the package
# author, not derivable from the composer package name. For these two we
# only count require/use statement occurrences, not real call sites, and
# flag the result as a "weak" signal downstream.
WEAK_ECOSYSTEMS = {"ruby", "php"}


# --- dependency name extraction (new logic, not in cartridge_scan.py) ------

def list_npm_deps(root):
    """Returns (name, manifest_path) pairs for every dependency listed in
    package.json (dependencies, devDependencies, peerDependencies,
    optionalDependencies). Only reads the first package.json found."""
    dependencies = []
    for manifest in find_files(root, names={"package.json"}):
        data = read_json(manifest)
        if not isinstance(data, dict):
            continue
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for name in (data.get(key) or {}):
                dependencies.append((name, manifest))
        break
    return dependencies


def list_python_deps(root):
    """Returns (name, manifest_path) pairs from requirements*.txt,
    pyproject.toml (both PEP 621 and Poetry dependency tables), and
    Pipfile's [packages]/[dev-packages] sections."""
    dependencies = []
    for requirements_file in find_files(root, suffixes=("requirements.txt",)):
        for line in read_text(requirements_file).splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # "requests==2.31.0" -> "requests": cut at the first version
            # specifier, extras bracket, environment marker, or whitespace.
            name = re.split(r"[<>=!~;\[\s]", line, maxsplit=1)[0].strip()
            if name:
                dependencies.append((name, requirements_file))
    for pyproject_file in find_files(root, names={"pyproject.toml"}):
        text = read_text(pyproject_file)
        # PEP 621: dependencies = ["requests>=2.0", "flask"]
        pep621_match = re.search(r"dependencies\s*=\s*\[(.*?)\]", text, re.DOTALL)
        if pep621_match:
            for spec in re.findall(r'["\']([^"\']+)["\']', pep621_match.group(1)):
                name = re.split(r"[<>=!~;\[\s]", spec, maxsplit=1)[0].strip()
                if name:
                    dependencies.append((name, pyproject_file))
        # Poetry: [tool.poetry.dependencies] table, one "name = ..." per line.
        in_poetry_section = False
        for line in text.splitlines():
            stripped_line = line.strip()
            if stripped_line.startswith("["):
                in_poetry_section = stripped_line == "[tool.poetry.dependencies]"
                continue
            if in_poetry_section and "=" in stripped_line and not stripped_line.startswith("#"):
                name = stripped_line.split("=", 1)[0].strip().strip('"\'')
                if name and name != "python":
                    dependencies.append((name, pyproject_file))
    for pipfile in find_files(root, names={"Pipfile"}):
        text = read_text(pipfile)
        in_packages_section = False
        for line in text.splitlines():
            stripped_line = line.strip()
            if stripped_line.startswith("["):
                in_packages_section = stripped_line in ("[packages]", "[dev-packages]")
                continue
            if in_packages_section and "=" in stripped_line and not stripped_line.startswith("#"):
                name = stripped_line.split("=", 1)[0].strip().strip('"\'')
                if name:
                    dependencies.append((name, pipfile))
    return dependencies


def list_go_deps(root):
    """Returns (module_path, manifest_path) pairs from go.mod's require
    directives, both the single-line and parenthesized-block forms."""
    dependencies = []
    for go_mod_file in find_files(root, names={"go.mod"}):
        text = read_text(go_mod_file)
        in_require_block = False
        for line in text.splitlines():
            stripped_line = line.strip()
            if stripped_line.startswith("require ("):
                in_require_block = True
                continue
            if in_require_block:
                if stripped_line == ")":
                    in_require_block = False
                    continue
                match = re.match(r"^(\S+)\s+v\S+", stripped_line)
                if match:
                    dependencies.append((match.group(1), go_mod_file))
                continue
            match = re.match(r"^require\s+(\S+)\s+v\S+", stripped_line)
            if match:
                dependencies.append((match.group(1), go_mod_file))
    return dependencies


def list_java_deps(root):
    """Returns (matching_prefix, manifest, display_name) triples.

    matching_prefix is the Maven groupId: Java import statements
    conventionally start with the groupId (e.g. groupId
    "org.springframework" -> imports "org.springframework.*"), so that's
    what usage matching keys off, not the artifactId. Gradle dependency
    strings ("group:artifact:version") give us both parts directly.
    """
    dependencies = []
    for pom_file in find_files(root, names={"pom.xml"}):
        text = read_text(pom_file)
        for match in re.finditer(
                r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>", text):
            group_id, artifact_id = match.group(1), match.group(2)
            dependencies.append((group_id, pom_file, f"{group_id}:{artifact_id}"))
    for gradle_file in find_files(root, names={"build.gradle", "build.gradle.kts"}):
        text = read_text(gradle_file)
        for match in re.finditer(r"[\'\"]([\w.\-]+):([\w.\-]+):[\w.\-\[\],+]+[\'\"]", text):
            group_id, artifact_id = match.group(1), match.group(2)
            dependencies.append((group_id, gradle_file, f"{group_id}:{artifact_id}"))
    return dependencies


def list_ruby_deps(root):
    """Returns (gem_name, manifest_path) pairs from `gem "..."` lines in
    the Gemfile."""
    dependencies = []
    for gemfile in find_files(root, names={"Gemfile"}):
        for match in re.finditer(r"^\s*gem\s+['\"]([^'\"]+)['\"]", read_text(gemfile), re.MULTILINE):
            dependencies.append((match.group(1), gemfile))
    return dependencies


def list_php_deps(root):
    """Returns ("vendor/package", manifest_path) pairs from composer.json's
    require and require-dev sections, skipping the "php" pseudo-package."""
    dependencies = []
    for composer_json_file in find_files(root, names={"composer.json"}):
        data = read_json(composer_json_file)
        if not isinstance(data, dict):
            continue
        for key in ("require", "require-dev"):
            for name in (data.get(key) or {}):
                if name != "php" and "/" in name:
                    dependencies.append((name, composer_json_file))
    return dependencies


def list_rust_deps(root):
    """Returns (crate_name, manifest_path) pairs from the
    [dependencies]/[dev-dependencies]/[build-dependencies] tables in
    Cargo.toml."""
    dependencies = []
    for cargo_toml_file in find_files(root, names={"Cargo.toml"}):
        text = read_text(cargo_toml_file)
        in_deps_section = False
        for line in text.splitlines():
            stripped_line = line.strip()
            if stripped_line.startswith("["):
                in_deps_section = stripped_line in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]")
                continue
            if in_deps_section and "=" in stripped_line and not stripped_line.startswith("#"):
                name = stripped_line.split("=", 1)[0].strip().strip('"\'')
                if name:
                    dependencies.append((name, cargo_toml_file))
    return dependencies


def list_dotnet_deps(root):
    """Returns (package_id, manifest_path) pairs from <PackageReference>
    tags across every .csproj file."""
    dependencies = []
    for csproj_file in find_files(root, suffixes=(".csproj",)):
        for match in re.finditer(r'<PackageReference\s+Include="([^"]+)"', read_text(csproj_file)):
            dependencies.append((match.group(1), csproj_file))
    return dependencies


def list_dart_deps(root):
    """Returns (package_name, manifest_path) pairs from the top-level
    `dependencies:` block in pubspec.yaml."""
    dependencies = []
    for pubspec_file in find_files(root, names={"pubspec.yaml"}):
        text = read_text(pubspec_file)
        in_deps_section = False
        for line in text.splitlines():
            if re.match(r"^dependencies:\s*$", line):
                in_deps_section = True
                continue
            if in_deps_section:
                if re.match(r"^\S", line):
                    in_deps_section = False
                    continue
                match = re.match(r"^  (\S[^:]*):", line)
                if match:
                    dependencies.append((match.group(1), pubspec_file))
    return dependencies


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
    """Matches ES `import` (default/namespace/named) and CommonJS
    `require()` forms, in that order. Returns (module_path, bound_names)."""
    match = re.match(r"^\s*import\s+(\w+)\s*,?\s*from\s+['\"]([^'\"]+)['\"]", line)
    if match:
        return match.group(2), [match.group(1)]
    match = re.match(r"^\s*import\s+\*\s+as\s+(\w+)\s+from\s+['\"]([^'\"]+)['\"]", line)
    if match:
        return match.group(2), [match.group(1)]
    match = re.match(r"^\s*import\s+\{([^}]+)\}\s+from\s+['\"]([^'\"]+)['\"]", line)
    if match:
        bound_names = []
        for part in match.group(1).split(","):
            part = part.strip()
            if not part:
                continue
            # "foo as bar" -> the local binding is "bar", not "foo".
            bound_names.append(part.split(" as ")[-1].strip())
        return match.group(2), bound_names
    match = re.match(r"^\s*(?:const|let|var)\s+\{([^}]+)\}\s*=\s*require\(['\"]([^'\"]+)['\"]\)", line)
    if match:
        bound_names = [p.strip().split(":")[-1].strip() for p in match.group(1).split(",") if p.strip()]
        return match.group(2), bound_names
    match = re.match(r"^\s*(?:const|let|var)\s+(\w+)\s*=\s*require\(['\"]([^'\"]+)['\"]\)", line)
    if match:
        return match.group(2), [match.group(1)]
    # Side-effect-only import/require, e.g. `import 'polyfill';`. No bound
    # name to look for elsewhere, but it still counts as a files_importing hit.
    match = re.match(r"^\s*import\s+['\"]([^'\"]+)['\"]", line) or \
        re.match(r"^\s*require\(['\"]([^'\"]+)['\"]\)", line)
    if match:
        return match.group(1), []
    return None


def extract_python(line):
    """Matches `from module import a, b` and `import module [as alias]`.
    Returns (top_level_module, bound_names)."""
    match = re.match(r"^\s*from\s+([\w.]+)\s+import\s+(.+)", line)
    if match:
        module = match.group(1).split(".")[0]
        bound_names = []
        for part in match.group(2).split(","):
            part = part.strip().strip("()")
            if not part:
                continue
            bound_names.append(part.split(" as ")[-1].strip())
        return module, bound_names
    match = re.match(r"^\s*import\s+([\w.]+)(?:\s+as\s+(\w+))?", line)
    if match:
        module = match.group(1).split(".")[0]
        bound_name = match.group(2) or module
        return module, [bound_name]
    return None


def extract_go(line):
    """Matches a Go import path, aliased or not. Returns (import_path,
    bound_names).

    Two shapes to handle: a single-line `import "path"` (the "import"
    keyword sits on the same line as the path), and a bare `"path"` line
    inside a parenthesized `import (...)` block (no "import" keyword at
    all there, just an optional alias). Trying the bare-quote pattern
    first would misparse "import" itself as the alias in the single-line
    form, so the "import"-prefixed pattern has to be tried first.
    """
    match = re.match(r'^\s*import\s+(?:(\w+)\s+)?"([^"]+)"\s*$', line)
    if not match:
        match = re.match(r'^\s*(?:(\w+)\s+)?"([^"]+)"\s*$', line)
    if match:
        alias, path = match.group(1), match.group(2)
        bound_name = alias or path.rstrip("/").split("/")[-1]
        return path, [bound_name]
    return None


def extract_java(line):
    """Matches `import [static] a.b.Class;` (wildcard imports too).
    Returns (dotted_path, bound_names)."""
    match = re.match(r"^\s*import\s+(?:static\s+)?([\w.]+)(\.\*)?;", line)
    if match:
        dotted_path = match.group(1)
        bound_name = dotted_path.split(".")[-1]
        return dotted_path, [bound_name]
    return None


def extract_rust(line):
    """Matches `use crate::path::Symbol;`. Returns (crate_name,
    bound_names)."""
    match = re.match(r"^\s*use\s+([\w:]+)(?:::\{[^}]*\})?(?:::(\w+))?", line)
    if match:
        crate_name = match.group(1).split("::")[0]
        bound_name = match.group(2) or crate_name
        return crate_name, [bound_name]
    return None


def extract_dotnet(line):
    """Matches `using Namespace.Sub;`. Returns (dotted_namespace,
    bound_names)."""
    match = re.match(r"^\s*using\s+([\w.]+)\s*;", line)
    if match:
        dotted_namespace = match.group(1)
        return dotted_namespace, [dotted_namespace.split(".")[-1]]
    return None


def extract_dart(line):
    """Matches `import 'package:name/path.dart' [as alias];`. Returns
    (package_name, bound_names)."""
    match = re.match(r"^\s*import\s+['\"]package:([\w.\-]+)/[^'\"]*['\"](?:\s+as\s+(\w+))?", line)
    if match:
        package_name = match.group(1)
        bound_name = match.group(2) or package_name.replace("-", "_")
        return package_name, [bound_name]
    return None


def extract_weak(pattern):
    """Wraps a simple require/use regex for the WEAK_ECOSYSTEMS, where no
    real bound symbol name can be recovered, only the fact of the import."""
    def match_line(line):
        match = pattern.match(line)
        if match:
            return match.group(1), []
        return None
    return match_line


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
    """Does an import's module_key (from an EXTRACTORS function) refer to
    dep_name (a name from a LIST_DEPS function)? Ecosystem-specific because
    every language resolves an import string to a package name differently."""
    if ecosystem == "npm":
        # Scoped packages ("@scope/pkg/sub/path") match on the first two
        # path segments; unscoped packages match on the first segment only.
        if module_key.startswith("@"):
            parts = module_key.split("/")
            module_key = "/".join(parts[:2]) if len(parts) > 1 else module_key
        else:
            module_key = module_key.split("/")[0]
        return module_key == dep_name
    if ecosystem == "python":
        # PyPI package names and importable module names sometimes differ
        # only by hyphen-vs-underscore (a real name-vs-import mismatch, e.g.
        # beautifulsoup4/bs4, isn't recoverable from text alone).
        return module_key == dep_name or module_key.replace("-", "_") == dep_name.replace("-", "_")
    if ecosystem == "go":
        return module_key == dep_name
    if ecosystem == "java":
        # dep_match_key is the groupId (see list_java_deps); an import
        # matches if it's exactly that groupId or a sub-package of it.
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
        # PHP namespaces are PSR-4-mapped by the package author and aren't
        # derivable from the composer "vendor/package" name in general.
        # This guesses the common convention (CamelCase each segment) and
        # will miss packages that don't follow it, that's the tradeoff for
        # getting any signal at all out of a static regex sweep.
        vendor, _, package = dep_name.partition("/")
        guessed_namespace = "".join(p.capitalize() for p in re.split(r"[-_]", vendor)) + "\\" + \
            "".join(p.capitalize() for p in re.split(r"[-_]", package))
        return module_key.startswith(guessed_namespace.split("\\")[0])
    return False


def usage_tier(files_importing, call_site_count):
    """Heuristic cutoffs, not a precise measurement, see SKILL.md Step 1
    for the caveats. Keep these in sync with the thresholds documented
    there if they ever change."""
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


def scan_usage_for_ecosystem(root, ecosystem, dependency_entries):
    """dependency_entries: list of (name, manifest_file) pairs, or
    (matching_key, manifest_file, display_name) triples for java."""
    if not dependency_entries:
        return []
    extensions = SOURCE_EXTENSIONS[ecosystem]
    extract_from_line = EXTRACTORS[ecosystem]
    weak_signal = ecosystem in WEAK_ECOSYSTEMS

    if ecosystem == "java":
        # Java lists (matching_prefix=groupId, manifest, display_name); dedupe
        # by display name since the same artifact can appear in more than
        # one manifest (a multi-module pom, both pom.xml and build.gradle).
        java_dep_by_display_name = {}
        for match_key, manifest, display_name in dependency_entries:
            java_dep_by_display_name.setdefault(display_name, {"match_key": match_key, "manifest": manifest})
        dependency_index = [
            (display_name, v["match_key"], v["manifest"])
            for display_name, v in java_dep_by_display_name.items()
        ]
    else:
        dependency_names = sorted({name for name, _manifest in dependency_entries})
        dependency_index = [(name, None, None) for name in dependency_names]

    usage_by_name = {
        name: {"files_importing": 0, "call_site_count": 0, "symbols": set()}
        for name, _match_key, _manifest in dependency_index
    }

    for path in find_files(root, suffixes=extensions):
        text = read_text(path)
        if not text:
            continue
        lines = text.splitlines()
        hits_in_file = {}
        for line_index, line in enumerate(lines):
            extracted = extract_from_line(line)
            if not extracted:
                continue
            module_key, bound_names = extracted
            for name, match_key, _manifest in dependency_index:
                if module_matches(ecosystem, module_key, name, match_key):
                    hits_in_file.setdefault(name, {"bound": set(), "import_lines": set()})
                    hits_in_file[name]["bound"].update(bound_names)
                    hits_in_file[name]["import_lines"].add(line_index)

        if not hits_in_file:
            continue
        file_body = "\n".join(lines)
        for name, hit_info in hits_in_file.items():
            usage_by_name[name]["files_importing"] += 1
            usage_by_name[name]["symbols"].update(hit_info["bound"])
            if weak_signal or not hit_info["bound"]:
                # No real symbol to search for (weak ecosystem, or a
                # side-effect-only import): fall back to counting the
                # import statements themselves.
                usage_by_name[name]["call_site_count"] += len(hit_info["import_lines"])
                continue
            symbol_call_sites = 0
            for symbol in hit_info["bound"]:
                if not symbol or not re.match(r"^\w+$", symbol):
                    continue
                # Count every whole-word occurrence of the bound symbol in
                # the file, then subtract one per import line to exclude
                # the symbol's own appearance in the import statement.
                # This is an approximation, not an exact call-site count:
                # it can overcount when the symbol name also shows up
                # inside the import path/module string itself (e.g. a
                # package named the same as its own path segment), and it
                # can't distinguish a real call from an unrelated variable
                # that happens to share the name. See SKILL.md's usage
                # caveats.
                raw_matches = len(re.findall(r"\b" + re.escape(symbol) + r"\b", file_body))
                symbol_call_sites += raw_matches - len(hit_info["import_lines"])
            usage_by_name[name]["call_site_count"] += max(symbol_call_sites, 0)

    results = []
    for name, usage in usage_by_name.items():
        # call_site_count only means something once we've actually seen a
        # bound symbol to search for; weak-signal ecosystems always report
        # their (import-count-only) total instead.
        call_site_count = usage["call_site_count"] if (usage["symbols"] or weak_signal) else None
        results.append({
            "name": name,
            "files_importing": usage["files_importing"],
            "call_site_count": call_site_count,
            "distinct_symbols_used": sorted(usage["symbols"]) if usage["symbols"] else [],
            "usage_tier": usage_tier(usage["files_importing"], call_site_count)
            if usage["files_importing"] else "unused",
            "usage_signal": "weak" if weak_signal else "standard",
        })
    return sorted(results, key=lambda d: d["name"])


def run_usage(root):
    """Runs every ecosystem's LIST_DEPS lister, then scan_usage_for_ecosystem()
    on whatever it finds. Returns {ecosystem: [usage entry, ...]}, omitting
    any ecosystem with no dependencies at all."""
    usage_by_ecosystem = {}
    for ecosystem, list_deps in LIST_DEPS.items():
        dependencies = list_deps(root)
        if not dependencies:
            continue
        usage_by_ecosystem[ecosystem] = scan_usage_for_ecosystem(root, ecosystem, dependencies)
    return usage_by_ecosystem


# --- pinned-version resolution (needed to scope OSV queries correctly) -----
# Without a version, an OSV lookup returns every vulnerability ever
# reported against the package, not just ones affecting what's actually
# installed. Best-effort per ecosystem; None means "couldn't resolve,"
# not "no version." None of these are real lockfile parsers, they're
# regex/JSON-key lookups scoped to exactly the fields needed here.

def resolve_version_npm(root, name):
    """Resolved version from package-lock.json, handling both the v2/v3
    (flat "packages" map) and v1 (nested "dependencies" map) shapes."""
    for lockfile in find_files(root, names={"package-lock.json"}):
        lock_data = read_json(lockfile)
        if not isinstance(lock_data, dict):
            continue
        # npm lockfile v2/v3 shape: flat "packages" map keyed by node_modules path.
        packages = lock_data.get("packages")
        if isinstance(packages, dict):
            entry = packages.get(f"node_modules/{name}")
            if isinstance(entry, dict) and entry.get("version"):
                return entry["version"]
        # npm lockfile v1 shape: nested "dependencies" map keyed by name.
        legacy_deps = lock_data.get("dependencies")
        if isinstance(legacy_deps, dict) and isinstance(legacy_deps.get(name), dict):
            version = legacy_deps[name].get("version")
            if version:
                return version
    return None


def resolve_version_python(root, name):
    """Resolved version from a pinned requirements.txt line, poetry.lock,
    or Pipfile.lock, tried in that order, first match wins."""
    for requirements_file in find_files(root, suffixes=("requirements.txt",)):
        for line in read_text(requirements_file).splitlines():
            match = re.match(r"^\s*" + re.escape(name) + r"\s*==\s*(\S+)", line, re.IGNORECASE)
            if match:
                return match.group(1)
    for lockfile in find_files(root, names={"poetry.lock"}):
        text = read_text(lockfile)
        # poetry.lock is TOML, but a full parser is overkill for pulling
        # two fields: split into [[package]] blocks and regex each one.
        for block in re.split(r"^\[\[package\]\]\s*$", text, flags=re.MULTILINE):
            name_match = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
            version_match = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
            if name_match and version_match and name_match.group(1).lower() == name.lower():
                return version_match.group(1)
    for lockfile in find_files(root, names={"Pipfile.lock"}):
        lock_data = read_json(lockfile)
        if isinstance(lock_data, dict):
            for section in ("default", "develop"):
                entry = (lock_data.get(section) or {}).get(name)
                if isinstance(entry, dict) and entry.get("version"):
                    return entry["version"].lstrip("=")
    return None


def resolve_version_go(root, name):
    """Resolved version straight from go.mod's require line, Go pins the
    version right there, no separate lockfile lookup needed."""
    for go_mod_file in find_files(root, names={"go.mod"}):
        for line in read_text(go_mod_file).splitlines():
            match = re.match(r"^\s*" + re.escape(name) + r"\s+(v\S+)", line.strip())
            if match:
                return match.group(1)
    return None


def resolve_version_rust(root, name):
    """Resolved version from the matching [[package]] block in Cargo.lock."""
    for lockfile in find_files(root, names={"Cargo.lock"}):
        text = read_text(lockfile)
        for block in re.split(r"^\[\[package\]\]\s*$", text, flags=re.MULTILINE):
            name_match = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
            version_match = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
            if name_match and version_match and name_match.group(1) == name:
                return version_match.group(1)
    return None


def resolve_version_ruby(root, name):
    """Resolved version from the gem's line in Gemfile.lock's specs:
    block, e.g. "    rails (7.0.0)"."""
    for lockfile in find_files(root, names={"Gemfile.lock"}):
        match = re.search(r"^\s{4}" + re.escape(name) + r"\s+\(([^)]+)\)", read_text(lockfile), re.MULTILINE)
        if match:
            return match.group(1)
    return None


def resolve_version_php(root, name):
    """Resolved version from the matching entry in composer.lock's
    packages/packages-dev arrays."""
    for lockfile in find_files(root, names={"composer.lock"}):
        lock_data = read_json(lockfile)
        if not isinstance(lock_data, dict):
            continue
        for section in ("packages", "packages-dev"):
            for package_entry in (lock_data.get(section) or []):
                if isinstance(package_entry, dict) and package_entry.get("name") == name \
                        and package_entry.get("version"):
                    return package_entry["version"]
    return None


def resolve_version_dart(root, name):
    """Resolved version from the package's block in pubspec.lock."""
    for lockfile in find_files(root, names={"pubspec.lock"}):
        lines = read_text(lockfile).splitlines()
        for line_index, line in enumerate(lines):
            if re.match(r"^  " + re.escape(name) + r":\s*$", line):
                # Version lives a few lines below the package name, inside
                # its block; stop looking once we hit the next top-level entry.
                for lookahead_index in range(line_index + 1, min(line_index + 8, len(lines))):
                    match = re.match(r'^\s+version:\s*"([^"]+)"', lines[lookahead_index])
                    if match:
                        return match.group(1)
                    if re.match(r"^  \S", lines[lookahead_index]):
                        break
    return None


def resolve_version_java(root, group_artifact):
    """Resolved/declared version for a "group:artifact" pair, from an
    explicit <version> tag in pom.xml or the version segment of a Gradle
    "group:artifact:version" dependency string."""
    group_id, _, artifact_id = group_artifact.partition(":")
    for pom_file in find_files(root, names={"pom.xml"}):
        text = read_text(pom_file)
        match = re.search(
            r"<dependency>\s*<groupId>" + re.escape(group_id) + r"</groupId>\s*<artifactId>" +
            re.escape(artifact_id) + r"</artifactId>\s*<version>([^<]+)</version>", text)
        if match:
            return match.group(1)
    for gradle_file in find_files(root, names={"build.gradle", "build.gradle.kts"}):
        match = re.search(
            r"[\'\"]" + re.escape(group_id) + r":" + re.escape(artifact_id) + r":([\w.\-]+)[\'\"]",
            read_text(gradle_file))
        if match:
            return match.group(1)
    return None


def resolve_version_dotnet(root, name):
    """Declared version from the matching <PackageReference>'s Version
    attribute in a .csproj file (no NuGet lockfile to prefer over it)."""
    for csproj_file in find_files(root, suffixes=(".csproj",)):
        match = re.search(
            r'<PackageReference\s+Include="' + re.escape(name) + r'"\s+Version="([^"]+)"',
            read_text(csproj_file))
        if match:
            return match.group(1)
    return None


RESOLVE_VERSION = {
    "npm": resolve_version_npm, "python": resolve_version_python, "go": resolve_version_go,
    "rust": resolve_version_rust, "ruby": resolve_version_ruby, "php": resolve_version_php,
    "dart": resolve_version_dart, "java": resolve_version_java, "dotnet": resolve_version_dotnet,
}


def resolve_version(root, ecosystem, name):
    """Dispatches to the right resolve_version_* function for ecosystem.
    Returns None for an unsupported ecosystem or any parse failure."""
    resolver = RESOLVE_VERSION.get(ecosystem)
    if not resolver:
        return None
    try:
        return resolver(root, name)
    except (OSError, re.error):
        return None


# --- health mode: live registry lookups ---------------------------------

def http_json(url, method="GET", data=None, headers=None, timeout=10):
    """Stdlib-only HTTP JSON helper, no `requests` dependency. Returns None
    on any network/parse failure rather than raising, every caller in this
    file treats a failed lookup as "field unavailable," not a crash."""
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    request_headers.update(headers or {})
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, TimeoutError):
        return None


OSV_ECOSYSTEM = {
    "npm": "npm", "python": "PyPI", "go": "Go", "rust": "crates.io",
    "ruby": "RubyGems", "php": "Packagist", "java": "Maven", "dotnet": "NuGet",
    "dart": "Pub",
}


def check_osv(ecosystem, name, version=None):
    """Queries OSV.dev for known vulnerabilities. Without a version, OSV
    returns the package's entire historical advisory list, not just ones
    affecting what's actually pinned, so the result is marked
    version_scoped accordingly and health_tier() only lets a scoped match
    force the "at risk" tier."""
    osv_ecosystem = OSV_ECOSYSTEM.get(ecosystem)
    if not osv_ecosystem:
        return {"status": "unavailable", "vulnerabilities": [], "version_scoped": False}
    package = {"name": name, "ecosystem": osv_ecosystem}
    query = {"version": version, "package": package} if version else {"package": package}
    response_data = http_json("https://api.osv.dev/v1/query", method="POST", data=query)
    if response_data is None:
        return {"status": "unknown", "vulnerabilities": [], "version_scoped": bool(version)}
    vulnerability_ids = [v.get("id") for v in (response_data.get("vulns") or [])]
    return {"status": "ok", "vulnerabilities": vulnerability_ids, "version_scoped": bool(version)}


def health_npm(name):
    """Latest publish time and maintainer count from the npm registry
    metadata endpoint, plus last-month downloads from npm's stats API."""
    registry_data = http_json(f"https://registry.npmjs.org/{name}")
    downloads_data = http_json(f"https://api.npmjs.org/downloads/point/last-month/{name}")
    if registry_data is None:
        return {"recency": None, "maintainers": None, "downloads": None}
    latest_version = (registry_data.get("dist-tags") or {}).get("latest")
    publish_times = registry_data.get("time") or {}
    return {
        "recency": publish_times.get(latest_version),
        "maintainers": len(registry_data.get("maintainers") or []),
        "downloads": (downloads_data or {}).get("downloads"),
    }


def health_python(name):
    """Latest release upload time from PyPI's JSON API (no maintainer
    count, PyPI's API doesn't expose one), plus last-month downloads from
    pypistats.org."""
    registry_data = http_json(f"https://pypi.org/pypi/{name}/json")
    if registry_data is None:
        return {"recency": None, "maintainers": "n/a", "downloads": None}
    releases = registry_data.get("releases") or {}
    latest_version = (registry_data.get("info") or {}).get("version")
    upload_time = None
    for release_file in (releases.get(latest_version) or []):
        upload_time = release_file.get("upload_time_iso_8601") or release_file.get("upload_time")
        break
    # PyPI's own API stopped exposing download counts years ago; pypistats.org
    # is a third-party service that fills that gap, best-effort.
    downloads_data = http_json(f"https://pypistats.org/api/packages/{name}/recent")
    downloads = None
    if downloads_data:
        downloads = (downloads_data.get("data") or {}).get("last_month")
    return {"recency": upload_time, "maintainers": "n/a", "downloads": downloads}


def health_go(name):
    """Latest version's publish time from Go's official module proxy.
    No maintainer count or download volume, neither concept exists for
    Go modules."""
    module_path = name.lower()
    registry_data = http_json(f"https://proxy.golang.org/{module_path}/@latest")
    if registry_data is None:
        return {"recency": None, "maintainers": "n/a", "downloads": "n/a"}
    return {"recency": registry_data.get("Time"), "maintainers": "n/a", "downloads": "n/a"}


def health_rust(name):
    """Last-updated time and download count from crates.io's crate
    endpoint, plus owner count from its separate owners endpoint."""
    registry_data = http_json(f"https://crates.io/api/v1/crates/{name}")
    if registry_data is None:
        return {"recency": None, "maintainers": None, "downloads": None}
    crate = registry_data.get("crate") or {}
    owners_data = http_json(f"https://crates.io/api/v1/crates/{name}/owners")
    maintainer_count = len((owners_data or {}).get("users") or []) if owners_data else None
    return {
        "recency": crate.get("updated_at"),
        "maintainers": maintainer_count,
        "downloads": crate.get("downloads"),
    }


def health_ruby(name):
    """Version-created time and download count from RubyGems' gem
    endpoint. "maintainers" is really the free-text `authors` field, not
    a real count, labeled as such."""
    registry_data = http_json(f"https://rubygems.org/api/v1/gems/{name}.json")
    if registry_data is None:
        return {"recency": None, "maintainers": "n/a (authors string, not a count)", "downloads": None}
    return {
        "recency": registry_data.get("version_created_at"),
        "maintainers": registry_data.get("authors", "n/a"),
        "downloads": registry_data.get("downloads"),
    }


def health_php(vendor_pkg):
    """Latest version's publish time from Packagist's v2 metadata
    endpoint, plus maintainer count from its separate package-info
    endpoint. No download volume, Packagist doesn't expose one."""
    registry_data = http_json(f"https://repo.packagist.org/p2/{vendor_pkg}.json")
    if registry_data is None:
        return {"recency": None, "maintainers": None, "downloads": "n/a"}
    versions = ((registry_data.get("packages") or {}).get(vendor_pkg) or [])
    recency = versions[0].get("time") if versions else None
    maintainers_data = http_json(f"https://packagist.org/packages/{vendor_pkg}.json")
    maintainer_count = None
    if maintainers_data:
        maintainer_count = len((maintainers_data.get("package") or {}).get("maintainers") or [])
    return {"recency": recency, "maintainers": maintainer_count, "downloads": "n/a"}


def health_java(group_artifact):
    """Latest version's index timestamp from the Maven Central search API.
    No maintainer count or download volume, Maven Central exposes neither."""
    group_id, _, artifact_id = group_artifact.partition(":")
    query = f"g:{group_id}+AND+a:{artifact_id}" if artifact_id else f"a:{group_id}"
    registry_data = http_json(f"https://search.maven.org/solrsearch/select?q={query}&core=gav&rows=1&wt=json")
    if not registry_data:
        return {"recency": None, "maintainers": "n/a", "downloads": "n/a"}
    docs = ((registry_data.get("response") or {}).get("docs") or [])
    recency = docs[0].get("timestamp") if docs else None
    return {"recency": recency, "maintainers": "n/a", "downloads": "n/a"}


def health_dotnet(name):
    """Latest catalog entry's publish time from NuGet's registration API.
    No maintainer count or download volume, parsing those out of this API
    reliably isn't worth the guesswork."""
    registry_data = http_json(f"https://api.nuget.org/v3/registration5-semver1/{name.lower()}/index.json")
    if not registry_data:
        return {"recency": None, "maintainers": "n/a", "downloads": "n/a"}
    try:
        version_pages = registry_data.get("items") or []
        latest_page = version_pages[-1]
        catalog_items = latest_page.get("items") or []
        recency = catalog_items[-1]["catalogEntry"]["published"] if catalog_items else None
    except (IndexError, KeyError, TypeError):
        recency = None
    return {"recency": recency, "maintainers": "n/a", "downloads": "n/a"}


def health_dart(name):
    """Latest version's publish time and publisher (a single identity, not
    a maintainer count) from pub.dev's package API. No download volume,
    pub.dev doesn't expose one."""
    registry_data = http_json(f"https://pub.dev/api/packages/{name}")
    if not registry_data:
        return {"recency": None, "maintainers": "n/a", "downloads": "n/a"}
    return {
        "recency": (registry_data.get("latest") or {}).get("published"),
        "maintainers": registry_data.get("publisher") or "n/a",
        "downloads": "n/a",
    }


HEALTH_FN = {
    "npm": health_npm, "python": health_python, "go": health_go,
    "rust": health_rust, "ruby": health_ruby, "php": health_php,
    "java": health_java, "dotnet": health_dotnet, "dart": health_dart,
}


def health_tier(recency, maintainers, downloads, vuln_status):
    """Combines the raw health fields into one of healthy/slowing/at_risk/
    unknown, per the thresholds in references/registry-health-signals.md.
    Any field that isn't a real number (an "n/a" string, a missing value)
    is treated as not present, not as zero."""
    # A known vulnerability in the version actually pinned overrides every
    # other signal, however healthy the project otherwise looks. An
    # *unscoped* result (couldn't resolve the pinned version) doesn't get
    # this power, see check_osv()'s docstring for why.
    if vuln_status.get("vulnerabilities") and vuln_status.get("version_scoped"):
        return "at_risk"

    def months_since(iso_timestamp):
        if not iso_timestamp:
            return None
        try:
            from datetime import datetime, timezone
            normalized = iso_timestamp.replace("Z", "+00:00")
            published_at = datetime.fromisoformat(normalized)
            if published_at.tzinfo is None:
                published_at = published_at.replace(tzinfo=timezone.utc)
            age = datetime.now(timezone.utc) - published_at
            return age.days / 30.0
        except (ValueError, TypeError):
            return None

    months_since_release = months_since(recency) if isinstance(recency, str) else None
    maintainer_count = maintainers if isinstance(maintainers, int) else None
    download_count = downloads if isinstance(downloads, int) else None

    if months_since_release is None and maintainer_count is None and download_count is None:
        return "unknown"

    if months_since_release is not None and months_since_release > 12:
        return "at_risk"
    if maintainer_count is not None and maintainer_count == 0:
        return "at_risk"

    if months_since_release is not None and months_since_release < 3 and (
            maintainer_count is None or maintainer_count >= 2 or
            (download_count is not None and download_count >= 10000)):
        return "healthy"

    return "slowing"


def run_health(ecosystem, names, root=None):
    """For each name: looks up registry health data, resolves its pinned
    version from root's lockfile (if root is given), checks OSV for
    vulnerabilities in that version, and computes a health tier. Returns
    {name: {...}}."""
    health_lookup = HEALTH_FN.get(ecosystem)
    results = {}
    for name in names:
        registry_data = health_lookup(name) if health_lookup else \
            {"recency": None, "maintainers": "n/a", "downloads": "n/a"}
        pinned_version = resolve_version(root, ecosystem, name) if root else None
        vulnerability_info = check_osv(ecosystem, name, pinned_version)
        results[name] = {
            "pinned_version": pinned_version,
            "recency": registry_data.get("recency"),
            "maintainers": registry_data.get("maintainers"),
            "downloads": registry_data.get("downloads"),
            "vulnerabilities": vulnerability_info,
            "health_tier": health_tier(registry_data.get("recency"), registry_data.get("maintainers"),
                                        registry_data.get("downloads"), vulnerability_info),
        }
    return results


# --- main ------------------------------------------------------------------

def main():
    """CLI entry point, dispatches to run_usage() or run_health() based on
    sys.argv[1], see the module docstring for the full argument shapes."""
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
