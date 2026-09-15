#!/usr/bin/env python3
# ******************************************************************************
# * TITLE:        Dead Weight Detector
# * FILE:         dead_weight_scan.py
# * PART OF:      dead-weight-detector skill (skill-sec-arcade repo).
# *               Reuses cartridge_scan.py's manifest-discovery helpers
# *               (walk, find_files, read_text, read_json,
# *               install_requires_from_setup_py/_cfg) and cross-references
# *               abandoned_packages.py's curated list.
# * PURPOSE:      Answers two different questions about a repo's
# *               dependencies: (1) is a dependency actually used in the
# *               code, and how much ("usage" mode), and (2) is a specific,
# *               already-suspect dependency healthy upstream ("health"
# *               mode: is it still maintained, does it have known
# *               vulnerabilities, is it a known-abandoned package)? It
# *               exists to help someone decide which dependencies are
# *               safe to remove or worth replacing.
# *
# * HOW IT WORKS: Two independent modes, chosen by the first CLI argument:
# *               1) `usage <path>`: local only, no network. Lists every
# *                  direct dependency per ecosystem, then sweeps
# *                  first-party source files for import/require
# *                  statements, matching each import back to a
# *                  dependency name and computing a rough usage tier
# *                  (unused/minimal/light/moderate/heavy).
# *               2) `health <ecosystem> <repo_path> <name> [<name> ...]`:
# *                  live network calls. For each given package name:
# *                  resolves its pinned version from the local lockfile,
# *                  queries that ecosystem's public registry API for
# *                  release recency/maintainer count/downloads/
# *                  deprecation, queries OSV.dev (a cross-ecosystem
# *                  vulnerability database) for known vulnerabilities in
# *                  that pinned version, checks the curated
# *                  abandoned-package list, then combines all of that
# *                  into one health tier (healthy/slowing/at_risk/unknown).
# *               Both modes print one JSON object to stdout.
# *
# * USAGE:        python3 dead_weight_scan.py usage /home/user/my-repo
# *               python3 dead_weight_scan.py health python /home/user/my-repo requests flask
# * ARGUMENTS:    mode (positional, str, required) - "usage" or "health".
# *               usage mode: path (positional, str, optional, default ".").
# *               health mode: ecosystem (positional, str, required, e.g.
# *                 "python"); repo_path (positional, str, required, used
# *                 only to resolve pinned versions); name... (positional,
# *                 str, one or more, required) - package names to check.
# * INPUTS:       usage mode: the repo filesystem only, no network.
# *               health mode: repo_path's lockfiles (local, for version
# *                 resolution only) plus live HTTPS calls to each
# *                 ecosystem's public registry API and to OSV.dev.
# * OUTPUTS:      One JSON object printed to stdout per invocation. No
# *               files written, no prose/markdown.
# * EXIT CODES:   0 = success. 1 = missing/invalid CLI arguments, or an
# *               unrecognized mode (see main()'s usage_msg).
# * DEPENDENCIES: Python 3 standard library only (json, os, re, sys,
# *               urllib.error, urllib.request). Imports cartridge_scan.py
# *               and abandoned_packages.py from the same directory, both
# *               also stdlib-only.
# * PERMISSIONS:  usage mode: read-only filesystem access under the scanned
# *               path, no network. health mode: outbound HTTPS access to
# *               each ecosystem's public registry (npm, PyPI, Go module
# *               proxy, crates.io, RubyGems, Packagist, Maven Central,
# *               NuGet, pub.dev) and to OSV.dev; read-only local access to
# *               repo_path for lockfile version resolution.
# * ASSUMPTIONS:  health mode should only ever be called with names that
# *               have already been triaged (e.g. by usage mode, or by a
# *               human) as worth a deep dive, this bounds the number of
# *               outbound network calls; it is not meant to be run over
# *               every dependency in a large project.
# * FAILURE MODES:A registry that's unreachable, times out, or 404s simply
# *               leaves that package's fields as None/"unknown" rather
# *               than crashing the whole run (see http_json()). An
# *               unparseable manifest/lockfile leaves the corresponding
# *               count/version as None. usage mode's call-site counting
# *               is a heuristic (regex-based symbol matching, not a real
# *               parser) and can over- or under-count, see
# *               scan_usage_for_ecosystem()'s docstring.
# * SAFE TO RERUN:Yes. Both modes are read-only with respect to the
# *               scanned repo and produce no side effects; health mode
# *               makes outbound network requests but writes nothing
# *               anywhere and isn't rate-limit-sensitive for the small,
# *               already-triaged name lists it's meant to be called with.
# *
# * AUTHOR:       cameronww7
# * LAST UPDATED: 2026-09-15
# ******************************************************************************

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
from cartridge_scan import (  # noqa: E402
    walk, find_files, read_text, read_json, EXCLUDE_DIRS,
    install_requires_from_setup_py, install_requires_from_setup_cfg,
)
import abandoned_packages  # noqa: E402

# ===== CONFIGURATION =====

# Identifies this tool to registries in the health-check HTTP requests
# below; some registries (npm, PyPI) rate-limit or reject requests with
# no User-Agent at all.
USER_AGENT = "dead-weight-detector/1.0 (github.com/cameronww7/skill-sec-arcade)"

SOURCE_EXTENSIONS = {
    "javascript": (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
    "python": (".py",),
    "go": (".go",),
    "java": (".java",),
    "ruby": (".rb",),
    "php": (".php",),
    "rust": (".rs",),
    "dotnet": (".cs",),
    "dart": (".dart",),
    "cpp": (".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".hh", ".hxx"),
}

# Ruby and PHP can't be matched reliably by static regex: Ruby's `require`
# doesn't bind a symbol name at all (whatever the gem defines just becomes
# globally available), and PHP namespaces are PSR-4-mapped by the package
# author, not derivable from the composer package name. C/C++'s #include
# has the same problem: it doesn't bind a symbol either, and mapping a
# header path to a package name (e.g. #include <fmt/format.h> -> "fmt") is
# a convention, not a registry-enforced rule. For these three we only
# count require/use/#include occurrences, not real call sites, and flag
# the result as a "weak" signal downstream.
WEAK_ECOSYSTEMS = {"ruby", "php", "cpp"}


# ===== DEPENDENCY NAME EXTRACTION =====
# --- dependency name extraction (new logic, not in cartridge_scan.py) ------

# ------------------------------------------------------------------------
# list_javascript_deps
#
# WHAT IT DOES:   Lists every dependency declared in package.json.
# WHY IT EXISTS:  usage mode needs the set of direct dependencies to
#                 search source files for, per ecosystem; this is the
#                 JavaScript-specific lister.
#
# INPUTS:
#   root (str) - repo root to scan.
#
# RETURNS:
#   (list[tuple[str, str]]) - (dependency_name, manifest_path) pairs,
#   covering dependencies, devDependencies, peerDependencies, and
#   optionalDependencies. Empty list if no package.json exists.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      run_usage() via the LIST_DEPS dispatch table.
# CALLS:          find_files(), read_json().
#
# EXAMPLE:
#   list_javascript_deps("/repo")
#   -> [("react", "/repo/package.json"), ("lodash", "/repo/package.json")]
#--------------------------------------------------------------------------
def list_javascript_deps(root):
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
        # Only the first package.json is read, same reasoning as
        # scan_javascript() in cartridge_scan.py: a monorepo can have
        # several, and summing unrelated workspaces together would be
        # misleading rather than helpful.
        break
    return dependencies


# ------------------------------------------------------------------------
# list_python_deps
#
# WHAT IT DOES:   Lists every dependency declared across all of Python's
#                 common manifest formats.
# WHY IT EXISTS:  Python dependencies can be declared in requirements.txt,
#                 pyproject.toml (two different conventions), Pipfile,
#                 setup.py, or setup.cfg; usage mode needs the union of
#                 all of them to know what to search for.
#
# INPUTS:
#   root (str) - repo root to scan.
#
# RETURNS:
#   (list[tuple[str, str]]) - (package_name, manifest_path) pairs, one
#   per declared dependency across every manifest format found. Version
#   specifiers, extras, and environment markers are stripped from the
#   name. Empty list if no Python manifest exists.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      run_usage() via the LIST_DEPS dispatch table.
# CALLS:          find_files(), read_text(), install_requires_from_setup_py(),
#                 install_requires_from_setup_cfg().
#
# EXAMPLE:
#   # requirements.txt contains: requests==2.31.0
#   list_python_deps("/repo")
#   -> [("requests", "/repo/requirements.txt"), ...]
#--------------------------------------------------------------------------
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
    for setup_py_file in find_files(root, names={"setup.py"}):
        for spec in (install_requires_from_setup_py(setup_py_file) or []):
            name = re.split(r"[<>=!~;\[\s]", spec, maxsplit=1)[0].strip()
            if name:
                dependencies.append((name, setup_py_file))
    for setup_cfg_file in find_files(root, names={"setup.cfg"}):
        for spec in (install_requires_from_setup_cfg(setup_cfg_file) or []):
            name = re.split(r"[<>=!~;\[\s]", spec, maxsplit=1)[0].strip()
            if name:
                dependencies.append((name, setup_cfg_file))
    return dependencies


# ------------------------------------------------------------------------
# list_go_deps
#
# WHAT IT DOES:   Lists every module declared in go.mod's require
#                 directives.
# WHY IT EXISTS:  Go-specific dependency lister for usage mode.
#
# INPUTS:
#   root (str) - repo root to scan.
#
# RETURNS:
#   (list[tuple[str, str]]) - (module_path, manifest_path) pairs, from
#   both the single-line `require path vX.Y.Z` form and the parenthesized
#   `require (...)` block form. Empty list if no go.mod exists.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      run_usage() via the LIST_DEPS dispatch table.
# CALLS:          find_files(), read_text().
#
# EXAMPLE:
#   list_go_deps("/repo") -> [("github.com/pkg/errors", "/repo/go.mod")]
#--------------------------------------------------------------------------
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


# ------------------------------------------------------------------------
# list_java_deps
#
# WHAT IT DOES:   Lists every dependency declared in pom.xml, build.gradle
#                 (or .kts), or ivy.xml, keyed by Maven groupId.
# WHY IT EXISTS:  Java import statements conventionally start with the
#                 dependency's groupId (e.g. groupId "org.springframework"
#                 -> imports "org.springframework.*"), not its artifactId,
#                 so usage matching for Java needs the groupId specifically,
#                 not just a package name string the way other ecosystems
#                 do.
#
# INPUTS:
#   root (str) - repo root to scan.
#
# RETURNS:
#   (list[tuple[str, str, str]]) - (matching_prefix, manifest_path,
#   display_name) triples. matching_prefix is the groupId, used by
#   module_matches() to test whether an import belongs to this
#   dependency. display_name is "groupId:artifactId", shown in the report
#   instead of the bare groupId.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      run_usage() via the LIST_DEPS dispatch table.
# CALLS:          find_files(), read_text().
#
# EXAMPLE:
#   list_java_deps("/repo")
#   -> [("org.springframework", "/repo/pom.xml",
#        "org.springframework:spring-core")]
#--------------------------------------------------------------------------
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
    for ivy_file in find_files(root, names={"ivy.xml"}):
        text = read_text(ivy_file)
        # Ivy doesn't guarantee org/name/rev attribute ordering the way
        # positional regex-matching would assume, so each attribute is
        # searched for independently within the tag's attribute blob.
        for tag_match in re.finditer(r"<dependency\b([^>]*)/?>", text):
            attrs = tag_match.group(1)
            org_match = re.search(r'org="([^"]+)"', attrs)
            name_match = re.search(r'name="([^"]+)"', attrs)
            if org_match and name_match:
                org, name = org_match.group(1), name_match.group(1)
                dependencies.append((org, ivy_file, f"{org}:{name}"))
    return dependencies


# ------------------------------------------------------------------------
# list_ruby_deps
#
# WHAT IT DOES:   Lists every gem declared in the Gemfile.
# WHY IT EXISTS:  Ruby-specific dependency lister for usage mode.
#
# INPUTS:
#   root (str) - repo root to scan.
#
# RETURNS:
#   (list[tuple[str, str]]) - (gem_name, manifest_path) pairs. Empty list
#   if no Gemfile exists.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      run_usage() via the LIST_DEPS dispatch table.
# CALLS:          find_files(), read_text().
#
# EXAMPLE:
#   list_ruby_deps("/repo") -> [("rails", "/repo/Gemfile")]
#--------------------------------------------------------------------------
def list_ruby_deps(root):
    """Returns (gem_name, manifest_path) pairs from `gem "..."` lines in
    the Gemfile."""
    dependencies = []
    for gemfile in find_files(root, names={"Gemfile"}):
        for match in re.finditer(r"^\s*gem\s+['\"]([^'\"]+)['\"]", read_text(gemfile), re.MULTILINE):
            dependencies.append((match.group(1), gemfile))
    return dependencies


# ------------------------------------------------------------------------
# list_php_deps
#
# WHAT IT DOES:   Lists every package declared in composer.json's require
#                 sections.
# WHY IT EXISTS:  PHP-specific dependency lister for usage mode.
#
# INPUTS:
#   root (str) - repo root to scan.
#
# RETURNS:
#   (list[tuple[str, str]]) - ("vendor/package", manifest_path) pairs from
#   require and require-dev, skipping the "php" pseudo-package (a required
#   PHP version, not a real dependency) and any entry without a "/" (PHP
#   extension requirements like "ext-curl" aren't installable packages).
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      run_usage() via the LIST_DEPS dispatch table.
# CALLS:          find_files(), read_json().
#
# EXAMPLE:
#   list_php_deps("/repo") -> [("monolog/monolog", "/repo/composer.json")]
#--------------------------------------------------------------------------
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


# ------------------------------------------------------------------------
# list_rust_deps
#
# WHAT IT DOES:   Lists every crate declared in Cargo.toml's dependency
#                 tables.
# WHY IT EXISTS:  Rust-specific dependency lister for usage mode.
#
# INPUTS:
#   root (str) - repo root to scan.
#
# RETURNS:
#   (list[tuple[str, str]]) - (crate_name, manifest_path) pairs from
#   [dependencies], [dev-dependencies], and [build-dependencies]. Empty
#   list if no Cargo.toml exists.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      run_usage() via the LIST_DEPS dispatch table.
# CALLS:          find_files(), read_text().
#
# EXAMPLE:
#   list_rust_deps("/repo") -> [("serde", "/repo/Cargo.toml")]
#--------------------------------------------------------------------------
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


# ------------------------------------------------------------------------
# list_dotnet_deps
#
# WHAT IT DOES:   Lists every package declared via <PackageReference> in
#                 .csproj files, or `nuget` lines in paket.dependencies.
# WHY IT EXISTS:  .NET-specific dependency lister for usage mode, covering
#                 both the built-in NuGet CLI and the Paket tool.
#
# INPUTS:
#   root (str) - repo root to scan.
#
# RETURNS:
#   (list[tuple[str, str]]) - (package_id, manifest_path) pairs.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      run_usage() via the LIST_DEPS dispatch table.
# CALLS:          find_files(), read_text().
#
# EXAMPLE:
#   list_dotnet_deps("/repo") -> [("Newtonsoft.Json", "/repo/App.csproj")]
#--------------------------------------------------------------------------
def list_dotnet_deps(root):
    """Returns (package_id, manifest_path) pairs from <PackageReference>
    tags across every .csproj file, plus `nuget PackageName ...` lines in
    paket.dependencies."""
    dependencies = []
    for csproj_file in find_files(root, suffixes=(".csproj",)):
        for match in re.finditer(r'<PackageReference\s+Include="([^"]+)"', read_text(csproj_file)):
            dependencies.append((match.group(1), csproj_file))
    for paket_deps_file in find_files(root, names={"paket.dependencies"}):
        for match in re.finditer(r"^\s*nuget\s+(\S+)", read_text(paket_deps_file), re.MULTILINE | re.IGNORECASE):
            dependencies.append((match.group(1), paket_deps_file))
    return dependencies


# ------------------------------------------------------------------------
# list_dart_deps
#
# WHAT IT DOES:   Lists every package in pubspec.yaml's top-level
#                 dependencies block.
# WHY IT EXISTS:  Dart/Flutter-specific dependency lister for usage mode.
#
# INPUTS:
#   root (str) - repo root to scan.
#
# RETURNS:
#   (list[tuple[str, str]]) - (package_name, manifest_path) pairs.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      run_usage() via the LIST_DEPS dispatch table.
# CALLS:          find_files(), read_text().
#
# EXAMPLE:
#   list_dart_deps("/repo") -> [("http", "/repo/pubspec.yaml")]
#--------------------------------------------------------------------------
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


# ------------------------------------------------------------------------
# list_cpp_deps
#
# WHAT IT DOES:   Lists every direct dependency declared via Conan
#                 (conanfile.txt/conanfile.py) or vcpkg (vcpkg.json).
# WHY IT EXISTS:  C/C++-specific dependency lister for usage mode.
#                 Deliberately limited to real, named, direct-dependency
#                 manifests, unlike cartridge_scan.py's scan_cpp() this
#                 does not include conan.lock's transitive graph or the
#                 CMakeLists.txt/.gitmodules structural signals, usage
#                 scanning only makes sense for a package you can actually
#                 name and search imports for.
#
# INPUTS:
#   root (str) - repo root to scan.
#
# RETURNS:
#   (list[tuple[str, str]]) - (package_name, manifest_path) pairs.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      run_usage() via the LIST_DEPS dispatch table.
# CALLS:          find_files(), read_text(), read_json().
#
# EXAMPLE:
#   list_cpp_deps("/repo") -> [("fmt", "/repo/conanfile.txt")]
#--------------------------------------------------------------------------
def list_cpp_deps(root):
    """Returns (package_name, manifest_path) pairs from Conan's
    conanfile.txt [requires] section, conanfile.py self.requires() calls,
    and vcpkg.json's "dependencies" array. Deliberately limited to these
    two *direct*-dependency manifests, not conan.lock's transitive graph
    and not the CMakeLists.txt/.gitmodules structural signals cartridge_scan.py
    reports separately, usage/health scanning only makes sense for a real,
    named, direct dependency."""
    dependencies = []
    for conanfile_txt in find_files(root, names={"conanfile.txt"}):
        text = read_text(conanfile_txt)
        in_requires_section = False
        for line in text.splitlines():
            stripped_line = line.strip()
            if stripped_line.startswith("["):
                in_requires_section = stripped_line in ("[requires]", "[build_requires]", "[tool_requires]")
                continue
            if in_requires_section and stripped_line and not stripped_line.startswith("#"):
                name = stripped_line.split("/", 1)[0].strip()
                if name:
                    dependencies.append((name, conanfile_txt))
    for conanfile_py in find_files(root, names={"conanfile.py"}):
        text = read_text(conanfile_py)
        for match in re.finditer(r"self\.(?:requires|build_requires|tool_requires)\(\s*['\"]([^/'\"]+)/", text):
            dependencies.append((match.group(1), conanfile_py))
    for vcpkg_json_file in find_files(root, names={"vcpkg.json"}):
        data = read_json(vcpkg_json_file)
        if isinstance(data, dict):
            for dep in (data.get("dependencies") or []):
                if isinstance(dep, str):
                    dependencies.append((dep, vcpkg_json_file))
                elif isinstance(dep, dict) and dep.get("name"):
                    dependencies.append((dep["name"], vcpkg_json_file))
    return dependencies


# Dispatch table: ecosystem key -> its list_*_deps function. run_usage()
# iterates this instead of hardcoding all ten ecosystem names itself.
LIST_DEPS = {
    "javascript": list_javascript_deps,
    "python": list_python_deps,
    "go": list_go_deps,
    "java": list_java_deps,
    "ruby": list_ruby_deps,
    "php": list_php_deps,
    "rust": list_rust_deps,
    "dotnet": list_dotnet_deps,
    "dart": list_dart_deps,
    "cpp": list_cpp_deps,
}


# ===== IMPORT-LINE EXTRACTION =====
# --- per-ecosystem import-line extraction ------------------------------
# Each extractor takes a source line and returns (module_key, bound_names)
# or None. module_key is what gets matched against the dependency name
# (or, for java, the matching prefix); bound_names is the list of
# identifiers a call-site sweep should look for elsewhere in the file.

# ------------------------------------------------------------------------
# extract_js
#
# WHAT IT DOES:   Recognizes an ES `import` or CommonJS `require()`
#                 statement on a single source line and extracts what
#                 module it imports and what local name(s) it binds.
# WHY IT EXISTS:  JavaScript has several different import syntaxes (ES
#                 default/namespace/named imports, CommonJS destructured
#                 or plain require, side-effect-only imports); usage
#                 scanning needs to recognize all of them to find where a
#                 dependency is actually used, not just declared.
#
# INPUTS:
#   line (str) - one line of JavaScript/TypeScript source.
#
# RETURNS:
#   (tuple[str, list[str]] or None) - (module_path, bound_names) if the
#   line matches a recognized import form, where bound_names are the
#   local identifiers this import creates (empty list for a side-effect-
#   only import, which has nothing to search for downstream). None if the
#   line doesn't match any recognized import form.
#
# RAISES/ERRORS:  None.
# SIDE EFFECTS:   None.
# CALLED BY:      scan_usage_for_ecosystem() via the EXTRACTORS dispatch
#                 table.
# CALLS:          re.match().
#
# EXAMPLE:
#   extract_js('import axios from "axios";')
#   -> ("axios", ["axios"])
#   extract_js('const { useState } = require("react");')
#   -> ("react", ["useState"])
#   extract_js('import "polyfill";')
#   -> ("polyfill", [])
#--------------------------------------------------------------------------
def extract_js(line):
    """Matches ES `import` (default/namespace/named) and CommonJS
    `require()` forms, in that order. Returns (module_path, bound_names)."""
    # `import Foo from "mod"` (default import): binds one local name.
    match = re.match(r"^\s*import\s+(\w+)\s*,?\s*from\s+['\"]([^'\"]+)['\"]", line)
    if match:
        return match.group(2), [match.group(1)]
    # `import * as Foo from "mod"` (namespace import): binds one local name.
    match = re.match(r"^\s*import\s+\*\s+as\s+(\w+)\s+from\s+['\"]([^'\"]+)['\"]", line)
    if match:
        return match.group(2), [match.group(1)]
    # `import { a, b as c } from "mod"` (named imports): binds each name,
    # using the "as" alias when present.
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
    # `const { a, b: c } = require("mod")` (CommonJS destructure).
    match = re.match(r"^\s*(?:const|let|var)\s+\{([^}]+)\}\s*=\s*require\(['\"]([^'\"]+)['\"]\)", line)
    if match:
        bound_names = [p.strip().split(":")[-1].strip() for p in match.group(1).split(",") if p.strip()]
        return match.group(2), bound_names
    # `const foo = require("mod")` (CommonJS plain require).
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


# ------------------------------------------------------------------------
# extract_python
#
# WHAT IT DOES:   Recognizes a `from module import ...` or `import
#                 module` statement and extracts the top-level module name
#                 and locally bound name(s).
# WHY IT EXISTS:  Python-specific import extractor for usage scanning.
#
# INPUTS:
#   line (str) - one line of Python source.
#
# RETURNS:
#   (tuple[str, list[str]] or None) - (top_level_module, bound_names), or
#   None if the line isn't an import statement. Only the top-level package
#   name is returned (e.g. "os" for "import os.path"), since that's what
#   a PyPI package name maps to.
#
# RAISES/ERRORS:  None.
# SIDE EFFECTS:   None.
# CALLED BY:      scan_usage_for_ecosystem() via the EXTRACTORS dispatch
#                 table.
# CALLS:          re.match().
#
# EXAMPLE:
#   extract_python("from flask import Flask, request")
#   -> ("flask", ["Flask", "request"])
#   extract_python("import numpy as np")
#   -> ("numpy", ["np"])
#--------------------------------------------------------------------------
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


# ------------------------------------------------------------------------
# extract_go
#
# WHAT IT DOES:   Recognizes a Go import path, aliased or not, whether
#                 written as a single-line `import "path"` or a bare
#                 quoted line inside an `import (...)` block.
# WHY IT EXISTS:  Go-specific import extractor for usage scanning.
#
# INPUTS:
#   line (str) - one line of Go source.
#
# RETURNS:
#   (tuple[str, list[str]] or None) - (import_path, bound_names), or None
#   if the line isn't an import.
#
# RAISES/ERRORS:  None.
# SIDE EFFECTS:   None.
# CALLED BY:      scan_usage_for_ecosystem() via the EXTRACTORS dispatch
#                 table.
# CALLS:          re.match().
#
# EXAMPLE:
#   extract_go('import "github.com/pkg/errors"')
#   -> ("github.com/pkg/errors", ["errors"])
#   extract_go('	e "github.com/pkg/errors"')  # inside an import (...) block
#   -> ("github.com/pkg/errors", ["e"])
#--------------------------------------------------------------------------
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
    # BE CAREFUL if editing this: the order of these two checks matters.
    # Trying the bare-quote pattern before the "import"-prefixed one would
    # misread `import "path"` itself, treating the literal word "import"
    # as a package alias.
    match = re.match(r'^\s*import\s+(?:(\w+)\s+)?"([^"]+)"\s*$', line)
    if not match:
        match = re.match(r'^\s*(?:(\w+)\s+)?"([^"]+)"\s*$', line)
    if match:
        alias, path = match.group(1), match.group(2)
        bound_name = alias or path.rstrip("/").split("/")[-1]
        return path, [bound_name]
    return None


# ------------------------------------------------------------------------
# extract_java
#
# WHAT IT DOES:   Recognizes a Java `import` (including `import static`
#                 and wildcard imports) and extracts its dotted path and
#                 bound name.
# WHY IT EXISTS:  Java-specific import extractor for usage scanning.
#
# INPUTS:
#   line (str) - one line of Java source.
#
# RETURNS:
#   (tuple[str, list[str]] or None) - (dotted_path, bound_names), or None
#   if the line isn't an import.
#
# RAISES/ERRORS:  None.
# SIDE EFFECTS:   None.
# CALLED BY:      scan_usage_for_ecosystem() via the EXTRACTORS dispatch
#                 table.
# CALLS:          re.match().
#
# EXAMPLE:
#   extract_java("import org.springframework.web.bind.annotation.GetMapping;")
#   -> ("org.springframework.web.bind.annotation.GetMapping", ["GetMapping"])
#--------------------------------------------------------------------------
def extract_java(line):
    """Matches `import [static] a.b.Class;` (wildcard imports too).
    Returns (dotted_path, bound_names)."""
    match = re.match(r"^\s*import\s+(?:static\s+)?([\w.]+)(\.\*)?;", line)
    if match:
        dotted_path = match.group(1)
        bound_name = dotted_path.split(".")[-1]
        return dotted_path, [bound_name]
    return None


# ------------------------------------------------------------------------
# extract_rust
#
# WHAT IT DOES:   Recognizes a Rust `use crate::path::Symbol;` statement
#                 and extracts the crate name and bound symbol.
# WHY IT EXISTS:  Rust-specific import extractor for usage scanning.
#
# INPUTS:
#   line (str) - one line of Rust source.
#
# RETURNS:
#   (tuple[str, list[str]] or None) - (crate_name, bound_names), or None
#   if the line isn't a `use` statement.
#
# RAISES/ERRORS:  None.
# SIDE EFFECTS:   None.
# CALLED BY:      scan_usage_for_ecosystem() via the EXTRACTORS dispatch
#                 table.
# CALLS:          re.match().
#
# EXAMPLE:
#   extract_rust("use serde::Deserialize;")
#   -> ("serde", ["Deserialize"])
#--------------------------------------------------------------------------
def extract_rust(line):
    """Matches `use crate::path::Symbol;`. Returns (crate_name,
    bound_names)."""
    match = re.match(r"^\s*use\s+([\w:]+)(?:::\{[^}]*\})?(?:::(\w+))?", line)
    if match:
        crate_name = match.group(1).split("::")[0]
        bound_name = match.group(2) or crate_name
        return crate_name, [bound_name]
    return None


# ------------------------------------------------------------------------
# extract_dotnet
#
# WHAT IT DOES:   Recognizes a C# `using Namespace.Sub;` statement.
# WHY IT EXISTS:  .NET-specific import extractor for usage scanning.
#
# INPUTS:
#   line (str) - one line of C# source.
#
# RETURNS:
#   (tuple[str, list[str]] or None) - (dotted_namespace, bound_names), or
#   None if the line isn't a `using` statement.
#
# RAISES/ERRORS:  None.
# SIDE EFFECTS:   None.
# CALLED BY:      scan_usage_for_ecosystem() via the EXTRACTORS dispatch
#                 table.
# CALLS:          re.match().
#
# EXAMPLE:
#   extract_dotnet("using Newtonsoft.Json;")
#   -> ("Newtonsoft.Json", ["Json"])
#--------------------------------------------------------------------------
def extract_dotnet(line):
    """Matches `using Namespace.Sub;`. Returns (dotted_namespace,
    bound_names)."""
    match = re.match(r"^\s*using\s+([\w.]+)\s*;", line)
    if match:
        dotted_namespace = match.group(1)
        return dotted_namespace, [dotted_namespace.split(".")[-1]]
    return None


# ------------------------------------------------------------------------
# extract_dart
#
# WHAT IT DOES:   Recognizes a Dart `import 'package:name/path.dart'`
#                 statement, with an optional `as alias`.
# WHY IT EXISTS:  Dart-specific import extractor for usage scanning.
#
# INPUTS:
#   line (str) - one line of Dart source.
#
# RETURNS:
#   (tuple[str, list[str]] or None) - (package_name, bound_names), or None
#   if the line isn't a package: import (relative/dart: imports aren't
#   matched here, they aren't third-party dependencies).
#
# RAISES/ERRORS:  None.
# SIDE EFFECTS:   None.
# CALLED BY:      scan_usage_for_ecosystem() via the EXTRACTORS dispatch
#                 table.
# CALLS:          re.match().
#
# EXAMPLE:
#   extract_dart("import 'package:http/http.dart' as http;")
#   -> ("http", ["http"])
#--------------------------------------------------------------------------
def extract_dart(line):
    """Matches `import 'package:name/path.dart' [as alias];`. Returns
    (package_name, bound_names)."""
    match = re.match(r"^\s*import\s+['\"]package:([\w.\-]+)/[^'\"]*['\"](?:\s+as\s+(\w+))?", line)
    if match:
        package_name = match.group(1)
        bound_name = match.group(2) or package_name.replace("-", "_")
        return package_name, [bound_name]
    return None


# ------------------------------------------------------------------------
# extract_cpp
#
# WHAT IT DOES:   Recognizes a C/C++ `#include <path>` or `#include
#                 "path"` directive and extracts the first path segment.
# WHY IT EXISTS:  C/C++-specific import extractor for usage scanning. A
#                 header include doesn't bind a named symbol the way an
#                 import/use statement does in other languages, so this
#                 only ever returns an empty bound_names list, see
#                 WEAK_ECOSYSTEMS.
#
# INPUTS:
#   line (str) - one line of C/C++ source.
#
# RETURNS:
#   (tuple[str, list[str]] or None) - (first_path_segment, []), or None if
#   the line isn't an #include.
#
# RAISES/ERRORS:  None.
# SIDE EFFECTS:   None.
# CALLED BY:      scan_usage_for_ecosystem() via the EXTRACTORS dispatch
#                 table.
# CALLS:          re.match().
#
# EXAMPLE:
#   extract_cpp('#include <fmt/format.h>') -> ("fmt", [])
#--------------------------------------------------------------------------
def extract_cpp(line):
    """Matches `#include <path>` or `#include "path"`. Returns
    (first_path_segment, []): a C/C++ header doesn't bind a named symbol
    the way an import/use statement does, so this is a weak, path-based
    signal only, see WEAK_ECOSYSTEMS."""
    match = re.match(r'^\s*#include\s*[<"]([^>"]+)[>"]', line)
    if match:
        return match.group(1).split("/")[0], []
    return None


# ------------------------------------------------------------------------
# extract_weak
#
# WHAT IT DOES:   Builds a simple line-matching function from a regex,
#                 for ecosystems where no real bound symbol can be
#                 recovered (only the fact that an import happened).
# WHY IT EXISTS:  Ruby's `require`/`require_relative` and PHP's `use`
#                 don't bind a symbol name usage scanning can search for
#                 elsewhere (see WEAK_ECOSYSTEMS's module docstring), so
#                 rather than duplicating a tiny "match this regex, return
#                 group 1" function twice, this factory builds both from
#                 one shared implementation.
#
# INPUTS:
#   pattern (re.Pattern) - a compiled regex with one capture group for the
#     module/namespace name, anchored to match from the start of a line.
#
# RETURNS:
#   (Callable[[str], tuple[str, list] or None]) - a function with the same
#   shape as extract_js/extract_python/etc: takes one source line, returns
#   (module_key, []) on a match or None otherwise.
#
# RAISES/ERRORS:  None.
# SIDE EFFECTS:   None.
# CALLED BY:      The EXTRACTORS dict literal below, to build the "ruby"
#                 and "php" entries.
# CALLS:          None directly; the returned closure calls pattern.match().
#
# EXAMPLE:
#   match_require = extract_weak(re.compile(r"^\s*require\s+['\"]([^'\"]+)['\"]"))
#   match_require("require 'json'") -> ("json", [])
#--------------------------------------------------------------------------
def extract_weak(pattern):
    """Wraps a simple require/use regex for the WEAK_ECOSYSTEMS, where no
    real bound symbol name can be recovered, only the fact of the import."""
    def match_line(line):
        match = pattern.match(line)
        if match:
            return match.group(1), []
        return None
    return match_line


# Dispatch table: ecosystem key -> its line-extractor function. Ruby and
# PHP are built from extract_weak() since they can't bind a real symbol
# name (see WEAK_ECOSYSTEMS above).
EXTRACTORS = {
    "javascript": extract_js,
    "python": extract_python,
    "go": extract_go,
    "java": extract_java,
    "ruby": extract_weak(re.compile(r"^\s*require(?:_relative)?\s+['\"]([^'\"]+)['\"]")),
    "php": extract_weak(re.compile(r"^\s*use\s+([\w\\]+)")),
    "rust": extract_rust,
    "dotnet": extract_dotnet,
    "dart": extract_dart,
    "cpp": extract_cpp,
}


# ------------------------------------------------------------------------
# module_matches
#
# WHAT IT DOES:   Decides whether an import's module_key (as extracted by
#                 an EXTRACTORS function) actually refers to a given
#                 dependency name (from a LIST_DEPS function).
# WHY IT EXISTS:  Every ecosystem resolves an import string to a package
#                 name by a different convention (npm scoped packages,
#                 Python's hyphen/underscore ambiguity, Java's groupId
#                 prefix matching, PHP's PSR-4 namespace mapping, etc.);
#                 this is the single place all of those conventions are
#                 encoded, so scan_usage_for_ecosystem() doesn't need to
#                 know any ecosystem-specific details itself.
#
# INPUTS:
#   ecosystem (str) - which ecosystem's matching rule to apply.
#   module_key (str) - the import path/module string extracted from
#     source, e.g. "@scope/pkg/sub" or "org.springframework.web".
#   dep_name (str) - the dependency name from the manifest to test against.
#   dep_match_key (str or None) - for java only, the groupId to match
#     against instead of dep_name (see list_java_deps()).
#
# RETURNS:
#   (bool) - True if module_key is considered to refer to dep_name (or,
#   for java, dep_match_key) under that ecosystem's naming convention;
#   False otherwise, including for any ecosystem not explicitly handled.
#
# RAISES/ERRORS:  None.
# SIDE EFFECTS:   None.
# CALLED BY:      scan_usage_for_ecosystem().
# CALLS:          re.split() (PHP branch only).
#
# EXAMPLE:
#   module_matches("javascript", "@babel/core/lib/x", "@babel/core")
#   -> True
#   module_matches("python", "bs4", "beautifulsoup4")
#   -> False  # a genuine name-vs-import mismatch, not recoverable from
#             # text alone, see the inline comment in the function body.
#--------------------------------------------------------------------------
def module_matches(ecosystem, module_key, dep_name, dep_match_key=None):
    """Does an import's module_key (from an EXTRACTORS function) refer to
    dep_name (a name from a LIST_DEPS function)? Ecosystem-specific because
    every language resolves an import string to a package name differently."""
    if ecosystem == "javascript":
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
    if ecosystem == "cpp":
        # Header path's first segment vs. the Conan/vcpkg package name, a
        # best-effort convention (e.g. #include <fmt/format.h> -> "fmt"),
        # not guaranteed since header layout is author-chosen, not
        # registry-enforced.
        return module_key.lower() == dep_name.lower()
    return False


# ===== USAGE MODE =====

# ------------------------------------------------------------------------
# usage_tier
#
# WHAT IT DOES:   Buckets a dependency's usage into one of four rough
#                 tiers based on how many files import it and how many
#                 call sites were found.
# WHY IT EXISTS:  Turns two raw numbers into a single human-readable
#                 signal ("heavy"/"moderate"/"light"/"minimal") the
#                 dead-weight-detector skill can act on directly.
#
# INPUTS:
#   files_importing (int) - number of distinct files that import this
#     dependency.
#   call_site_count (int or None) - approximate number of times a bound
#     symbol from this dependency is referenced; if None, files_importing
#     is used in its place (this happens for weak-signal ecosystems or
#     side-effect-only imports, see scan_usage_for_ecosystem()).
#
# RETURNS:
#   (str) - one of "heavy", "moderate", "light", "minimal". Never called
#   with files_importing == 0 (the caller reports "unused" itself in that
#   case, see scan_usage_for_ecosystem()).
#
# RAISES/ERRORS:  None.
# SIDE EFFECTS:   None.
# CALLED BY:      scan_usage_for_ecosystem().
# CALLS:          None.
#
# EXAMPLE:
#   usage_tier(files_importing=6, call_site_count=50) -> "heavy"
#   usage_tier(files_importing=1, call_site_count=1)  -> "minimal"
#--------------------------------------------------------------------------
def usage_tier(files_importing, call_site_count):
    """Heuristic cutoffs, not a precise measurement, see SKILL.md Step 1
    for the caveats. Keep these in sync with the thresholds documented
    there if they ever change."""
    if call_site_count is None:
        call_site_count = files_importing
    # These thresholds (5 files / 20 call sites / etc.) are hand-picked
    # heuristics documented in SKILL.md, not derived from any formula. If
    # you change one, update SKILL.md's Step 1 to match, or the skill's
    # own explanation of these tiers will silently go stale.
    if files_importing >= 5 or call_site_count > 20:
        return "heavy"
    if files_importing >= 3:
        return "moderate"
    if call_site_count <= 2 and files_importing <= 1:
        return "minimal"
    if call_site_count <= 6:
        return "light"
    return "moderate"


# ------------------------------------------------------------------------
# scan_usage_for_ecosystem
#
# WHAT IT DOES:   For one ecosystem's dependencies, sweeps every matching
#                 source file for import statements, counts how many files
#                 import each dependency and (where possible) how many
#                 times its bound symbols are actually referenced, and
#                 assigns a usage tier to each.
# WHY IT EXISTS:  This is the core of usage mode: turning "what's declared
#                 as a dependency" plus "what's actually imported/used in
#                 source" into one usage report per dependency.
#
# INPUTS:
#   root (str) - repo root to scan.
#   ecosystem (str) - which ecosystem's extractor/matcher rules to use.
#   dependency_entries (list) - (name, manifest_file) pairs for most
#     ecosystems, or (matching_key, manifest_file, display_name) triples
#     for java specifically (see list_java_deps()).
#
# RETURNS:
#   (list[dict]) - one entry per distinct dependency name, each with
#   "name", "files_importing", "call_site_count" (int, or None if no real
#   bound symbol was ever found to count), "distinct_symbols_used",
#   "usage_tier", and "usage_signal" ("weak" for ruby/php/cpp, "standard"
#   otherwise). Sorted by name. Empty list if dependency_entries is empty.
#
# RAISES/ERRORS:  None expected; a malformed/unreadable source file is
#                 skipped via read_text()'s empty-string fallback.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      run_usage().
# CALLS:          find_files(), read_text(), the ecosystem's EXTRACTORS
#                 function, module_matches(), usage_tier().
#
# EXAMPLE:
#   scan_usage_for_ecosystem("/repo", "python",
#                             [("requests", "/repo/requirements.txt")])
#   -> [{"name": "requests", "files_importing": 4, "call_site_count": 12,
#        "distinct_symbols_used": ["get", "post"], "usage_tier": "moderate",
#        "usage_signal": "standard"}]
#--------------------------------------------------------------------------
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


# ------------------------------------------------------------------------
# run_usage
#
# WHAT IT DOES:   Runs every ecosystem's dependency lister, then the
#                 usage scan, for whichever ecosystems actually have
#                 dependencies in this repo.
# WHY IT EXISTS:  This is the top-level function for usage mode's
#                 "usage <path>" CLI invocation.
#
# INPUTS:
#   root (str) - repo root to scan.
#
# RETURNS:
#   (dict) - {ecosystem: [usage entry, ...]}, one key per ecosystem that
#   has at least one dependency, using the same entry shape returned by
#   scan_usage_for_ecosystem(). Ecosystems with zero dependencies are
#   omitted entirely rather than included with an empty list.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only; entirely local, no network).
# CALLED BY:      main() (usage mode).
# CALLS:          Every function in LIST_DEPS, scan_usage_for_ecosystem().
#
# EXAMPLE:
#   run_usage("/repo")
#   -> {"python": [...], "javascript": [...]}  # only ecosystems present
#--------------------------------------------------------------------------
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


# ===== PINNED-VERSION RESOLUTION =====
# --- pinned-version resolution (needed to scope OSV queries correctly) -----
# Without a version, an OSV lookup returns every vulnerability ever
# reported against the package, not just ones affecting what's actually
# installed. Best-effort per ecosystem; None means "couldn't resolve,"
# not "no version." None of these are real lockfile parsers, they're
# regex/JSON-key lookups scoped to exactly the fields needed here.

# ------------------------------------------------------------------------
# resolve_version_javascript
#
# WHAT IT DOES:   Resolves the pinned version of an npm package from
#                 whichever JavaScript lockfile is present.
# WHY IT EXISTS:  health mode needs the exact installed version to scope
#                 its OSV.dev vulnerability query correctly (see the
#                 module docstring); this dispatches to the right
#                 lockfile-specific resolver.
#
# INPUTS:
#   root (str) - repo root, used to locate the lockfile.
#   name (str) - npm package name to resolve.
#
# RETURNS:
#   (str or None) - the resolved version string, or None if no lockfile
#   has an entry for name.
#
# RAISES/ERRORS:  None expected (delegates to functions that already
#                 handle their own parse failures).
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      resolve_version() via the RESOLVE_VERSION dispatch table.
# CALLS:          _resolve_version_package_lock_json(),
#                 _resolve_version_yarn_lock(), _resolve_version_pnpm_lock().
#
# EXAMPLE:
#   resolve_version_javascript("/repo", "left-pad") -> "1.3.0"
#--------------------------------------------------------------------------
def resolve_version_javascript(root, name):
    """Resolved version from package-lock.json, yarn.lock, or
    pnpm-lock.yaml, tried in that order, first match wins."""
    version = _resolve_version_package_lock_json(root, name)
    if version:
        return version
    version = _resolve_version_yarn_lock(root, name)
    if version:
        return version
    return _resolve_version_pnpm_lock(root, name)


# ------------------------------------------------------------------------
# _resolve_version_package_lock_json
#
# WHAT IT DOES:   Resolves a package's version from package-lock.json,
#                 handling both the modern (v2/v3) and legacy (v1) shapes.
# WHY IT EXISTS:  npm changed package-lock.json's internal structure
#                 between major lockfile versions; this isolates that
#                 version-shape handling from the rest of
#                 resolve_version_javascript().
#
# INPUTS:
#   root (str) - repo root, used to locate package-lock.json.
#   name (str) - npm package name to resolve.
#
# RETURNS:
#   (str or None) - the resolved version, or None if not found in either
#   lockfile shape.
#
# RAISES/ERRORS:  None expected; malformed JSON is handled by read_json()
#                 returning None.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      resolve_version_javascript().
# CALLS:          find_files(), read_json().
#
# EXAMPLE:
#   _resolve_version_package_lock_json("/repo", "left-pad") -> "1.3.0"
#--------------------------------------------------------------------------
def _resolve_version_package_lock_json(root, name):
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


# ------------------------------------------------------------------------
# _resolve_version_yarn_lock
#
# WHAT IT DOES:   Resolves a package's version from a classic (v1) format
#                 yarn.lock file.
# WHY IT EXISTS:  yarn.lock isn't JSON, TOML, or YAML, it's its own
#                 lightly-structured text format; this hand-rolled block
#                 splitter/matcher is what makes it readable without a
#                 dedicated parser dependency.
#
# INPUTS:
#   root (str) - repo root, used to locate yarn.lock.
#   name (str) - npm package name to resolve.
#
# RETURNS:
#   (str or None) - the resolved version, or None if not found. Only
#   classic v1-format yarn.lock is handled; Yarn Berry (v2+) uses a
#   different syntax entirely and isn't parsed here.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      resolve_version_javascript().
# CALLS:          find_files(), read_text().
#
# EXAMPLE:
#   # yarn.lock contains:
#   #   left-pad@^1.0.0:
#   #     version "1.3.0"
#   _resolve_version_yarn_lock("/repo", "left-pad") -> "1.3.0"
#--------------------------------------------------------------------------
def _resolve_version_yarn_lock(root, name):
    """Resolved version from yarn.lock, classic v1 format only (Berry/v2
    lockfiles use a different syntax entirely and aren't handled here).
    Not a real parser: splits the file on blank lines into entry blocks,
    finds each block's header line (unindented, non-comment, ending in
    ":", not necessarily the block's first line since a leading "#"
    comment can share a block with the header it precedes), matches one
    whose comma-separated `name@range` header includes name, then regexes
    out that block's `version "X.Y.Z"` line."""
    escaped_name = re.escape(name)
    # Matches a package's version-range spec within a comma-separated
    # header line, e.g. the `left-pad@^1.0.0` part of
    # `left-pad@^1.0.0, left-pad@^1.1.0:`.
    header_pattern = re.compile(r'(?:^|,\s*)"?' + escaped_name + r'@[^,":]+"?')
    for lockfile in find_files(root, names={"yarn.lock"}):
        for block in re.split(r"\n\s*\n", read_text(lockfile)):
            lines = block.splitlines()
            header = next(
                (line for line in lines
                 if line.rstrip().endswith(":") and not line.startswith((" ", "\t", "#"))),
                None,
            )
            if not header or not header_pattern.search(header):
                continue
            for line in lines:
                match = re.match(r'^\s*version\s+"([^"]+)"', line)
                if match:
                    return match.group(1)
    return None


# ------------------------------------------------------------------------
# _resolve_version_pnpm_lock
#
# WHAT IT DOES:   Resolves a package's version from pnpm-lock.yaml's
#                 "packages:" section.
# WHY IT EXISTS:  No YAML parser is available in this stdlib-only tool, so
#                 pnpm's lockfile is read with a regex scan instead,
#                 handling both its older ("/name@version:") and newer v9
#                 ("name@version:" or "name@version(peerDep@version):")
#                 key formats.
#
# INPUTS:
#   root (str) - repo root, used to locate pnpm-lock.yaml.
#   name (str) - npm package name to resolve.
#
# RETURNS:
#   (str or None) - the resolved version, or None if not found.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      resolve_version_javascript().
# CALLS:          find_files(), read_text().
#
# EXAMPLE:
#   # pnpm-lock.yaml contains: "  left-pad@1.3.0:"
#   _resolve_version_pnpm_lock("/repo", "left-pad") -> "1.3.0"
#--------------------------------------------------------------------------
def _resolve_version_pnpm_lock(root, name):
    """Resolved version from pnpm-lock.yaml's "packages:" section. No YAML
    parser dependency is available (stdlib-only), so this regex-scans for
    a line shaped like "/name@version:" (older lockfile versions) or
    "name@version:" / "name@version(peerDep@version):" (lockfile v9),
    stopping the version capture at the first "(" or ":"."""
    pattern = re.compile(r"^/?" + re.escape(name) + r"@([^(:'\"]+)")
    for lockfile in find_files(root, names={"pnpm-lock.yaml"}):
        in_packages_section = False
        for line in read_text(lockfile).splitlines():
            if re.match(r"^packages:\s*$", line):
                in_packages_section = True
                continue
            if not in_packages_section:
                continue
            if re.match(r"^\S", line):
                # An unindented line means we've reached the next
                # top-level YAML key, i.e. left the packages: section.
                in_packages_section = False
                continue
            match = pattern.match(line.strip())
            if match:
                return match.group(1)
    return None


# ------------------------------------------------------------------------
# resolve_version_python
#
# WHAT IT DOES:   Resolves a package's pinned version from a pinned
#                 requirements.txt/setup.py/setup.cfg entry, or from
#                 poetry.lock, uv.lock, or Pipfile.lock.
# WHY IT EXISTS:  Python-specific version resolver for health mode.
#
# INPUTS:
#   root (str) - repo root to scan.
#   name (str) - PyPI package name to resolve, matched case-insensitively.
#
# RETURNS:
#   (str or None) - the resolved/pinned version, or None if not found in
#   any of the checked sources. An unpinned requirements.txt line (e.g.
#   just "requests" with no "=="), or a version range, won't match, only
#   an exact "==" pin is read from requirements/setup files.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      resolve_version() via the RESOLVE_VERSION dispatch table.
# CALLS:          find_files(), read_text(), install_requires_from_setup_cfg(),
#                 install_requires_from_setup_py(), read_json().
#
# EXAMPLE:
#   # requirements.txt contains: requests==2.31.0
#   resolve_version_python("/repo", "requests") -> "2.31.0"
#--------------------------------------------------------------------------
def resolve_version_python(root, name):
    """Resolved version from a pinned requirements.txt/setup.py/setup.cfg
    line, poetry.lock, uv.lock, or Pipfile.lock, tried in that order,
    first match wins."""
    for requirements_file in find_files(root, suffixes=("requirements.txt",)):
        for line in read_text(requirements_file).splitlines():
            match = re.match(r"^\s*" + re.escape(name) + r"\s*==\s*(\S+)", line, re.IGNORECASE)
            if match:
                return match.group(1)
    for setup_cfg_file in find_files(root, names={"setup.cfg"}):
        for spec in (install_requires_from_setup_cfg(setup_cfg_file) or []):
            match = re.match(r"^\s*" + re.escape(name) + r"\s*==\s*(\S+)", spec, re.IGNORECASE)
            if match:
                return match.group(1)
    for setup_py_file in find_files(root, names={"setup.py"}):
        for spec in (install_requires_from_setup_py(setup_py_file) or []):
            match = re.match(r"^\s*" + re.escape(name) + r"\s*==\s*(\S+)", spec, re.IGNORECASE)
            if match:
                return match.group(1)
    for lockfile in find_files(root, names={"poetry.lock"}) + find_files(root, names={"uv.lock"}):
        text = read_text(lockfile)
        # poetry.lock/uv.lock are both TOML with the same [[package]] block
        # shape, a full parser is overkill for pulling two fields: split
        # into [[package]] blocks and regex each one.
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


# ------------------------------------------------------------------------
# resolve_version_go
#
# WHAT IT DOES:   Resolves a Go module's pinned version straight from
#                 go.mod.
# WHY IT EXISTS:  Go-specific version resolver for health mode. Unlike
#                 other ecosystems, Go pins the exact version right in the
#                 manifest itself, so no separate lockfile lookup is
#                 needed here.
#
# INPUTS:
#   root (str) - repo root to scan.
#   name (str) - Go module path to resolve.
#
# RETURNS:
#   (str or None) - the version string (including its "v" prefix, e.g.
#   "v1.2.3"), or None if not found in go.mod.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      resolve_version() via the RESOLVE_VERSION dispatch table.
# CALLS:          find_files(), read_text().
#
# EXAMPLE:
#   resolve_version_go("/repo", "github.com/pkg/errors") -> "v0.9.1"
#--------------------------------------------------------------------------
def resolve_version_go(root, name):
    """Resolved version straight from go.mod's require line, Go pins the
    version right there, no separate lockfile lookup needed."""
    for go_mod_file in find_files(root, names={"go.mod"}):
        for line in read_text(go_mod_file).splitlines():
            match = re.match(r"^\s*" + re.escape(name) + r"\s+(v\S+)", line.strip())
            if match:
                return match.group(1)
    return None


# ------------------------------------------------------------------------
# resolve_version_rust
#
# WHAT IT DOES:   Resolves a crate's pinned version from the matching
#                 [[package]] block in Cargo.lock.
# WHY IT EXISTS:  Rust-specific version resolver for health mode.
#
# INPUTS:
#   root (str) - repo root to scan.
#   name (str) - crate name to resolve, matched case-sensitively (crates.io
#     names are effectively case-sensitive-normalized already).
#
# RETURNS:
#   (str or None) - the resolved version, or None if not found.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      resolve_version() via the RESOLVE_VERSION dispatch table.
# CALLS:          find_files(), read_text().
#
# EXAMPLE:
#   resolve_version_rust("/repo", "serde") -> "1.0.195"
#--------------------------------------------------------------------------
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


# ------------------------------------------------------------------------
# resolve_version_ruby
#
# WHAT IT DOES:   Resolves a gem's pinned version from Gemfile.lock's
#                 specs: block.
# WHY IT EXISTS:  Ruby-specific version resolver for health mode.
#
# INPUTS:
#   root (str) - repo root to scan.
#   name (str) - gem name to resolve.
#
# RETURNS:
#   (str or None) - the resolved version, or None if not found.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      resolve_version() via the RESOLVE_VERSION dispatch table.
# CALLS:          find_files(), read_text().
#
# EXAMPLE:
#   # Gemfile.lock contains: "    rails (7.0.0)"
#   resolve_version_ruby("/repo", "rails") -> "7.0.0"
#--------------------------------------------------------------------------
def resolve_version_ruby(root, name):
    """Resolved version from the gem's line in Gemfile.lock's specs:
    block, e.g. "    rails (7.0.0)"."""
    for lockfile in find_files(root, names={"Gemfile.lock"}):
        match = re.search(r"^\s{4}" + re.escape(name) + r"\s+\(([^)]+)\)", read_text(lockfile), re.MULTILINE)
        if match:
            return match.group(1)
    return None


# ------------------------------------------------------------------------
# resolve_version_php
#
# WHAT IT DOES:   Resolves a package's pinned version from composer.lock.
# WHY IT EXISTS:  PHP-specific version resolver for health mode.
#
# INPUTS:
#   root (str) - repo root to scan.
#   name (str) - "vendor/package" name to resolve.
#
# RETURNS:
#   (str or None) - the resolved version, or None if not found in either
#   the packages or packages-dev array.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      resolve_version() via the RESOLVE_VERSION dispatch table.
# CALLS:          find_files(), read_json().
#
# EXAMPLE:
#   resolve_version_php("/repo", "monolog/monolog") -> "2.9.1"
#--------------------------------------------------------------------------
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


# ------------------------------------------------------------------------
# resolve_version_dart
#
# WHAT IT DOES:   Resolves a package's pinned version from its block in
#                 pubspec.lock.
# WHY IT EXISTS:  Dart-specific version resolver for health mode.
#
# INPUTS:
#   root (str) - repo root to scan.
#   name (str) - package name to resolve.
#
# RETURNS:
#   (str or None) - the resolved version, or None if not found.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      resolve_version() via the RESOLVE_VERSION dispatch table.
# CALLS:          find_files(), read_text().
#
# EXAMPLE:
#   resolve_version_dart("/repo", "http") -> "1.2.0"
#--------------------------------------------------------------------------
def resolve_version_dart(root, name):
    """Resolved version from the package's block in pubspec.lock."""
    for lockfile in find_files(root, names={"pubspec.lock"}):
        lines = read_text(lockfile).splitlines()
        for line_index, line in enumerate(lines):
            if re.match(r"^  " + re.escape(name) + r":\s*$", line):
                # Version lives a few lines below the package name, inside
                # its block; stop looking once we hit the next top-level entry.
                # 8-line lookahead is a practical cap (pubspec.lock blocks
                # are short), not a spec-defined limit.
                for lookahead_index in range(line_index + 1, min(line_index + 8, len(lines))):
                    match = re.match(r'^\s+version:\s*"([^"]+)"', lines[lookahead_index])
                    if match:
                        return match.group(1)
                    if re.match(r"^  \S", lines[lookahead_index]):
                        break
    return None


# ------------------------------------------------------------------------
# resolve_version_java
#
# WHAT IT DOES:   Resolves a "group:artifact" pair's version from pom.xml,
#                 build.gradle(.kts), or ivy.xml.
# WHY IT EXISTS:  Java-specific version resolver for health mode. Unlike
#                 most ecosystems, this reads a *declared* version
#                 straight from the manifest (Maven/Gradle/Ivy all pin the
#                 version at the declaration site itself), it isn't a
#                 lockfile lookup, none of these three formats has one.
#
# INPUTS:
#   root (str) - repo root to scan.
#   group_artifact (str) - "groupId:artifactId" pair to resolve.
#
# RETURNS:
#   (str or None) - the declared version, or None if not found or if the
#   version isn't a literal (e.g. a Gradle version catalog reference).
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      resolve_version() via the RESOLVE_VERSION dispatch table.
# CALLS:          find_files(), read_text().
#
# EXAMPLE:
#   resolve_version_java("/repo", "org.springframework:spring-core")
#   -> "6.1.2"
#--------------------------------------------------------------------------
def resolve_version_java(root, group_artifact):
    """Resolved/declared version for a "group:artifact" pair, from an
    explicit <version> tag in pom.xml, the version segment of a Gradle
    "group:artifact:version" dependency string, or an ivy.xml
    <dependency>'s rev="..." attribute."""
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
    for ivy_file in find_files(root, names={"ivy.xml"}):
        text = read_text(ivy_file)
        for tag_match in re.finditer(r"<dependency\b([^>]*)/?>", text):
            attrs = tag_match.group(1)
            if re.search(r'org="' + re.escape(group_id) + r'"', attrs) and \
                    re.search(r'name="' + re.escape(artifact_id) + r'"', attrs):
                rev_match = re.search(r'rev="([^"]+)"', attrs)
                if rev_match:
                    return rev_match.group(1)
    return None


# ------------------------------------------------------------------------
# resolve_version_dotnet
#
# WHAT IT DOES:   Resolves a NuGet package's version from a .csproj's
#                 <PackageReference> Version attribute, or from
#                 paket.lock.
# WHY IT EXISTS:  .NET-specific version resolver for health mode, covering
#                 both the built-in NuGet CLI convention and Paket.
#
# INPUTS:
#   root (str) - repo root to scan.
#   name (str) - package id to resolve.
#
# RETURNS:
#   (str or None) - the declared/resolved version, or None if not found.
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      resolve_version() via the RESOLVE_VERSION dispatch table.
# CALLS:          find_files(), read_text().
#
# EXAMPLE:
#   resolve_version_dotnet("/repo", "Newtonsoft.Json") -> "13.0.3"
#--------------------------------------------------------------------------
def resolve_version_dotnet(root, name):
    """Declared version from the matching <PackageReference>'s Version
    attribute in a .csproj file, or the resolved version from paket.lock's
    "Name (Version)" entry (same 4-space-indent convention as
    resolve_version_ruby)."""
    for csproj_file in find_files(root, suffixes=(".csproj",)):
        match = re.search(
            r'<PackageReference\s+Include="' + re.escape(name) + r'"\s+Version="([^"]+)"',
            read_text(csproj_file))
        if match:
            return match.group(1)
    for paket_lock_file in find_files(root, names={"paket.lock"}):
        match = re.search(r"^\s{4}" + re.escape(name) + r"\s+\(([^)]+)\)", read_text(paket_lock_file), re.MULTILINE)
        if match:
            return match.group(1)
    return None


# ------------------------------------------------------------------------
# resolve_version_cpp
#
# WHAT IT DOES:   Resolves a Conan package's version from conan.lock or,
#                 failing that, a pinned version in conanfile.txt.
# WHY IT EXISTS:  C/C++-specific version resolver for health mode. vcpkg
#                 has no per-package pinned version to resolve (see
#                 RETURNS below), so this only ever finds a version for
#                 Conan-managed packages.
#
# INPUTS:
#   root (str) - repo root to scan.
#   name (str) - Conan package name to resolve.
#
# RETURNS:
#   (str or None) - the resolved/pinned version, or None if not found, or
#   if the project only uses vcpkg (vcpkg pins the whole dependency set
#   via a single builtin-baseline commit in vcpkg.json, not a per-package
#   version, so there's genuinely nothing to resolve there).
#
# RAISES/ERRORS:  None expected.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      resolve_version() via the RESOLVE_VERSION dispatch table.
# CALLS:          find_files(), read_json(), read_text().
#
# EXAMPLE:
#   resolve_version_cpp("/repo", "fmt") -> "10.1.1"
#--------------------------------------------------------------------------
def resolve_version_cpp(root, name):
    """Resolved version from conan.lock's requires list ("name/version#rev%ts"
    reference strings, Conan 2.x lockfile shape only), or the version
    pinned directly in conanfile.txt's [requires] line if no lockfile
    match. Returns None for vcpkg-only projects: vcpkg pins via
    builtin-baseline in vcpkg.json, not a per-package version, so there's
    honestly nothing to resolve there."""
    for lockfile in find_files(root, names={"conan.lock"}):
        data = read_json(lockfile)
        if isinstance(data, dict):
            for key in ("requires", "build_requires", "tool_requires"):
                for ref in (data.get(key) or []):
                    if isinstance(ref, str) and ref.split("/", 1)[0] == name:
                        version = ref.split("/", 1)[1].split("#")[0].split("%")[0]
                        if version:
                            return version
    for conanfile_txt in find_files(root, names={"conanfile.txt"}):
        match = re.search(r"^\s*" + re.escape(name) + r"/([^\s#]+)", read_text(conanfile_txt), re.MULTILINE)
        if match:
            return match.group(1)
    return None


# Dispatch table: ecosystem key -> its resolve_version_* function.
RESOLVE_VERSION = {
    "javascript": resolve_version_javascript, "python": resolve_version_python, "go": resolve_version_go,
    "rust": resolve_version_rust, "ruby": resolve_version_ruby, "php": resolve_version_php,
    "dart": resolve_version_dart, "java": resolve_version_java, "dotnet": resolve_version_dotnet,
    "cpp": resolve_version_cpp,
}


# ------------------------------------------------------------------------
# resolve_version
#
# WHAT IT DOES:   Looks up and calls the right resolve_version_* function
#                 for a given ecosystem.
# WHY IT EXISTS:  Gives run_health() one call to make instead of a long
#                 if/elif chain over every ecosystem.
#
# INPUTS:
#   root (str) - repo root to scan.
#   ecosystem (str) - which ecosystem's resolver to use.
#   name (str) - package/module name to resolve.
#
# RETURNS:
#   (str or None) - the resolved version, or None if ecosystem has no
#   registered resolver, or if the resolver itself found nothing, or
#   raised an OSError/re.error while trying.
#
# RAISES/ERRORS:  Never raises; OSError and re.error from the underlying
#                 resolver are both caught and turned into None.
# SIDE EFFECTS:   None (read-only).
# CALLED BY:      run_health().
# CALLS:          The matching function in RESOLVE_VERSION.
#
# EXAMPLE:
#   resolve_version("/repo", "python", "requests") -> "2.31.0"
#--------------------------------------------------------------------------
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


# ===== HEALTH MODE: LIVE REGISTRY LOOKUPS =====
# --- health mode: live registry lookups ---------------------------------

# ------------------------------------------------------------------------
# http_json
#
# WHAT IT DOES:   Makes an HTTP request and parses the JSON response,
#                 without depending on the third-party `requests` library.
# WHY IT EXISTS:  This is the one place every registry call in health mode
#                 goes through, so timeout/error handling, the User-Agent
#                 header, and the "404 means confirmed absence" distinction
#                 are all consistent no matter which registry is being
#                 queried.
#
# INPUTS:
#   url (str) - full URL to request.
#   method (str) - HTTP method, "GET" or "POST".
#   data (dict or None) - if given, JSON-encoded and sent as the request
#     body (used for OSV.dev's POST query).
#   headers (dict or None) - extra headers to merge in on top of the
#     default User-Agent/Accept.
#   timeout (int) - seconds to wait before giving up. 10s default: long
#     enough for a normal registry response, short enough that one slow
#     package doesn't stall a whole health-mode batch.
#
# RETURNS:
#   (tuple[Any or None, bool]) - (data, not_found). data is the parsed
#   JSON body, or None on any failure (network error, timeout, bad JSON,
#   any non-2xx/404 status). not_found is True only for a confirmed HTTP
#   404 (package genuinely doesn't exist, or a typo), so callers can tell
#   "definitely absent" apart from "network hiccup, genuinely unknown."
#
# RAISES/ERRORS:  Never raises; HTTPError, URLError, ValueError (bad
#                 JSON), and TimeoutError are all caught.
# SIDE EFFECTS:   Makes an outbound network request.
# CALLED BY:      check_osv() and every health_* function.
# CALLS:          urllib.request.urlopen().
#
# EXAMPLE:
#   http_json("https://registry.npmjs.org/left-pad")
#   -> ({"name": "left-pad", ...}, False)
#   http_json("https://registry.npmjs.org/definitely-not-a-real-package")
#   -> (None, True)
#--------------------------------------------------------------------------
def http_json(url, method="GET", data=None, headers=None, timeout=10):
    """Stdlib-only HTTP JSON helper, no `requests` dependency. Returns
    (data, not_found): data is None on any failure, every caller in this
    file treats that as "field unavailable," not a crash. not_found is
    True only when the registry responded with HTTP 404, a confirmed
    absence (e.g. a private/internal package, or a typo) as distinct from
    a network/timeout/parse failure (not_found False, genuinely unknown,
    worth retrying rather than treated as "doesn't exist")."""
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    request_headers.update(headers or {})
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8")), False
    except urllib.error.HTTPError as error:
        return None, error.code == 404
    except (urllib.error.URLError, ValueError, TimeoutError):
        return None, False


# Maps this repo's internal ecosystem keys to OSV.dev's own ecosystem
# names, which don't always match (e.g. our "javascript" is OSV's "npm").
OSV_ECOSYSTEM = {
    "javascript": "npm", "python": "PyPI", "go": "Go", "rust": "crates.io",
    "ruby": "RubyGems", "php": "Packagist", "java": "Maven", "dotnet": "NuGet",
    "dart": "Pub", "cpp": "ConanCenter",
}


# ------------------------------------------------------------------------
# check_osv
#
# WHAT IT DOES:   Queries OSV.dev (Open Source Vulnerabilities, a
#                 cross-ecosystem public vulnerability database) for known
#                 vulnerabilities affecting a package.
# WHY IT EXISTS:  This is the one live vulnerability signal available for
#                 every ecosystem this tool supports, including ones
#                 (like C/C++) whose own package registries expose no
#                 health metadata at all.
#
# INPUTS:
#   ecosystem (str) - this repo's ecosystem key, translated internally to
#     OSV's own name via OSV_ECOSYSTEM.
#   name (str) - package name to check.
#   version (str or None) - the pinned version to scope the query to. If
#     omitted, OSV returns every vulnerability ever reported for the
#     package across all versions, not just ones affecting what's
#     installed, see the version_scoped field below.
#
# RETURNS:
#   (dict) - {"status": "ok"|"unknown"|"unavailable", "vulnerabilities":
#   [vuln_id, ...], "version_scoped": bool}. "unavailable" means this
#   ecosystem has no OSV mapping; "unknown" means the request itself
#   failed (network/timeout); "ok" means OSV answered, though the
#   vulnerabilities list can still be empty (queried successfully, found
#   nothing). version_scoped is True only when a version was supplied,
#   callers (see health_tier()) must not treat an unscoped hit as
#   confirming the *installed* version is vulnerable.
#
# RAISES/ERRORS:  None expected; http_json() absorbs network failures.
# SIDE EFFECTS:   Makes an outbound network request (unless the ecosystem
#                 has no OSV mapping, in which case no request is made).
# CALLED BY:      run_health().
# CALLS:          http_json().
#
# EXAMPLE:
#   check_osv("python", "django", "1.11.0")
#   -> {"status": "ok", "vulnerabilities": ["GHSA-xxxx-...", ...],
#       "version_scoped": True}
#--------------------------------------------------------------------------
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
    response_data, _not_found = http_json("https://api.osv.dev/v1/query", method="POST", data=query)
    if response_data is None:
        return {"status": "unknown", "vulnerabilities": [], "version_scoped": bool(version)}
    vulnerability_ids = [v.get("id") for v in (response_data.get("vulns") or [])]
    return {"status": "ok", "vulnerabilities": vulnerability_ids, "version_scoped": bool(version)}


# ------------------------------------------------------------------------
# health_javascript
#
# WHAT IT DOES:   Fetches an npm package's latest publish time, maintainer
#                 count, deprecation message, and last-month download
#                 count.
# WHY IT EXISTS:  npm-specific registry health fetcher for health mode.
#
# INPUTS:
#   name (str) - npm package name.
#
# RETURNS:
#   (dict) - {"recency": ISO timestamp or None, "maintainers": int or
#   None, "downloads": int or None, "deprecated": str or None,
#   "registry_status": "ok"|"not_found"|"failed"}. A maintainer-set
#   `deprecated` message on the latest version is a stronger abandonment
#   signal than anything inferred from recency/maintainers/downloads
#   alone, see health_tier().
#
# RAISES/ERRORS:  None; failures surface as registry_status/None fields.
# SIDE EFFECTS:   Makes two outbound network requests (registry metadata,
#                 download stats).
# CALLED BY:      run_health() via the HEALTH_FN dispatch table.
# CALLS:          http_json().
#
# EXAMPLE:
#   health_javascript("left-pad")
#   -> {"recency": "2016-03-25T...", "maintainers": 1, "downloads": 2000000,
#       "deprecated": None, "registry_status": "ok"}
#--------------------------------------------------------------------------
def health_javascript(name):
    """Latest publish time, maintainer count, and declared-deprecation
    message (if any) from the npm registry metadata endpoint, plus
    last-month downloads from npm's stats API. A maintainer-set
    `deprecated` message on the latest version is a stronger abandonment
    signal than any inferred one, see health_tier()."""
    registry_data, not_found = http_json(f"https://registry.npmjs.org/{name}")
    downloads_data, _ = http_json(f"https://api.npmjs.org/downloads/point/last-month/{name}")
    if registry_data is None:
        return {
            "recency": None, "maintainers": None, "downloads": None, "deprecated": None,
            "registry_status": "not_found" if not_found else "failed",
        }
    latest_version = (registry_data.get("dist-tags") or {}).get("latest")
    publish_times = registry_data.get("time") or {}
    version_meta = (registry_data.get("versions") or {}).get(latest_version) or {}
    return {
        "recency": publish_times.get(latest_version),
        "maintainers": len(registry_data.get("maintainers") or []),
        "downloads": (downloads_data or {}).get("downloads"),
        "deprecated": version_meta.get("deprecated"),
        "registry_status": "ok",
    }


# ------------------------------------------------------------------------
# health_python
#
# WHAT IT DOES:   Fetches a PyPI package's latest release upload time,
#                 yanked/deprecation status, and last-month download count.
# WHY IT EXISTS:  Python-specific registry health fetcher for health mode.
#
# INPUTS:
#   name (str) - PyPI package name.
#
# RETURNS:
#   (dict) - {"recency": ISO timestamp or None, "maintainers": "n/a"
#   (PyPI's API exposes no maintainer count), "downloads": int or None,
#   "deprecated": str or None, "registry_status": "ok"|"not_found"|
#   "failed"}. "deprecated" is set when every distribution file for the
#   latest version is marked "yanked" on PyPI, that's PyPI's own
#   deprecation signal, surfaced the same way as npm's `deprecated` field.
#
# RAISES/ERRORS:  None; failures surface as registry_status/None fields.
# SIDE EFFECTS:   Makes two outbound network requests (PyPI JSON API,
#                 pypistats.org for downloads).
# CALLED BY:      run_health() via the HEALTH_FN dispatch table.
# CALLS:          http_json().
#
# EXAMPLE:
#   health_python("requests")
#   -> {"recency": "2023-05-22T...", "maintainers": "n/a",
#       "downloads": 50000000, "deprecated": None, "registry_status": "ok"}
#--------------------------------------------------------------------------
def health_python(name):
    """Latest release upload time from PyPI's JSON API (no maintainer
    count, PyPI's API doesn't expose one), plus last-month downloads from
    pypistats.org. If every distribution file for the latest version is
    marked "yanked", that's PyPI's own deprecation signal, surfaced the
    same way as npm's `deprecated` field."""
    registry_data, not_found = http_json(f"https://pypi.org/pypi/{name}/json")
    if registry_data is None:
        return {
            "recency": None, "maintainers": "n/a", "downloads": None, "deprecated": None,
            "registry_status": "not_found" if not_found else "failed",
        }
    releases = registry_data.get("releases") or {}
    latest_version = (registry_data.get("info") or {}).get("version")
    release_files = releases.get(latest_version) or []
    upload_time = None
    for release_file in release_files:
        upload_time = release_file.get("upload_time_iso_8601") or release_file.get("upload_time")
        break
    deprecated = None
    if release_files and all(release_file.get("yanked") for release_file in release_files):
        deprecated = release_files[0].get("yanked_reason") or "yanked on PyPI"
    # PyPI's own API stopped exposing download counts years ago; pypistats.org
    # is a third-party service that fills that gap, best-effort.
    downloads_data, _ = http_json(f"https://pypistats.org/api/packages/{name}/recent")
    downloads = None
    if downloads_data:
        downloads = (downloads_data.get("data") or {}).get("last_month")
    return {
        "recency": upload_time, "maintainers": "n/a", "downloads": downloads,
        "deprecated": deprecated, "registry_status": "ok",
    }


# ------------------------------------------------------------------------
# health_go
#
# WHAT IT DOES:   Fetches a Go module's latest version publish time from
#                 Go's official module proxy.
# WHY IT EXISTS:  Go-specific registry health fetcher for health mode. Go
#                 modules have no concept of maintainer count, download
#                 volume, or a deprecation flag, so this reports far less
#                 than most other ecosystems' health_* functions.
#
# INPUTS:
#   name (str) - Go module path.
#
# RETURNS:
#   (dict) - {"recency": ISO timestamp or None, "maintainers": "n/a",
#   "downloads": "n/a", "deprecated": None, "registry_status":
#   "ok"|"not_found"|"failed"}.
#
# RAISES/ERRORS:  None; failures surface as registry_status/None fields.
# SIDE EFFECTS:   Makes one outbound network request.
# CALLED BY:      run_health() via the HEALTH_FN dispatch table.
# CALLS:          http_json().
#
# EXAMPLE:
#   health_go("github.com/pkg/errors")
#   -> {"recency": "2020-01-14T...", "maintainers": "n/a",
#       "downloads": "n/a", "deprecated": None, "registry_status": "ok"}
#--------------------------------------------------------------------------
def health_go(name):
    """Latest version's publish time from Go's official module proxy.
    No maintainer count or download volume, neither concept exists for
    Go modules; no deprecation flag either."""
    # The Go module proxy requires the module path to be lowercased
    # ("case encoding" for modules with uppercase letters is a separate,
    # more complex scheme not implemented here; this simple .lower() is
    # correct for the overwhelming majority of real-world module paths).
    module_path = name.lower()
    registry_data, not_found = http_json(f"https://proxy.golang.org/{module_path}/@latest")
    if registry_data is None:
        return {
            "recency": None, "maintainers": "n/a", "downloads": "n/a", "deprecated": None,
            "registry_status": "not_found" if not_found else "failed",
        }
    return {
        "recency": registry_data.get("Time"), "maintainers": "n/a", "downloads": "n/a",
        "deprecated": None, "registry_status": "ok",
    }


# ------------------------------------------------------------------------
# health_rust
#
# WHAT IT DOES:   Fetches a crate's last-updated time, download count, and
#                 owner count from crates.io.
# WHY IT EXISTS:  Rust-specific registry health fetcher for health mode.
#
# INPUTS:
#   name (str) - crate name.
#
# RETURNS:
#   (dict) - {"recency": ISO timestamp or None, "maintainers": int or
#   None, "downloads": int or None, "deprecated": None (crates.io exposes
#   no deprecation flag), "registry_status": "ok"|"not_found"|"failed"}.
#
# RAISES/ERRORS:  None; failures surface as registry_status/None fields.
# SIDE EFFECTS:   Makes two outbound network requests (crate metadata,
#                 owners).
# CALLED BY:      run_health() via the HEALTH_FN dispatch table.
# CALLS:          http_json().
#
# EXAMPLE:
#   health_rust("serde")
#   -> {"recency": "2024-01-08T...", "maintainers": 3,
#       "downloads": 400000000, "deprecated": None, "registry_status": "ok"}
#--------------------------------------------------------------------------
def health_rust(name):
    """Last-updated time and download count from crates.io's crate
    endpoint, plus owner count from its separate owners endpoint. No
    deprecation flag, crates.io exposes none."""
    registry_data, not_found = http_json(f"https://crates.io/api/v1/crates/{name}")
    if registry_data is None:
        return {
            "recency": None, "maintainers": None, "downloads": None, "deprecated": None,
            "registry_status": "not_found" if not_found else "failed",
        }
    crate = registry_data.get("crate") or {}
    owners_data, _ = http_json(f"https://crates.io/api/v1/crates/{name}/owners")
    maintainer_count = len((owners_data or {}).get("users") or []) if owners_data else None
    return {
        "recency": crate.get("updated_at"),
        "maintainers": maintainer_count,
        "downloads": crate.get("downloads"),
        "deprecated": None,
        "registry_status": "ok",
    }


# ------------------------------------------------------------------------
# health_ruby
#
# WHAT IT DOES:   Fetches a gem's version-created time, authors string,
#                 and download count from RubyGems.
# WHY IT EXISTS:  Ruby-specific registry health fetcher for health mode.
#
# INPUTS:
#   name (str) - gem name.
#
# RETURNS:
#   (dict) - {"recency": ISO timestamp or None, "maintainers": str
#   (RubyGems only exposes a free-text `authors` field, not a real
#   maintainer count, labeled as such), "downloads": int or None,
#   "deprecated": None (RubyGems exposes no deprecation flag),
#   "registry_status": "ok"|"not_found"|"failed"}.
#
# RAISES/ERRORS:  None; failures surface as registry_status/None fields.
# SIDE EFFECTS:   Makes one outbound network request.
# CALLED BY:      run_health() via the HEALTH_FN dispatch table.
# CALLS:          http_json().
#
# EXAMPLE:
#   health_ruby("rails")
#   -> {"recency": "2023-12-13T...", "maintainers": "David Heinemeier Hansson",
#       "downloads": 500000000, "deprecated": None, "registry_status": "ok"}
#--------------------------------------------------------------------------
def health_ruby(name):
    """Version-created time and download count from RubyGems' gem
    endpoint. "maintainers" is really the free-text `authors` field, not
    a real count, labeled as such. No deprecation flag exposed."""
    registry_data, not_found = http_json(f"https://rubygems.org/api/v1/gems/{name}.json")
    if registry_data is None:
        return {
            "recency": None, "maintainers": "n/a (authors string, not a count)", "downloads": None,
            "deprecated": None, "registry_status": "not_found" if not_found else "failed",
        }
    return {
        "recency": registry_data.get("version_created_at"),
        "maintainers": registry_data.get("authors", "n/a"),
        "downloads": registry_data.get("downloads"),
        "deprecated": None,
        "registry_status": "ok",
    }


# ------------------------------------------------------------------------
# health_php
#
# WHAT IT DOES:   Fetches a Composer package's latest publish time and
#                 maintainer count from Packagist.
# WHY IT EXISTS:  PHP-specific registry health fetcher for health mode.
#
# INPUTS:
#   vendor_pkg (str) - "vendor/package" name.
#
# RETURNS:
#   (dict) - {"recency": ISO timestamp or None, "maintainers": int or
#   None, "downloads": "n/a" (Packagist exposes no download volume in
#   this API), "deprecated": None (no deprecation flag either),
#   "registry_status": "ok"|"not_found"|"failed"}.
#
# RAISES/ERRORS:  None; failures surface as registry_status/None fields.
# SIDE EFFECTS:   Makes two outbound network requests (v2 metadata,
#                 package-info for maintainers).
# CALLED BY:      run_health() via the HEALTH_FN dispatch table.
# CALLS:          http_json().
#
# EXAMPLE:
#   health_php("monolog/monolog")
#   -> {"recency": "2023-10-27T...", "maintainers": 2, "downloads": "n/a",
#       "deprecated": None, "registry_status": "ok"}
#--------------------------------------------------------------------------
def health_php(vendor_pkg):
    """Latest version's publish time from Packagist's v2 metadata
    endpoint, plus maintainer count from its separate package-info
    endpoint. No download volume or deprecation flag, Packagist exposes
    neither."""
    registry_data, not_found = http_json(f"https://repo.packagist.org/p2/{vendor_pkg}.json")
    if registry_data is None:
        return {
            "recency": None, "maintainers": None, "downloads": "n/a", "deprecated": None,
            "registry_status": "not_found" if not_found else "failed",
        }
    versions = ((registry_data.get("packages") or {}).get(vendor_pkg) or [])
    recency = versions[0].get("time") if versions else None
    maintainers_data, _ = http_json(f"https://packagist.org/packages/{vendor_pkg}.json")
    maintainer_count = None
    if maintainers_data:
        maintainer_count = len((maintainers_data.get("package") or {}).get("maintainers") or [])
    return {
        "recency": recency, "maintainers": maintainer_count, "downloads": "n/a",
        "deprecated": None, "registry_status": "ok",
    }


# ------------------------------------------------------------------------
# health_java
#
# WHAT IT DOES:   Fetches a Maven artifact's latest index timestamp from
#                 Maven Central's search API.
# WHY IT EXISTS:  Java-specific registry health fetcher for health mode.
#                 Maven Central exposes no maintainer count, download
#                 volume, or deprecation flag at all, so this reports the
#                 least of any ecosystem here.
#
# INPUTS:
#   group_artifact (str) - "groupId:artifactId" pair, or just a bare
#     artifactId (used as a fallback search term if there's no ":").
#
# RETURNS:
#   (dict) - {"recency": epoch-millisecond timestamp or None,
#   "maintainers": "n/a", "downloads": "n/a", "deprecated": None,
#   "registry_status": "ok"|"not_found"|"failed"}. Note recency here is a
#   raw Maven Central index timestamp (milliseconds since epoch), not an
#   ISO 8601 string like most other ecosystems' health_* functions return.
#
# RAISES/ERRORS:  None; failures surface as registry_status/None fields.
# SIDE EFFECTS:   Makes one outbound network request.
# CALLED BY:      run_health() via the HEALTH_FN dispatch table.
# CALLS:          http_json().
#
# EXAMPLE:
#   health_java("org.springframework:spring-core")
#   -> {"recency": 1702300000000, "maintainers": "n/a", "downloads": "n/a",
#       "deprecated": None, "registry_status": "ok"}
#--------------------------------------------------------------------------
def health_java(group_artifact):
    """Latest version's index timestamp from the Maven Central search API.
    No maintainer count, download volume, or deprecation flag, Maven
    Central exposes none of those."""
    group_id, _, artifact_id = group_artifact.partition(":")
    query = f"g:{group_id}+AND+a:{artifact_id}" if artifact_id else f"a:{group_id}"
    registry_data, not_found = http_json(f"https://search.maven.org/solrsearch/select?q={query}&core=gav&rows=1&wt=json")
    if not registry_data:
        return {
            "recency": None, "maintainers": "n/a", "downloads": "n/a", "deprecated": None,
            "registry_status": "not_found" if not_found else "failed",
        }
    docs = ((registry_data.get("response") or {}).get("docs") or [])
    recency = docs[0].get("timestamp") if docs else None
    return {
        "recency": recency, "maintainers": "n/a", "downloads": "n/a",
        "deprecated": None, "registry_status": "ok",
    }


# ------------------------------------------------------------------------
# health_dotnet
#
# WHAT IT DOES:   Fetches a NuGet package's latest catalog entry publish
#                 time from NuGet's registration API.
# WHY IT EXISTS:  .NET-specific registry health fetcher for health mode.
#
# INPUTS:
#   name (str) - NuGet package id.
#
# RETURNS:
#   (dict) - {"recency": ISO timestamp or None, "maintainers": "n/a",
#   "downloads": "n/a", "deprecated": None, "registry_status":
#   "ok"|"not_found"|"failed"}. No maintainer count, download volume, or
#   deprecation flag, parsing those reliably out of this API isn't worth
#   the guesswork involved.
#
# RAISES/ERRORS:  None; failures (including malformed/unexpected response
#                 shapes, caught via IndexError/KeyError/TypeError) all
#                 surface as recency=None rather than crashing.
# SIDE EFFECTS:   Makes one outbound network request.
# CALLED BY:      run_health() via the HEALTH_FN dispatch table.
# CALLS:          http_json().
#
# EXAMPLE:
#   health_dotnet("Newtonsoft.Json")
#   -> {"recency": "2023-03-08T...", "maintainers": "n/a",
#       "downloads": "n/a", "deprecated": None, "registry_status": "ok"}
#--------------------------------------------------------------------------
def health_dotnet(name):
    """Latest catalog entry's publish time from NuGet's registration API.
    No maintainer count, download volume, or deprecation flag, parsing
    those out of this API reliably isn't worth the guesswork."""
    registry_data, not_found = http_json(f"https://api.nuget.org/v3/registration5-semver1/{name.lower()}/index.json")
    if not registry_data:
        return {
            "recency": None, "maintainers": "n/a", "downloads": "n/a", "deprecated": None,
            "registry_status": "not_found" if not_found else "failed",
        }
    try:
        # NuGet's registration API paginates versions into "pages"; the
        # latest version lives in the last page's last catalog item. This
        # nested indexing is fragile if NuGet ever changes this response
        # shape, hence the broad except below.
        version_pages = registry_data.get("items") or []
        latest_page = version_pages[-1]
        catalog_items = latest_page.get("items") or []
        recency = catalog_items[-1]["catalogEntry"]["published"] if catalog_items else None
    except (IndexError, KeyError, TypeError):
        recency = None
    return {
        "recency": recency, "maintainers": "n/a", "downloads": "n/a",
        "deprecated": None, "registry_status": "ok",
    }


# ------------------------------------------------------------------------
# health_dart
#
# WHAT IT DOES:   Fetches a package's latest version publish time and
#                 publisher identity from pub.dev.
# WHY IT EXISTS:  Dart-specific registry health fetcher for health mode.
#
# INPUTS:
#   name (str) - package name.
#
# RETURNS:
#   (dict) - {"recency": ISO timestamp or None, "maintainers": str (a
#   single publisher identity, not a count) or "n/a", "downloads": "n/a"
#   (pub.dev exposes no download volume here), "deprecated": None,
#   "registry_status": "ok"|"not_found"|"failed"}.
#
# RAISES/ERRORS:  None; failures surface as registry_status/None fields.
# SIDE EFFECTS:   Makes one outbound network request.
# CALLED BY:      run_health() via the HEALTH_FN dispatch table.
# CALLS:          http_json().
#
# EXAMPLE:
#   health_dart("http")
#   -> {"recency": "2024-02-19T...", "maintainers": "dart.dev",
#       "downloads": "n/a", "deprecated": None, "registry_status": "ok"}
#--------------------------------------------------------------------------
def health_dart(name):
    """Latest version's publish time and publisher (a single identity, not
    a maintainer count) from pub.dev's package API. No download volume or
    deprecation flag, pub.dev exposes neither here."""
    registry_data, not_found = http_json(f"https://pub.dev/api/packages/{name}")
    if not registry_data:
        return {
            "recency": None, "maintainers": "n/a", "downloads": "n/a", "deprecated": None,
            "registry_status": "not_found" if not_found else "failed",
        }
    return {
        "recency": (registry_data.get("latest") or {}).get("published"),
        "maintainers": registry_data.get("publisher") or "n/a",
        "downloads": "n/a",
        "deprecated": None,
        "registry_status": "ok",
    }


# ------------------------------------------------------------------------
# health_cpp
#
# WHAT IT DOES:   Reports that no registry health metadata is available
#                 for C/C++ packages.
# WHY IT EXISTS:  Neither ConanCenter nor vcpkg expose a public metadata
#                 API comparable to npm/PyPI/crates.io, so rather than
#                 guessing or omitting the field entirely, this function
#                 makes the "unavailable" state explicit and consistent
#                 with every other ecosystem's response shape.
#
# INPUTS:
#   _name (str) - unused (accepted so this function matches every other
#     HEALTH_FN entry's one-argument signature); the leading underscore
#     signals that.
#
# RETURNS:
#   (dict) - {"recency": None, "maintainers": "n/a", "downloads": "n/a",
#   "deprecated": None, "registry_status": "unavailable"}. Always the
#   same value regardless of input.
#
# RAISES/ERRORS:  None.
# SIDE EFFECTS:   None. Unlike every other health_* function, this makes
#                 no network request at all, there's no endpoint to call.
# CALLED BY:      run_health() via the HEALTH_FN dispatch table.
# CALLS:          None.
#
# EXAMPLE:
#   health_cpp("fmt")
#   -> {"recency": None, "maintainers": "n/a", "downloads": "n/a",
#       "deprecated": None, "registry_status": "unavailable"}
#--------------------------------------------------------------------------
def health_cpp(_name):
    """Neither ConanCenter nor vcpkg expose a public metadata API
    comparable to npm/PyPI/crates.io, so recency/maintainers/downloads
    honestly report unavailable here rather than a guess. The OSV
    vulnerability check still runs independently in run_health() (it's
    the one live signal available for this ecosystem)."""
    return {
        "recency": None, "maintainers": "n/a", "downloads": "n/a", "deprecated": None,
        "registry_status": "unavailable",
    }


# Dispatch table: ecosystem key -> its health_* registry fetcher.
HEALTH_FN = {
    "javascript": health_javascript, "python": health_python, "go": health_go,
    "rust": health_rust, "ruby": health_ruby, "php": health_php,
    "java": health_java, "dotnet": health_dotnet, "dart": health_dart,
    "cpp": health_cpp,
}


# ------------------------------------------------------------------------
# health_tier
#
# WHAT IT DOES:   Combines every raw health signal (recency, maintainer
#                 count, download volume, vulnerability status, explicit
#                 deprecation, curated abandonment) into one overall
#                 verdict: healthy, slowing, at_risk, or unknown.
# WHY IT EXISTS:  This is the single place that decides, given several
#                 independent and sometimes-missing signals, what the
#                 bottom-line answer is. Keeping that decision in one
#                 function means the priority order between signals (a
#                 confirmed deprecation always wins, a scoped
#                 vulnerability always wins, etc.) is written once and
#                 applied consistently.
#
# INPUTS:
#   recency (str or None) - ISO 8601 timestamp of the latest release, or
#     a non-string value (like Maven's epoch-millisecond timestamp, or the
#     "n/a" strings some health_* functions return) which is treated as
#     "not present" rather than parsed.
#   maintainers (int, str, or None) - maintainer count if it's a real int;
#     any other type (including "n/a" strings) is treated as "not present."
#   downloads (int, str, or None) - same treatment as maintainers.
#   vuln_status (dict) - the dict returned by check_osv().
#   deprecated (str or None) - a maintainer-declared deprecation message,
#     if any.
#   abandoned (dict or None) - the entry returned by
#     abandoned_packages.lookup(), if any.
#
# RETURNS:
#   (str) - one of "at_risk", "healthy", "slowing", "unknown". "unknown"
#   only when none of recency/maintainers/downloads could be read as a
#   real value, distinguishing "genuinely can't tell" from "checked and
#   it's fine."
#
# RAISES/ERRORS:  None; a malformed recency timestamp is caught internally
#                 (ValueError/TypeError) and treated as missing.
# SIDE EFFECTS:   None.
# CALLED BY:      run_health().
# CALLS:          None external; defines and calls a local months_since()
#                 helper.
#
# EXAMPLE:
#   health_tier("2016-03-25T00:00:00Z", 1, 2000000,
#               {"vulnerabilities": [], "version_scoped": True})
#   -> "at_risk"  # recency is far more than 12 months old
#--------------------------------------------------------------------------
def health_tier(recency, maintainers, downloads, vuln_status, deprecated=None, abandoned=None):
    """Combines the raw health fields into one of healthy/slowing/at_risk/
    unknown, per the thresholds in references/registry-health-signals.md.
    Any field that isn't a real number (an "n/a" string, a missing value)
    is treated as not present, not as zero."""
    # A maintainer-declared deprecation (npm's `deprecated` field, a PyPI
    # release with every file yanked) or a hit in the curated
    # abandoned-package list overrides every other signal, these are more
    # precise than any threshold inferred from recency/maintainers/downloads.
    if deprecated or abandoned:
        return "at_risk"
    # A known vulnerability in the version actually pinned overrides every
    # other signal, however healthy the project otherwise looks. An
    # *unscoped* result (couldn't resolve the pinned version) doesn't get
    # this power, see check_osv()'s docstring for why.
    if vuln_status.get("vulnerabilities") and vuln_status.get("version_scoped"):
        return "at_risk"

    def months_since(iso_timestamp):
        # ------------------------------------------------------------
        # months_since
        # WHAT IT DOES: Converts an ISO 8601 timestamp string into how
        #   many months ago that was, relative to right now.
        # WHY IT EXISTS: health_tier() needs a single, forgiving
        #   timestamp-age calculation that never raises, since
        #   different registries format timestamps slightly
        #   differently (some use "Z", some an explicit offset, some
        #   have no offset at all).
        # INPUTS: iso_timestamp (str or None/other) - the value to
        #   parse; anything falsy short-circuits to None immediately.
        # RETURNS: (float or None) - approximate months elapsed (using
        #   a flat 30-day month, not calendar-accurate), or None if
        #   iso_timestamp is empty or not parseable.
        # RAISES/ERRORS: None; ValueError/TypeError from a bad format
        #   are caught internally.
        # CALLED BY: health_tier(), for each of the three raw inputs.
        # ------------------------------------------------------------
        if not iso_timestamp:
            return None
        try:
            from datetime import datetime, timezone
            # "Z" (Zulu/UTC) isn't accepted by fromisoformat() on older
            # Python versions; normalizing it to "+00:00" first avoids
            # that incompatibility.
            normalized = iso_timestamp.replace("Z", "+00:00")
            published_at = datetime.fromisoformat(normalized)
            if published_at.tzinfo is None:
                # A timestamp with no timezone info at all is assumed to
                # already be UTC; BE CAREFUL if a new registry is added
                # whose timestamps are naive but in local time instead,
                # this assumption would silently misjudge recency for it.
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

    # These specific cutoffs (12 months stale, 0 maintainers, <3 months +
    # healthy maintainer/download counts) are documented thresholds in
    # references/registry-health-signals.md, not arbitrary; keep both in
    # sync if either changes.
    if months_since_release is not None and months_since_release > 12:
        return "at_risk"
    if maintainer_count is not None and maintainer_count == 0:
        return "at_risk"

    if months_since_release is not None and months_since_release < 3 and (
            maintainer_count is None or maintainer_count >= 2 or
            (download_count is not None and download_count >= 10000)):
        return "healthy"

    return "slowing"


# ------------------------------------------------------------------------
# run_health
#
# WHAT IT DOES:   For each given package name: fetches registry health
#                 data, resolves its pinned version, checks OSV.dev for
#                 vulnerabilities in that version, checks the curated
#                 abandoned-package list, and computes an overall health
#                 tier.
# WHY IT EXISTS:  This is the top-level function for health mode's
#                 "health <ecosystem> <repo_path> <name>..." CLI
#                 invocation; it's what ties together every other
#                 function in this section into one per-package result.
#
# INPUTS:
#   ecosystem (str) - which ecosystem's health_*/resolve_version_*
#     functions to use.
#   names (list[str]) - package names to check. Should already be
#     triaged/limited by the caller, see the module docstring's note on
#     bounding outbound calls.
#   root (str or None) - repo path to resolve pinned versions from; if
#     None, no version resolution is attempted (every OSV check runs
#     unscoped).
#
# RETURNS:
#   (dict) - {name: {"pinned_version", "recency", "maintainers",
#   "downloads", "deprecated", "registry_status", "vulnerabilities",
#   "abandoned", "health_tier"}} for every name in names.
#
# RAISES/ERRORS:  None expected; every sub-call already handles its own
#                 failures internally.
# SIDE EFFECTS:   Makes multiple outbound network requests per name
#                 (registry metadata, OSV.dev). Reads root's lockfiles
#                 locally if root is given.
# CALLED BY:      main() (health mode).
# CALLS:          HEALTH_FN's matching function, resolve_version(),
#                 check_osv(), abandoned_packages.lookup(), health_tier().
#
# EXAMPLE:
#   run_health("python", ["nose"], root="/repo")
#   -> {"nose": {"pinned_version": "1.3.7", "recency": None,
#                "maintainers": "n/a", "downloads": 120000,
#                "deprecated": None, "registry_status": "ok",
#                "vulnerabilities": {...}, "abandoned": {"reason": "...",
#                "replacement": "pytest"}, "health_tier": "at_risk"}}
#--------------------------------------------------------------------------
def run_health(ecosystem, names, root=None):
    """For each name: looks up registry health data, resolves its pinned
    version from root's lockfile (if root is given), checks OSV for
    vulnerabilities in that version, checks the curated abandoned-package
    list, and computes a health tier. Returns {name: {...}}."""
    health_lookup = HEALTH_FN.get(ecosystem)
    results = {}
    for name in names:
        registry_data = health_lookup(name) if health_lookup else {
            "recency": None, "maintainers": "n/a", "downloads": "n/a", "deprecated": None,
            "registry_status": "unavailable",
        }
        pinned_version = resolve_version(root, ecosystem, name) if root else None
        vulnerability_info = check_osv(ecosystem, name, pinned_version)
        abandoned_entry = abandoned_packages.lookup(ecosystem, name)
        results[name] = {
            "pinned_version": pinned_version,
            "recency": registry_data.get("recency"),
            "maintainers": registry_data.get("maintainers"),
            "downloads": registry_data.get("downloads"),
            "deprecated": registry_data.get("deprecated"),
            "registry_status": registry_data.get("registry_status", "ok"),
            "vulnerabilities": vulnerability_info,
            "abandoned": abandoned_entry,
            "health_tier": health_tier(
                registry_data.get("recency"), registry_data.get("maintainers"),
                registry_data.get("downloads"), vulnerability_info,
                deprecated=registry_data.get("deprecated"), abandoned=abandoned_entry,
            ),
        }
    return results


# ===== MAIN =====
# --- main ------------------------------------------------------------------

# ------------------------------------------------------------------------
# main
#
# WHAT IT DOES:   CLI entry point. Reads sys.argv to decide between usage
#                 mode and health mode, runs the corresponding function,
#                 and prints its result as JSON.
# WHY IT EXISTS:  This is what actually gets invoked when the script is
#                 run from the command line or by the dead-weight-detector
#                 skill.
#
# INPUTS:
#   None directly (reads sys.argv). sys.argv[1] must be "usage" or
#   "health"; the remaining arguments depend on the mode, see the module
#   docstring and USAGE field above.
#
# RETURNS:
#   (None) - prints JSON to stdout; calls sys.exit(1) on bad arguments or
#   an unrecognized mode instead of returning normally.
#
# RAISES/ERRORS:  Calls sys.exit(1) (not a raised exception) when
#                 sys.argv is too short or mode isn't "usage"/"health". An
#                 unhandled exception from run_usage()/run_health() would
#                 still propagate and crash with a non-zero exit, neither
#                 function is expected to raise under normal use.
# SIDE EFFECTS:   Prints to stdout. usage mode reads the filesystem only;
#                 health mode also makes outbound network requests.
# CALLED BY:      The `if __name__ == "__main__":` guard at the bottom of
#                 this file.
# CALLS:          run_usage(), run_health().
#
# EXAMPLE:
#   $ python3 dead_weight_scan.py usage /home/user/my-repo
#   {"python": [...], "javascript": [...]}
#   $ python3 dead_weight_scan.py health python /home/user/my-repo nose
#   {"nose": {...}}
#--------------------------------------------------------------------------
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
