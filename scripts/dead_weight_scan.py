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

################################################################################
# FUNCTION: list_javascript_deps
#
# PURPOSE
#     Lists every dependency declared in package.json, so usage mode
#     knows what JavaScript dependency names to search source files for.
#
# RESPONSIBILITIES
#     - Find the repo's package.json.
#     - Collect every dependency name across its dependencies,
#       devDependencies, peerDependencies, and optionalDependencies
#       sections.
#
# PROCESS OVERVIEW
#     1. Find package.json files under root.
#     2. Parse the first one found as JSON.
#     3. Collect every name from its dependencies, devDependencies,
#        peerDependencies, and optionalDependencies sections, paired
#        with the manifest path.
#     4. Return the collected pairs.
#
# IMPORTANT DETAILS
#     - Only the first package.json is read, same reasoning as
#       scan_javascript() in cartridge_scan.py: a monorepo can have
#       several, and summing unrelated workspaces together would be
#       misleading rather than helpful.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     list[tuple[str, str]]
#         (dependency_name, manifest_path) pairs. Empty list if no
#         package.json exists.
#
# FAILURE CASES
#     - No package.json found: returns an empty list.
################################################################################
def list_javascript_deps(root):
    """Returns (name, manifest_path) pairs for every dependency listed in
    package.json (dependencies, devDependencies, peerDependencies,
    optionalDependencies). Only reads the first package.json found."""
    dependencies = []
    for manifest in find_files(root, names={"package.json"}):
        package_json_contents = read_json(manifest)
        if not isinstance(package_json_contents, dict):
            continue
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for name in (package_json_contents.get(key) or {}):
                dependencies.append((name, manifest))
        # Only the first package.json is read, same reasoning as
        # scan_javascript() in cartridge_scan.py: a monorepo can have
        # several, and summing unrelated workspaces together would be
        # misleading rather than helpful.
        break
    return dependencies


################################################################################
# FUNCTION: list_python_deps
#
# PURPOSE
#     Lists every dependency declared across all of Python's common
#     manifest formats, so usage mode has the union of all of them to
#     search source files for.
#
# RESPONSIBILITIES
#     - Find every Python manifest format: requirements*.txt,
#       pyproject.toml (PEP 621 and Poetry), Pipfile, setup.py, and
#       setup.cfg.
#     - Extract each manifest's declared dependency names, with version
#       specifiers, extras, and environment markers stripped off.
#
# PROCESS OVERVIEW
#     1. For each requirements*.txt file, extract the package name from
#        each non-comment, non-option line.
#     2. For each pyproject.toml, extract names from its PEP 621
#        dependencies array and its [tool.poetry.dependencies] table.
#     3. For each Pipfile, extract names from its [packages] and
#        [dev-packages] sections.
#     4. For each setup.py, extract names via
#        install_requires_from_setup_py().
#     5. For each setup.cfg, extract names via
#        install_requires_from_setup_cfg().
#     6. Return all collected (name, manifest_path) pairs.
#
# IMPORTANT DETAILS
#     - A requirement spec like "requests==2.31.0" is cut at the first
#       version specifier, extras bracket, environment marker, or
#       whitespace to get the bare name "requests".
#     - Poetry's Python version constraint (the "python" key in
#       [tool.poetry.dependencies]) is excluded, since it isn't a real
#       dependency.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     list[tuple[str, str]]
#         (package_name, manifest_path) pairs, one per declared
#         dependency across every manifest format found. Empty list if
#         no Python manifest exists.
#
# FAILURE CASES
#     - No Python manifest found: returns an empty list.
################################################################################
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


################################################################################
# FUNCTION: list_go_deps
#
# PURPOSE
#     Lists every module declared in go.mod's require directives, the
#     Go-specific dependency lister for usage mode.
#
# RESPONSIBILITIES
#     - Find go.mod files.
#     - Extract every module path from both the single-line and
#       parenthesized-block require forms.
#
# PROCESS OVERVIEW
#     1. Find go.mod files under root.
#     2. For each one, track whether the current line is inside a
#        parenthesized `require ( ... )` block.
#     3. Inside that block, extract the module path from each line.
#     4. Outside that block, extract the module path from any
#        single-line `require path vX.Y.Z` statement.
#     5. Return all collected (module_path, manifest_path) pairs.
#
# IMPORTANT DETAILS
#     - None.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     list[tuple[str, str]]
#         (module_path, manifest_path) pairs. Empty list if no go.mod
#         exists.
#
# FAILURE CASES
#     - No go.mod found: returns an empty list.
################################################################################
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


################################################################################
# FUNCTION: list_java_deps
#
# PURPOSE
#     Lists every dependency declared in pom.xml, build.gradle (or
#     .kts), or ivy.xml, keyed by Maven groupId. Java import statements
#     conventionally start with the dependency's groupId (e.g. groupId
#     "org.springframework" -> imports "org.springframework.*"), not its
#     artifactId, so usage matching for Java needs the groupId
#     specifically, not just a package name string the way other
#     ecosystems do.
#
# RESPONSIBILITIES
#     - Find pom.xml, build.gradle/build.gradle.kts, and ivy.xml files.
#     - Extract each dependency's groupId and artifactId (or Ivy's
#       equivalent org/name attributes).
#
# PROCESS OVERVIEW
#     1. For each pom.xml, extract every <groupId>/<artifactId> pair
#        from its <dependency> tags.
#     2. For each build.gradle/build.gradle.kts, extract every
#        "group:artifact:version" dependency string.
#     3. For each ivy.xml, extract every org/name attribute pair from
#        its <dependency> tags, searching for each attribute
#        independently since Ivy doesn't guarantee attribute order.
#     4. Return all collected (matching_prefix, manifest_path,
#        display_name) triples.
#
# IMPORTANT DETAILS
#     - matching_prefix is always the groupId (or Ivy's org), since
#       that's what a Java import statement starts with; display_name
#       is "groupId:artifactId" so the report shows the full dependency
#       identity, not just the groupId used for matching.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     list[tuple[str, str, str]]
#         (matching_prefix, manifest_path, display_name) triples.
#         matching_prefix is the groupId, used by module_matches() to
#         test whether an import belongs to this dependency.
#
# FAILURE CASES
#     - No pom.xml, build.gradle/build.gradle.kts, or ivy.xml found:
#       returns an empty list.
################################################################################
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


################################################################################
# FUNCTION: list_ruby_deps
#
# PURPOSE
#     Lists every gem declared in the Gemfile, the Ruby-specific
#     dependency lister for usage mode.
#
# RESPONSIBILITIES
#     - Find Gemfile files.
#     - Extract every `gem "..."` declaration's gem name.
#
# PROCESS OVERVIEW
#     1. Find Gemfile files under root.
#     2. For each one, extract the gem name from every `gem "..."` line.
#     3. Return all collected (gem_name, manifest_path) pairs.
#
# IMPORTANT DETAILS
#     - None.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     list[tuple[str, str]]
#         (gem_name, manifest_path) pairs. Empty list if no Gemfile
#         exists.
#
# FAILURE CASES
#     - No Gemfile found: returns an empty list.
################################################################################
def list_ruby_deps(root):
    """Returns (gem_name, manifest_path) pairs from `gem "..."` lines in
    the Gemfile."""
    dependencies = []
    for gemfile in find_files(root, names={"Gemfile"}):
        for match in re.finditer(r"^\s*gem\s+['\"]([^'\"]+)['\"]", read_text(gemfile), re.MULTILINE):
            dependencies.append((match.group(1), gemfile))
    return dependencies


################################################################################
# FUNCTION: list_php_deps
#
# PURPOSE
#     Lists every package declared in composer.json's require sections,
#     the PHP-specific dependency lister for usage mode.
#
# RESPONSIBILITIES
#     - Find composer.json files.
#     - Extract every real package name from the require and
#       require-dev sections.
#
# PROCESS OVERVIEW
#     1. Find composer.json files under root.
#     2. Parse each one as JSON.
#     3. Collect every name from its require and require-dev sections,
#        excluding the "php" pseudo-package and any name without a "/".
#     4. Return all collected (name, manifest_path) pairs.
#
# IMPORTANT DETAILS
#     - "php" itself can appear as a pseudo-dependency (a required PHP
#       version), not a real package, so it's excluded.
#     - An entry without a "/" is a PHP extension requirement (e.g.
#       "ext-curl"), not an installable Composer package, so it's
#       excluded too.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     list[tuple[str, str]]
#         ("vendor/package", manifest_path) pairs. Empty list if no
#         composer.json exists.
#
# FAILURE CASES
#     - No composer.json found: returns an empty list.
################################################################################
def list_php_deps(root):
    """Returns ("vendor/package", manifest_path) pairs from composer.json's
    require and require-dev sections, skipping the "php" pseudo-package."""
    dependencies = []
    for composer_json_file in find_files(root, names={"composer.json"}):
        composer_json_contents = read_json(composer_json_file)
        if not isinstance(composer_json_contents, dict):
            continue
        for key in ("require", "require-dev"):
            for name in (composer_json_contents.get(key) or {}):
                if name != "php" and "/" in name:
                    dependencies.append((name, composer_json_file))
    return dependencies


################################################################################
# FUNCTION: list_rust_deps
#
# PURPOSE
#     Lists every crate declared in Cargo.toml's dependency tables, the
#     Rust-specific dependency lister for usage mode.
#
# RESPONSIBILITIES
#     - Find Cargo.toml files.
#     - Extract every crate name from the dependencies,
#       dev-dependencies, and build-dependencies tables.
#
# PROCESS OVERVIEW
#     1. Find Cargo.toml files under root.
#     2. For each one, track whether the current line is inside a
#        dependencies/dev-dependencies/build-dependencies table.
#     3. Inside one of those tables, extract the crate name from each
#        `name = ...` line.
#     4. Return all collected (crate_name, manifest_path) pairs.
#
# IMPORTANT DETAILS
#     - None.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     list[tuple[str, str]]
#         (crate_name, manifest_path) pairs. Empty list if no
#         Cargo.toml exists.
#
# FAILURE CASES
#     - No Cargo.toml found: returns an empty list.
################################################################################
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


################################################################################
# FUNCTION: list_dotnet_deps
#
# PURPOSE
#     Lists every package declared via <PackageReference> in .csproj
#     files, or `nuget` lines in paket.dependencies, the .NET-specific
#     dependency lister for usage mode, covering both the built-in
#     NuGet CLI and the Paket tool.
#
# RESPONSIBILITIES
#     - Find .csproj and paket.dependencies files.
#     - Extract every package ID from <PackageReference> tags and
#       `nuget` lines.
#
# PROCESS OVERVIEW
#     1. Find .csproj files under root and extract each
#        <PackageReference Include="..."> tag's package ID.
#     2. Find paket.dependencies files under root and extract each
#        `nuget PackageName ...` line's package ID.
#     3. Return all collected (package_id, manifest_path) pairs.
#
# IMPORTANT DETAILS
#     - None.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     list[tuple[str, str]]
#         (package_id, manifest_path) pairs. Empty list if no .csproj
#         or paket.dependencies file exists.
#
# FAILURE CASES
#     - No .csproj and no paket.dependencies found: returns an empty
#       list.
################################################################################
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


################################################################################
# FUNCTION: list_dart_deps
#
# PURPOSE
#     Lists every package in pubspec.yaml's top-level dependencies
#     block, the Dart/Flutter-specific dependency lister for usage
#     mode.
#
# RESPONSIBILITIES
#     - Find pubspec.yaml files.
#     - Extract every package name from the top-level dependencies:
#       block only. dev_dependencies is intentionally not included:
#       cartridge_scan.py's scan_dart() counts both for its inventory
#       total, but usage scanning here only needs the dependencies a
#       repo actually ships with.
#
# PROCESS OVERVIEW
#     1. Find pubspec.yaml files under root.
#     2. For each one, track whether the current line is inside the
#        top-level dependencies: block.
#     3. Inside that block, extract the package name from each
#        2-space-indented "name:" line.
#     4. Return all collected (package_name, manifest_path) pairs.
#
# IMPORTANT DETAILS
#     - A line with no leading whitespace means the next top-level YAML
#       key has been reached, i.e. the dependencies: block has ended.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     list[tuple[str, str]]
#         (package_name, manifest_path) pairs. Empty list if no
#         pubspec.yaml exists.
#
# FAILURE CASES
#     - No pubspec.yaml found: returns an empty list.
################################################################################
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


################################################################################
# FUNCTION: list_cpp_deps
#
# PURPOSE
#     Lists every direct dependency declared via Conan
#     (conanfile.txt/conanfile.py) or vcpkg (vcpkg.json), the
#     C/C++-specific dependency lister for usage mode. Deliberately
#     limited to real, named, direct-dependency manifests: usage/health
#     scanning only makes sense for a package you can actually name and
#     search imports for.
#
# RESPONSIBILITIES
#     - Find conanfile.txt, conanfile.py, and vcpkg.json files.
#     - Extract every direct dependency's name from each format.
#
# PROCESS OVERVIEW
#     1. For each conanfile.txt, track whether the current line is
#        inside a requires/build_requires/tool_requires section, and
#        extract the package name (the part before the first "/") from
#        each non-comment line inside it.
#     2. For each conanfile.py, extract the package name from every
#        self.requires()/self.build_requires()/self.tool_requires()
#        call.
#     3. For each vcpkg.json, extract every entry in its "dependencies"
#        array, whether that entry is a bare string or a
#        {"name": ...} dict.
#     4. Return all collected (package_name, manifest_path) pairs.
#
# IMPORTANT DETAILS
#     - Unlike cartridge_scan.py's scan_cpp(), this does not include
#       conan.lock's transitive dependency graph, or the
#       CMakeLists.txt/.gitmodules structural signals scan_cpp()
#       reports separately; both of those describe dependencies that
#       usage scanning cannot meaningfully search imports for.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     list[tuple[str, str]]
#         (package_name, manifest_path) pairs. Empty list if no Conan
#         or vcpkg manifest exists.
#
# FAILURE CASES
#     - No conanfile.txt, conanfile.py, or vcpkg.json found: returns an
#       empty list.
################################################################################
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
        vcpkg_json_contents = read_json(vcpkg_json_file)
        if isinstance(vcpkg_json_contents, dict):
            for vcpkg_dependency_entry in (vcpkg_json_contents.get("dependencies") or []):
                if isinstance(vcpkg_dependency_entry, str):
                    dependencies.append((vcpkg_dependency_entry, vcpkg_json_file))
                elif isinstance(vcpkg_dependency_entry, dict) and vcpkg_dependency_entry.get("name"):
                    dependencies.append((vcpkg_dependency_entry["name"], vcpkg_json_file))
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

################################################################################
# FUNCTION: extract_js
#
# PURPOSE
#     Recognizes an ES `import` or CommonJS `require()` statement on a
#     single source line and extracts what module it imports and what
#     local name(s) it binds. JavaScript has several different import
#     syntaxes (ES default/namespace/named imports, CommonJS
#     destructured or plain require, side-effect-only imports); usage
#     scanning needs to recognize all of them to find where a
#     dependency is actually used, not just declared.
#
# RESPONSIBILITIES
#     - Try each recognized import form, in a fixed order, against the
#       line.
#     - For whichever form matches, extract the imported module path
#       and the local name(s) it binds.
#
# PROCESS OVERVIEW
#     1. Try to match a default import (`import Foo from "mod"`).
#     2. Try to match a namespace import (`import * as Foo from
#        "mod"`).
#     3. Try to match named imports (`import { a, b as c } from
#        "mod"`), resolving each name's "as" alias if present.
#     4. Try to match a CommonJS destructured require (`const { a, b:
#        c } = require("mod")`).
#     5. Try to match a CommonJS plain require (`const foo =
#        require("mod")`).
#     6. Try to match a side-effect-only import or require (`import
#        "polyfill";` or `require("polyfill")`).
#     7. Return None if none of the above matched.
#
# IMPORTANT DETAILS
#     - A side-effect-only import binds no local name, so its
#       bound_names list is empty; it still counts as a
#       files_importing hit downstream, just with nothing to search
#       for as a call site.
#
# PARAMETERS
#     line (str)
#         One line of JavaScript/TypeScript source.
#
# RETURNS
#     tuple[str, list[str]] or None
#         (module_path, bound_names) if the line matches a recognized
#         import form. None if the line doesn't match any recognized
#         import form.
#
# FAILURE CASES
#     - Line doesn't match any recognized import form: returns None.
################################################################################
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
        bound_names = []
        for part in match.group(1).split(","):
            stripped_part = part.strip()
            if stripped_part:
                bound_names.append(stripped_part.split(":")[-1].strip())
        return match.group(2), bound_names
    # `const foo = require("mod")` (CommonJS plain require).
    match = re.match(r"^\s*(?:const|let|var)\s+(\w+)\s*=\s*require\(['\"]([^'\"]+)['\"]\)", line)
    if match:
        return match.group(2), [match.group(1)]
    # Side-effect-only import/require, e.g. `import 'polyfill';`. No bound
    # name to look for elsewhere, but it still counts as a files_importing hit.
    match = re.match(r"^\s*import\s+['\"]([^'\"]+)['\"]", line)
    if not match:
        match = re.match(r"^\s*require\(['\"]([^'\"]+)['\"]\)", line)
    if match:
        return match.group(1), []
    return None


################################################################################
# FUNCTION: extract_python
#
# PURPOSE
#     Recognizes a `from module import ...` or `import module`
#     statement and extracts the top-level module name and locally
#     bound name(s), the Python-specific import extractor for usage
#     scanning.
#
# RESPONSIBILITIES
#     - Try both recognized import forms against the line.
#     - Reduce the matched module path to its top-level package name.
#     - Extract the locally bound name(s), resolving any "as" alias.
#
# PROCESS OVERVIEW
#     1. Try to match a `from module import a, b` statement.
#     2. If matched, reduce the module path to its top-level segment
#        and extract each imported name's local binding, using the
#        "as" alias when present.
#     3. Otherwise, try to match a plain `import module [as alias]`
#        statement.
#     4. If matched, reduce the module path to its top-level segment
#        and use the alias, or the module name itself, as the bound
#        name.
#     5. Return None if neither form matched.
#
# IMPORTANT DETAILS
#     - Only the top-level package name is returned (e.g. "os" for
#       "import os.path"), since that's what a PyPI package name maps
#       to.
#
# PARAMETERS
#     line (str)
#         One line of Python source.
#
# RETURNS
#     tuple[str, list[str]] or None
#         (top_level_module, bound_names), or None if the line isn't
#         an import statement.
#
# FAILURE CASES
#     - Line isn't a `from ... import ...` or `import ...` statement:
#       returns None.
################################################################################
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


################################################################################
# FUNCTION: extract_go
#
# PURPOSE
#     Recognizes a Go import path, aliased or not, whether written as a
#     single-line `import "path"` or a bare quoted line inside an
#     `import (...)` block, the Go-specific import extractor for usage
#     scanning.
#
# RESPONSIBILITIES
#     - Try the "import"-prefixed single-line form first.
#     - Fall back to the bare-quote block-line form.
#     - Extract the import path and its bound local name, using the
#       alias when present or the path's last segment otherwise.
#
# PROCESS OVERVIEW
#     1. Try to match the single-line `import "path"` (or aliased
#        `import alias "path"`) form.
#     2. If that didn't match, try to match a bare `"path"` (or
#        aliased `alias "path"`) line, the shape used inside a
#        parenthesized `import (...)` block.
#     3. If either matched, use the alias if present, or the path's
#        last "/"-separated segment otherwise, as the bound name.
#     4. Return None if neither form matched.
#
# IMPORTANT DETAILS
#     - The "import"-prefixed pattern must be tried before the
#       bare-quote pattern. Trying the bare-quote pattern first would
#       misread `import "path"` itself, treating the literal word
#       "import" as a package alias.
#
# PARAMETERS
#     line (str)
#         One line of Go source.
#
# RETURNS
#     tuple[str, list[str]] or None
#         (import_path, bound_names), or None if the line isn't an
#         import.
#
# FAILURE CASES
#     - Line isn't an import in either recognized form: returns None.
################################################################################
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


################################################################################
# FUNCTION: extract_java
#
# PURPOSE
#     Recognizes a Java `import` (including `import static` and
#     wildcard imports) and extracts its dotted path and bound name,
#     the Java-specific import extractor for usage scanning.
#
# RESPONSIBILITIES
#     - Match a Java import statement, including the optional `static`
#       keyword and an optional trailing `.*` wildcard.
#     - Extract the dotted import path and its bound local name (the
#       path's last segment).
#
# PROCESS OVERVIEW
#     1. Try to match an `import [static] a.b.Class;` (or
#        `a.b.*;`) statement.
#     2. If matched, take the last dot-separated segment of the dotted
#        path as the bound name.
#     3. Return None if the line doesn't match.
#
# IMPORTANT DETAILS
#     - None.
#
# PARAMETERS
#     line (str)
#         One line of Java source.
#
# RETURNS
#     tuple[str, list[str]] or None
#         (dotted_path, bound_names), or None if the line isn't an
#         import.
#
# FAILURE CASES
#     - Line isn't an import statement: returns None.
################################################################################
def extract_java(line):
    """Matches `import [static] a.b.Class;` (wildcard imports too).
    Returns (dotted_path, bound_names)."""
    match = re.match(r"^\s*import\s+(?:static\s+)?([\w.]+)(\.\*)?;", line)
    if match:
        dotted_path = match.group(1)
        bound_name = dotted_path.split(".")[-1]
        return dotted_path, [bound_name]
    return None


################################################################################
# FUNCTION: extract_rust
#
# PURPOSE
#     Recognizes a Rust `use crate::path::Symbol;` statement and
#     extracts the crate name and bound symbol, the Rust-specific
#     import extractor for usage scanning.
#
# RESPONSIBILITIES
#     - Match a `use` statement.
#     - Reduce its path to the top-level crate name.
#     - Extract the bound symbol, or fall back to the crate name if
#       none was given.
#
# PROCESS OVERVIEW
#     1. Try to match a `use crate::path::Symbol;` statement.
#     2. If matched, take the first "::"-separated segment as the
#        crate name.
#     3. Use the matched symbol as the bound name, or the crate name
#        itself if no symbol was captured.
#     4. Return None if the line doesn't match.
#
# IMPORTANT DETAILS
#     - None.
#
# PARAMETERS
#     line (str)
#         One line of Rust source.
#
# RETURNS
#     tuple[str, list[str]] or None
#         (crate_name, bound_names), or None if the line isn't a `use`
#         statement.
#
# FAILURE CASES
#     - Line isn't a `use` statement: returns None.
################################################################################
def extract_rust(line):
    """Matches `use crate::path::Symbol;`. Returns (crate_name,
    bound_names)."""
    match = re.match(r"^\s*use\s+([\w:]+)(?:::\{[^}]*\})?(?:::(\w+))?", line)
    if match:
        crate_name = match.group(1).split("::")[0]
        bound_name = match.group(2) or crate_name
        return crate_name, [bound_name]
    return None


################################################################################
# FUNCTION: extract_dotnet
#
# PURPOSE
#     Recognizes a C# `using Namespace.Sub;` statement, the
#     .NET-specific import extractor for usage scanning.
#
# RESPONSIBILITIES
#     - Match a `using` statement.
#     - Extract the dotted namespace and its bound local name (the
#       namespace's last segment).
#
# PROCESS OVERVIEW
#     1. Try to match a `using Namespace.Sub;` statement.
#     2. If matched, take the last dot-separated segment as the bound
#        name.
#     3. Return None if the line doesn't match.
#
# IMPORTANT DETAILS
#     - None.
#
# PARAMETERS
#     line (str)
#         One line of C# source.
#
# RETURNS
#     tuple[str, list[str]] or None
#         (dotted_namespace, bound_names), or None if the line isn't a
#         `using` statement.
#
# FAILURE CASES
#     - Line isn't a `using` statement: returns None.
################################################################################
def extract_dotnet(line):
    """Matches `using Namespace.Sub;`. Returns (dotted_namespace,
    bound_names)."""
    match = re.match(r"^\s*using\s+([\w.]+)\s*;", line)
    if match:
        dotted_namespace = match.group(1)
        return dotted_namespace, [dotted_namespace.split(".")[-1]]
    return None


################################################################################
# FUNCTION: extract_dart
#
# PURPOSE
#     Recognizes a Dart `import 'package:name/path.dart'` statement,
#     with an optional `as alias`, the Dart-specific import extractor
#     for usage scanning.
#
# RESPONSIBILITIES
#     - Match a `package:` import statement specifically.
#     - Extract the package name and its bound local name, using the
#       alias when present.
#
# PROCESS OVERVIEW
#     1. Try to match an `import 'package:name/path.dart' [as alias];`
#        statement.
#     2. If matched, use the alias if present, or the package name
#        with hyphens converted to underscores otherwise, as the bound
#        name.
#     3. Return None if the line doesn't match.
#
# IMPORTANT DETAILS
#     - Only `package:` imports are matched; relative and `dart:`
#       imports are not, since they aren't third-party dependencies.
#
# PARAMETERS
#     line (str)
#         One line of Dart source.
#
# RETURNS
#     tuple[str, list[str]] or None
#         (package_name, bound_names), or None if the line isn't a
#         `package:` import.
#
# FAILURE CASES
#     - Line isn't a `package:` import: returns None.
################################################################################
def extract_dart(line):
    """Matches `import 'package:name/path.dart' [as alias];`. Returns
    (package_name, bound_names)."""
    match = re.match(r"^\s*import\s+['\"]package:([\w.\-]+)/[^'\"]*['\"](?:\s+as\s+(\w+))?", line)
    if match:
        package_name = match.group(1)
        bound_name = match.group(2) or package_name.replace("-", "_")
        return package_name, [bound_name]
    return None


################################################################################
# FUNCTION: extract_cpp
#
# PURPOSE
#     Recognizes a C/C++ `#include <path>` or `#include "path"`
#     directive and extracts the first path segment, the
#     C/C++-specific import extractor for usage scanning.
#
# RESPONSIBILITIES
#     - Match an #include directive, angle-bracket or quoted form.
#     - Extract the first "/"-separated segment of the included path.
#
# PROCESS OVERVIEW
#     1. Try to match an `#include <path>` or `#include "path"`
#        directive.
#     2. If matched, take the first "/"-separated segment of the path.
#     3. Return None if the line doesn't match.
#
# IMPORTANT DETAILS
#     - A header include doesn't bind a named symbol the way an
#       import/use statement does in other languages, so this always
#       returns an empty bound_names list; see WEAK_ECOSYSTEMS.
#
# PARAMETERS
#     line (str)
#         One line of C/C++ source.
#
# RETURNS
#     tuple[str, list[str]] or None
#         (first_path_segment, []), or None if the line isn't an
#         #include.
#
# FAILURE CASES
#     - Line isn't an #include directive: returns None.
################################################################################
def extract_cpp(line):
    """Matches `#include <path>` or `#include "path"`. Returns
    (first_path_segment, []): a C/C++ header doesn't bind a named symbol
    the way an import/use statement does, so this is a weak, path-based
    signal only, see WEAK_ECOSYSTEMS."""
    match = re.match(r'^\s*#include\s*[<"]([^>"]+)[>"]', line)
    if match:
        return match.group(1).split("/")[0], []
    return None


################################################################################
# FUNCTION: extract_weak
#
# PURPOSE
#     Builds a simple line-matching function from a regex, for
#     ecosystems where no real bound symbol can be recovered (only the
#     fact that an import happened). Ruby's `require`/`require_relative`
#     and PHP's `use` don't bind a symbol name usage scanning can
#     search for elsewhere (see WEAK_ECOSYSTEMS's module docstring), so
#     rather than duplicating a tiny "match this regex, return group 1"
#     function twice, this factory builds both from one shared
#     implementation.
#
# RESPONSIBILITIES
#     - Return a function that matches a source line against the given
#       pattern.
#     - That returned function extracts the pattern's captured
#       module/namespace name on a match, with an empty bound_names
#       list.
#
# PROCESS OVERVIEW
#     1. Define a closure that matches a line against pattern.
#     2. On a match, that closure returns (captured_name, []).
#     3. On no match, that closure returns None.
#     4. Return the closure itself, not its result.
#
# IMPORTANT DETAILS
#     - The returned function has the same shape as
#       extract_js/extract_python/etc: it takes one source line and
#       returns (module_key, []) or None, so it can be dropped
#       directly into the EXTRACTORS dispatch table.
#
# PARAMETERS
#     pattern (re.Pattern)
#         A compiled regex with one capture group for the
#         module/namespace name, anchored to match from the start of a
#         line.
#
# RETURNS
#     Callable[[str], tuple[str, list] or None]
#         A function that takes one source line and returns
#         (module_key, []) on a match, or None otherwise.
#
# FAILURE CASES
#     - None; the returned function itself never raises, and returns
#       None on no match.
################################################################################
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


################################################################################
# FUNCTION: module_matches
#
# PURPOSE
#     Decides whether an import's module_key (as extracted by an
#     EXTRACTORS function) actually refers to a given dependency name
#     (from a LIST_DEPS function). Every ecosystem resolves an import
#     string to a package name by a different convention (npm scoped
#     packages, Python's hyphen/underscore ambiguity, Java's groupId
#     prefix matching, PHP's PSR-4 namespace mapping, etc.); this is the
#     single place all of those conventions are encoded, so
#     scan_usage_for_ecosystem() doesn't need to know any
#     ecosystem-specific details itself.
#
# RESPONSIBILITIES
#     - Apply the correct matching rule for the given ecosystem.
#     - Return whether module_key refers to dep_name (or, for Java,
#       dep_match_key) under that rule.
#
# PROCESS OVERVIEW
#     1. Look at which ecosystem was given.
#     2. Apply that ecosystem's specific matching rule (see IMPORTANT
#        DETAILS for each one) to module_key and dep_name/dep_match_key.
#     3. Return the boolean result.
#     4. For any ecosystem not explicitly handled, return False.
#
# IMPORTANT DETAILS
#     - javascript: a scoped package ("@scope/pkg/sub/path") matches on
#       its first two path segments; an unscoped package matches on its
#       first segment only.
#     - python: PyPI package names and importable module names
#       sometimes differ only by hyphen-vs-underscore, so both the
#       literal names and their hyphen/underscore-normalized forms are
#       compared. A genuine name-vs-import mismatch (e.g.
#       beautifulsoup4/bs4) isn't recoverable from text alone.
#     - java: dep_match_key is the groupId (see list_java_deps()); an
#       import matches if it's exactly that groupId or a sub-package of
#       it.
#     - php: PHP namespaces are PSR-4-mapped by the package author and
#       aren't derivable from the composer "vendor/package" name in
#       general. This guesses the common convention (CamelCase each
#       segment of the vendor name) and will miss packages that don't
#       follow it, that's the tradeoff for getting any signal at all
#       out of a static regex sweep.
#     - cpp: compares the header path's first segment against the
#       Conan/vcpkg package name, a best-effort convention (e.g.
#       #include <fmt/format.h> -> "fmt"), not guaranteed since header
#       layout is author-chosen, not registry-enforced.
#
# PARAMETERS
#     ecosystem (str)
#         Which ecosystem's matching rule to apply.
#     module_key (str)
#         The import path/module string extracted from source, e.g.
#         "@scope/pkg/sub" or "org.springframework.web".
#     dep_name (str)
#         The dependency name from the manifest to test against.
#     dep_match_key (str or None)
#         For java only, the groupId to match against instead of
#         dep_name.
#
# RETURNS
#     bool
#         True if module_key is considered to refer to dep_name (or,
#         for java, dep_match_key) under that ecosystem's naming
#         convention; False otherwise, including for any ecosystem not
#         explicitly handled.
#
# FAILURE CASES
#     - Ecosystem not explicitly handled: returns False.
################################################################################
def module_matches(ecosystem, module_key, dep_name, dep_match_key=None):
    """Does an import's module_key (from an EXTRACTORS function) refer to
    dep_name (a name from a LIST_DEPS function)? Ecosystem-specific because
    every language resolves an import string to a package name differently."""
    if ecosystem == "javascript":
        # Scoped packages ("@scope/pkg/sub/path") match on the first two
        # path segments; unscoped packages match on the first segment only.
        if module_key.startswith("@"):
            scoped_path_parts = module_key.split("/")
            if len(scoped_path_parts) > 1:
                module_key = "/".join(scoped_path_parts[:2])
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
        vendor_name, _, package_name = dep_name.partition("/")
        guessed_vendor_namespace_segment = "".join(
            word.capitalize() for word in re.split(r"[-_]", vendor_name))
        return module_key.startswith(guessed_vendor_namespace_segment)
    if ecosystem == "cpp":
        # Header path's first segment vs. the Conan/vcpkg package name, a
        # best-effort convention (e.g. #include <fmt/format.h> -> "fmt"),
        # not guaranteed since header layout is author-chosen, not
        # registry-enforced.
        return module_key.lower() == dep_name.lower()
    return False


# ===== USAGE MODE =====

# These thresholds are hand-picked heuristics documented in SKILL.md
# Step 1, not derived from any formula. If you change one, update
# SKILL.md's Step 1 to match, or the skill's own explanation of these
# tiers will silently go stale.
HEAVY_FILES_IMPORTING_THRESHOLD = 5
HEAVY_CALL_SITE_COUNT_THRESHOLD = 20
MODERATE_FILES_IMPORTING_THRESHOLD = 3
MINIMAL_CALL_SITE_COUNT_THRESHOLD = 2
MINIMAL_FILES_IMPORTING_THRESHOLD = 1
LIGHT_CALL_SITE_COUNT_THRESHOLD = 6

################################################################################
# FUNCTION: usage_tier
#
# PURPOSE
#     Buckets a dependency's usage into one of four rough tiers based
#     on how many files import it and how many call sites were found,
#     turning two raw numbers into a single human-readable signal the
#     dead-weight-detector skill can act on directly.
#
# RESPONSIBILITIES
#     - Treat a missing call site count as equivalent to the files
#       importing count.
#     - Apply the hand-picked thresholds, in order, to decide the tier.
#
# PROCESS OVERVIEW
#     1. If call_site_count is None, use files_importing in its place.
#     2. If files_importing or call_site_count is high enough, return
#        "heavy".
#     3. Otherwise, if files_importing is moderately high, return
#        "moderate".
#     4. Otherwise, if both numbers are very low, return "minimal".
#     5. Otherwise, if call_site_count is still fairly low, return
#        "light".
#     6. Otherwise, return "moderate".
#
# IMPORTANT DETAILS
#     - These are heuristic cutoffs, not a precise measurement; see
#       SKILL.md Step 1 for the caveats. Keep the threshold constants
#       above in sync with the thresholds documented there if they
#       ever change.
#     - Never called with files_importing == 0; the caller reports
#       "unused" itself in that case, see scan_usage_for_ecosystem().
#
# PARAMETERS
#     files_importing (int)
#         Number of distinct files that import this dependency.
#     call_site_count (int or None)
#         Approximate number of times a bound symbol from this
#         dependency is referenced; if None, files_importing is used
#         in its place (this happens for weak-signal ecosystems or
#         side-effect-only imports, see scan_usage_for_ecosystem()).
#
# RETURNS
#     str
#         One of "heavy", "moderate", "light", "minimal".
#
# FAILURE CASES
#     - None.
################################################################################
def usage_tier(files_importing, call_site_count):
    """Heuristic cutoffs, not a precise measurement, see SKILL.md Step 1
    for the caveats. Keep these in sync with the thresholds documented
    there if they ever change."""
    if call_site_count is None:
        call_site_count = files_importing
    if files_importing >= HEAVY_FILES_IMPORTING_THRESHOLD or call_site_count > HEAVY_CALL_SITE_COUNT_THRESHOLD:
        return "heavy"
    if files_importing >= MODERATE_FILES_IMPORTING_THRESHOLD:
        return "moderate"
    if call_site_count <= MINIMAL_CALL_SITE_COUNT_THRESHOLD and files_importing <= MINIMAL_FILES_IMPORTING_THRESHOLD:
        return "minimal"
    if call_site_count <= LIGHT_CALL_SITE_COUNT_THRESHOLD:
        return "light"
    return "moderate"


################################################################################
# FUNCTION: scan_usage_for_ecosystem
#
# PURPOSE
#     For one ecosystem's dependencies, sweeps every matching source
#     file for import statements, counts how many files import each
#     dependency and (where possible) how many times its bound symbols
#     are actually referenced, and assigns a usage tier to each. This
#     is the core of usage mode: turning "what's declared as a
#     dependency" plus "what's actually imported/used in source" into
#     one usage report per dependency.
#
# RESPONSIBILITIES
#     - Build a de-duplicated index of dependencies to search for.
#     - Sweep every source file with a matching extension for import
#       statements.
#     - Match each import back to a dependency via module_matches().
#     - Count files-importing and (where possible) call-site totals
#       per dependency.
#     - Assign a usage tier to each dependency.
#
# PROCESS OVERVIEW
#     1. If dependency_entries is empty, return an empty list.
#     2. Build a de-duplicated dependency index: for java, dedupe by
#        display name (a multi-module pom can list the same artifact
#        more than once); for every other ecosystem, dedupe by name.
#     3. Start a zeroed usage-tracking entry for every dependency in
#        that index.
#     4. For each source file with a matching extension, extract every
#        recognized import line and match each one against every
#        dependency in the index.
#     5. For each dependency matched in that file, record the file as
#        an importer, record its bound symbol names, and either count
#        the raw import-line occurrences (for weak-signal ecosystems or
#        side-effect-only imports) or count whole-word occurrences of
#        each bound symbol elsewhere in the file.
#     6. Once every file has been swept, build one result entry per
#        dependency: its files-importing count, call-site count (or
#        None if no real bound symbol was ever found), sorted distinct
#        symbols used, computed usage tier (or "unused" if never
#        imported), and usage signal ("weak" or "standard").
#     7. Return the result entries, sorted by name.
#
# IMPORTANT DETAILS
#     - Counting a bound symbol's call sites is an approximation, not
#       an exact count: it can overcount when the symbol name also
#       shows up inside the import path/module string itself, and it
#       can't distinguish a real call from an unrelated variable that
#       happens to share the name. See SKILL.md's usage caveats.
#     - call_site_count is only meaningful once a real bound symbol has
#       been seen to search for; weak-signal ecosystems always report
#       their import-count-only total instead, via usage_signal
#       "weak".
#     - A malformed/unreadable source file is skipped via
#       read_text()'s empty-string fallback, not treated as an error.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     ecosystem (str)
#         Which ecosystem's extractor/matcher rules to use.
#     dependency_entries (list)
#         (name, manifest_file) pairs for most ecosystems, or
#         (matching_key, manifest_file, display_name) triples for java
#         specifically (see list_java_deps()).
#
# RETURNS
#     list[dict]
#         One entry per distinct dependency name, each with "name",
#         "files_importing", "call_site_count", "distinct_symbols_used",
#         "usage_tier", and "usage_signal". Sorted by name. Empty list
#         if dependency_entries is empty.
#
# FAILURE CASES
#     - dependency_entries is empty: returns an empty list.
################################################################################
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
        dependency_index = []
        for display_name, dependency_info in java_dep_by_display_name.items():
            dependency_index.append((display_name, dependency_info["match_key"], dependency_info["manifest"]))
    else:
        distinct_dependency_names = set()
        for name, _manifest in dependency_entries:
            distinct_dependency_names.add(name)
        dependency_index = []
        for name in sorted(distinct_dependency_names):
            dependency_index.append((name, None, None))

    usage_by_name = {}
    for name, _match_key, _manifest in dependency_index:
        usage_by_name[name] = {"files_importing": 0, "call_site_count": 0, "symbols": set()}

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
        if usage["symbols"] or weak_signal:
            call_site_count = usage["call_site_count"]
        else:
            call_site_count = None

        if usage["files_importing"]:
            dependency_usage_tier = usage_tier(usage["files_importing"], call_site_count)
        else:
            dependency_usage_tier = "unused"

        if weak_signal:
            usage_signal = "weak"
        else:
            usage_signal = "standard"

        results.append({
            "name": name,
            "files_importing": usage["files_importing"],
            "call_site_count": call_site_count,
            "distinct_symbols_used": sorted(usage["symbols"]),
            "usage_tier": dependency_usage_tier,
            "usage_signal": usage_signal,
        })
    return sorted(results, key=lambda entry: entry["name"])


################################################################################
# FUNCTION: run_usage
#
# PURPOSE
#     Runs every ecosystem's dependency lister, then the usage scan,
#     for whichever ecosystems actually have dependencies in this
#     repo. This is the top-level function for usage mode's "usage
#     <path>" CLI invocation.
#
# RESPONSIBILITIES
#     - Run every ecosystem's LIST_DEPS lister against root.
#     - For every ecosystem that found at least one dependency, run
#       scan_usage_for_ecosystem() on those dependencies.
#     - Collect the results, keyed by ecosystem.
#
# PROCESS OVERVIEW
#     1. For each ecosystem in LIST_DEPS, list its dependencies.
#     2. If that ecosystem has no dependencies, skip it entirely.
#     3. Otherwise, run scan_usage_for_ecosystem() and record the
#        result under that ecosystem's key.
#     4. Return the collected results.
#
# IMPORTANT DETAILS
#     - Ecosystems with zero dependencies are omitted entirely from
#       the result, rather than included with an empty list.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     dict
#         {ecosystem: [usage entry, ...]}, one key per ecosystem that
#         has at least one dependency, using the same entry shape
#         returned by scan_usage_for_ecosystem().
#
# FAILURE CASES
#     - None expected.
################################################################################
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

################################################################################
# FUNCTION: resolve_version_javascript
#
# PURPOSE
#     Resolves the pinned version of an npm package from whichever
#     JavaScript lockfile is present. health mode needs the exact
#     installed version to scope its OSV.dev vulnerability query
#     correctly (see the module docstring); this dispatches to the
#     right lockfile-specific resolver.
#
# RESPONSIBILITIES
#     - Try each lockfile-specific resolver in turn.
#     - Return the first resolved version found.
#
# PROCESS OVERVIEW
#     1. Try _resolve_version_package_lock_json().
#     2. If that found nothing, try _resolve_version_yarn_lock().
#     3. If that found nothing, try _resolve_version_pnpm_lock().
#
# IMPORTANT DETAILS
#     - Tried in that order, first match wins.
#
# PARAMETERS
#     root (str)
#         Repo root, used to locate the lockfile.
#     name (str)
#         npm package name to resolve.
#
# RETURNS
#     str or None
#         The resolved version string, or None if no lockfile has an
#         entry for name.
#
# FAILURE CASES
#     - No lockfile has an entry for name: returns None.
################################################################################
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


################################################################################
# FUNCTION: _resolve_version_package_lock_json
#
# PURPOSE
#     Resolves a package's version from package-lock.json, handling
#     both the modern (v2/v3) and legacy (v1) shapes. npm changed
#     package-lock.json's internal structure between major lockfile
#     versions; this isolates that version-shape handling from the
#     rest of resolve_version_javascript().
#
# RESPONSIBILITIES
#     - Find package-lock.json files.
#     - Check the v2/v3 flat "packages" map shape first.
#     - Check the v1 nested "dependencies" map shape if the v2/v3 shape
#       didn't have an entry.
#
# PROCESS OVERVIEW
#     1. Find package-lock.json files under root.
#     2. Parse each one as JSON.
#     3. Check its "packages" map (v2/v3 shape) for a
#        "node_modules/<name>" entry with a version.
#     4. If not found there, check its "dependencies" map (v1 shape)
#        for a <name> entry with a version.
#     5. Return the first version found, or None if neither shape has
#        an entry for name.
#
# IMPORTANT DETAILS
#     - None.
#
# PARAMETERS
#     root (str)
#         Repo root, used to locate package-lock.json.
#     name (str)
#         npm package name to resolve.
#
# RETURNS
#     str or None
#         The resolved version, or None if not found in either
#         lockfile shape.
#
# FAILURE CASES
#     - No package-lock.json, or neither shape has an entry for name:
#       returns None.
################################################################################
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


################################################################################
# FUNCTION: _resolve_version_yarn_lock
#
# PURPOSE
#     Resolves a package's version from a classic (v1) format yarn.lock
#     file. yarn.lock isn't JSON, TOML, or YAML, it's its own
#     lightly-structured text format; this hand-rolled block
#     splitter/matcher is what makes it readable without a dedicated
#     parser dependency.
#
# RESPONSIBILITIES
#     - Split the lockfile into entry blocks.
#     - Find each block's unindented header line.
#     - Match the block whose header's comma-separated `name@range`
#       list includes the target package.
#     - Extract that block's `version "X.Y.Z"` line.
#
# PROCESS OVERVIEW
#     1. Find yarn.lock files under root.
#     2. Split each file's text on blank lines into entry blocks.
#     3. Within each block, find the header line: unindented,
#        non-comment, ending in ":".
#     4. If that header's comma-separated `name@range` list matches
#        the target package, search the rest of the block for its
#        `version "X.Y.Z"` line and return that version.
#
# IMPORTANT DETAILS
#     - Only classic v1-format yarn.lock is handled; Yarn Berry (v2+)
#       uses a different syntax entirely and isn't parsed here.
#     - A block's header line isn't necessarily its first line, since a
#       leading "#" comment can share a block with the header it
#       precedes.
#
# PARAMETERS
#     root (str)
#         Repo root, used to locate yarn.lock.
#     name (str)
#         npm package name to resolve.
#
# RETURNS
#     str or None
#         The resolved version, or None if not found.
#
# FAILURE CASES
#     - No yarn.lock, or no matching block found: returns None.
################################################################################
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
            header = None
            for line in lines:
                if line.rstrip().endswith(":") and not line.startswith((" ", "\t", "#")):
                    header = line
                    break
            if not header or not header_pattern.search(header):
                continue
            for line in lines:
                match = re.match(r'^\s*version\s+"([^"]+)"', line)
                if match:
                    return match.group(1)
    return None


################################################################################
# FUNCTION: _resolve_version_pnpm_lock
#
# PURPOSE
#     Resolves a package's version from pnpm-lock.yaml's "packages:"
#     section. No YAML parser is available in this stdlib-only tool, so
#     pnpm's lockfile is read with a regex scan instead, handling both
#     its older ("/name@version:") and newer v9
#     ("name@version:" or "name@version(peerDep@version):") key
#     formats.
#
# RESPONSIBILITIES
#     - Find pnpm-lock.yaml files.
#     - Track when the current line is inside the "packages:" section.
#     - Match a package key line for the target package, in either the
#       older or newer key format.
#
# PROCESS OVERVIEW
#     1. Find pnpm-lock.yaml files under root.
#     2. For each one, track whether the current line is inside the
#        "packages:" section.
#     3. Inside that section, match each line against the target
#        package's key pattern, stopping the version capture at the
#        first "(" or ":".
#     4. Return the first version found.
#
# IMPORTANT DETAILS
#     - An unindented line inside the "packages:" section means the
#       next top-level YAML key has been reached, i.e. the "packages:"
#       section has ended.
#
# PARAMETERS
#     root (str)
#         Repo root, used to locate pnpm-lock.yaml.
#     name (str)
#         npm package name to resolve.
#
# RETURNS
#     str or None
#         The resolved version, or None if not found.
#
# FAILURE CASES
#     - No pnpm-lock.yaml, or no matching package key: returns None.
################################################################################
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


################################################################################
# FUNCTION: resolve_version_python
#
# PURPOSE
#     Resolves a package's pinned version from a pinned
#     requirements.txt/setup.py/setup.cfg entry, or from poetry.lock,
#     uv.lock, or Pipfile.lock, the Python-specific version resolver
#     for health mode.
#
# RESPONSIBILITIES
#     - Check requirements.txt lines for an exact "==" pin.
#     - Check setup.cfg's and setup.py's install_requires entries for
#       an exact "==" pin.
#     - Check poetry.lock/uv.lock's [[package]] blocks for a matching
#       name.
#     - Check Pipfile.lock's default/develop sections for a matching
#       name.
#
# PROCESS OVERVIEW
#     1. Check every requirements.txt line for an exact "=="-pinned
#        match on name.
#     2. Check every setup.cfg's install_requires entries the same way.
#     3. Check every setup.py's install_requires entries the same way.
#     4. Check every poetry.lock/uv.lock's [[package]] blocks for a
#        name match, and return that block's version.
#     5. Check every Pipfile.lock's default and develop sections for a
#        name match, and return that entry's version.
#     6. Return None if none of the above found a match.
#
# IMPORTANT DETAILS
#     - name is matched case-insensitively throughout.
#     - An unpinned requirements.txt line (e.g. just "requests" with no
#       "=="), or a version range, won't match; only an exact "=="
#       pin is read from requirements/setup files.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     name (str)
#         PyPI package name to resolve, matched case-insensitively.
#
# RETURNS
#     str or None
#         The resolved/pinned version, or None if not found in any of
#         the checked sources.
#
# FAILURE CASES
#     - No pinned entry found in any checked source: returns None.
################################################################################
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


################################################################################
# FUNCTION: resolve_version_go
#
# PURPOSE
#     Resolves a Go module's pinned version straight from go.mod, the
#     Go-specific version resolver for health mode. Unlike other
#     ecosystems, Go pins the exact version right in the manifest
#     itself, so no separate lockfile lookup is needed here.
#
# RESPONSIBILITIES
#     - Find go.mod files.
#     - Match the target module's require line and extract its version.
#
# PROCESS OVERVIEW
#     1. Find go.mod files under root.
#     2. For each line, check whether it matches the target module
#        name followed by a version.
#     3. Return the first version found.
#
# IMPORTANT DETAILS
#     - None.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     name (str)
#         Go module path to resolve.
#
# RETURNS
#     str or None
#         The version string (including its "v" prefix, e.g.
#         "v1.2.3"), or None if not found in go.mod.
#
# FAILURE CASES
#     - No go.mod, or no matching require line: returns None.
################################################################################
def resolve_version_go(root, name):
    """Resolved version straight from go.mod's require line, Go pins the
    version right there, no separate lockfile lookup needed."""
    for go_mod_file in find_files(root, names={"go.mod"}):
        for line in read_text(go_mod_file).splitlines():
            match = re.match(r"^\s*" + re.escape(name) + r"\s+(v\S+)", line.strip())
            if match:
                return match.group(1)
    return None


################################################################################
# FUNCTION: resolve_version_rust
#
# PURPOSE
#     Resolves a crate's pinned version from the matching [[package]]
#     block in Cargo.lock, the Rust-specific version resolver for
#     health mode.
#
# RESPONSIBILITIES
#     - Find Cargo.lock files.
#     - Split each one into [[package]] blocks.
#     - Match the block whose name field equals the target crate name.
#
# PROCESS OVERVIEW
#     1. Find Cargo.lock files under root.
#     2. Split each file's text into [[package]] blocks.
#     3. For each block, extract its name and version fields.
#     4. Return the version of the first block whose name matches.
#
# IMPORTANT DETAILS
#     - name is matched case-sensitively; crates.io names are
#       effectively case-sensitive-normalized already.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     name (str)
#         Crate name to resolve.
#
# RETURNS
#     str or None
#         The resolved version, or None if not found.
#
# FAILURE CASES
#     - No Cargo.lock, or no matching block: returns None.
################################################################################
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


################################################################################
# FUNCTION: resolve_version_ruby
#
# PURPOSE
#     Resolves a gem's pinned version from Gemfile.lock's specs: block,
#     the Ruby-specific version resolver for health mode.
#
# RESPONSIBILITIES
#     - Find Gemfile.lock files.
#     - Match the target gem's 4-space-indented specs: line and extract
#       its version.
#
# PROCESS OVERVIEW
#     1. Find Gemfile.lock files under root.
#     2. Search each one for a 4-space-indented line naming the target
#        gem, followed by its version in parentheses.
#     3. Return the first version found.
#
# IMPORTANT DETAILS
#     - None.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     name (str)
#         Gem name to resolve.
#
# RETURNS
#     str or None
#         The resolved version, or None if not found.
#
# FAILURE CASES
#     - No Gemfile.lock, or no matching line: returns None.
################################################################################
def resolve_version_ruby(root, name):
    """Resolved version from the gem's line in Gemfile.lock's specs:
    block, e.g. "    rails (7.0.0)"."""
    for lockfile in find_files(root, names={"Gemfile.lock"}):
        match = re.search(r"^\s{4}" + re.escape(name) + r"\s+\(([^)]+)\)", read_text(lockfile), re.MULTILINE)
        if match:
            return match.group(1)
    return None


################################################################################
# FUNCTION: resolve_version_php
#
# PURPOSE
#     Resolves a package's pinned version from composer.lock, the
#     PHP-specific version resolver for health mode.
#
# RESPONSIBILITIES
#     - Find composer.lock files.
#     - Search both the packages and packages-dev arrays for a
#       matching entry.
#
# PROCESS OVERVIEW
#     1. Find composer.lock files under root.
#     2. Parse each one as JSON.
#     3. Search its packages and packages-dev arrays for an entry
#        whose name matches and that has a version.
#     4. Return the first matching version found.
#
# IMPORTANT DETAILS
#     - None.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     name (str)
#         "vendor/package" name to resolve.
#
# RETURNS
#     str or None
#         The resolved version, or None if not found in either the
#         packages or packages-dev array.
#
# FAILURE CASES
#     - No composer.lock, or no matching entry: returns None.
################################################################################
def resolve_version_php(root, name):
    """Resolved version from the matching entry in composer.lock's
    packages/packages-dev arrays."""
    for lockfile in find_files(root, names={"composer.lock"}):
        composer_lock_contents = read_json(lockfile)
        if not isinstance(composer_lock_contents, dict):
            continue
        for section in ("packages", "packages-dev"):
            for package_entry in (composer_lock_contents.get(section) or []):
                if isinstance(package_entry, dict) and package_entry.get("name") == name \
                        and package_entry.get("version"):
                    return package_entry["version"]
    return None


# pubspec.lock blocks are short in practice; this is a practical cap on
# how far to look ahead for a package's version: line, not a spec-defined
# limit.
PUBSPEC_LOCK_VERSION_LOOKAHEAD_LINES = 8

################################################################################
# FUNCTION: resolve_version_dart
#
# PURPOSE
#     Resolves a package's pinned version from its block in
#     pubspec.lock, the Dart-specific version resolver for health mode.
#
# RESPONSIBILITIES
#     - Find pubspec.lock files.
#     - Locate the target package's block by its unindented name line.
#     - Look ahead within that block for its version line.
#
# PROCESS OVERVIEW
#     1. Find pubspec.lock files under root.
#     2. For each line, check whether it is the target package's
#        2-space-indented name line.
#     3. If so, look ahead up to PUBSPEC_LOCK_VERSION_LOOKAHEAD_LINES
#        lines for a "version:" line, stopping early if the next
#        top-level entry is reached first.
#     4. Return the first version found.
#
# IMPORTANT DETAILS
#     - The version line lives a few lines below the package name,
#       inside its block, not on the name line itself.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     name (str)
#         Package name to resolve.
#
# RETURNS
#     str or None
#         The resolved version, or None if not found.
#
# FAILURE CASES
#     - No pubspec.lock, or no matching block: returns None.
################################################################################
def resolve_version_dart(root, name):
    """Resolved version from the package's block in pubspec.lock."""
    for lockfile in find_files(root, names={"pubspec.lock"}):
        lines = read_text(lockfile).splitlines()
        for line_index, line in enumerate(lines):
            if re.match(r"^  " + re.escape(name) + r":\s*$", line):
                # Version lives a few lines below the package name, inside
                # its block; stop looking once we hit the next top-level entry.
                lookahead_end_index = min(line_index + PUBSPEC_LOCK_VERSION_LOOKAHEAD_LINES, len(lines))
                for lookahead_index in range(line_index + 1, lookahead_end_index):
                    match = re.match(r'^\s+version:\s*"([^"]+)"', lines[lookahead_index])
                    if match:
                        return match.group(1)
                    if re.match(r"^  \S", lines[lookahead_index]):
                        break
    return None


################################################################################
# FUNCTION: resolve_version_java
#
# PURPOSE
#     Resolves a "group:artifact" pair's version from pom.xml,
#     build.gradle(.kts), or ivy.xml, the Java-specific version
#     resolver for health mode. Unlike most ecosystems, this reads a
#     declared version straight from the manifest (Maven/Gradle/Ivy
#     all pin the version at the declaration site itself); it isn't a
#     lockfile lookup, since none of these three formats has one.
#
# RESPONSIBILITIES
#     - Split group_artifact into its groupId and artifactId.
#     - Check pom.xml's matching <dependency> tag for a <version>.
#     - Check build.gradle/build.gradle.kts's matching dependency
#       string for a version segment.
#     - Check ivy.xml's matching <dependency> tag for a rev attribute.
#
# PROCESS OVERVIEW
#     1. Split group_artifact into groupId and artifactId.
#     2. Search pom.xml files for a <dependency> tag with matching
#        <groupId>/<artifactId> and an explicit <version>.
#     3. Search build.gradle/build.gradle.kts files for a
#        "group:artifact:version" string matching groupId and
#        artifactId.
#     4. Search ivy.xml files for a <dependency> tag with matching
#        org/name attributes and a rev attribute.
#     5. Return the first version found.
#
# IMPORTANT DETAILS
#     - Returns None if the version isn't a literal (e.g. a Gradle
#       version catalog reference), since only literal version strings
#       are matched by these regexes.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     group_artifact (str)
#         "groupId:artifactId" pair to resolve.
#
# RETURNS
#     str or None
#         The declared version, or None if not found.
#
# FAILURE CASES
#     - No matching manifest entry found: returns None.
################################################################################
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


################################################################################
# FUNCTION: resolve_version_dotnet
#
# PURPOSE
#     Resolves a NuGet package's version from a .csproj's
#     <PackageReference> Version attribute, or from paket.lock, the
#     .NET-specific version resolver for health mode, covering both
#     the built-in NuGet CLI convention and Paket.
#
# RESPONSIBILITIES
#     - Check every .csproj's matching <PackageReference> tag for a
#       Version attribute.
#     - Check every paket.lock's matching entry for a version.
#
# PROCESS OVERVIEW
#     1. Search .csproj files for a <PackageReference Include="name"
#        Version="..."> tag.
#     2. If found, return its version.
#     3. Otherwise, search paket.lock files for the package's
#        4-space-indented "Name (Version)" entry.
#     4. Return the first version found.
#
# IMPORTANT DETAILS
#     - paket.lock uses the same 4-space-indent convention as
#       resolve_version_ruby's Gemfile.lock lookup.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     name (str)
#         Package id to resolve.
#
# RETURNS
#     str or None
#         The declared/resolved version, or None if not found.
#
# FAILURE CASES
#     - No matching .csproj or paket.lock entry: returns None.
################################################################################
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


################################################################################
# FUNCTION: resolve_version_cpp
#
# PURPOSE
#     Resolves a Conan package's version from conan.lock or, failing
#     that, a pinned version in conanfile.txt, the C/C++-specific
#     version resolver for health mode. vcpkg has no per-package
#     pinned version to resolve (see FAILURE CASES), so this only ever
#     finds a version for Conan-managed packages.
#
# RESPONSIBILITIES
#     - Check conan.lock's requires/build_requires/tool_requires lists
#       for a matching package reference.
#     - Check conanfile.txt's [requires] line for a matching pinned
#       version if conan.lock had no match.
#
# PROCESS OVERVIEW
#     1. Search conan.lock's requires, build_requires, and
#        tool_requires lists for a "name/version#rev%ts" reference
#        string whose name matches.
#     2. If found, strip the "#rev" and "%ts" suffixes and return the
#        version.
#     3. Otherwise, search conanfile.txt for the target package's
#        pinned "name/version" line.
#     4. Return the first version found.
#
# IMPORTANT DETAILS
#     - The conan.lock format handled here is the Conan 2.x lockfile
#       shape only.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     name (str)
#         Conan package name to resolve.
#
# RETURNS
#     str or None
#         The resolved/pinned version, or None if not found.
#
# FAILURE CASES
#     - No matching conan.lock or conanfile.txt entry: returns None.
#     - Project only uses vcpkg: returns None, since vcpkg pins the
#       whole dependency set via a single builtin-baseline commit in
#       vcpkg.json, not a per-package version, so there's genuinely
#       nothing to resolve there.
################################################################################
def resolve_version_cpp(root, name):
    """Resolved version from conan.lock's requires list ("name/version#rev%ts"
    reference strings, Conan 2.x lockfile shape only), or the version
    pinned directly in conanfile.txt's [requires] line if no lockfile
    match. Returns None for vcpkg-only projects: vcpkg pins via
    builtin-baseline in vcpkg.json, not a per-package version, so there's
    honestly nothing to resolve there."""
    for lockfile in find_files(root, names={"conan.lock"}):
        conan_lock_contents = read_json(lockfile)
        if isinstance(conan_lock_contents, dict):
            for key in ("requires", "build_requires", "tool_requires"):
                for ref in (conan_lock_contents.get(key) or []):
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


################################################################################
# FUNCTION: resolve_version
#
# PURPOSE
#     Looks up and calls the right resolve_version_* function for a
#     given ecosystem, so run_health() has one call to make instead of
#     a long if/elif chain over every ecosystem.
#
# RESPONSIBILITIES
#     - Look up the ecosystem's resolver in RESOLVE_VERSION.
#     - Call it, catching any parse-related failure.
#
# PROCESS OVERVIEW
#     1. Look up ecosystem's resolver function in RESOLVE_VERSION.
#     2. If there is no registered resolver for this ecosystem, return
#        None.
#     3. Call the resolver with root and name.
#     4. If the resolver raises OSError or re.error, return None
#        instead of propagating.
#     5. Return the resolver's result.
#
# IMPORTANT DETAILS
#     - None.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     ecosystem (str)
#         Which ecosystem's resolver to use.
#     name (str)
#         Package/module name to resolve.
#
# RETURNS
#     str or None
#         The resolved version, or None if ecosystem has no registered
#         resolver, or if the resolver itself found nothing, or raised
#         an OSError/re.error while trying.
#
# FAILURE CASES
#     - Ecosystem has no registered resolver: returns None.
#     - Resolver raises OSError or re.error: returns None instead of
#       propagating.
################################################################################
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

# 10s is long enough for a normal registry response, short enough that
# one slow package doesn't stall a whole health-mode batch.
HTTP_DEFAULT_TIMEOUT_SECONDS = 10

################################################################################
# FUNCTION: http_json
#
# PURPOSE
#     Makes an HTTP request and parses the JSON response, without
#     depending on the third-party `requests` library. This is the one
#     place every registry call in health mode goes through, so
#     timeout/error handling, the User-Agent header, and the "404
#     means confirmed absence" distinction are all consistent no
#     matter which registry is being queried.
#
# RESPONSIBILITIES
#     - Build the request with a consistent User-Agent/Accept header,
#       merging in any extra headers.
#     - JSON-encode the request body, if given.
#     - Make the request and parse its JSON response.
#     - Distinguish a confirmed HTTP 404 from every other failure mode.
#
# PROCESS OVERVIEW
#     1. Build the request headers, starting from the default
#        User-Agent/Accept pair and merging in any extra headers.
#     2. If data was given, JSON-encode it as the request body and add
#        a Content-Type header.
#     3. Send the request.
#     4. On success, parse and return the JSON response body.
#     5. On an HTTP error, return None and whether the status was 404.
#     6. On a network error, timeout, or invalid JSON, return None and
#        False.
#
# IMPORTANT DETAILS
#     - not_found is True only for a confirmed HTTP 404 (package
#       genuinely doesn't exist, or a typo), so callers can tell
#       "definitely absent" apart from "network hiccup, genuinely
#       unknown."
#
# PARAMETERS
#     url (str)
#         Full URL to request.
#     method (str)
#         HTTP method, "GET" or "POST".
#     data (dict or None)
#         If given, JSON-encoded and sent as the request body (used
#         for OSV.dev's POST query).
#     headers (dict or None)
#         Extra headers to merge in on top of the default
#         User-Agent/Accept.
#     timeout (int)
#         Seconds to wait before giving up.
#
# RETURNS
#     tuple[Any or None, bool]
#         (data, not_found). data is the parsed JSON body, or None on
#         any failure. not_found is True only for a confirmed HTTP 404.
#
# FAILURE CASES
#     - Network error, timeout, or invalid JSON: returns (None, False).
#     - HTTP error: returns (None, True) if the status was 404, else
#       (None, False).
################################################################################
def http_json(url, method="GET", data=None, headers=None, timeout=HTTP_DEFAULT_TIMEOUT_SECONDS):
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


################################################################################
# FUNCTION: check_osv
#
# PURPOSE
#     Queries OSV.dev (Open Source Vulnerabilities, a cross-ecosystem
#     public vulnerability database) for known vulnerabilities
#     affecting a package. This is the one live vulnerability signal
#     available for every ecosystem this tool supports, including ones
#     (like C/C++) whose own package registries expose no health
#     metadata at all.
#
# RESPONSIBILITIES
#     - Translate this repo's ecosystem key to OSV's own ecosystem
#       name.
#     - Build and send the OSV.dev query, scoped to a version when one
#       is given.
#     - Report whether the query was version-scoped, so callers can
#       tell a confirmed hit from an unscoped one.
#
# PROCESS OVERVIEW
#     1. Translate ecosystem to OSV's own ecosystem name.
#     2. If there's no OSV mapping for this ecosystem, return an
#        "unavailable" result immediately.
#     3. Build the query, including a version field only if version
#        was given.
#     4. Send the query to OSV.dev.
#     5. If the request failed, return an "unknown" result.
#     6. Otherwise, collect every returned vulnerability's id and
#        return an "ok" result.
#
# IMPORTANT DETAILS
#     - version_scoped is True only when a version was supplied.
#       Callers (see health_tier()) must not treat an unscoped hit as
#       confirming the installed version is vulnerable, since without
#       a version OSV returns every vulnerability ever reported for
#       the package across all versions.
#
# PARAMETERS
#     ecosystem (str)
#         This repo's ecosystem key, translated internally to OSV's
#         own name via OSV_ECOSYSTEM.
#     name (str)
#         Package name to check.
#     version (str or None)
#         The pinned version to scope the query to.
#
# RETURNS
#     dict
#         {"status": "ok"|"unknown"|"unavailable", "vulnerabilities":
#         [vuln_id, ...], "version_scoped": bool}.
#
# FAILURE CASES
#     - Ecosystem has no OSV mapping: returns status "unavailable".
#     - Request fails (network/timeout): returns status "unknown".
################################################################################
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
    if version:
        query = {"version": version, "package": package}
    else:
        query = {"package": package}

    response_data, _not_found = http_json("https://api.osv.dev/v1/query", method="POST", data=query)
    if response_data is None:
        return {"status": "unknown", "vulnerabilities": [], "version_scoped": bool(version)}

    vulnerability_ids = []
    for vulnerability_entry in (response_data.get("vulns") or []):
        vulnerability_ids.append(vulnerability_entry.get("id"))
    return {"status": "ok", "vulnerabilities": vulnerability_ids, "version_scoped": bool(version)}


################################################################################
# FUNCTION: health_javascript
#
# PURPOSE
#     Fetches an npm package's latest publish time, maintainer count,
#     deprecation message, and last-month download count, the
#     npm-specific registry health fetcher for health mode.
#
# RESPONSIBILITIES
#     - Fetch the package's registry metadata.
#     - Fetch its last-month download count.
#     - Extract recency, maintainer count, and deprecation message
#       from the registry metadata.
#
# PROCESS OVERVIEW
#     1. Request the package's registry metadata.
#     2. Request its last-month download count.
#     3. If the registry metadata request failed, return a result with
#        every field empty and the appropriate registry_status.
#     4. Otherwise, extract the latest version's publish time,
#        maintainer count, and deprecation message from the metadata,
#        plus the download count from the downloads request.
#
# IMPORTANT DETAILS
#     - A maintainer-set `deprecated` message on the latest version is
#       a stronger abandonment signal than anything inferred from
#       recency/maintainers/downloads alone; see health_tier().
#
# PARAMETERS
#     name (str)
#         npm package name.
#
# RETURNS
#     dict
#         {"recency": ISO timestamp or None, "maintainers": int or
#         None, "downloads": int or None, "deprecated": str or None,
#         "registry_status": "ok"|"not_found"|"failed"}.
#
# FAILURE CASES
#     - Registry metadata request fails: registry_status is
#       "not_found" (confirmed HTTP 404) or "failed" (any other
#       failure), and every other field is None.
################################################################################
def health_javascript(name):
    """Latest publish time, maintainer count, and declared-deprecation
    message (if any) from the npm registry metadata endpoint, plus
    last-month downloads from npm's stats API. A maintainer-set
    `deprecated` message on the latest version is a stronger abandonment
    signal than any inferred one, see health_tier()."""
    registry_data, not_found = http_json(f"https://registry.npmjs.org/{name}")
    downloads_data, _ = http_json(f"https://api.npmjs.org/downloads/point/last-month/{name}")
    if registry_data is None:
        if not_found:
            registry_status = "not_found"
        else:
            registry_status = "failed"
        return {
            "recency": None, "maintainers": None, "downloads": None, "deprecated": None,
            "registry_status": registry_status,
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


################################################################################
# FUNCTION: health_python
#
# PURPOSE
#     Fetches a PyPI package's latest release upload time,
#     yanked/deprecation status, and last-month download count, the
#     Python-specific registry health fetcher for health mode.
#
# RESPONSIBILITIES
#     - Fetch the package's PyPI JSON API metadata.
#     - Determine the latest version's upload time.
#     - Determine whether the latest version's files are all yanked.
#     - Fetch its last-month download count from pypistats.org.
#
# PROCESS OVERVIEW
#     1. Request the package's PyPI JSON API metadata.
#     2. If that request failed, return a result with every field
#        empty and the appropriate registry_status.
#     3. Otherwise, find the latest version's release files and read
#        the first one's upload time.
#     4. If every release file for the latest version is marked
#        "yanked", treat that as a deprecation signal.
#     5. Request the package's last-month download count from
#        pypistats.org.
#     6. Return the combined result.
#
# IMPORTANT DETAILS
#     - "deprecated" is set when every distribution file for the
#       latest version is marked "yanked" on PyPI; that's PyPI's own
#       deprecation signal, surfaced the same way as npm's
#       `deprecated` field.
#     - PyPI's own API stopped exposing download counts years ago;
#       pypistats.org is a third-party service that fills that gap,
#       best-effort.
#
# PARAMETERS
#     name (str)
#         PyPI package name.
#
# RETURNS
#     dict
#         {"recency": ISO timestamp or None, "maintainers": "n/a",
#         "downloads": int or None, "deprecated": str or None,
#         "registry_status": "ok"|"not_found"|"failed"}.
#
# FAILURE CASES
#     - PyPI JSON API request fails: registry_status is "not_found"
#       (confirmed HTTP 404) or "failed" (any other failure), and
#       every other field is None.
################################################################################
def health_python(name):
    """Latest release upload time from PyPI's JSON API (no maintainer
    count, PyPI's API doesn't expose one), plus last-month downloads from
    pypistats.org. If every distribution file for the latest version is
    marked "yanked", that's PyPI's own deprecation signal, surfaced the
    same way as npm's `deprecated` field."""
    registry_data, not_found = http_json(f"https://pypi.org/pypi/{name}/json")
    if registry_data is None:
        if not_found:
            registry_status = "not_found"
        else:
            registry_status = "failed"
        return {
            "recency": None, "maintainers": "n/a", "downloads": None, "deprecated": None,
            "registry_status": registry_status,
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


################################################################################
# FUNCTION: health_go
#
# PURPOSE
#     Fetches a Go module's latest version publish time from Go's
#     official module proxy, the Go-specific registry health fetcher
#     for health mode. Go modules have no concept of maintainer count,
#     download volume, or a deprecation flag, so this reports far less
#     than most other ecosystems' health_* functions.
#
# RESPONSIBILITIES
#     - Lowercase the module path, as the Go module proxy requires.
#     - Fetch the module's latest version metadata.
#     - Extract its publish time.
#
# PROCESS OVERVIEW
#     1. Lowercase the module path.
#     2. Request the module's latest version metadata from the Go
#        module proxy.
#     3. If that request failed, return a result with recency empty
#        and the appropriate registry_status.
#     4. Otherwise, return the publish time from the response.
#
# IMPORTANT DETAILS
#     - The Go module proxy requires the module path to be lowercased.
#       "Case encoding" for modules with uppercase letters is a
#       separate, more complex scheme not implemented here; this
#       simple .lower() is correct for the overwhelming majority of
#       real-world module paths.
#
# PARAMETERS
#     name (str)
#         Go module path.
#
# RETURNS
#     dict
#         {"recency": ISO timestamp or None, "maintainers": "n/a",
#         "downloads": "n/a", "deprecated": None, "registry_status":
#         "ok"|"not_found"|"failed"}.
#
# FAILURE CASES
#     - Module proxy request fails: registry_status is "not_found"
#       (confirmed HTTP 404) or "failed" (any other failure), and
#       recency is None.
################################################################################
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
        if not_found:
            registry_status = "not_found"
        else:
            registry_status = "failed"
        return {
            "recency": None, "maintainers": "n/a", "downloads": "n/a", "deprecated": None,
            "registry_status": registry_status,
        }
    return {
        "recency": registry_data.get("Time"), "maintainers": "n/a", "downloads": "n/a",
        "deprecated": None, "registry_status": "ok",
    }


################################################################################
# FUNCTION: health_rust
#
# PURPOSE
#     Fetches a crate's last-updated time, download count, and owner
#     count from crates.io, the Rust-specific registry health fetcher
#     for health mode.
#
# RESPONSIBILITIES
#     - Fetch the crate's metadata.
#     - Fetch its owner list.
#     - Extract last-updated time, download count, and owner count.
#
# PROCESS OVERVIEW
#     1. Request the crate's metadata.
#     2. If that request failed, return a result with every field
#        empty and the appropriate registry_status.
#     3. Otherwise, request the crate's owners.
#     4. Return the combined result: last-updated time and download
#        count from the metadata, owner count from the owners
#        response.
#
# IMPORTANT DETAILS
#     - crates.io exposes no deprecation flag, so "deprecated" is
#       always None here.
#
# PARAMETERS
#     name (str)
#         Crate name.
#
# RETURNS
#     dict
#         {"recency": ISO timestamp or None, "maintainers": int or
#         None, "downloads": int or None, "deprecated": None,
#         "registry_status": "ok"|"not_found"|"failed"}.
#
# FAILURE CASES
#     - Crate metadata request fails: registry_status is "not_found"
#       (confirmed HTTP 404) or "failed" (any other failure), and
#       every other field is None.
################################################################################
def health_rust(name):
    """Last-updated time and download count from crates.io's crate
    endpoint, plus owner count from its separate owners endpoint. No
    deprecation flag, crates.io exposes none."""
    registry_data, not_found = http_json(f"https://crates.io/api/v1/crates/{name}")
    if registry_data is None:
        if not_found:
            registry_status = "not_found"
        else:
            registry_status = "failed"
        return {
            "recency": None, "maintainers": None, "downloads": None, "deprecated": None,
            "registry_status": registry_status,
        }
    crate = registry_data.get("crate") or {}
    owners_data, _ = http_json(f"https://crates.io/api/v1/crates/{name}/owners")
    if owners_data:
        maintainer_count = len((owners_data or {}).get("users") or [])
    else:
        maintainer_count = None
    return {
        "recency": crate.get("updated_at"),
        "maintainers": maintainer_count,
        "downloads": crate.get("downloads"),
        "deprecated": None,
        "registry_status": "ok",
    }


################################################################################
# FUNCTION: health_ruby
#
# PURPOSE
#     Fetches a gem's version-created time, authors string, and
#     download count from RubyGems, the Ruby-specific registry health
#     fetcher for health mode.
#
# RESPONSIBILITIES
#     - Fetch the gem's metadata.
#     - Extract version-created time, authors string, and download
#       count.
#
# PROCESS OVERVIEW
#     1. Request the gem's metadata.
#     2. If that request failed, return a result with every field
#        empty and the appropriate registry_status.
#     3. Otherwise, return its version-created time, authors string,
#        and download count.
#
# IMPORTANT DETAILS
#     - "maintainers" is really RubyGems' free-text `authors` field,
#       not a real maintainer count; the field is labeled as such.
#     - RubyGems exposes no deprecation flag, so "deprecated" is
#       always None here.
#
# PARAMETERS
#     name (str)
#         Gem name.
#
# RETURNS
#     dict
#         {"recency": ISO timestamp or None, "maintainers": str,
#         "downloads": int or None, "deprecated": None,
#         "registry_status": "ok"|"not_found"|"failed"}.
#
# FAILURE CASES
#     - Gem metadata request fails: registry_status is "not_found"
#       (confirmed HTTP 404) or "failed" (any other failure), and
#       every other field is empty.
################################################################################
def health_ruby(name):
    """Version-created time and download count from RubyGems' gem
    endpoint. "maintainers" is really the free-text `authors` field, not
    a real count, labeled as such. No deprecation flag exposed."""
    registry_data, not_found = http_json(f"https://rubygems.org/api/v1/gems/{name}.json")
    if registry_data is None:
        if not_found:
            registry_status = "not_found"
        else:
            registry_status = "failed"
        return {
            "recency": None, "maintainers": "n/a (authors string, not a count)", "downloads": None,
            "deprecated": None, "registry_status": registry_status,
        }
    return {
        "recency": registry_data.get("version_created_at"),
        "maintainers": registry_data.get("authors", "n/a"),
        "downloads": registry_data.get("downloads"),
        "deprecated": None,
        "registry_status": "ok",
    }


################################################################################
# FUNCTION: health_php
#
# PURPOSE
#     Fetches a Composer package's latest publish time and maintainer
#     count from Packagist, the PHP-specific registry health fetcher
#     for health mode.
#
# RESPONSIBILITIES
#     - Fetch the package's v2 metadata.
#     - Fetch its maintainer list from the separate package-info
#       endpoint.
#     - Extract latest publish time and maintainer count.
#
# PROCESS OVERVIEW
#     1. Request the package's v2 metadata.
#     2. If that request failed, return a result with every field
#        empty and the appropriate registry_status.
#     3. Otherwise, extract the latest version's publish time.
#     4. Request the package's maintainer list from the package-info
#        endpoint and count its entries.
#     5. Return the combined result.
#
# IMPORTANT DETAILS
#     - Packagist exposes no download volume or deprecation flag in
#       this API, so "downloads" is always "n/a" and "deprecated" is
#       always None here.
#
# PARAMETERS
#     vendor_pkg (str)
#         "vendor/package" name.
#
# RETURNS
#     dict
#         {"recency": ISO timestamp or None, "maintainers": int or
#         None, "downloads": "n/a", "deprecated": None,
#         "registry_status": "ok"|"not_found"|"failed"}.
#
# FAILURE CASES
#     - v2 metadata request fails: registry_status is "not_found"
#       (confirmed HTTP 404) or "failed" (any other failure), and
#       every other field is empty.
################################################################################
def health_php(vendor_pkg):
    """Latest version's publish time from Packagist's v2 metadata
    endpoint, plus maintainer count from its separate package-info
    endpoint. No download volume or deprecation flag, Packagist exposes
    neither."""
    registry_data, not_found = http_json(f"https://repo.packagist.org/p2/{vendor_pkg}.json")
    if registry_data is None:
        if not_found:
            registry_status = "not_found"
        else:
            registry_status = "failed"
        return {
            "recency": None, "maintainers": None, "downloads": "n/a", "deprecated": None,
            "registry_status": registry_status,
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


################################################################################
# FUNCTION: health_java
#
# PURPOSE
#     Fetches a Maven artifact's latest index timestamp from Maven
#     Central's search API, the Java-specific registry health fetcher
#     for health mode. Maven Central exposes no maintainer count,
#     download volume, or deprecation flag at all, so this reports the
#     least of any ecosystem here.
#
# RESPONSIBILITIES
#     - Split group_artifact into a groupId and artifactId, if
#       possible.
#     - Build the appropriate Maven Central search query.
#     - Extract the latest matching document's index timestamp.
#
# PROCESS OVERVIEW
#     1. Split group_artifact into groupId and artifactId.
#     2. If there's an artifactId, build a query matching both; if
#        there isn't (a bare artifactId was given as group_artifact),
#        build a query matching just that as an artifactId.
#     3. Request Maven Central's search API with that query.
#     4. If that request failed, return a result with recency empty
#        and the appropriate registry_status.
#     5. Otherwise, return the first matching document's timestamp.
#
# IMPORTANT DETAILS
#     - recency here is a raw Maven Central index timestamp
#       (milliseconds since epoch), not an ISO 8601 string like most
#       other ecosystems' health_* functions return.
#
# PARAMETERS
#     group_artifact (str)
#         "groupId:artifactId" pair, or just a bare artifactId (used
#         as a fallback search term if there's no ":").
#
# RETURNS
#     dict
#         {"recency": epoch-millisecond timestamp or None,
#         "maintainers": "n/a", "downloads": "n/a", "deprecated":
#         None, "registry_status": "ok"|"not_found"|"failed"}.
#
# FAILURE CASES
#     - Search API request fails: registry_status is "not_found"
#       (confirmed HTTP 404) or "failed" (any other failure), and
#       recency is None.
################################################################################
def health_java(group_artifact):
    """Latest version's index timestamp from the Maven Central search API.
    No maintainer count, download volume, or deprecation flag, Maven
    Central exposes none of those."""
    group_id, _, artifact_id = group_artifact.partition(":")
    if artifact_id:
        query = f"g:{group_id}+AND+a:{artifact_id}"
    else:
        query = f"a:{group_id}"
    registry_data, not_found = http_json(f"https://search.maven.org/solrsearch/select?q={query}&core=gav&rows=1&wt=json")
    if not registry_data:
        if not_found:
            registry_status = "not_found"
        else:
            registry_status = "failed"
        return {
            "recency": None, "maintainers": "n/a", "downloads": "n/a", "deprecated": None,
            "registry_status": registry_status,
        }
    docs = ((registry_data.get("response") or {}).get("docs") or [])
    recency = docs[0].get("timestamp") if docs else None
    return {
        "recency": recency, "maintainers": "n/a", "downloads": "n/a",
        "deprecated": None, "registry_status": "ok",
    }


################################################################################
# FUNCTION: health_dotnet
#
# PURPOSE
#     Fetches a NuGet package's latest catalog entry publish time from
#     NuGet's registration API, the .NET-specific registry health
#     fetcher for health mode.
#
# RESPONSIBILITIES
#     - Fetch the package's registration index.
#     - Navigate its paginated version list to the latest catalog
#       entry.
#     - Extract that entry's publish time.
#
# PROCESS OVERVIEW
#     1. Request the package's registration index.
#     2. If that request failed, return a result with recency empty
#        and the appropriate registry_status.
#     3. Otherwise, navigate to the last page's last catalog item and
#        read its publish time, treating any unexpected shape as a
#        missing value rather than raising.
#     4. Return the result.
#
# IMPORTANT DETAILS
#     - No maintainer count, download volume, or deprecation flag;
#       parsing those out of this API reliably isn't worth the
#       guesswork involved.
#
# PARAMETERS
#     name (str)
#         NuGet package id.
#
# RETURNS
#     dict
#         {"recency": ISO timestamp or None, "maintainers": "n/a",
#         "downloads": "n/a", "deprecated": None, "registry_status":
#         "ok"|"not_found"|"failed"}.
#
# FAILURE CASES
#     - Registration index request fails: registry_status is
#       "not_found" (confirmed HTTP 404) or "failed" (any other
#       failure), and recency is None.
#     - Registration index has an unexpected shape (caught via
#       IndexError/KeyError/TypeError): recency is None.
################################################################################
def health_dotnet(name):
    """Latest catalog entry's publish time from NuGet's registration API.
    No maintainer count, download volume, or deprecation flag, parsing
    those out of this API reliably isn't worth the guesswork."""
    registry_data, not_found = http_json(f"https://api.nuget.org/v3/registration5-semver1/{name.lower()}/index.json")
    if not registry_data:
        if not_found:
            registry_status = "not_found"
        else:
            registry_status = "failed"
        return {
            "recency": None, "maintainers": "n/a", "downloads": "n/a", "deprecated": None,
            "registry_status": registry_status,
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


################################################################################
# FUNCTION: health_dart
#
# PURPOSE
#     Fetches a package's latest version publish time and publisher
#     identity from pub.dev, the Dart-specific registry health fetcher
#     for health mode.
#
# RESPONSIBILITIES
#     - Fetch the package's metadata.
#     - Extract the latest version's publish time and the package's
#       publisher.
#
# PROCESS OVERVIEW
#     1. Request the package's metadata.
#     2. If that request failed, return a result with every field
#        empty and the appropriate registry_status.
#     3. Otherwise, return the latest version's publish time and the
#        package's publisher.
#
# IMPORTANT DETAILS
#     - "maintainers" here is a single publisher identity, not a real
#       maintainer count.
#     - pub.dev exposes no download volume or deprecation flag in this
#       API, so "downloads" is always "n/a" and "deprecated" is always
#       None here.
#
# PARAMETERS
#     name (str)
#         Package name.
#
# RETURNS
#     dict
#         {"recency": ISO timestamp or None, "maintainers": str or
#         "n/a", "downloads": "n/a", "deprecated": None,
#         "registry_status": "ok"|"not_found"|"failed"}.
#
# FAILURE CASES
#     - Package metadata request fails: registry_status is
#       "not_found" (confirmed HTTP 404) or "failed" (any other
#       failure), and every other field is empty.
################################################################################
def health_dart(name):
    """Latest version's publish time and publisher (a single identity, not
    a maintainer count) from pub.dev's package API. No download volume or
    deprecation flag, pub.dev exposes neither here."""
    registry_data, not_found = http_json(f"https://pub.dev/api/packages/{name}")
    if not registry_data:
        if not_found:
            registry_status = "not_found"
        else:
            registry_status = "failed"
        return {
            "recency": None, "maintainers": "n/a", "downloads": "n/a", "deprecated": None,
            "registry_status": registry_status,
        }
    return {
        "recency": (registry_data.get("latest") or {}).get("published"),
        "maintainers": registry_data.get("publisher") or "n/a",
        "downloads": "n/a",
        "deprecated": None,
        "registry_status": "ok",
    }


################################################################################
# FUNCTION: health_cpp
#
# PURPOSE
#     Reports that no registry health metadata is available for C/C++
#     packages. Neither ConanCenter nor vcpkg expose a public metadata
#     API comparable to npm/PyPI/crates.io, so rather than guessing or
#     omitting the field entirely, this function makes the
#     "unavailable" state explicit and consistent with every other
#     ecosystem's response shape.
#
# RESPONSIBILITIES
#     - Return the fixed "unavailable" result shape.
#
# PROCESS OVERVIEW
#     1. Return the same fixed dict regardless of input.
#
# IMPORTANT DETAILS
#     - Unlike every other health_* function, this makes no network
#       request at all; there's no endpoint to call. The OSV
#       vulnerability check still runs independently in run_health(),
#       since it's the one live signal available for this ecosystem.
#
# PARAMETERS
#     _name (str)
#         Unused; accepted only so this function matches every other
#         HEALTH_FN entry's one-argument signature.
#
# RETURNS
#     dict
#         {"recency": None, "maintainers": "n/a", "downloads": "n/a",
#         "deprecated": None, "registry_status": "unavailable"}.
#         Always the same value regardless of input.
#
# FAILURE CASES
#     - None.
################################################################################
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


# A flat 30-day month, not calendar-accurate, used only to turn a
# timestamp's age into an approximate number of months for health_tier()'s
# thresholds below.
APPROXIMATE_DAYS_PER_MONTH = 30.0

# These specific cutoffs are documented thresholds in
# references/registry-health-signals.md, not arbitrary; keep both in sync
# if either changes.
STALE_RELEASE_MONTHS_THRESHOLD = 12
ZERO_MAINTAINERS_COUNT = 0
RECENT_RELEASE_MONTHS_THRESHOLD = 3
HEALTHY_MAINTAINER_COUNT_THRESHOLD = 2
HEALTHY_DOWNLOAD_COUNT_THRESHOLD = 10000

################################################################################
# FUNCTION: months_since
#
# PURPOSE
#     Converts an ISO 8601 timestamp string into how many months ago
#     that was, relative to right now. health_tier() needs a single,
#     forgiving timestamp-age calculation that never raises, since
#     different registries format timestamps slightly differently
#     (some use "Z", some an explicit offset, some have no offset at
#     all).
#
# RESPONSIBILITIES
#     - Normalize the timestamp's "Z" suffix, if present, to an
#       explicit "+00:00" offset.
#     - Parse the normalized timestamp.
#     - Assume UTC for a timestamp with no timezone info at all.
#     - Compute the elapsed time in months.
#
# PROCESS OVERVIEW
#     1. If iso_timestamp is falsy, return None immediately.
#     2. Normalize a trailing "Z" to "+00:00".
#     3. Parse the normalized timestamp.
#     4. If the parsed timestamp has no timezone info, assume UTC.
#     5. Compute the elapsed time between now and the parsed timestamp.
#     6. Convert that elapsed time to an approximate number of months
#        and return it.
#     7. If parsing failed at any point, return None instead of
#        raising.
#
# IMPORTANT DETAILS
#     - "Z" (Zulu/UTC) isn't accepted by fromisoformat() on older
#       Python versions; normalizing it to "+00:00" first avoids that
#       incompatibility.
#     - A timestamp with no timezone info at all is assumed to already
#       be UTC. BE CAREFUL if a new registry is added whose timestamps
#       are naive but in local time instead; this assumption would
#       silently misjudge recency for it.
#     - Months are approximated using APPROXIMATE_DAYS_PER_MONTH, not
#       calendar-accurate.
#
# PARAMETERS
#     iso_timestamp (str or None/other)
#         The value to parse; anything falsy short-circuits to None
#         immediately.
#
# RETURNS
#     float or None
#         Approximate months elapsed, or None if iso_timestamp is
#         empty or not parseable.
#
# FAILURE CASES
#     - iso_timestamp is empty, malformed, or otherwise not parseable
#       (ValueError/TypeError): returns None.
################################################################################
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
        return age.days / APPROXIMATE_DAYS_PER_MONTH
    except (ValueError, TypeError):
        return None


################################################################################
# FUNCTION: health_tier
#
# PURPOSE
#     Combines every raw health signal (recency, maintainer count,
#     download volume, vulnerability status, explicit deprecation,
#     curated abandonment) into one overall verdict: healthy, slowing,
#     at_risk, or unknown. This is the single place that decides,
#     given several independent and sometimes-missing signals, what
#     the bottom-line answer is. Keeping that decision in one function
#     means the priority order between signals (a confirmed
#     deprecation always wins, a scoped vulnerability always wins,
#     etc.) is written once and applied consistently.
#
# RESPONSIBILITIES
#     - Give deprecation and curated abandonment the highest priority.
#     - Give a version-scoped vulnerability the next priority.
#     - Normalize recency, maintainers, and downloads to either a real
#       value or "not present."
#     - Apply the documented thresholds to whatever real values remain.
#
# PROCESS OVERVIEW
#     1. If deprecated or abandoned is set, return "at_risk"
#        immediately.
#     2. If vuln_status has vulnerabilities and is version-scoped,
#        return "at_risk" immediately.
#     3. Convert recency to months-since-release if it's a string,
#        else treat it as not present.
#     4. Treat maintainers/downloads as their real int value if they
#        are one, else treat them as not present.
#     5. If none of the three signals could be read as a real value,
#        return "unknown".
#     6. If the release is stale enough, or there are zero
#        maintainers, return "at_risk".
#     7. If the release is recent enough and either the maintainer or
#        download count looks healthy (or maintainer count is
#        unknown), return "healthy".
#     8. Otherwise, return "slowing".
#
# IMPORTANT DETAILS
#     - Any field that isn't a real number (an "n/a" string, a missing
#       value) is treated as not present, not as zero.
#     - A maintainer-declared deprecation (npm's `deprecated` field, a
#       PyPI release with every file yanked) or a hit in the curated
#       abandoned-package list overrides every other signal; these are
#       more precise than any threshold inferred from
#       recency/maintainers/downloads.
#     - A known vulnerability in the version actually pinned overrides
#       every other signal, however healthy the project otherwise
#       looks. An unscoped result (couldn't resolve the pinned
#       version) doesn't get this power; see check_osv()'s docstring
#       for why.
#     - "unknown" is returned only when none of
#       recency/maintainers/downloads could be read as a real value,
#       distinguishing "genuinely can't tell" from "checked and it's
#       fine."
#
# PARAMETERS
#     recency (str or None)
#         ISO 8601 timestamp of the latest release, or a non-string
#         value (like Maven's epoch-millisecond timestamp, or the
#         "n/a" strings some health_* functions return), which is
#         treated as "not present" rather than parsed.
#     maintainers (int, str, or None)
#         Maintainer count if it's a real int; any other type
#         (including "n/a" strings) is treated as "not present."
#     downloads (int, str, or None)
#         Same treatment as maintainers.
#     vuln_status (dict)
#         The dict returned by check_osv().
#     deprecated (str or None)
#         A maintainer-declared deprecation message, if any.
#     abandoned (dict or None)
#         The entry returned by abandoned_packages.lookup(), if any.
#
# RETURNS
#     str
#         One of "at_risk", "healthy", "slowing", "unknown".
#
# FAILURE CASES
#     - None; a malformed recency timestamp is caught internally by
#       months_since() and treated as missing.
################################################################################
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

    if isinstance(recency, str):
        months_since_release = months_since(recency)
    else:
        months_since_release = None

    if isinstance(maintainers, int):
        maintainer_count = maintainers
    else:
        maintainer_count = None

    if isinstance(downloads, int):
        download_count = downloads
    else:
        download_count = None

    if months_since_release is None and maintainer_count is None and download_count is None:
        return "unknown"

    if months_since_release is not None and months_since_release > STALE_RELEASE_MONTHS_THRESHOLD:
        return "at_risk"
    if maintainer_count is not None and maintainer_count == ZERO_MAINTAINERS_COUNT:
        return "at_risk"

    release_is_recent = months_since_release is not None and months_since_release < RECENT_RELEASE_MONTHS_THRESHOLD
    maintainer_or_download_count_looks_healthy = (
        maintainer_count is None
        or maintainer_count >= HEALTHY_MAINTAINER_COUNT_THRESHOLD
        or (download_count is not None and download_count >= HEALTHY_DOWNLOAD_COUNT_THRESHOLD)
    )
    if release_is_recent and maintainer_or_download_count_looks_healthy:
        return "healthy"

    return "slowing"


################################################################################
# FUNCTION: run_health
#
# PURPOSE
#     For each given package name: fetches registry health data,
#     resolves its pinned version, checks OSV.dev for vulnerabilities
#     in that version, checks the curated abandoned-package list, and
#     computes an overall health tier. This is the top-level function
#     for health mode's "health <ecosystem> <repo_path> <name>..." CLI
#     invocation; it's what ties together every other function in
#     this section into one per-package result.
#
# RESPONSIBILITIES
#     - Look up the ecosystem's health_* fetcher, if one exists.
#     - For each name, fetch its registry health data.
#     - Resolve its pinned version, if a repo root was given.
#     - Check OSV.dev for vulnerabilities in that version.
#     - Check the curated abandoned-package list.
#     - Compute an overall health tier from all of the above.
#
# PROCESS OVERVIEW
#     1. Look up the ecosystem's health_* fetcher function.
#     2. For each name in names:
#        a. Fetch its registry health data, or a fixed "unavailable"
#           result if this ecosystem has no health fetcher.
#        b. Resolve its pinned version from root's lockfile, if root
#           was given.
#        c. Check OSV.dev for vulnerabilities in that version.
#        d. Check the curated abandoned-package list.
#        e. Compute its overall health tier.
#        f. Record the combined result under name.
#     3. Return the collected results.
#
# IMPORTANT DETAILS
#     - names should already be triaged/limited by the caller; see the
#       module docstring's note on bounding outbound calls.
#     - If root is None, no version resolution is attempted, and every
#       OSV check runs unscoped.
#
# PARAMETERS
#     ecosystem (str)
#         Which ecosystem's health_*/resolve_version_* functions to
#         use.
#     names (list[str])
#         Package names to check.
#     root (str or None)
#         Repo path to resolve pinned versions from.
#
# RETURNS
#     dict
#         {name: {"pinned_version", "recency", "maintainers",
#         "downloads", "deprecated", "registry_status",
#         "vulnerabilities", "abandoned", "health_tier"}} for every
#         name in names.
#
# FAILURE CASES
#     - None expected; every sub-call already handles its own
#       failures internally.
################################################################################
def run_health(ecosystem, names, root=None):
    """For each name: looks up registry health data, resolves its pinned
    version from root's lockfile (if root is given), checks OSV for
    vulnerabilities in that version, checks the curated abandoned-package
    list, and computes a health tier. Returns {name: {...}}."""
    health_lookup = HEALTH_FN.get(ecosystem)
    results = {}
    for name in names:
        if health_lookup:
            registry_data = health_lookup(name)
        else:
            registry_data = {
                "recency": None, "maintainers": "n/a", "downloads": "n/a", "deprecated": None,
                "registry_status": "unavailable",
            }

        if root:
            pinned_version = resolve_version(root, ecosystem, name)
        else:
            pinned_version = None
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

################################################################################
# FUNCTION: main
#
# PURPOSE
#     Serves as the CLI entry point: reads sys.argv to decide between
#     usage mode and health mode, runs the corresponding function, and
#     prints its result as JSON. This is what actually gets invoked
#     when the script is run from the command line or by the
#     dead-weight-detector skill.
#
# RESPONSIBILITIES
#     - Validate that a mode argument was given.
#     - Parse the remaining arguments according to that mode's shape.
#     - Run the matching top-level function and print its result as
#       JSON.
#
# PROCESS OVERVIEW
#     1. If no mode argument was given, print a usage error and exit
#        with status 1.
#     2. If the mode is "usage", parse the optional path argument
#        (defaulting to "."), run run_usage(), and print its result.
#     3. If the mode is "health", validate that ecosystem, repo_path,
#        and at least one name were given (exiting with status 1 and
#        a usage error if not), then run run_health() and print its
#        result.
#     4. If the mode is neither, print an unknown-mode error and exit
#        with status 1.
#
# IMPORTANT DETAILS
#     - usage mode reads the filesystem only; health mode also makes
#       outbound network requests.
#
# PARAMETERS
#     None
#         Reads sys.argv directly: sys.argv[1] must be "usage" or
#         "health"; the remaining arguments depend on the mode, see
#         the module docstring.
#
# RETURNS
#     None
#         Prints JSON to stdout; calls sys.exit(1) on bad arguments or
#         an unrecognized mode instead of returning normally.
#
# FAILURE CASES
#     - No mode argument given: prints a usage error and exits with
#       status 1.
#     - Mode is "health" but fewer than 3 further arguments were
#       given: prints a usage error and exits with status 1.
#     - Mode is neither "usage" nor "health": prints an unknown-mode
#       error and exits with status 1.
################################################################################
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
