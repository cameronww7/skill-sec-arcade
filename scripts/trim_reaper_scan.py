#!/usr/bin/env python3
# ******************************************************************************
# * TITLE:        Trim Reaper Scan
# * FILE:         trim_reaper_scan.py
# * PART OF:      trim-reaper skill (skill-sec-arcade repo). Imports
# *               cartridge_scan.py's manifest-discovery helpers (walk,
# *               find_files, read_text, read_json, EXCLUDE_DIRS) and
# *               dead_weight_scan.py's import-recognition plumbing
# *               (EXTRACTORS, module_matches, SOURCE_EXTENSIONS,
# *               WEAK_ECOSYSTEMS), the same cross-script reuse pattern
# *               dead_weight_scan.py already uses for cartridge_scan.py.
# * PURPOSE:      Answers three questions no existing script in this repo
# *               answers: (1) which dependencies run code during install
# *               ("lifecycle-scripts"), (2) which dependencies are
# *               version-pinned loosely enough that a routine install
# *               could silently pull a different release
# *               ("unpinned-versions"), and (3) for a candidate
# *               dependency, is there any first-party reference to it at
# *               all, searched across nine separate categories
# *               ("candidates"). All three exist to give trim-reaper's
# *               Phase 0/1 security ranking and removal decisions hard
# *               evidence instead of a guess.
# *
# * HOW IT WORKS: Three independent subcommands, chosen by the first CLI
# *               argument. All three are local-only, read-only sweeps of
# *               the filesystem under <path>, no network access, no
# *               subprocess calls, same safety posture as
# *               cartridge_scan.py.
# *               1) `lifecycle-scripts <path>`: per-ecosystem detection
# *                  of install-time code execution hooks (npm
# *                  pre/post/install scripts, Python setup.py build
# *                  hooks, Rust build.rs, PHP Composer event scripts).
# *                  Honestly reports a dependency as "unverifiable"
# *                  rather than silently clean when its own manifest
# *                  isn't physically present to inspect (e.g. no
# *                  node_modules checkout locally).
# *               2) `unpinned-versions <path>`: classifies every
# *                  declared dependency's version specifier per its
# *                  ecosystem's own grammar into exact/caret/tilde/
# *                  range/wildcard/git_or_url/unknown.
# *               3) `candidates <path>`: for every direct dependency in
# *                  every detected workspace, searches the whole repo
# *                  for any reference to it across nine categories
# *                  (source imports, dynamic loading, string
# *                  references, tool configs, scripts/Makefiles, tests,
# *                  Dockerfiles/CI, peer requirements, side-effect
# *                  imports), plus a type-definition-pair check. Output
# *                  is a candidate list, never proof: a zero-reference
# *                  result means "searched and found nothing," not
# *                  "confirmed unused."
# *               All three print one JSON object to stdout.
# *
# * USAGE:        python3 trim_reaper_scan.py lifecycle-scripts [path]
# *               python3 trim_reaper_scan.py unpinned-versions [path]
# *               python3 trim_reaper_scan.py candidates [path]
# * ARGUMENTS:    mode (positional, str, required) - one of the three
# *               subcommands above. path (positional, str, optional,
# *               default ".") - repo root to scan.
# * INPUTS:       The filesystem under path only. No network access.
# * OUTPUTS:      One JSON object printed to stdout per invocation. No
# *               files written, no prose or markdown, interpretation is
# *               the trim-reaper skill's job.
# * EXIT CODES:   0 = success. 1 = missing/invalid CLI arguments, or an
# *               unrecognized mode.
# * DEPENDENCIES: Python 3 standard library only (ast, json, os, re,
# *               sys). Imports cartridge_scan.py and dead_weight_scan.py
# *               from the same directory, both also stdlib-only.
# * PERMISSIONS:  Read-only filesystem access under path. No network. No
# *               write access anywhere.
# * ASSUMPTIONS:  Safe to *read* (never execute) any file under path,
# *               including an untrusted repo's own setup.py, same reason
# *               cartridge_scan.py's install_requires_from_setup_py()
# *               parses it with ast instead of importing it.
# * FAILURE MODES:A single unreadable or malformed file is skipped rather
# *               than crashing the whole scan, matching
# *               cartridge_scan.py's own tolerance. The "candidates"
# *               search is a heuristic text sweep, not a real parser or
# *               data-flow analysis; it can miss a genuinely obscure
# *               reference (string concatenation building a dynamic
# *               import across several files, for example) and is
# *               designed to err toward over-flagging a dynamic-loading
# *               risk rather than under-flagging it, see
# *               scan_dynamic_loading_risk()'s docstring.
# * SAFE TO RERUN:Yes. Strictly read-only; nothing on disk is created,
# *               modified, or deleted.
# *
# * AUTHOR:       cameronww7
# * LAST UPDATED: 2026-10-24
# ******************************************************************************

"""Trim Reaper Scan: install-script, unpinned-version, and unused-dependency
candidate detection for the trim-reaper skill.

Three independent subcommands:

  lifecycle-scripts <path>
      Local only, no network. Finds dependencies that run code during
      install (npm lifecycle scripts, Python setup.py build hooks, Rust
      build.rs, PHP Composer event scripts). Reports "unverifiable"
      honestly wherever a dependency's own manifest isn't physically
      present to inspect, rather than reporting a false-clean result.

  unpinned-versions <path>
      Local only, no network. Classifies every declared dependency's
      version specifier into exact/caret/tilde/range/wildcard/
      git_or_url/unknown, using each ecosystem's own version-specifier
      grammar.

  candidates <path>
      Local only, no network. For every direct dependency in every
      detected workspace, searches the whole repo for a reference to it
      across nine categories. Never claims proof: a dependency with no
      hits across all nine categories is "zero_references_found": true,
      a candidate for human review, not a removal order.

Prints one JSON object to stdout per invocation. No prose, no markdown.
"""

import ast
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cartridge_scan import (  # noqa: E402
    walk, find_files, read_text, read_json, EXCLUDE_DIRS,
)
from dead_weight_scan import (  # noqa: E402
    EXTRACTORS, SOURCE_EXTENSIONS, WEAK_ECOSYSTEMS, module_matches,
)

# ===== CONFIGURATION =====

# Filenames this tool treats as "tool config," searched for a package's
# installed name, import name, or a known short-name form (see
# SHORT_NAME_PREFIXES_BY_ECOSYSTEM below) when deciding whether a
# dependency is referenced only by a lint/build/test tool's own config,
# never as a real source import.
TOOL_CONFIG_NAMES = {
    ".eslintrc", ".eslintrc.json", ".eslintrc.js", ".eslintrc.yml", ".eslintrc.yaml",
    "babel.config.js", "babel.config.json", ".babelrc", ".babelrc.json",
    "jest.config.js", "jest.config.json", "jest.config.ts",
    "webpack.config.js", "rollup.config.js", "vite.config.js",
    "tsconfig.json", "jsconfig.json", ".prettierrc", ".prettierrc.json",
    ".stylelintrc", ".stylelintrc.json", "postcss.config.js",
    "pytest.ini", "tox.ini", "setup.cfg", ".flake8", "mypy.ini", ".pylintrc",
    "pyproject.toml", ".rubocop.yml", "phpcs.xml", "rector.php",
    "nuget.config", "analysis_options.yaml", ".clang-format",
}
TOOL_CONFIG_SUFFIXES = ("CMakeLists.txt",)

# Known short-name prefixes a dependency's installed name is stripped of
# before being referenced in a tool's own config, e.g. the npm package
# "eslint-plugin-react" is referenced in .eslintrc as just "react". Only
# JavaScript tooling has this convention in wide, predictable use.
SHORT_NAME_PREFIXES_BY_ECOSYSTEM = {
    "javascript": (
        "eslint-plugin-", "eslint-config-", "babel-plugin-", "babel-preset-",
        "webpack-", "postcss-", "stylelint-config-",
    ),
}

# Filenames/suffixes this tool treats as CI configuration, searched
# alongside Dockerfiles for the "dockerfiles_and_ci" evidence category.
CI_CONFIG_SUFFIXES = (
    ".github/workflows", ".gitlab-ci.yml", "Jenkinsfile", ".circleci/config.yml",
    "azure-pipelines.yml", ".drone.yml",
)

# Directory/filename markers this tool treats as "this file is a test or
# fixture," for the "tests_and_fixtures" evidence category. Deliberately
# broad: a false positive here (a non-test file that happens to match)
# only means an extra place gets searched, not a wrong verdict.
TEST_PATH_MARKERS = ("test", "tests", "spec", "__tests__", "fixtures", "fixture")

# Curated installed-name -> import-name overrides for well-known cases
# where the two genuinely differ and can't be derived from the installed
# name by any text rule (module_matches()'s own docstring calls this gap
# out explicitly for python: "beautifulsoup4/bs4 isn't recoverable from
# text alone"). Keyed by the installed name, lowercased. This is the
# same kind of small, hand-curated lookup table as
# abandoned_packages.py's list, not an attempt at a general solution.
KNOWN_IMPORT_NAME_OVERRIDES = {
    "python": {
        "beautifulsoup4": "bs4",
        "pyyaml": "yaml",
        "python-dateutil": "dateutil",
        "scikit-learn": "sklearn",
        "opencv-python": "cv2",
        "pillow": "PIL",
        "protobuf": "google",
    },
}

################################################################################
# FUNCTION: known_import_names
#
# PURPOSE
#     Expands a dependency's installed name into every name its own
#     source imports might actually use, so a package whose import name
#     genuinely differs from its installed name (e.g. Python's
#     beautifulsoup4/bs4) isn't wrongly reported as unreferenced just
#     because nothing in the codebase imports it by its installed name.
#
# RESPONSIBILITIES
#     - Always include the installed name itself.
#     - If KNOWN_IMPORT_NAME_OVERRIDES has an entry for this ecosystem
#       and installed name, also include the known import name.
#
# PROCESS OVERVIEW
#     1. Start the result list with installed_name.
#     2. Look up installed_name (lowercased) in this ecosystem's
#        override table.
#     3. If found, add the known import name.
#     4. Return the result list.
#
# IMPORTANT DETAILS
#     - This table is necessarily incomplete; it covers only the
#       handful of mismatches common enough to curate by hand. A
#       mismatch not listed here will still be missed, same limitation
#       module_matches() in dead_weight_scan.py already documents.
#
# PARAMETERS
#     ecosystem (str)
#         Ecosystem key.
#     installed_name (str)
#         The dependency's installed name.
#
# RETURNS
#     list[str]
#         [installed_name], or [installed_name, known_import_name] if a
#         curated override exists.
#
# FAILURE CASES
#     - None.
################################################################################
def known_import_names(ecosystem, installed_name):
    """Returns [installed_name] plus a curated import-name override, for
    the handful of ecosystem/name pairs where the two are known to differ
    and aren't recoverable from text alone (see KNOWN_IMPORT_NAME_OVERRIDES)."""
    names = [installed_name]
    override = KNOWN_IMPORT_NAME_OVERRIDES.get(ecosystem, {}).get(installed_name.lower())
    if override:
        names.append(override)
    return names


# Dynamic-loading syntax per ecosystem: a regex whose match means "this
# line loads a module/class by a name that isn't a literal string right
# here," the signal scan_dynamic_loading_risk() looks for. Ecosystems
# with no meaningful dynamic-loading idiom reachable by static text
# search (Rust, Dart, C/C++) are intentionally absent.
DYNAMIC_LOADING_PATTERNS_BY_ECOSYSTEM = {
    "javascript": re.compile(r"\b(?:require|import)\s*\(\s*(?!['\"])"),
    "python": re.compile(r"\b(?:importlib\.import_module|__import__)\s*\(\s*(?!['\"])"),
    "go": re.compile(r"\breflect\.(?:TypeOf|ValueOf|New)\s*\("),
    "java": re.compile(r"\bClass\.forName\s*\(\s*(?!['\"])"),
    "ruby": re.compile(r"\b(?:const_get|send)\s*\(\s*(?!['\"])"),
    "php": re.compile(r"\bcall_user_func(?:_array)?\s*\(\s*(?!['\"])|new\s+\$"),
    "dotnet": re.compile(r"\b(?:Activator\.CreateInstance|Type\.GetType)\s*\("),
}


# ===== SHARED HELPERS =====

################################################################################
# FUNCTION: find_term_in_files
#
# PURPOSE
#     Gives every evidence category in this file one shared "does any of
#     these files mention any of these terms" primitive, so the
#     whole-word matching rule and the evidence shape only have to be
#     written once.
#
# RESPONSIBILITIES
#     - Read each file's text.
#     - Search it for a whole-word (not substring-inside-another-word)
#       match of any term in `terms`.
#     - Record the file, matching term, and matched line number for the
#       first hit per file.
#
# PROCESS OVERVIEW
#     1. For each file path, read its text.
#     2. For each line, check every term for a whole-word match using a
#        boundary that treats hyphens and underscores as part of the
#        word, not a boundary, since package names routinely contain
#        them.
#     3. On the first match in a file, record it and move to the next
#        file.
#     4. Return every file's match.
#
# IMPORTANT DETAILS
#     - Matching is case-sensitive. Package names are case-sensitive
#       identifiers in every ecosystem this tool covers; a
#       case-insensitive match would create false hits against unrelated
#       English words that happen to share a package's name.
#     - Only the first matching line per file is recorded, not every
#       occurrence; this is evidence that a reference exists, not a full
#       usage count.
#
# PARAMETERS
#     file_paths (list[str])
#         Files to search.
#     terms (iterable[str])
#         Whole-word terms to search for, e.g. a package's installed
#         name, import name, and short-name form.
#
# RETURNS
#     list[dict]
#         One entry per file with a match: {"file", "matched_term",
#         "line"}. Empty list if no file matched.
#
# FAILURE CASES
#     - None expected; unreadable files simply produce no match (via
#       read_text()'s own tolerance).
################################################################################
def find_term_in_files(file_paths, terms):
    """Searches every file in file_paths for a whole-word match of any
    term in terms (hyphen/underscore treated as part of the word, not a
    boundary). Returns {"file", "matched_term", "line"} per file with a
    hit, first match only per file."""
    compiled_terms = [(term, re.compile(r"(?<![\w\-])" + re.escape(term) + r"(?![\w\-])"))
                       for term in terms if term]
    hits = []
    for file_path in file_paths:
        text = read_text(file_path)
        if not text:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            matched_term = None
            for term, pattern in compiled_terms:
                if pattern.search(line):
                    matched_term = term
                    break
            if matched_term:
                hits.append({"file": file_path, "matched_term": matched_term, "line": line_number})
                break
    return hits


################################################################################
# FUNCTION: find_term_in_manifest_scripts_field
#
# PURPOSE
#     Searches only a package.json/composer.json manifest's "scripts"
#     field values for a term, instead of the whole manifest file. A
#     generic whole-file search would trivially "find" every dependency
#     inside its own declaration line in the dependencies section,
#     making every candidate look referenced by its own manifest, which
#     is not real evidence of use.
#
# RESPONSIBILITIES
#     - Parse each manifest as JSON.
#     - Search only its "scripts" field's values for a whole-word match.
#
# PROCESS OVERVIEW
#     1. For each manifest path, parse it as JSON.
#     2. Read its "scripts" field, a mapping of script name to command
#        string.
#     3. For each script's command string, check for a whole-word match
#        of any term.
#     4. Record the manifest, matched term, and script name for the
#        first match per manifest.
#     5. Return every manifest's match.
#
# IMPORTANT DETAILS
#     - A manifest with no "scripts" field, or one that isn't valid
#       JSON, simply contributes no hits, it is not an error.
#
# PARAMETERS
#     manifest_paths (list[str])
#         package.json/composer.json files to search.
#     terms (iterable[str])
#         Whole-word terms to search for.
#
# RETURNS
#     list[dict]
#         One entry per manifest with a match: {"file", "matched_term",
#         "script"}. Empty list if none matched.
#
# FAILURE CASES
#     - Manifest isn't valid JSON or has no "scripts" field: contributes
#       no hits for that manifest.
################################################################################
def find_term_in_manifest_scripts_field(manifest_paths, terms):
    """Searches only a package.json/composer.json's "scripts" field
    values for a whole-word term match, never the whole manifest (which
    would trivially self-match every dependency's own declaration line)."""
    compiled_terms = [(term, re.compile(r"(?<![\w\-])" + re.escape(term) + r"(?![\w\-])"))
                       for term in terms if term]
    hits = []
    for manifest_path in manifest_paths:
        manifest_contents = read_json(manifest_path)
        if not isinstance(manifest_contents, dict):
            continue
        scripts = manifest_contents.get("scripts")
        if not isinstance(scripts, dict):
            continue
        for script_name, command in scripts.items():
            if not isinstance(command, str):
                continue
            for term, pattern in compiled_terms:
                if pattern.search(command):
                    hits.append({"file": manifest_path, "matched_term": term, "script": script_name})
                    break
            else:
                continue
            break
    return hits


################################################################################
# FUNCTION: short_name_candidates
#
# PURPOSE
#     Expands a dependency's installed name into every form a tool
#     config file might reasonably reference it by, so a package
#     referenced only by its conventional short name (e.g.
#     "eslint-plugin-react" written as just "react" in .eslintrc) isn't
#     wrongly reported as unreferenced.
#
# RESPONSIBILITIES
#     - Always include the installed name itself.
#     - If the ecosystem has known short-name prefixes and the name
#       starts with one, also include the name with that prefix
#       stripped.
#
# PROCESS OVERVIEW
#     1. Start the result set with the installed name.
#     2. Look up this ecosystem's known short-name prefixes.
#     3. For the first prefix the name starts with, add the name with
#        that prefix removed.
#     4. Return the result set.
#
# IMPORTANT DETAILS
#     - Only one prefix is stripped even if, in principle, more than one
#       could match; package names are not expected to combine multiple
#       known prefixes.
#
# PARAMETERS
#     ecosystem (str)
#         Ecosystem key, e.g. "javascript".
#     installed_name (str)
#         The dependency's name as declared in its manifest.
#
# RETURNS
#     set[str]
#         The installed name, plus its short-name form if this
#         ecosystem has a matching known prefix.
#
# FAILURE CASES
#     - None.
################################################################################
def short_name_candidates(ecosystem, installed_name):
    """Returns {installed_name} plus, for ecosystems with a known
    short-name convention (see SHORT_NAME_PREFIXES_BY_ECOSYSTEM), the name
    with its conventional prefix stripped."""
    names = {installed_name}
    for prefix in SHORT_NAME_PREFIXES_BY_ECOSYSTEM.get(ecosystem, ()):
        if installed_name.startswith(prefix) and len(installed_name) > len(prefix):
            names.add(installed_name[len(prefix):])
            break
    return names


# ===== LIFECYCLE SCRIPT DETECTION =====

################################################################################
# FUNCTION: find_javascript_lifecycle_scripts
#
# PURPOSE
#     Finds every npm-family package (first-party or, when a local
#     node_modules checkout exists, third-party) that declares a
#     preinstall, install, or postinstall script, the install-time code
#     execution hook npm/yarn/pnpm all honor.
#
# RESPONSIBILITIES
#     - Read every package.json under the repo root, including inside
#       node_modules (deliberately bypassing EXCLUDE_DIRS's usual
#       node_modules pruning, since this check specifically needs to
#       inspect dependencies' own manifests).
#     - Record each one with a preinstall/install/postinstall script.
#
# PROCESS OVERVIEW
#     1. Walk the repo root without EXCLUDE_DIRS pruning (unlike every
#        other scan in this file), since node_modules is exactly where
#        third-party package.json files live.
#     2. Parse each package.json found.
#     3. If its "scripts" object has a preinstall, install, or
#        postinstall key, record the package name, which hook fired, and
#        the manifest path.
#     4. Return the collected records.
#
# IMPORTANT DETAILS
#     - This can only see a dependency's lifecycle scripts when that
#       dependency is physically installed locally (node_modules
#       present). A fresh checkout with no node_modules yet installed
#       will find none here, that's why run_lifecycle_scripts() reports
#       coverage honestly rather than implying a clean scan is complete.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     list[dict]
#         One entry per package with a lifecycle script: {"name", "hook",
#         "source_file"}. Empty list if none found or no node_modules is
#         present.
#
# FAILURE CASES
#     - No package.json anywhere under root: returns an empty list.
################################################################################
def find_javascript_lifecycle_scripts(root):
    """Finds every package.json (first-party or, if node_modules exists
    locally, third-party) with a preinstall/install/postinstall script.
    Deliberately walks node_modules, unlike every other search in this
    file, since that is exactly where a dependency's own manifest lives."""
    hits = []
    for dirpath, _dirnames, filenames in os.walk(root):
        if ".git" in dirpath.split(os.sep):
            continue
        if "package.json" not in filenames:
            continue
        manifest_path = os.path.join(dirpath, "package.json")
        package_json_contents = read_json(manifest_path)
        if not isinstance(package_json_contents, dict):
            continue
        scripts = package_json_contents.get("scripts") or {}
        for hook in ("preinstall", "install", "postinstall"):
            if scripts.get(hook):
                hits.append({
                    "name": package_json_contents.get("name", "(unnamed)"),
                    "hook": hook,
                    "source_file": manifest_path,
                })
    return hits


################################################################################
# FUNCTION: find_python_build_hooks
#
# PURPOSE
#     Finds Python packages that run custom code at build/install time
#     via setup.py's cmdclass argument or a build_ext override, without
#     ever importing or executing setup.py itself.
#
# RESPONSIBILITIES
#     - Parse each setup.py found into an AST, never import or exec it.
#     - Detect a cmdclass keyword argument on a setup() call, or a class
#       definition that subclasses build_ext or install.
#
# PROCESS OVERVIEW
#     1. Find every setup.py under root.
#     2. Parse each one's source into an AST.
#     3. Walk the AST for a setup() call with a cmdclass keyword
#        argument, and separately for any class definition subclassing
#        build_ext or install.
#     4. Record a hit for either signal.
#     5. Return the collected records.
#
# IMPORTANT DETAILS
#     - Only a repo's own vendored/first-party setup.py files are ever
#       physically present to inspect; a third-party dependency
#       installed from PyPI as a wheel has no setup.py on disk at all,
#       so this is structurally unable to see most third-party build
#       hooks. run_lifecycle_scripts() reports this gap explicitly.
#     - Uses ast.parse(), never ast.literal_eval() on the whole call,
#       since cmdclass values are typically class references, not
#       literals; this function only needs to know a cmdclass argument
#       exists, not evaluate its value.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     list[dict]
#         One entry per setup.py with a detected build hook: {"name",
#         "hook", "source_file"}. Empty list if none found.
#
# FAILURE CASES
#     - No setup.py found: returns an empty list.
#     - A setup.py with a syntax error: skipped, not counted as a hit.
################################################################################
def find_python_build_hooks(root):
    """Finds setup.py files with a cmdclass argument or a build_ext/install
    subclass, parsed via ast (never imported/executed). Can only see this
    for a setup.py physically present on disk, which a wheel-installed
    third-party dependency normally isn't, see run_lifecycle_scripts()."""
    hits = []
    for setup_py_file in find_files(root, names={"setup.py"}):
        try:
            syntax_tree = ast.parse(read_text(setup_py_file))
        except SyntaxError:
            continue

        package_name = os.path.basename(os.path.dirname(setup_py_file)) or "(unnamed)"

        has_cmdclass_argument = False
        for node in ast.walk(syntax_tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "setup":
                has_cmdclass_argument = any(keyword.arg == "cmdclass" for keyword in node.keywords)
                if has_cmdclass_argument:
                    break
        if has_cmdclass_argument:
            hits.append({"name": package_name, "hook": "setup(cmdclass=...)", "source_file": setup_py_file})
            continue

        for node in ast.walk(syntax_tree):
            if not isinstance(node, ast.ClassDef):
                continue
            base_names = [base.id for base in node.bases if isinstance(base, ast.Name)]
            if "build_ext" in base_names or "install" in base_names:
                hits.append({"name": package_name, "hook": f"class {node.name}(build_ext/install)",
                             "source_file": setup_py_file})
                break
    return hits


################################################################################
# FUNCTION: find_rust_build_scripts
#
# PURPOSE
#     Finds Rust crates with a build.rs build script, Cargo's own
#     install-time (really, compile-time) arbitrary code execution hook.
#
# RESPONSIBILITIES
#     - Find every Cargo.toml.
#     - Detect either an explicit `build = "..."` key or a build.rs file
#       sitting next to it (Cargo's implicit default).
#
# PROCESS OVERVIEW
#     1. Find every Cargo.toml under root.
#     2. For each one, check its text for a `build = ` key under
#        [package].
#     3. If absent, check whether a build.rs file exists in the same
#        directory, Cargo's implicit default build script path.
#     4. Record a hit for either signal.
#     5. Return the collected records.
#
# IMPORTANT DETAILS
#     - Same physical-presence limitation as Python: a crates.io
#       dependency's source is not checked out locally in a typical
#       repo, so this only reliably finds first-party or vendored
#       crates. run_lifecycle_scripts() reports this gap explicitly.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     list[dict]
#         One entry per crate with a build script: {"name",
#         "source_file"}. Empty list if none found.
#
# FAILURE CASES
#     - No Cargo.toml found: returns an empty list.
################################################################################
def find_rust_build_scripts(root):
    """Finds Cargo.toml files with an explicit `build = "..."` key or an
    implicit build.rs sitting next to them. Same physical-presence
    limitation as Python's setup.py: only sees crates checked out
    locally."""
    hits = []
    for cargo_toml_file in find_files(root, names={"Cargo.toml"}):
        crate_dir = os.path.dirname(cargo_toml_file)
        text = read_text(cargo_toml_file)
        has_explicit_build_key = bool(re.search(r'^\s*build\s*=\s*["\']', text, re.MULTILINE))
        has_implicit_build_rs = os.path.isfile(os.path.join(crate_dir, "build.rs"))
        if has_explicit_build_key or has_implicit_build_rs:
            crate_name_match = re.search(r'^\s*name\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
            crate_name = crate_name_match.group(1) if crate_name_match else os.path.basename(crate_dir)
            hits.append({"name": crate_name, "source_file": cargo_toml_file})
    return hits


################################################################################
# FUNCTION: find_php_composer_scripts
#
# PURPOSE
#     Finds project-level Composer scripts that fire on
#     install/update, the PHP ecosystem's closest equivalent to npm's
#     lifecycle hooks.
#
# RESPONSIBILITIES
#     - Read every composer.json found.
#     - Record any pre/post-install-cmd or pre/post-update-cmd script.
#
# PROCESS OVERVIEW
#     1. Find every composer.json under root.
#     2. Parse each one as JSON.
#     3. Check its "scripts" object for any of the four Composer
#        install/update event keys.
#     4. Record a hit for each one present.
#     5. Return the collected records.
#
# IMPORTANT DETAILS
#     - This only sees the project's own declared scripts, not a
#       dependency's Composer plugin hooks, which run from the
#       dependency's own code and aren't discoverable by reading
#       composer.json alone. Reported as a project-level signal only,
#       never claimed as full coverage of what could run during
#       `composer install`.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     list[dict]
#         One entry per composer.json with an install/update script:
#         {"name", "hook", "source_file"}. Empty list if none found.
#
# FAILURE CASES
#     - No composer.json found: returns an empty list.
################################################################################
def find_php_composer_scripts(root):
    """Finds composer.json files with a pre/post-install-cmd or
    pre/post-update-cmd script. Project-level only, a dependency's own
    Composer plugin hooks aren't visible from composer.json alone."""
    hits = []
    for composer_json_file in find_files(root, names={"composer.json"}):
        composer_json_contents = read_json(composer_json_file)
        if not isinstance(composer_json_contents, dict):
            continue
        scripts = composer_json_contents.get("scripts") or {}
        for hook in ("pre-install-cmd", "post-install-cmd", "pre-update-cmd", "post-update-cmd"):
            if hook in scripts:
                hits.append({
                    "name": composer_json_contents.get("name", "(unnamed)"),
                    "hook": hook,
                    "source_file": composer_json_file,
                })
    return hits


# Ecosystems with a genuine, statically-checkable install-time code
# execution mechanism. Go modules, Java (Maven/Gradle), .NET, Dart, and
# C/C++ are intentionally absent: Go and Dart's package managers run no
# arbitrary code on install at all; Maven/Gradle/NuGet build hooks exist
# but require inspecting a dependency's own build file, which (like
# Python/Rust) is normally not checked out locally, with no equivalent
# "implicit default file" signal worth guessing at the way build.rs is.
LIFECYCLE_SCRIPT_FINDERS = {
    "javascript": find_javascript_lifecycle_scripts,
    "python": find_python_build_hooks,
    "rust": find_rust_build_scripts,
    "php": find_php_composer_scripts,
}

ECOSYSTEMS_WITH_NO_LIFECYCLE_MECHANISM = ("go", "java", "dotnet", "dart", "cpp")

################################################################################
# FUNCTION: run_lifecycle_scripts
#
# PURPOSE
#     Entry point for the `lifecycle-scripts` subcommand: runs every
#     ecosystem-specific finder and assembles one honest report of what
#     was found, what couldn't be checked, and which ecosystems have no
#     comparable mechanism at all.
#
# RESPONSIBILITIES
#     - Run each finder in LIFECYCLE_SCRIPT_FINDERS.
#     - Record which ecosystems were checked vs. have no mechanism to
#       check.
#     - State the coverage limitation plainly: this can only see a
#       lifecycle script when the dependency declaring it is physically
#       present on disk.
#
# PROCESS OVERVIEW
#     1. Run every finder in LIFECYCLE_SCRIPT_FINDERS, tagging each hit
#        with its ecosystem.
#     2. Collect the results into one list.
#     3. Return the ecosystems checked, the hits found, and the fixed
#        coverage-limitation note.
#
# IMPORTANT DETAILS
#     - None beyond what's already documented on each finder function.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     dict
#         {"ecosystems_checked", "ecosystems_with_no_lifecycle_mechanism",
#         "packages_with_lifecycle_scripts", "coverage_limitation"}.
#
# FAILURE CASES
#     - None; a finder that finds nothing simply contributes no hits.
################################################################################
def run_lifecycle_scripts(root):
    """Runs every ecosystem-specific lifecycle-script finder and returns
    one combined, honestly-scoped report."""
    hits = []
    for ecosystem, finder in LIFECYCLE_SCRIPT_FINDERS.items():
        for hit in finder(root):
            hit_with_ecosystem = {"ecosystem": ecosystem}
            hit_with_ecosystem.update(hit)
            hits.append(hit_with_ecosystem)

    return {
        "ecosystems_checked": sorted(LIFECYCLE_SCRIPT_FINDERS.keys()),
        "ecosystems_with_no_lifecycle_mechanism": list(ECOSYSTEMS_WITH_NO_LIFECYCLE_MECHANISM),
        "packages_with_lifecycle_scripts": hits,
        "coverage_limitation": (
            "A lifecycle/build script can only be detected for a dependency whose own "
            "manifest is physically present on disk (a local node_modules checkout for "
            "JavaScript, a vendored crate for Rust, etc). A dependency resolved only from "
            "a lockfile with nothing installed locally yet cannot be checked and is not "
            "included here, it is not reported as clean."
        ),
    }


# ===== UNPINNED VERSION CLASSIFICATION =====

################################################################################
# FUNCTION: classify_version_specifier
#
# PURPOSE
#     Classifies one dependency's declared version specifier into a
#     single pin_class, using the specifier grammar of the ecosystem it
#     came from. This is the one place that grammar-specific knowledge
#     lives, so callers never have to know, for example, that a bare
#     version number means something different in Cargo than it does in
#     npm.
#
# RESPONSIBILITIES
#     - Recognize a git/URL/path source first, regardless of ecosystem,
#       since that overrides any version-range reasoning.
#     - Apply the correct classification rule for the specifier's
#       ecosystem.
#
# PROCESS OVERVIEW
#     1. Check whether the specifier looks like a git/URL/local-path
#        source rather than a version number, if so, classify it
#        git_or_url immediately regardless of ecosystem.
#     2. Otherwise, apply the ecosystem-specific rule: look for a
#        leading operator (^, ~, =, >=, etc.), a wildcard character, or
#        (for Cargo specifically) the absence of any operator at all,
#        which Cargo treats as an implicit caret.
#     3. Return the matched pin_class, or "unknown" if nothing matched.
#
# IMPORTANT DETAILS
#     - A bare version number ("1.2.3") means "exact" in npm, PEP 440,
#       and most ecosystems, but means "caret" (i.e. a range) in Cargo,
#       that's Cargo's own documented default and the specific nuance
#       this function exists to get right rather than applying one rule
#       everywhere.
#     - Maven's range-bracket syntax ("[1.0,2.0)") and a bare property
#       placeholder ("${some.property}") are both common in pom.xml;
#       the latter cannot be resolved without evaluating the POM's
#       property inheritance, so it is "unknown", not guessed at.
#
# PARAMETERS
#     ecosystem (str)
#         Which ecosystem's grammar to apply.
#     specifier (str)
#         The raw declared version specifier, e.g. "^1.2.3" or
#         "[1.0,2.0)".
#
# RETURNS
#     str
#         One of "exact", "caret", "tilde", "range", "wildcard",
#         "git_or_url", "unknown".
#
# FAILURE CASES
#     - specifier is empty or unrecognized: returns "unknown".
################################################################################
def classify_version_specifier(ecosystem, specifier):
    """Classifies specifier into exact/caret/tilde/range/wildcard/
    git_or_url/unknown, using ecosystem's own version-specifier grammar.
    A bare version number is "exact" everywhere except Cargo, where it is
    "caret" by Cargo's own documented default."""
    specifier = (specifier or "").strip()
    if not specifier:
        return "unknown"

    looks_like_git_or_url_or_path = bool(re.match(
        r"^(?:git\+|git:|https?://|github:|file:|path\s*=|git\s*=)", specifier, re.IGNORECASE
    ))
    if looks_like_git_or_url_or_path:
        return "git_or_url"

    if ecosystem in ("javascript", "python", "dart", "php"):
        if specifier.startswith("^"):
            return "caret"
        if specifier.startswith("~"):
            return "tilde"
        if "*" in specifier or specifier.lower() in ("any", "latest", "dev-master"):
            return "wildcard"
        if re.search(r"[<>]|,|\s", specifier) or specifier.count(".") and ("<" in specifier or ">" in specifier):
            return "range"
        if re.match(r"^={0,2}\d", specifier):
            return "exact"
        return "unknown"

    if ecosystem == "rust":
        if specifier.startswith("="):
            return "exact"
        if specifier.startswith("~"):
            return "tilde"
        if "*" in specifier:
            return "wildcard"
        if re.search(r"[<>]|,", specifier):
            return "range"
        if re.match(r"^\d", specifier):
            # Cargo's own documented default: a bare version number with
            # no operator is treated as caret (compatible-updates), not
            # an exact pin, unlike almost every other ecosystem here.
            return "caret"
        return "unknown"

    if ecosystem in ("maven", "java"):
        if re.match(r"^[\[\(]", specifier):
            return "range"
        if specifier.startswith("${"):
            return "unknown"
        if specifier.upper() in ("LATEST", "RELEASE"):
            return "wildcard"
        if re.match(r"^\d", specifier):
            return "exact"
        return "unknown"

    if ecosystem == "go":
        # go.mod always records a fully resolved version (a semver tag or
        # a pseudo-version); Go modules have no caret/tilde/range syntax
        # in the manifest itself.
        if re.match(r"^v\d", specifier):
            return "exact"
        return "unknown"

    if ecosystem == "ruby":
        if specifier.startswith("~>"):
            return "tilde"
        if specifier.startswith("="):
            return "exact"
        if re.search(r"[<>]", specifier):
            return "range"
        if re.match(r"^\d", specifier):
            return "exact"
        return "unknown"

    if ecosystem == "dotnet":
        if "*" in specifier:
            return "wildcard"
        if re.match(r"^[\[\(]", specifier):
            return "range"
        if re.match(r"^\d", specifier):
            return "exact"
        return "unknown"

    if ecosystem == "cpp":
        if re.match(r"^\[", specifier):
            return "range"
        if re.match(r"^\d", specifier):
            return "exact"
        return "unknown"

    return "unknown"


################################################################################
# FUNCTION: extract_javascript_version_specifiers
#
# PURPOSE
#     Lists every dependency declared in package.json alongside its raw
#     version specifier string, the input classify_version_specifier()
#     needs for the JavaScript ecosystem.
#
# RESPONSIBILITIES
#     - Find every package.json.
#     - Collect each name/specifier pair from its dependencies,
#       devDependencies, peerDependencies, and optionalDependencies
#       sections.
#
# PROCESS OVERVIEW
#     1. Find every package.json under root.
#     2. Parse each one as JSON.
#     3. For each of the four dependency sections, collect every
#        name/specifier pair, paired with the manifest path.
#     4. Return all collected entries.
#
# IMPORTANT DETAILS
#     - Unlike cartridge_scan.py's/dead_weight_scan.py's "only the first
#       package.json" convention, every package.json found is read here:
#       unpinned-version reporting is meant to cover every workspace in
#       a monorepo, not just the root.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     list[dict]
#         {"manifest_file", "name", "declared_specifier"} per
#         dependency. Empty list if no package.json exists.
#
# FAILURE CASES
#     - No package.json found: returns an empty list.
################################################################################
def extract_javascript_version_specifiers(root):
    """Returns {"manifest_file", "name", "declared_specifier"} for every
    dependency in every package.json found (all four dependency
    sections, every manifest, not just the first)."""
    entries = []
    for manifest in find_files(root, names={"package.json"}):
        package_json_contents = read_json(manifest)
        if not isinstance(package_json_contents, dict):
            continue
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for name, specifier in (package_json_contents.get(key) or {}).items():
                if isinstance(specifier, str):
                    entries.append({"manifest_file": manifest, "name": name, "declared_specifier": specifier})
    return entries


################################################################################
# FUNCTION: extract_python_version_specifiers
#
# PURPOSE
#     Lists every dependency declared across requirements*.txt and
#     pyproject.toml alongside its raw version specifier string, the
#     input classify_version_specifier() needs for the Python ecosystem.
#
# RESPONSIBILITIES
#     - Find requirements*.txt and pyproject.toml files.
#     - Split each declared requirement into its bare name and its
#       version specifier portion.
#
# PROCESS OVERVIEW
#     1. For each requirements*.txt file, split each non-comment,
#        non-option line at the first version-operator character into a
#        name and a specifier.
#     2. For each pyproject.toml, do the same for its PEP 621
#        dependencies array entries and its [tool.poetry.dependencies]
#        table values.
#     3. Return all collected entries.
#
# IMPORTANT DETAILS
#     - A requirements.txt line with no version operator at all (a bare
#       "requests") is recorded with an empty specifier, which
#       classify_version_specifier() reports as "unknown" rather than
#       "wildcard"; pip's own behavior for a bare name (take whatever
#       the resolver picks) is closer to unpinned-and-unspecified than a
#       documented wildcard syntax.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     list[dict]
#         {"manifest_file", "name", "declared_specifier"} per
#         dependency. Empty list if no Python manifest exists.
#
# FAILURE CASES
#     - No requirements*.txt or pyproject.toml found: returns an empty
#       list.
################################################################################
def extract_python_version_specifiers(root):
    """Returns {"manifest_file", "name", "declared_specifier"} for every
    dependency in requirements*.txt and pyproject.toml (PEP 621 and
    Poetry dependency tables)."""
    entries = []
    for requirements_file in find_files(root, suffixes=("requirements.txt",)):
        for line in read_text(requirements_file).splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            split_match = re.match(r"^([\w.\-\[\]]+)\s*(.*)$", line)
            if split_match:
                name = re.split(r"[\[]", split_match.group(1))[0]
                entries.append({
                    "manifest_file": requirements_file, "name": name,
                    "declared_specifier": split_match.group(2).strip(),
                })
    for pyproject_file in find_files(root, names={"pyproject.toml"}):
        text = read_text(pyproject_file)
        pep621_match = re.search(r"dependencies\s*=\s*\[(.*?)\]", text, re.DOTALL)
        if pep621_match:
            for spec in re.findall(r'["\']([^"\']+)["\']', pep621_match.group(1)):
                split_match = re.match(r"^([\w.\-]+)\s*(.*)$", spec)
                if split_match:
                    entries.append({
                        "manifest_file": pyproject_file, "name": split_match.group(1),
                        "declared_specifier": split_match.group(2).strip(),
                    })
        in_poetry_section = False
        for line in text.splitlines():
            stripped_line = line.strip()
            if stripped_line.startswith("["):
                in_poetry_section = stripped_line == "[tool.poetry.dependencies]"
                continue
            if in_poetry_section and "=" in stripped_line and not stripped_line.startswith("#"):
                name, _, value = stripped_line.partition("=")
                name = name.strip().strip('"\'')
                if name and name != "python":
                    entries.append({
                        "manifest_file": pyproject_file, "name": name,
                        "declared_specifier": value.strip().strip('"\''),
                    })
    return entries


################################################################################
# FUNCTION: extract_rust_version_specifiers
#
# PURPOSE
#     Lists every crate declared in Cargo.toml's dependency tables
#     alongside its raw version specifier string, the input
#     classify_version_specifier() needs for the Rust ecosystem.
#
# RESPONSIBILITIES
#     - Find Cargo.toml files.
#     - Collect each crate name and its version specifier from the
#       dependencies, dev-dependencies, and build-dependencies tables,
#       covering both the inline-string and inline-table forms.
#
# PROCESS OVERVIEW
#     1. Find every Cargo.toml under root.
#     2. Track whether the current line is inside a
#        dependencies/dev-dependencies/build-dependencies table.
#     3. Inside that table, extract the crate name and, from either a
#        plain string value or a `{ version = "...", ... }` inline
#        table, the version specifier.
#     4. Return all collected entries.
#
# IMPORTANT DETAILS
#     - A dependency declared only with `git = "..."` or `path = "..."`
#       and no version key at all is recorded with specifier "git" or
#       "path" respectively, which classify_version_specifier() already
#       recognizes as git_or_url.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     list[dict]
#         {"manifest_file", "name", "declared_specifier"} per
#         dependency. Empty list if no Cargo.toml exists.
#
# FAILURE CASES
#     - No Cargo.toml found: returns an empty list.
################################################################################
def extract_rust_version_specifiers(root):
    """Returns {"manifest_file", "name", "declared_specifier"} for every
    crate in Cargo.toml's dependency tables, covering both the plain
    string form (`serde = "1.0"`) and the inline-table form
    (`serde = { version = "1.0", features = [...] }`)."""
    entries = []
    for cargo_toml_file in find_files(root, names={"Cargo.toml"}):
        text = read_text(cargo_toml_file)
        in_deps_section = False
        for line in text.splitlines():
            stripped_line = line.strip()
            if stripped_line.startswith("["):
                in_deps_section = stripped_line in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]")
                continue
            if not in_deps_section or "=" not in stripped_line or stripped_line.startswith("#"):
                continue
            name, _, value = stripped_line.partition("=")
            name = name.strip().strip('"\'')
            if not name:
                continue
            value = value.strip()
            if value.startswith("{"):
                version_match = re.search(r'version\s*=\s*"([^"]+)"', value)
                if version_match:
                    specifier = version_match.group(1)
                elif "git" in value:
                    specifier = "git"
                elif "path" in value:
                    specifier = "path"
                else:
                    specifier = ""
            else:
                specifier = value.strip('"\'')
            entries.append({"manifest_file": cargo_toml_file, "name": name, "declared_specifier": specifier})
    return entries


# Dispatch table: ecosystem key -> its version-specifier extractor.
# Ecosystems not listed here (go, java, ruby, php, dotnet, dart, cpp)
# have a less common or more structurally varied manifest shape for this
# specific purpose; adding them follows the same pattern as the three
# below if a future need arises.
VERSION_SPECIFIER_EXTRACTORS = {
    "javascript": extract_javascript_version_specifiers,
    "python": extract_python_version_specifiers,
    "rust": extract_rust_version_specifiers,
}

################################################################################
# FUNCTION: run_unpinned_versions
#
# PURPOSE
#     Entry point for the `unpinned-versions` subcommand: runs every
#     ecosystem's extractor and classifier, and assembles one combined
#     report.
#
# RESPONSIBILITIES
#     - Run each extractor in VERSION_SPECIFIER_EXTRACTORS.
#     - Classify each entry's specifier via classify_version_specifier().
#
# PROCESS OVERVIEW
#     1. For each ecosystem in VERSION_SPECIFIER_EXTRACTORS, run its
#        extractor.
#     2. For each entry, classify its specifier and whether that class
#        counts as an exact pin.
#     3. Return the combined list.
#
# IMPORTANT DETAILS
#     - "is_pinned_exact" is a convenience boolean (pin_class == "exact")
#       so a caller can filter without re-deriving the rule.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     dict
#         {"dependencies": [...]}, one entry per dependency found across
#         every supported ecosystem's manifests.
#
# FAILURE CASES
#     - None; an ecosystem with no manifest simply contributes no
#       entries.
################################################################################
def run_unpinned_versions(root):
    """Runs every ecosystem's version-specifier extractor and classifier,
    returns one combined {"dependencies": [...]} report."""
    dependencies = []
    for ecosystem, extractor in VERSION_SPECIFIER_EXTRACTORS.items():
        for entry in extractor(root):
            pin_class = classify_version_specifier(ecosystem, entry["declared_specifier"])
            dependencies.append({
                "ecosystem": ecosystem,
                "manifest_file": entry["manifest_file"],
                "name": entry["name"],
                "declared_specifier": entry["declared_specifier"],
                "pin_class": pin_class,
                "is_pinned_exact": pin_class == "exact",
            })
    return {"dependencies": dependencies}


# ===== UNUSED-DEPENDENCY CANDIDATE SEARCH =====

################################################################################
# FUNCTION: list_workspace_manifests
#
# PURPOSE
#     Finds every manifest of a given ecosystem under root, grouping
#     them as separate workspaces, unlike cartridge_scan.py's and
#     dead_weight_scan.py's own listers, which deliberately read only the
#     first manifest found to avoid mixing unrelated workspaces together
#     into one count. The candidates search needs the opposite: every
#     workspace evaluated on its own, per the spec's monorepo rule.
#
# RESPONSIBILITIES
#     - Find every manifest file for the given ecosystem.
#     - Parse each one and collect its declared dependency names.
#
# PROCESS OVERVIEW
#     1. Find every manifest file matching this ecosystem's manifest
#        name.
#     2. Parse each one and collect every declared dependency name from
#        its dependency sections.
#     3. Return one workspace entry per manifest found.
#
# IMPORTANT DETAILS
#     - Only javascript, rust, and go get genuine per-manifest workspace
#       separation here, these are the ecosystems with a common,
#       well-understood multi-manifest-per-repo convention
#       (workspaces/pnpm-workspace.yaml, Cargo workspaces, multi-module
#       Go repos). Every other ecosystem is treated as one implicit
#       workspace rooted at the repo root, matching
#       cartridge_scan.py's/dead_weight_scan.py's existing scope for
#       those ecosystems; extending real workspace separation to them is
#       a reasonable future addition, not attempted here.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     ecosystem (str)
#         Ecosystem key; must be one of "javascript", "rust", "go", or
#         any key in dead_weight_scan.LIST_DEPS for the single-workspace
#         path.
#
# RETURNS
#     list[dict]
#         One entry per workspace: {"workspace_path", "manifest_file",
#         "dependency_names"}.
#
# FAILURE CASES
#     - No manifest found for this ecosystem: returns an empty list.
################################################################################
def list_workspace_manifests(root, ecosystem):
    """Finds every manifest for `ecosystem`, one workspace entry per
    manifest (unlike cartridge_scan.py/dead_weight_scan.py's "first
    manifest only" listers), for javascript/rust/go. Every other
    ecosystem gets one implicit root-level workspace."""
    workspaces = []

    if ecosystem == "javascript":
        for manifest in find_files(root, names={"package.json"}):
            package_json_contents = read_json(manifest)
            if not isinstance(package_json_contents, dict):
                continue
            dependency_names = []
            for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                dependency_names.extend((package_json_contents.get(key) or {}).keys())
            workspaces.append({
                "workspace_path": os.path.dirname(manifest), "manifest_file": manifest,
                "dependency_names": sorted(set(dependency_names)),
            })
        return workspaces

    if ecosystem == "rust":
        for cargo_toml_file in find_files(root, names={"Cargo.toml"}):
            dependency_names = [entry["name"] for entry in extract_rust_version_specifiers(root)
                                 if entry["manifest_file"] == cargo_toml_file]
            workspaces.append({
                "workspace_path": os.path.dirname(cargo_toml_file), "manifest_file": cargo_toml_file,
                "dependency_names": sorted(set(dependency_names)),
            })
        return workspaces

    if ecosystem == "go":
        for go_mod_file in find_files(root, names={"go.mod"}):
            text = read_text(go_mod_file)
            dependency_names = []
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
                        dependency_names.append(match.group(1))
                    continue
                match = re.match(r"^require\s+(\S+)\s+v\S+", stripped_line)
                if match:
                    dependency_names.append(match.group(1))
            workspaces.append({
                "workspace_path": os.path.dirname(go_mod_file), "manifest_file": go_mod_file,
                "dependency_names": sorted(set(dependency_names)),
            })
        return workspaces

    return []


# Ecosystems covered by the candidates search's own name listers above,
# plus the remaining ecosystems reachable only through
# dead_weight_scan.LIST_DEPS's single-manifest listers for a
# repo-root-only workspace. Java is handled through LIST_DEPS's
# (matching_prefix, manifest, display_name) triple shape, every other
# ecosystem there through its (name, manifest) pair shape.
WORKSPACE_AWARE_ECOSYSTEMS = ("javascript", "rust", "go")


################################################################################
# FUNCTION: gather_search_universe
#
# PURPOSE
#     Builds the one shared set of file-path buckets every evidence
#     category below searches, so each category only has to describe
#     which bucket(s) it cares about, not re-walk the filesystem itself.
#
# RESPONSIBILITIES
#     - Find every source file for a given ecosystem.
#     - Separate those into "test-like" and "non-test" buckets.
#     - Find every tool-config, script/Makefile, Dockerfile/CI, and
#       generic text file in the repo, independent of ecosystem (a
#       config file or CI pipeline can reference a dependency from any
#       language).
#
# PROCESS OVERVIEW
#     1. Find every source file matching this ecosystem's extensions.
#     2. Split them into test-like (path contains a marker from
#        TEST_PATH_MARKERS) and non-test buckets.
#     3. Find every tool-config file by name/suffix.
#     4. Find package.json/composer.json files, kept separate since
#        they must be searched only within their "scripts" field (see
#        find_term_in_manifest_scripts_field()), never as whole-file
#        text.
#     5. Find Makefile/*.sh files, searched as whole-file text.
#     6. Find Dockerfile*/CI config files for the dockerfiles_and_ci
#        bucket.
#     7. Return all buckets together.
#
# IMPORTANT DETAILS
#     - This is computed once per ecosystem per `candidates` run, not
#       once per candidate dependency, since every candidate in the same
#       ecosystem searches the same universe of files.
#     - manifest_scripts_field_files and raw_script_files are kept as
#       two separate buckets, not one combined "scripts_and_makefiles"
#       list, because they need two different search functions: a
#       manifest's "scripts" field values only, vs. a Makefile/shell
#       script's whole text.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     ecosystem (str)
#         Ecosystem key, used only to select source file extensions.
#
# RETURNS
#     dict
#         {"source_non_test", "source_test", "tool_configs",
#         "manifest_scripts_field_files", "raw_script_files",
#         "dockerfiles_and_ci"}, each a list of file paths.
#
# FAILURE CASES
#     - None; any empty bucket simply means that category has nothing to
#       search.
################################################################################
def gather_search_universe(root, ecosystem):
    """Builds the shared file-path buckets every evidence category
    searches: source files (split test vs. non-test), tool configs,
    scripts/Makefiles, and Dockerfiles/CI. Computed once per ecosystem,
    reused across every candidate dependency in that ecosystem."""
    source_extensions = SOURCE_EXTENSIONS.get(ecosystem, ())
    all_source_files = find_files(root, suffixes=source_extensions) if source_extensions else []
    source_test, source_non_test = [], []
    for file_path in all_source_files:
        # Checked relative to `root`, not the absolute path: a repo
        # checked out somewhere whose own path happens to contain a word
        # like "test" (e.g. "/home/user/testing/my-project") must not
        # have every one of its files misclassified as test-like.
        relative_path = os.path.relpath(file_path, root).lower()
        is_test_like = any(marker in relative_path for marker in TEST_PATH_MARKERS)
        (source_test if is_test_like else source_non_test).append(file_path)

    tool_configs = find_files(root, names=TOOL_CONFIG_NAMES, suffixes=TOOL_CONFIG_SUFFIXES)
    manifest_scripts_field_files = find_files(root, names={"package.json", "composer.json"})
    raw_script_files = find_files(root, names={"Makefile", "makefile"}, suffixes=(".sh",))
    dockerfiles_and_ci = find_files(
        root, names={"Jenkinsfile", ".gitlab-ci.yml", "azure-pipelines.yml", ".drone.yml"},
        suffixes=("Dockerfile",))
    dockerfiles_and_ci += [f for f in find_files(root, suffixes=(".yml", ".yaml"))
                            if ".github/workflows" in f.replace(os.sep, "/")
                            or ".circleci" in f.replace(os.sep, "/")]

    return {
        "source_non_test": source_non_test,
        "source_test": source_test,
        "tool_configs": tool_configs,
        "manifest_scripts_field_files": manifest_scripts_field_files,
        "raw_script_files": raw_script_files,
        "dockerfiles_and_ci": dockerfiles_and_ci,
    }


################################################################################
# FUNCTION: scan_source_imports
#
# PURPOSE
#     Searches an ecosystem's non-test source files for a real import of
#     a candidate dependency, reusing dead_weight_scan.py's own
#     per-ecosystem import extractors and matching rule instead of
#     re-deriving how each language's import syntax maps to a package
#     name.
#
# RESPONSIBILITIES
#     - Run this ecosystem's EXTRACTORS function against every line of
#       every non-test source file.
#     - Test each extracted module key against the candidate name via
#       module_matches().
#     - Separate side-effect-only imports (no bound local name) into
#       their own list, since they are their own evidence category in
#       the spec, not folded into "a real import."
#
# PROCESS OVERVIEW
#     1. If this ecosystem has no EXTRACTORS entry, return empty results
#        for both categories immediately.
#     2. For each non-test source file, read its lines.
#     3. For each line, run the extractor; skip lines it doesn't
#        recognize as an import.
#     4. If the extracted module key matches the candidate name, record
#        the hit under side_effect_imports if bound_names is empty and
#        the ecosystem is javascript (the only ecosystem where a
#        side-effect import is a distinct, meaningful signal), otherwise
#        under source_imports.
#     5. Return both category's hits.
#
# IMPORTANT DETAILS
#     - WEAK_ECOSYSTEMS (ruby, php, cpp) extractors recover no bound
#       symbol name at all; their hits still count as source_imports
#       evidence, just without a side_effect_imports distinction, since
#       that distinction only has meaning where a real local binding
#       could have existed in the first place.
#
# PARAMETERS
#     ecosystem (str)
#         Ecosystem key.
#     source_files (list[str])
#         Non-test source files to search.
#     import_names (list[str])
#         Every name an import of this dependency might use (the
#         installed name plus any curated override from
#         known_import_names()).
#     dependency_match_key (str or None)
#         For java only, the groupId to match against (see
#         module_matches()).
#
# RETURNS
#     tuple[list[dict], list[dict]]
#         (source_import_hits, side_effect_import_hits), each
#         {"file", "line"}.
#
# FAILURE CASES
#     - Ecosystem not in EXTRACTORS: returns ([], []).
################################################################################
def scan_source_imports(ecosystem, source_files, import_names, dependency_match_key=None):
    """Searches source_files for a real import matching any name in
    import_names, via dead_weight_scan.py's own EXTRACTORS/module_matches().
    Side-effect-only JavaScript imports are split into their own return
    list, a distinct evidence category per the spec."""
    extractor = EXTRACTORS.get(ecosystem)
    if not extractor:
        return [], []

    source_import_hits, side_effect_import_hits = [], []
    for file_path in source_files:
        text = read_text(file_path)
        if not text:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            extracted = extractor(line)
            if not extracted:
                continue
            module_key, bound_names = extracted
            matches_any_import_name = any(
                module_matches(ecosystem, module_key, name, dependency_match_key) for name in import_names
            )
            if not matches_any_import_name:
                continue
            hit = {"file": file_path, "line": line_number}
            if ecosystem == "javascript" and not bound_names:
                side_effect_import_hits.append(hit)
            else:
                source_import_hits.append(hit)
    return source_import_hits, side_effect_import_hits


################################################################################
# FUNCTION: scan_dynamic_loading_risk
#
# PURPOSE
#     Flags whether this ecosystem's source tree contains any
#     dynamic-loading call whose target isn't a literal string right
#     there on the line, the signal that a candidate could be loaded by
#     a name built at runtime (a config value, a computed string) and
#     therefore invisible to scan_source_imports()'s static matching.
#
# RESPONSIBILITIES
#     - Search this ecosystem's non-test source files for a
#       dynamic-loading pattern with a non-literal argument.
#     - Report every such site found, without claiming it specifically
#       targets any one candidate.
#
# PROCESS OVERVIEW
#     1. If this ecosystem has no dynamic-loading pattern defined,
#        return an empty list immediately.
#     2. Search every non-test source file's lines against the pattern.
#     3. Record every matching line.
#     4. Return the collected sites.
#
# IMPORTANT DETAILS
#     - This is deliberately conservative in the direction of
#       over-flagging, not under-flagging: a match here is reported for
#       EVERY candidate dependency in this ecosystem, not pinpointed to
#       the one it might actually load, because determining that would
#       require real data-flow analysis (tracing where the string
#       argument's value actually comes from), which this tool, a static
#       text sweep, cannot do. The cost of this conservatism is more
#       manual review triggered than strictly necessary; the
#       alternative, silently missing a real dynamic reference and
#       reporting a used dependency as safe to remove, is the worse
#       failure mode for a tool whose own stated rule is "candidate
#       list, never proof."
#     - Rust, Dart, and C/C++ have no entry in
#       DYNAMIC_LOADING_PATTERNS_BY_ECOSYSTEM: none of them have a
#       commonly-used, statically-recognizable dynamic-module-loading
#       idiom comparable to the others (Rust's closest analogues require
#       unsafe FFI or build-time macro expansion, not a runtime call
#       this kind of text search could meaningfully catch).
#
# PARAMETERS
#     ecosystem (str)
#         Ecosystem key.
#     source_files (list[str])
#         Non-test source files to search.
#
# RETURNS
#     list[dict]
#         {"file", "line"} for every dynamic-loading site found. Empty
#         list if this ecosystem has no defined pattern, or none matched.
#
# FAILURE CASES
#     - Ecosystem not in DYNAMIC_LOADING_PATTERNS_BY_ECOSYSTEM: returns
#       an empty list.
################################################################################
def scan_dynamic_loading_risk(ecosystem, source_files):
    """Finds every dynamic-loading call with a non-literal argument in
    this ecosystem's source. Deliberately reported for every candidate in
    the ecosystem, not pinpointed to one, real data-flow analysis would be
    needed to do that and this is a static text sweep; see this
    function's own docstring for why over-flagging beats under-flagging
    here."""
    pattern = DYNAMIC_LOADING_PATTERNS_BY_ECOSYSTEM.get(ecosystem)
    if not pattern:
        return []
    hits = []
    for file_path in source_files:
        text = read_text(file_path)
        if not text:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                hits.append({"file": file_path, "line": line_number})
    return hits


################################################################################
# FUNCTION: find_javascript_cli_binaries
#
# PURPOSE
#     Lists the CLI binary name(s) a JavaScript package declares via its
#     own "bin" field, so the candidates search can also check for
#     references to the binary name itself (e.g. a Makefile calling
#     `eslint` rather than importing the `eslint` package).
#
# RESPONSIBILITIES
#     - Read the dependency's own package.json, if a local
#       node_modules checkout makes it available.
#     - Collect its "bin" field's key(s), or, if "bin" is a bare string,
#       the package's own name.
#
# PROCESS OVERVIEW
#     1. Look for node_modules/<name>/package.json (handling a scoped
#        package's nested directory layout).
#     2. If found, parse it and read its "bin" field.
#     3. If "bin" is a string, the binary name is the package's own
#        name. If "bin" is a dict, its keys are the binary names.
#     4. Return the collected binary names.
#
# IMPORTANT DETAILS
#     - Only resolvable when node_modules is present locally, same
#       physical-presence limitation as the lifecycle-script finders.
#       Returns an empty list, not a guess, when it isn't.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#     installed_name (str)
#         The package's installed name, e.g. "eslint" or
#         "@scope/tool".
#
# RETURNS
#     list[str]
#         Binary names this package declares. Empty list if
#         undeterminable.
#
# FAILURE CASES
#     - No local node_modules entry for this package: returns an empty
#       list.
################################################################################
def find_javascript_cli_binaries(root, installed_name):
    """Reads node_modules/<name>/package.json's "bin" field, if a local
    install makes it available. Returns [] (not a guess) if not."""
    package_dir = os.path.join(root, "node_modules", *installed_name.split("/"))
    manifest_path = os.path.join(package_dir, "package.json")
    package_json_contents = read_json(manifest_path)
    if not isinstance(package_json_contents, dict):
        return []
    bin_field = package_json_contents.get("bin")
    if isinstance(bin_field, str):
        return [installed_name.split("/")[-1]]
    if isinstance(bin_field, dict):
        return list(bin_field.keys())
    return []


################################################################################
# FUNCTION: find_type_definition_pair
#
# PURPOSE
#     Checks whether a JavaScript dependency has a matching `@types/`
#     package declared in the same workspace, so Phase 1's removal
#     decision evaluates the pair together instead of orphaning one half
#     of it.
#
# RESPONSIBILITIES
#     - Build the conventional `@types/<name>` package name for an
#       unscoped package (scoped packages use a different, less uniform
#       convention and are intentionally not guessed at here).
#     - Check whether that name appears in the workspace's own
#       dependency list.
#
# PROCESS OVERVIEW
#     1. If installed_name starts with "@" (a scoped package), return
#        no pair, this ecosystem's scoped-package types convention
#        (`@types/scope__name`) is inconsistent enough across tooling
#        that guessing it would create false pairs.
#     2. Otherwise, build the candidate types package name
#        "@types/<installed_name>".
#     3. Check whether that name is present in workspace_dependency_names.
#     4. Return the pairing result.
#
# IMPORTANT DETAILS
#     - None.
#
# PARAMETERS
#     installed_name (str)
#         The package's installed name.
#     workspace_dependency_names (list[str])
#         Every dependency name declared in the same workspace, to check
#         the types package against.
#
# RETURNS
#     dict or None
#         {"package", "present"} if installed_name is unscoped, None for
#         a scoped package.
#
# FAILURE CASES
#     - installed_name is a scoped package: returns None, not a guess.
################################################################################
def find_type_definition_pair(installed_name, workspace_dependency_names):
    """Checks for a matching @types/<name> package in the same workspace.
    Returns None for a scoped package (@scope/name), whose @types
    convention isn't uniform enough to guess at reliably."""
    if installed_name.startswith("@"):
        return None
    types_package_name = f"@types/{installed_name}"
    return {"package": types_package_name, "present": types_package_name in workspace_dependency_names}


################################################################################
# FUNCTION: build_candidate_entry
#
# PURPOSE
#     Runs every evidence category for one candidate dependency and
#     assembles its full report entry, the heart of the `candidates`
#     subcommand.
#
# RESPONSIBILITIES
#     - Run scan_source_imports(), the tool-config/string-reference
#       search, the scripts/Makefiles search, the tests search, and the
#       Dockerfiles/CI search for this one candidate.
#     - Fold in the ecosystem-wide dynamic_loading_hits already computed
#       once for the whole ecosystem.
#     - Note peer_requirements_of_retained_packages and
#       side_effect_imports as not_applicable where the ecosystem has no
#       meaningful concept of either.
#     - Decide zero_references_found from every category together.
#
# PROCESS OVERVIEW
#     1. Run scan_source_imports() for source_imports and
#        side_effect_imports.
#     2. Search the tool_configs bucket using short_name_candidates()'s
#        expanded name set for tool_configs.
#     3. Search the same expanded name set against scripts_and_makefiles,
#        source_test (for tests_and_fixtures), and dockerfiles_and_ci.
#     4. Search every non-test, non-source file under root for a quoted
#        string literal of the name, for string_references, excluding
#        the ecosystem's own manifests/lockfiles so a dependency isn't
#        trivially "referenced" by its own declaration.
#     5. Attach the ecosystem-wide dynamic_loading_hits list.
#     6. Attach CLI binary names (javascript only) and search for them
#        too, folded into scripts_and_makefiles and tests_and_fixtures.
#     7. Mark peer_requirements_of_retained_packages "not_applicable"
#        (see IMPORTANT DETAILS) and side_effect_imports "not_applicable"
#        for non-javascript ecosystems.
#     8. Set zero_references_found True only if every category's hit
#        count is zero.
#     9. Return the full entry.
#
# IMPORTANT DETAILS
#     - peer_requirements_of_retained_packages is reported
#       "not_applicable" for every ecosystem in this version: checking
#       whether another retained package declares this candidate as a
#       peer dependency requires inspecting that OTHER package's own
#       manifest, which (like lifecycle-script detection) is only
#       possible when it's physically installed locally, and even then
#       requires knowing every "other retained package" up front, a
#       scope decision properly made by the calling skill (which
#       packages are actually being retained), not by this scanner in
#       isolation. Reported honestly as not_applicable rather than
#       guessed at from this scan alone.
#
# PARAMETERS
#     root (str)
#         Repo root, used only for the CLI-binary and types-pair
#         lookups that need the full tree, not just the search universe.
#     ecosystem (str)
#         Ecosystem key.
#     installed_name (str)
#         The candidate's installed name.
#     dependency_match_key (str or None)
#         For java only, the groupId to match imports against.
#     workspace_dependency_names (list[str])
#         Every dependency name in the same workspace, for the
#         type-definition-pair check.
#     search_universe (dict)
#         Output of gather_search_universe() for this ecosystem.
#     dynamic_loading_hits (list[dict])
#         Output of scan_dynamic_loading_risk() for this ecosystem,
#         computed once and shared across every candidate.
#     string_reference_files (list[str])
#         Every non-source, non-manifest file in the repo, for the
#         string_references category.
#
# RETURNS
#     dict
#         One full candidate entry, see run_candidates()'s own output
#         schema.
#
# FAILURE CASES
#     - None expected; an empty search_universe bucket just means that
#       category finds nothing.
################################################################################
def build_candidate_entry(root, ecosystem, installed_name, dependency_match_key, workspace_dependency_names,
                           search_universe, dynamic_loading_hits, string_reference_files):
    """Runs every evidence category for one candidate dependency and
    returns its full report entry. See this module's FUNCTION doc block
    above for the per-category rules."""
    import_names = known_import_names(ecosystem, installed_name)
    name_terms = short_name_candidates(ecosystem, installed_name) | set(import_names)

    source_import_hits, side_effect_import_hits = scan_source_imports(
        ecosystem, search_universe["source_non_test"], import_names, dependency_match_key)

    tool_config_hits = find_term_in_files(search_universe["tool_configs"], name_terms)
    scripts_and_makefiles_hits = (
        find_term_in_manifest_scripts_field(search_universe["manifest_scripts_field_files"], name_terms)
        + find_term_in_files(search_universe["raw_script_files"], name_terms)
    )
    tests_hits = find_term_in_files(search_universe["source_test"], name_terms)
    dockerfiles_and_ci_hits = find_term_in_files(search_universe["dockerfiles_and_ci"], name_terms)
    string_reference_hits = find_term_in_files(string_reference_files, name_terms)

    cli_binaries = find_javascript_cli_binaries(root, installed_name) if ecosystem == "javascript" else []
    if cli_binaries:
        scripts_and_makefiles_hits += find_term_in_manifest_scripts_field(
            search_universe["manifest_scripts_field_files"], cli_binaries)
        scripts_and_makefiles_hits += find_term_in_files(search_universe["raw_script_files"], cli_binaries)
        tests_hits += find_term_in_files(search_universe["source_test"], cli_binaries)

    type_definition_pair = (
        find_type_definition_pair(installed_name, workspace_dependency_names)
        if ecosystem == "javascript" else None
    )

    search_results = {
        "source_imports": {"hit_count": len(source_import_hits), "locations": source_import_hits},
        "dynamic_loading": {"hit_count": len(dynamic_loading_hits), "locations": dynamic_loading_hits},
        "string_references": {"hit_count": len(string_reference_hits), "locations": string_reference_hits},
        "tool_configs": {"hit_count": len(tool_config_hits), "locations": tool_config_hits},
        "scripts_and_makefiles": {"hit_count": len(scripts_and_makefiles_hits), "locations": scripts_and_makefiles_hits},
        "tests_and_fixtures": {"hit_count": len(tests_hits), "locations": tests_hits},
        "dockerfiles_and_ci": {"hit_count": len(dockerfiles_and_ci_hits), "locations": dockerfiles_and_ci_hits},
        "peer_requirements_of_retained_packages": {"status": "not_applicable", "hit_count": 0, "locations": []},
        "side_effect_imports": (
            {"hit_count": len(side_effect_import_hits), "locations": side_effect_import_hits}
            if ecosystem == "javascript" else {"status": "not_applicable", "hit_count": 0, "locations": []}
        ),
    }
    total_hit_count = sum(category.get("hit_count", 0) for category in search_results.values())

    return {
        "ecosystem": ecosystem,
        "installed_name": installed_name,
        "import_names": import_names,
        "cli_binaries": cli_binaries,
        "type_definition_pair": type_definition_pair,
        "search_results": search_results,
        "zero_references_found": total_hit_count == 0,
    }


################################################################################
# FUNCTION: run_candidates
#
# PURPOSE
#     Entry point for the `candidates` subcommand: for every workspace
#     of every ecosystem, builds a full evidence report for every
#     declared dependency.
#
# RESPONSIBILITIES
#     - For javascript/rust/go, evaluate each detected workspace
#       separately.
#     - For every other ecosystem, evaluate one implicit root-level
#       workspace via dead_weight_scan.LIST_DEPS.
#     - Compute each ecosystem's shared search universe and
#       dynamic-loading risk once, reused across every candidate in that
#       ecosystem.
#
# PROCESS OVERVIEW
#     1. For each ecosystem with real workspace support, list its
#        workspaces via list_workspace_manifests().
#     2. For each other ecosystem, get its single dependency list via
#        dead_weight_scan.LIST_DEPS and treat the repo root as one
#        workspace.
#     3. For each ecosystem actually present, compute its search
#        universe and dynamic-loading risk once.
#     4. For each workspace, build a candidate entry for every declared
#        dependency.
#     5. Return all workspaces together.
#
# IMPORTANT DETAILS
#     - string_reference_files (every non-manifest, non-lockfile file in
#       the repo) is computed once globally, not per ecosystem, since a
#       string reference to a dependency can appear in any file
#       regardless of which ecosystem declared it.
#
# PARAMETERS
#     root (str)
#         Repo root to scan.
#
# RETURNS
#     dict
#         {"workspaces": [{"workspace_path", "ecosystem", "candidates":
#         [...]}]}.
#
# FAILURE CASES
#     - No manifest found for any ecosystem: returns {"workspaces": []}.
################################################################################
def run_candidates(root):
    """Entry point for the `candidates` subcommand. Builds a full
    evidence report for every declared dependency in every detected
    workspace. See build_candidate_entry() for the per-dependency
    search."""
    from dead_weight_scan import LIST_DEPS  # noqa: E402 (deferred to keep module import order simple)

    string_reference_files = [
        f for f in find_files(root, suffixes=tuple(
            ext for exts in SOURCE_EXTENSIONS.values() for ext in exts) + (
            ".json", ".yml", ".yaml", ".toml", ".cfg", ".ini", ".conf", ".md"))
        if os.path.basename(f) not in {
            "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
            "Cargo.toml", "Cargo.lock", "go.mod", "go.sum", "composer.json", "composer.lock",
            "Gemfile", "Gemfile.lock", "pom.xml", "pubspec.yaml", "pubspec.lock",
        }
    ]

    workspaces = []
    seen_ecosystems = set()

    for ecosystem in WORKSPACE_AWARE_ECOSYSTEMS:
        workspace_manifests = list_workspace_manifests(root, ecosystem)
        if not workspace_manifests:
            continue
        seen_ecosystems.add(ecosystem)
        search_universe = gather_search_universe(root, ecosystem)
        dynamic_loading_hits = scan_dynamic_loading_risk(ecosystem, search_universe["source_non_test"])
        for workspace in workspace_manifests:
            candidates = [
                build_candidate_entry(
                    root, ecosystem, name, None, workspace["dependency_names"],
                    search_universe, dynamic_loading_hits, string_reference_files)
                for name in workspace["dependency_names"]
            ]
            workspaces.append({
                "workspace_path": workspace["workspace_path"], "ecosystem": ecosystem, "candidates": candidates,
            })

    for ecosystem, lister in LIST_DEPS.items():
        if ecosystem in seen_ecosystems:
            continue
        dependency_entries = lister(root)
        if not dependency_entries:
            continue
        search_universe = gather_search_universe(root, ecosystem)
        dynamic_loading_hits = scan_dynamic_loading_risk(ecosystem, search_universe["source_non_test"])
        workspace_dependency_names = [
            (entry[2] if ecosystem == "java" else entry[0]) for entry in dependency_entries
        ]
        candidates = []
        for entry in dependency_entries:
            if ecosystem == "java":
                match_key, _manifest, display_name = entry
                name_for_report = display_name
                dependency_match_key = match_key
            else:
                name_for_report, _manifest = entry
                dependency_match_key = None
            candidates.append(build_candidate_entry(
                root, ecosystem, name_for_report, dependency_match_key, workspace_dependency_names,
                search_universe, dynamic_loading_hits, string_reference_files))
        workspaces.append({"workspace_path": root, "ecosystem": ecosystem, "candidates": candidates})

    return {"workspaces": workspaces}


# ===== MAIN =====

################################################################################
# FUNCTION: main
#
# PURPOSE
#     CLI entry point: dispatches to the subcommand named by the first
#     argument and prints its JSON result.
#
# RESPONSIBILITIES
#     - Validate that a recognized subcommand was given.
#     - Resolve the optional path argument, defaulting to the current
#       directory.
#     - Print exactly one JSON object to stdout.
#
# PROCESS OVERVIEW
#     1. Check that at least one argument (the subcommand) was given.
#     2. Check that the subcommand is one of the three recognized modes.
#     3. Resolve the path argument.
#     4. Call the matching run_*() function and print its result as
#        indented JSON.
#
# IMPORTANT DETAILS
#     - None beyond what's already documented on each run_*() function.
#
# PARAMETERS
#     None (reads sys.argv directly).
#
# RETURNS
#     None
#         Prints to stdout and calls sys.exit() on error instead.
#
# FAILURE CASES
#     - No subcommand given, or an unrecognized one: prints a JSON error
#       object and exits 1.
################################################################################
def main():
    """CLI entry point, dispatches to run_lifecycle_scripts(),
    run_unpinned_versions(), or run_candidates() based on sys.argv[1]."""
    usage_msg = "usage: trim_reaper_scan.py lifecycle-scripts|unpinned-versions|candidates [path]"
    if len(sys.argv) < 2:
        print(json.dumps({"error": usage_msg}))
        sys.exit(1)

    mode = sys.argv[1]
    root = os.path.abspath(sys.argv[2] if len(sys.argv) > 2 else ".")

    if mode == "lifecycle-scripts":
        print(json.dumps(run_lifecycle_scripts(root), indent=2))
    elif mode == "unpinned-versions":
        print(json.dumps(run_unpinned_versions(root), indent=2))
    elif mode == "candidates":
        print(json.dumps(run_candidates(root), indent=2))
    else:
        print(json.dumps({"error": f"unknown mode {mode!r}, expected lifecycle-scripts, unpinned-versions, or candidates"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
