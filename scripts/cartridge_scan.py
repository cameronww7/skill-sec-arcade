#!/usr/bin/env python3
"""Cartridge Scanner: repo inventory for cartridge-scanner skill.

Walks a repo, runs `scc` for language/LOC stats (falls back to a rough
manual count if `scc` isn't installed), inventories package manager
manifests/lockfiles with approximate dependency counts, flags any
non-default (private/internal) package registries, and finds
Dockerfiles/compose files and common IaC file types.

Prints one JSON object to stdout. No prose, no markdown: interpretation
is the calling skill's job, not this script's.

`walk`, `find_files`, `read_text`, `read_json`, and `EXCLUDE_DIRS` are
also imported directly by dead_weight_scan.py, keep their names and
signatures stable.
"""

import ast
import configparser
import json
import os
import re
import subprocess
import sys
from urllib.parse import urlparse

# Directories that are never first-party code: dependency caches, build
# output, and VCS metadata. Pruned from every walk below, both for `scc`'s
# fallback LOC count and for manifest/source-file discovery.
EXCLUDE_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "env",
    "site-packages", "dist", "build", "target", ".tox",
    ".mypy_cache", "__pycache__", "bower_components", ".terraform",
    ".serverless",
}

# Small, deliberately partial extension map used only when `scc` isn't
# installed. `scc` itself recognizes far more languages; this fallback
# exists to keep the report non-empty, not to replace it.
FALLBACK_EXT_LANG = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".go": "Go",
    ".java": "Java", ".kt": "Kotlin", ".rb": "Ruby", ".php": "PHP",
    ".rs": "Rust", ".cs": "C#", ".c": "C", ".h": "C", ".cpp": "C++",
    ".hpp": "C++", ".swift": "Swift", ".dart": "Dart",
    ".sh": "Shell", ".yaml": "YAML", ".yml": "YAML", ".tf": "Terraform",
    ".sql": "SQL", ".scala": "Scala", ".m": "Objective-C",
    ".html": "HTML", ".css": "CSS", ".scss": "SCSS",
}

# The public default registry host(s) per ecosystem. Any manifest/config
# pointing somewhere else is flagged as a private/internal registry, see
# add_if_private() below.
DEFAULT_REGISTRY_HOSTS = {
    "javascript": {"registry.npmjs.org"},
    "pip": {"pypi.org", "files.pythonhosted.org"},
    "maven": {"repo.maven.apache.org", "repo1.maven.org", "central.sonatype.com"},
    "gem": {"rubygems.org"},
    "composer": {"repo.packagist.org"},
    "cargo": {"crates.io", "static.crates.io"},
    "nuget": {"api.nuget.org", "www.nuget.org"},
}


def read_text(path):
    """Reads a file as UTF-8, tolerating decode errors. Returns "" on any
    failure (missing file, permission error, etc.) instead of raising."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


def read_json(path):
    """Reads and parses a file as JSON. Returns None if it's missing,
    unreadable, or not valid JSON, never raises."""
    try:
        return json.loads(read_text(path))
    except (ValueError, TypeError):
        return None


def walk(root):
    """Drop-in replacement for os.walk(root) that prunes EXCLUDE_DIRS from
    dirnames in place, so nothing under them is ever visited or yielded."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        yield dirpath, dirnames, filenames


def find_files(root, names=None, suffixes=None):
    """Finds every file under root (via walk(), so EXCLUDE_DIRS is already
    pruned) whose filename is an exact match in `names` or ends with one
    of `suffixes`. Returns a plain list of full paths, unsorted."""
    names = set(names or [])
    suffixes = tuple(suffixes or ())
    hits = []
    for dirpath, _dirnames, filenames in walk(root):
        for filename in filenames:
            if filename in names or (suffixes and filename.endswith(suffixes)):
                hits.append(os.path.join(dirpath, filename))
    return hits


# --- scc / fallback LOC -----------------------------------------------

def run_scc(root):
    """Shells out to the `scc` CLI for language/LOC stats. Returns a list
    of per-language dicts, or None if `scc` isn't installed, times out, or
    exits non-zero, the caller falls back to fallback_loc_scan() in that
    case."""
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
        raw_entries = json.loads(proc.stdout)
    except ValueError:
        return None
    languages = []
    for entry in raw_entries:
        # scc's JSON keys are PascalCase; normalize to our snake_case schema.
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
    """Rough manual LOC count used only when `scc` isn't available: files
    and total line count per language in FALLBACK_EXT_LANG. No
    comment/blank/complexity split, that data needs a real tokenizer."""
    languages_by_name = {}
    for dirpath, _dirnames, filenames in walk(root):
        for filename in filenames:
            ext = os.path.splitext(filename)[1].lower()
            language = FALLBACK_EXT_LANG.get(ext)
            if not language:
                continue
            path = os.path.join(dirpath, filename)
            text = read_text(path)
            if not text and os.path.getsize(path) > 0:
                continue  # unreadable/binary
            entry = languages_by_name.setdefault(language, {
                "name": language, "files": 0, "lines": 0,
                "code": 0, "comment": 0, "blank": 0, "complexity": 0,
            })
            entry["files"] += 1
            entry["lines"] += text.count("\n") + (1 if text and not text.endswith("\n") else 0)
    return list(languages_by_name.values())


def totals_of(languages):
    """Sums the files/lines/code/comment/blank fields across every
    language entry (from run_scc() or fallback_loc_scan()) into one dict."""
    totals = {"files": 0, "lines": 0, "code": 0, "comment": 0, "blank": 0}
    for language in languages:
        for key in totals:
            totals[key] += language.get(key, 0)
    return totals


# --- generic helpers for manifest/lockfile parsing ---------------------

def toml_section_lines(text, header):
    """Returns the raw lines belonging to a `[header]` TOML table, up to
    (not including) the next `[...]` table header. Not a real TOML parser,
    just enough to hand a table's body to count_key_value_lines()."""
    lines = text.splitlines()
    section_lines = []
    in_section = False
    for line in lines:
        stripped_line = line.strip()
        if stripped_line.startswith("["):
            in_section = stripped_line == f"[{header}]"
            continue
        if in_section:
            section_lines.append(line)
    return section_lines


def count_key_value_lines(lines, exclude_keys=()):
    """Counts `key = value` lines (as produced by toml_section_lines()),
    skipping blanks, comments, and any key named in exclude_keys."""
    count = 0
    for line in lines:
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith("#"):
            continue
        match = re.match(r'^["\']?([\w.\-/@]+)["\']?\s*=', stripped_line)
        if match and match.group(1) not in exclude_keys:
            count += 1
    return count


def host_of(url):
    """Extracts the hostname from a URL string. Returns None for anything
    unparseable rather than raising."""
    try:
        return urlparse(url).hostname
    except ValueError:
        return None


def add_if_private(private_registries, ecosystem, url, source_file, default_hosts):
    """Appends a private-registry entry if url's host isn't one of
    default_hosts for this ecosystem. No-op if the host matches a default
    or can't be parsed, this is the single choke point every scan_*
    function routes registry URLs through."""
    host = host_of(url)
    if not host or host in default_hosts:
        return
    private_registries.append({"ecosystem": ecosystem, "host": host, "url": url, "source_file": source_file})


# --- per-ecosystem package manager inventory ----------------------------

def scan_javascript(root, package_managers, private_registries):
    """JavaScript, via npm/yarn/pnpm: declared count from package.json,
    resolved count from whichever lockfile is present (format differs by
    tool), plus any non-default registry found in package.json or .npmrc.
    Appends one entry to package_managers if any npm manifest/lockfile
    exists."""
    manifests = find_files(root, names={"package.json"})
    lockfiles = find_files(root, names={"package-lock.json", "yarn.lock", "pnpm-lock.yaml"})
    if not manifests and not lockfiles:
        return
    declared_count = None
    for manifest in manifests:
        data = read_json(manifest)
        if not isinstance(data, dict):
            continue
        declared_count = sum(len(data.get(key) or {}) for key in
                              ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"))
        publish_registry = (data.get("publishConfig") or {}).get("registry")
        if publish_registry:
            add_if_private(private_registries, "javascript", publish_registry, manifest,
                            DEFAULT_REGISTRY_HOSTS["javascript"])
        break
    resolved_count = None
    for lockfile in lockfiles:
        filename = os.path.basename(lockfile)
        text = read_text(lockfile)
        if filename == "package-lock.json":
            data = read_json(lockfile)
            if isinstance(data, dict) and isinstance(data.get("packages"), dict):
                # v2/v3 lockfile: flat "packages" map, one entry per resolved
                # package plus a "" entry for the root project itself.
                resolved_count = len(data["packages"]) - (1 if "" in data["packages"] else 0)
            elif isinstance(data, dict) and isinstance(data.get("dependencies"), dict):
                # v1 lockfile: nested "dependencies" tree, walk it recursively.
                def count_nested_deps(deps):
                    count = 0
                    for value in deps.values():
                        count += 1
                        if isinstance(value, dict) and isinstance(value.get("dependencies"), dict):
                            count += count_nested_deps(value["dependencies"])
                    return count
                resolved_count = count_nested_deps(data["dependencies"])
        elif filename == "yarn.lock":
            # yarn.lock entries are blocks whose header line starts at
            # column 0 and ends with ":", one block per resolved package.
            resolved_count = sum(1 for line in text.splitlines()
                                  if line and not line[0].isspace() and line.rstrip().endswith(":")
                                  and not line.startswith("#")) or None
        elif filename == "pnpm-lock.yaml":
            resolved_count = len(re.findall(r"^\s{2}[^\s#][^:]*:\s*$", text, re.MULTILINE)) or None
        if resolved_count is not None:
            break
    for npmrc_file in find_files(root, names={".npmrc"}):
        text = read_text(npmrc_file)
        for match in re.finditer(r"^(?:@[\w-]+:)?registry\s*=\s*(\S+)", text, re.MULTILINE):
            add_if_private(private_registries, "javascript", match.group(1), npmrc_file,
                            DEFAULT_REGISTRY_HOSTS["javascript"])
    package_managers.append({"ecosystem": "javascript", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


def install_requires_from_setup_cfg(path):
    """setup.cfg's [options] install_requires field via stdlib configparser
    (setup.cfg is genuine INI, no need for a hand-rolled continuation-line
    parser; configparser already correctly joins the "install_requires =\\n
    pkg1\\n    pkg2" continuation form into one string). Returns a list of
    requirement-spec strings (version specifier still attached, same shape
    as a requirements.txt line), or None if unparseable/absent."""
    parser = configparser.ConfigParser()
    try:
        parser.read_string(read_text(path))
    except configparser.Error:
        return None
    if not parser.has_option("options", "install_requires"):
        return None
    raw = parser.get("options", "install_requires")
    return [line.strip() for line in raw.replace(",", "\n").splitlines() if line.strip()]


def install_requires_from_setup_py(path):
    """setup.py's setup(install_requires=...) argument, extracted via ast
    in parse-only mode. This tool never executes code from a scanned repo,
    a real concern for a security-tooling suite pointed at untrusted repos,
    so only a literal list/tuple of strings is resolved; a computed value
    (a variable, a call to a helper that reads requirements.txt, etc.)
    can't be resolved statically and is honestly skipped, not guessed."""
    try:
        tree = ast.parse(read_text(path))
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "setup":
            for keyword in node.keywords:
                if keyword.arg == "install_requires":
                    try:
                        value = ast.literal_eval(keyword.value)
                    except (ValueError, SyntaxError):
                        return None
                    if isinstance(value, (list, tuple)):
                        return [v for v in value if isinstance(v, str)]
    return None


def scan_python(root, package_managers, private_registries):
    """Python: declared count from requirements*.txt, pyproject.toml
    (PEP 621 and Poetry), Pipfile, setup.py, and setup.cfg; resolved count
    from Pipfile.lock, poetry.lock, and uv.lock; non-default index URLs
    from any of those plus pip.conf/pip.ini."""
    requirements_files = find_files(root, suffixes=("requirements.txt",)) + \
        [f for f in find_files(root, suffixes=(".txt",)) if os.path.basename(f).startswith("requirements")]
    requirements_files = sorted(set(requirements_files))
    pyproject_files = find_files(root, names={"pyproject.toml"})
    pipfiles = find_files(root, names={"Pipfile"})
    setup_pys = find_files(root, names={"setup.py"})
    setup_cfgs = find_files(root, names={"setup.cfg"})
    pipfile_locks = find_files(root, names={"Pipfile.lock"})
    poetry_locks = find_files(root, names={"poetry.lock"})
    uv_locks = find_files(root, names={"uv.lock"})
    manifests = requirements_files + pyproject_files + pipfiles + setup_pys + setup_cfgs
    lockfiles = pipfile_locks + poetry_locks + uv_locks
    if not manifests and not lockfiles:
        return
    declared_count = None
    for requirements_file in requirements_files:
        text = read_text(requirements_file)
        count = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-"):
                match = re.match(r"--(?:extra-)?index-url\s+(\S+)", line)
                if match:
                    add_if_private(private_registries, "pip", match.group(1), requirements_file,
                                    DEFAULT_REGISTRY_HOSTS["pip"])
                continue
            count += 1
        declared_count = (declared_count or 0) + count
    for pyproject_file in pyproject_files:
        text = read_text(pyproject_file)
        pep621_match = re.search(r"dependencies\s*=\s*\[(.*?)\]", text, re.DOTALL)
        if pep621_match:
            declared_count = (declared_count or 0) + len(re.findall(r'["\']([^"\']+)["\']', pep621_match.group(1)))
        poetry_dep_lines = toml_section_lines(text, "tool.poetry.dependencies")
        if poetry_dep_lines:
            declared_count = (declared_count or 0) + count_key_value_lines(poetry_dep_lines, exclude_keys={"python"})
        for source_match in re.finditer(
                r'\[\[tool\.poetry\.source\]\].*?url\s*=\s*["\']([^"\']+)["\']', text, re.DOTALL):
            add_if_private(private_registries, "pip", source_match.group(1), pyproject_file,
                            DEFAULT_REGISTRY_HOSTS["pip"])
    for pipfile in pipfiles:
        text = read_text(pipfile)
        for section in ("packages", "dev-packages"):
            section_lines = toml_section_lines(text, section)
            declared_count = (declared_count or 0) + count_key_value_lines(section_lines)
    for setup_py_file in setup_pys:
        requires = install_requires_from_setup_py(setup_py_file)
        if requires:
            declared_count = (declared_count or 0) + len(requires)
    for setup_cfg_file in setup_cfgs:
        requires = install_requires_from_setup_cfg(setup_cfg_file)
        if requires:
            declared_count = (declared_count or 0) + len(requires)
    resolved_count = None
    for lockfile in pipfile_locks:
        data = read_json(lockfile)
        if isinstance(data, dict):
            resolved_count = (resolved_count or 0) + len(data.get("default") or {}) + len(data.get("develop") or {})
    for lockfile in poetry_locks + uv_locks:
        text = read_text(lockfile)
        block_count = len(re.findall(r"^\[\[package\]\]\s*$", text, re.MULTILINE))
        if block_count:
            resolved_count = (resolved_count or 0) + block_count
    for pip_conf in find_files(root, names={"pip.conf", "pip.ini"}):
        text = read_text(pip_conf)
        match = re.search(r"index-url\s*=\s*(\S+)", text)
        if match:
            add_if_private(private_registries, "pip", match.group(1), pip_conf, DEFAULT_REGISTRY_HOSTS["pip"])
    package_managers.append({"ecosystem": "python", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


def scan_go(root, package_managers, private_registries):
    """Go: declared count from go.mod's require directives, resolved
    count from unique modules in go.sum, plus any `replace` directive
    that points at a private host instead of a version."""
    manifests = find_files(root, names={"go.mod"})
    lockfiles = find_files(root, names={"go.sum"})
    if not manifests and not lockfiles:
        return
    declared_count = None
    for go_mod_file in manifests:
        text = read_text(go_mod_file)
        count = 0
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
                if stripped_line and not stripped_line.startswith("//"):
                    count += 1
                continue
            if stripped_line.startswith("require ") and "(" not in stripped_line:
                count += 1
        declared_count = (declared_count or 0) + count
        for match in re.finditer(r"^replace\s+\S+\s*=>\s*(\S+)", text, re.MULTILINE):
            target = match.group(1)
            if "://" in target or (re.match(r"^[\w.-]+\.[a-z]{2,}/", target)):
                url = target if "://" in target else f"https://{target}"
                add_if_private(private_registries, "go", url, go_mod_file, set())
    resolved_count = None
    for go_sum_file in lockfiles:
        text = read_text(go_sum_file)
        # Each line is "module version hash"; a module usually appears
        # twice (module hash + go.mod hash), dedupe to unique modules.
        modules = {line.split()[0] for line in text.splitlines() if line.split()}
        if modules:
            resolved_count = (resolved_count or 0) + len(modules)
    package_managers.append({"ecosystem": "go", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


def scan_java(root, package_managers, private_registries):
    """Java/Maven/Gradle/Ivy: declared count from <dependency> tags
    (pom.xml), dependency-config calls (build.gradle), or <dependency
    org=.../> tags (ivy.xml), plus any custom Maven repository URL. No
    resolved count, none of the three has a default lockfile. Ivy resolvers
    are conventionally configured in a separate ivysettings.xml, not
    embedded in ivy.xml itself, so private-registry detection isn't
    attempted for Ivy manifests."""
    manifests = find_files(root, names={"pom.xml", "build.gradle", "build.gradle.kts", "ivy.xml"})
    if not manifests:
        return
    declared_count = None
    for manifest in manifests:
        text = read_text(manifest)
        if manifest.endswith("pom.xml"):
            declared_count = (declared_count or 0) + len(re.findall(r"<dependency>", text))
            repositories_block = re.search(r"<repositories>(.*?)</repositories>", text, re.DOTALL)
            if repositories_block:
                for url_match in re.finditer(r"<url>([^<]+)</url>", repositories_block.group(1)):
                    add_if_private(private_registries, "maven", url_match.group(1), manifest,
                                    DEFAULT_REGISTRY_HOSTS["maven"])
        elif manifest.endswith("ivy.xml"):
            # Ivy's <dependency org="..." name="..." rev="..."/> is a
            # self-closing attribute tag, unlike Maven's nested-element
            # <dependency>...</dependency>, so it needs its own count.
            declared_count = (declared_count or 0) + len(re.findall(r"<dependency\b", text))
        else:
            declared_count = (declared_count or 0) + len(re.findall(
                r"\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly)\s*[\(\'\"]",
                text))
            for url_match in re.finditer(r"maven\s*\{\s*url\s*[=]?\s*[\'\"]([^\'\"]+)[\'\"]", text):
                add_if_private(private_registries, "maven", url_match.group(1), manifest,
                                DEFAULT_REGISTRY_HOSTS["maven"])
    package_managers.append({"ecosystem": "java", "manifest_files": manifests, "lockfile_files": [],
                              "declared_dependencies": declared_count, "resolved_dependencies": None})


def scan_ruby(root, package_managers, private_registries):
    """Ruby/Bundler: declared count from `gem` lines in the Gemfile,
    resolved count from the GEM specs: block in Gemfile.lock, plus any
    non-default `source` line."""
    manifests = find_files(root, names={"Gemfile"})
    lockfiles = find_files(root, names={"Gemfile.lock"})
    if not manifests and not lockfiles:
        return
    declared_count = None
    for gemfile in manifests:
        text = read_text(gemfile)
        declared_count = (declared_count or 0) + len(re.findall(r"^\s*gem\s+['\"]", text, re.MULTILINE))
        for match in re.finditer(r"^\s*source\s+['\"]([^'\"]+)['\"]", text, re.MULTILINE):
            add_if_private(private_registries, "gem", match.group(1), gemfile, DEFAULT_REGISTRY_HOSTS["gem"])
    resolved_count = None
    for lockfile in lockfiles:
        text = read_text(lockfile)
        count = 0
        in_specs_section = False
        for line in text.splitlines():
            if line.strip() == "specs:":
                in_specs_section = True
                continue
            if in_specs_section:
                # Top-level gems are indented 4 spaces; their own
                # dependencies are indented 6, only count the former.
                if line.startswith("    ") and not line.startswith("      "):
                    count += 1
                elif line and not line.startswith(" "):
                    in_specs_section = False
        if count:
            resolved_count = (resolved_count or 0) + count
    package_managers.append({"ecosystem": "ruby", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


def scan_php(root, package_managers, private_registries):
    """PHP/Composer: declared count from require + require-dev in
    composer.json, resolved count from packages + packages-dev arrays in
    composer.lock, plus any custom repository URL."""
    manifests = find_files(root, names={"composer.json"})
    lockfiles = find_files(root, names={"composer.lock"})
    if not manifests and not lockfiles:
        return
    declared_count = None
    for composer_json_file in manifests:
        data = read_json(composer_json_file)
        if isinstance(data, dict):
            required = {k: v for k, v in (data.get("require") or {}).items() if k != "php"}
            required_dev = data.get("require-dev") or {}
            declared_count = (declared_count or 0) + len(required) + len(required_dev)
            repositories = data.get("repositories")
            if isinstance(repositories, list):
                for repository in repositories:
                    if isinstance(repository, dict) and repository.get("url"):
                        add_if_private(private_registries, "composer", repository["url"], composer_json_file,
                                        DEFAULT_REGISTRY_HOSTS["composer"])
            elif isinstance(repositories, dict):
                for repository in repositories.values():
                    if isinstance(repository, dict) and repository.get("url"):
                        add_if_private(private_registries, "composer", repository["url"], composer_json_file,
                                        DEFAULT_REGISTRY_HOSTS["composer"])
    resolved_count = None
    for lockfile in lockfiles:
        data = read_json(lockfile)
        if isinstance(data, dict):
            resolved_count = (resolved_count or 0) + len(data.get("packages") or []) + \
                len(data.get("packages-dev") or [])
    package_managers.append({"ecosystem": "php", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


def scan_rust(root, package_managers, private_registries):
    """Rust/Cargo: declared count from the [dependencies]/[dev-dependencies]/
    [build-dependencies] tables in Cargo.toml, resolved count from
    [[package]] blocks in Cargo.lock, plus any custom registry in a
    repo-local .cargo/config.toml."""
    manifests = find_files(root, names={"Cargo.toml"})
    lockfiles = find_files(root, names={"Cargo.lock"})
    if not manifests and not lockfiles:
        return
    declared_count = None
    for cargo_toml_file in manifests:
        text = read_text(cargo_toml_file)
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            declared_count = (declared_count or 0) + count_key_value_lines(toml_section_lines(text, section))
    for cargo_config_file in find_files(root, names={"config.toml"}):
        if os.path.basename(os.path.dirname(cargo_config_file)) != ".cargo":
            continue
        text = read_text(cargo_config_file)
        for match in re.finditer(r"registry\s*=\s*['\"]([^'\"]+)['\"]", text):
            add_if_private(private_registries, "cargo", match.group(1), cargo_config_file,
                            DEFAULT_REGISTRY_HOSTS["cargo"])
    resolved_count = None
    for lockfile in lockfiles:
        text = read_text(lockfile)
        block_count = len(re.findall(r"^\[\[package\]\]\s*$", text, re.MULTILINE))
        if block_count:
            resolved_count = (resolved_count or 0) + block_count
    package_managers.append({"ecosystem": "rust", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


def scan_dotnet(root, package_managers, private_registries):
    """.NET/NuGet/Paket: declared count from <PackageReference> tags across
    .csproj files plus `nuget` lines in paket.dependencies, resolved count
    from packages.lock.json and/or paket.lock (if present), plus any
    custom source in nuget.config or paket.dependencies. Paket and the
    NuGet CLI both resolve from the same NuGet registry, so they share one
    ecosystem entry here."""
    csproj_files = find_files(root, suffixes=(".csproj",))
    paket_deps_files = find_files(root, names={"paket.dependencies"})
    manifests = csproj_files + paket_deps_files
    packages_lock_files = find_files(root, names={"packages.lock.json"})
    paket_lock_files = find_files(root, names={"paket.lock"})
    lockfiles = packages_lock_files + paket_lock_files
    if not manifests and not lockfiles:
        return
    declared_count = None
    for csproj_file in csproj_files:
        text = read_text(csproj_file)
        declared_count = (declared_count or 0) + len(re.findall(r"<PackageReference\b", text))
    for paket_deps_file in paket_deps_files:
        text = read_text(paket_deps_file)
        declared_count = (declared_count or 0) + len(re.findall(r"^\s*nuget\s+\S+", text, re.MULTILINE | re.IGNORECASE))
        for source_match in re.finditer(r"^\s*source\s+(\S+)", text, re.MULTILINE | re.IGNORECASE):
            add_if_private(private_registries, "nuget", source_match.group(1), paket_deps_file,
                            DEFAULT_REGISTRY_HOSTS["nuget"])
    resolved_count = None
    for lockfile in packages_lock_files:
        data = read_json(lockfile)
        if isinstance(data, dict) and isinstance(data.get("dependencies"), dict):
            total = 0
            for framework_deps in data["dependencies"].values():
                if isinstance(framework_deps, dict):
                    total += len(framework_deps)
            if total:
                resolved_count = (resolved_count or 0) + total
    for paket_lock_file in paket_lock_files:
        text = read_text(paket_lock_file)
        # paket.lock's NUGET block uses the same indentation convention as
        # Gemfile.lock's specs: block, 4-space-indented lines are top-level
        # packages, 6-space-indented lines are their transitive deps.
        count = 0
        in_nuget_section = False
        for line in text.splitlines():
            if line.strip() == "NUGET":
                in_nuget_section = True
                continue
            if in_nuget_section:
                if line.startswith("    ") and not line.startswith("      ") and not line.strip().startswith("remote:"):
                    count += 1
                elif line and not line.startswith(" "):
                    in_nuget_section = False
        if count:
            resolved_count = (resolved_count or 0) + count
    for nuget_config_file in find_files(root, names={"nuget.config", "NuGet.Config"}):
        text = read_text(nuget_config_file)
        for match in re.finditer(r'<add\s+key="[^"]*"\s+value="([^"]+)"', text):
            if match.group(1).startswith("http"):
                add_if_private(private_registries, "nuget", match.group(1), nuget_config_file,
                                DEFAULT_REGISTRY_HOSTS["nuget"])
    package_managers.append({"ecosystem": "dotnet", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


def scan_dart(root, package_managers, _private_registries):
    """Dart/Flutter: declared count from the dependencies/dev_dependencies
    blocks in pubspec.yaml, resolved count from top-level package entries
    in pubspec.lock. Takes private_registries for signature symmetry with
    the other scan_* functions but pub.dev has no private-registry config
    convention to check."""
    manifests = find_files(root, names={"pubspec.yaml"})
    lockfiles = find_files(root, names={"pubspec.lock"})
    if not manifests and not lockfiles:
        return
    declared_count = None
    for pubspec_file in manifests:
        text = read_text(pubspec_file)
        in_deps_section = False
        count = 0
        for line in text.splitlines():
            if re.match(r"^(dependencies|dev_dependencies):\s*$", line):
                in_deps_section = True
                continue
            if in_deps_section:
                if re.match(r"^\S", line):
                    in_deps_section = False
                    continue
                if re.match(r"^  \S[^:]*:", line):
                    count += 1
        declared_count = (declared_count or 0) + count
    resolved_count = None
    for lockfile in lockfiles:
        text = read_text(lockfile)
        block_count = len(re.findall(r"^  \S[^:]*:\s*$", text, re.MULTILINE))
        if block_count:
            resolved_count = (resolved_count or 0) + block_count
    package_managers.append({"ecosystem": "dart", "manifest_files": manifests, "lockfile_files": lockfiles,
                              "declared_dependencies": declared_count, "resolved_dependencies": resolved_count})


def run_syft_conan(root):
    """Shells out to `syft dir:<root> -o json --select-catalogers conan,sbom`
    for Conan dependency detection: syft's conan-cataloger correctly
    handles both conan.lock v1 and v2 formats plus conaninfo.txt, and its
    sbom-cataloger picks up any vendor-supplied SBOM checked into the repo
    (*.cdx.json, *.spdx.json, *.syft.json), none of which the regex/JSON
    fallback in scan_cpp() can match. Returns a list of {"name", "version"}
    artifact dicts, or None if syft isn't installed, times out, or exits
    non-zero, the caller falls back to the manifest-only parse in that
    case, same optional-tool contract as run_scc()."""
    try:
        proc = subprocess.run(
            ["syft", f"dir:{root}", "-o", "json", "--select-catalogers", "conan,sbom"],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        return None
    return [a for a in (data.get("artifacts") or []) if a.get("name") and a.get("version")]


def scan_cpp_structural_signals(root):
    """Best-effort CMakeLists.txt find_package()/FetchContent_Declare()
    calls and .gitmodules submodule entries: a structural hint that a
    C/C++ dependency exists, not a real manifest entry. Most of the time
    there's no pinned version to report, find_package() usually has none
    at all, and a FetchContent GIT_TAG can be a branch name rather than a
    release, so this is deliberately kept out of declared_dependencies/
    resolved_dependencies in scan_cpp(), a lower-confidence signal, not a
    substitute for a real manifest. Mirrors the "structural regex signal,
    not deep analysis" approach already used for Dockerfile FROM scraping
    and IaC content-sniffing elsewhere in this file."""
    signals = []
    for cmake_file in find_files(root, names={"CMakeLists.txt"}):
        text = read_text(cmake_file)
        for match in re.finditer(r"find_package\(\s*([A-Za-z0-9_.-]+)", text):
            signals.append({"name": match.group(1), "source": "find_package", "file": cmake_file})
        for match in re.finditer(
                r"FetchContent_Declare\(\s*([A-Za-z0-9_.-]+)[^)]*?GIT_REPOSITORY\s+(\S+)(?:[^)]*?GIT_TAG\s+(\S+))?",
                text, re.DOTALL):
            signals.append({"name": match.group(1), "source": "FetchContent_Declare", "file": cmake_file,
                             "repository": match.group(2), "ref": match.group(3)})
    for gitmodules_file in find_files(root, names={".gitmodules"}):
        text = read_text(gitmodules_file)
        for match in re.finditer(r'\[submodule\s+"([^"]+)"\][^\[]*?url\s*=\s*(\S+)', text, re.DOTALL):
            signals.append({"name": match.group(1), "source": "gitmodules", "file": gitmodules_file,
                             "repository": match.group(2)})
    return signals


def scan_cpp(root, package_managers, private_registries):
    """C/C++: Conan (via syft when available, since it handles conan.lock
    v1+v2, conaninfo.txt, and vendor SBOMs, else conanfile.txt/
    conanfile.py + conan.lock v2-shape parsing) and vcpkg (vcpkg.json,
    always hand-rolled, syft has no vcpkg cataloger). CMakeLists.txt/
    .gitmodules structural signals are reported separately, see
    scan_cpp_structural_signals(). No private-registry detection in this
    pass, no reliable committed-file convention for Conan remotes (same
    call already made for Ivy/Dart)."""
    conanfile_txts = find_files(root, names={"conanfile.txt"})
    conanfile_pys = find_files(root, names={"conanfile.py"})
    vcpkg_jsons = find_files(root, names={"vcpkg.json"})
    conan_locks = find_files(root, names={"conan.lock"})
    manifests = conanfile_txts + conanfile_pys + vcpkg_jsons
    lockfiles = conan_locks
    unversioned_signals = scan_cpp_structural_signals(root)
    if not manifests and not lockfiles and not unversioned_signals:
        return

    declared_count = None
    for conanfile_txt in conanfile_txts:
        text = read_text(conanfile_txt)
        count = 0
        for section in ("requires", "build_requires", "tool_requires"):
            for line in toml_section_lines(text, section):
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith("#"):
                    count += 1
        declared_count = (declared_count or 0) + count
    for conanfile_py in conanfile_pys:
        text = read_text(conanfile_py)
        count = len(re.findall(r"self\.(?:requires|build_requires|tool_requires)\(", text))
        declared_count = (declared_count or 0) + count
    for vcpkg_json_file in vcpkg_jsons:
        data = read_json(vcpkg_json_file)
        if isinstance(data, dict):
            deps = data.get("dependencies")
            if isinstance(deps, list):
                declared_count = (declared_count or 0) + len(deps)

    resolved_count = None
    syft_packages = run_syft_conan(root) if (conanfile_txts or conanfile_pys or conan_locks) else None
    if syft_packages is not None:
        resolved_count = len(syft_packages) or None
    else:
        for lockfile in conan_locks:
            data = read_json(lockfile)
            if isinstance(data, dict):
                count = 0
                for key in ("requires", "build_requires", "tool_requires", "python_requires"):
                    value = data.get(key)
                    if isinstance(value, list):
                        count += len(value)
                if count:
                    resolved_count = (resolved_count or 0) + count

    package_managers.append({
        "ecosystem": "cpp", "manifest_files": manifests, "lockfile_files": lockfiles,
        "declared_dependencies": declared_count, "resolved_dependencies": resolved_count,
        "unversioned_signals": unversioned_signals,
    })


def scan_package_managers(root):
    """Runs every ecosystem's scan_* function and collects their results.
    Returns (package_managers, private_registries), the two lists every
    scan_* function appends/extends in place."""
    package_managers = []
    private_registries = []
    for scan_fn in (scan_javascript, scan_python, scan_go, scan_java, scan_ruby, scan_php, scan_rust, scan_dotnet,
                     scan_dart, scan_cpp):
        scan_fn(root, package_managers, private_registries)
    return package_managers, private_registries


# --- containers ----------------------------------------------------------

def scan_containers(root):
    """Finds every Dockerfile (including suffixed variants like
    Dockerfile.dev) with its FROM base images, and every
    docker-compose*.yml/.yaml file."""
    dockerfile_paths = list(find_files(root, names={"Dockerfile"}))
    for dirpath, _dirnames, filenames in walk(root):
        for filename in filenames:
            if filename.startswith("Dockerfile") and filename != "Dockerfile":
                dockerfile_paths.append(os.path.join(dirpath, filename))
    dockerfiles = []
    for path in sorted(set(dockerfile_paths)):
        text = read_text(path)
        base_images = re.findall(r"^FROM\s+(\S+)", text, re.MULTILINE)
        dockerfiles.append({"path": path, "base_images": base_images})
    compose_files = []
    for dirpath, _dirnames, filenames in walk(root):
        for filename in filenames:
            if re.match(r"^docker-compose.*\.ya?ml$", filename):
                compose_files.append(os.path.join(dirpath, filename))
    return {"dockerfiles": dockerfiles, "compose_files": sorted(compose_files)}


# --- IaC -------------------------------------------------------------------

def scan_iac(root):
    """Finds Infrastructure-as-Code files by a mix of filename (Terraform,
    Helm, Pulumi, Serverless, CDK) and content sniffing (CloudFormation,
    Kubernetes, Ansible, which all use plain .yml/.yaml/.json)."""
    result = {"terraform": [], "cloudformation": [], "kubernetes": [], "helm": [],
              "ansible": [], "pulumi": [], "serverless": [], "cdk": []}
    result["terraform"] = sorted(find_files(root, suffixes=(".tf", ".tfvars")))
    result["helm"] = sorted(find_files(root, names={"Chart.yaml"}))
    result["pulumi"] = sorted(find_files(root, names={"Pulumi.yaml"}))
    result["serverless"] = sorted(find_files(root, names={"serverless.yml", "serverless.yaml"}))
    result["cdk"] = sorted(find_files(root, names={"cdk.json"}))

    # These three overlap in file extension (.yml/.yaml/.json), so content
    # sniffing decides which bucket a file lands in. Checked in this order
    # since a CloudFormation template could technically also contain the
    # substring "kind:" in a resource property, but not the reverse.
    for dirpath, _dirnames, filenames in walk(root):
        for filename in filenames:
            if not filename.endswith((".yml", ".yaml", ".json")):
                continue
            path = os.path.join(dirpath, filename)
            text = read_text(path)
            if not text:
                continue
            if "AWSTemplateFormatVersion" in text or re.search(r"Type:\s*['\"]?AWS::", text):
                result["cloudformation"].append(path)
                continue
            if filename.endswith((".yml", ".yaml")) and "apiVersion:" in text and "kind:" in text:
                result["kubernetes"].append(path)
                continue
            if filename.endswith((".yml", ".yaml")) and "hosts:" in text and "tasks:" in text:
                result["ansible"].append(path)

    for key in result:
        result[key] = sorted(set(result[key]))
    return result


# --- main ------------------------------------------------------------------

def main():
    """CLI entry point: `cartridge_scan.py [path]` (defaults to `.`).
    Runs every scan and prints one JSON object to stdout."""
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
