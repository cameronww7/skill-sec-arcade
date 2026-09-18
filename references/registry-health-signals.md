# Registry Health Signals

Lookup table for `dead-weight-detector`'s health check (`dead_weight_scan.py health`). Documents which signal comes from where per ecosystem, since coverage is genuinely uneven, some registries expose a real maintainer list and download count, others expose neither. Better an honest gap here than a guessed number in a report.

## Per-ecosystem signal availability

| Ecosystem | Release recency | Maintainer count | Monthly downloads | Source |
|---|---|---|---|---|
| JavaScript (npm) | Yes | Yes (`maintainers[]`) | Yes | `registry.npmjs.org/<pkg>`, `api.npmjs.org/downloads/point/last-month/<pkg>` |
| Python (PyPI) | Yes | N/A, PyPI's API has no reliable maintainer list | Best-effort, third-party service | `pypi.org/pypi/<pkg>/json`, `pypistats.org/api/packages/<pkg>/recent` |

## Declared deprecation: a stronger signal than any threshold

npm and PyPI both let a maintainer declare a package deprecated directly,
rather than leaving it to be inferred from recency/maintainers/downloads:

- **npm**: the latest version's entry in the registry response's
  `versions` map carries a `deprecated` string when set. Surfaced as the
  `deprecated` field in `dead_weight_scan.py`'s health output.
- **Python (PyPI)**: individual release files carry a `yanked` boolean and
  `yanked_reason`. If every file for the latest version is yanked, that's
  treated the same as an explicit deprecation message.
- No other ecosystem covered here exposes an equivalent field; `deprecated`
  is always `None` for Go, Rust, Ruby, PHP, Java, .NET, Dart, and C/C++.

Separately, `dead_weight_scan.py` also checks a small hand-curated list of
well-known abandoned packages (`scripts/abandoned_packages.py`) with a
named replacement for each, for cases a live signal alone might not catch
(steady downloads on old code, no widely-known CVE, but the ecosystem has
moved on). Both an npm/PyPI `deprecated` hit and an abandoned-list hit
force the `at_risk` tier the same way a version-scoped OSV match does, see
below.
| Go | Yes | N/A, no registry concept of a maintainer | N/A, no registry concept of downloads | `proxy.golang.org/<module>/@latest` |
| Rust (crates.io) | Yes | Yes (owners endpoint) | Yes | `crates.io/api/v1/crates/<pkg>`, `.../owners` (requires a descriptive User-Agent header per crates.io policy) |
| Ruby (RubyGems) | Yes | Approximate, `authors` is a free-text string, not a real count | Yes | `rubygems.org/api/v1/gems/<pkg>.json` |
| PHP (Packagist) | Yes | Yes (`maintainers[]`) | N/A | `repo.packagist.org/p2/<vendor>/<pkg>.json`, `packagist.org/packages/<vendor>/<pkg>.json` |
| Java (Maven, Gradle, Ivy) | Yes, via Maven Central search (also covers Ivy artifacts, conventionally resolved from the same Maven-compatible repositories) | N/A | N/A | `search.maven.org/solrsearch/select` |
| .NET (NuGet, Paket) | Yes, via the registration API (Paket resolves from the same NuGet registry, no separate lookup) | N/A | N/A, total-download parsing is inconsistent across the API, skipped rather than guessed | `api.nuget.org/v3/registration5-semver1/<id>/index.json` |
| Dart (pub.dev) | Yes | Approximate, `publisher` is a single identity, not a count | N/A, pub.dev exposes no download metric | `pub.dev/api/packages/<pkg>` |
| C/C++ (Conan, vcpkg) | N/A, neither ConanCenter nor vcpkg expose a public metadata API comparable to the registries above | N/A | N/A | n/a (`registry_status: "unavailable"`, honestly, not guessed) |

## Vulnerability check: every ecosystem, one API

[OSV.dev](https://osv.dev) covers every ecosystem above through one query shape, and is the strongest signal in this report: a known unpatched vulnerability in the version actually pinned is a concrete problem, not a heuristic. `POST api.osv.dev/v1/query` with `{"package": {"name": ..., "ecosystem": osv_name}, "version": pinned_version}`.

OSV ecosystem-name mapping (the string OSV expects, not always the same as the name used elsewhere in this table):

| Ecosystem | OSV name |
|---|---|
| JavaScript | `npm` |
| Python | `PyPI` |
| Go | `Go` |
| Rust | `crates.io` |
| Ruby | `RubyGems` |
| PHP | `Packagist` |
| Java | `Maven` |
| .NET | `NuGet` |
| Dart | `Pub` |
| C/C++ | `ConanCenter` |

`ConanCenter` only covers Conan-sourced packages; vcpkg has no OSV ecosystem of its own. A vcpkg-sourced dependency name queried against `ConanCenter` will just come back with no vulnerabilities found rather than erroring, an absence of coverage, not a confirmed absence of vulnerabilities, don't present it as the latter.

**Version scoping matters.** Querying OSV without a version returns every vulnerability ever reported against the package, across its entire release history, not just ones affecting the version actually pinned in the lockfile. `dead_weight_scan.py` resolves the pinned version from the local lockfile before querying whenever it can; when it can't, the result is reported for awareness only and is marked `"version_scoped": false`, it does not by itself push a dependency to the At Risk tier.

## GitHub-archived check: repository-level, GitHub-only

`dead_weight_scan.py`'s `run_health()` also tries to resolve each package's repository URL out of the registry metadata it already fetches, and if that URL points at `github.com`, makes one `GET api.github.com/repos/<owner>/<repo>` call to read that repository's `archived` flag. A maintainer archiving a repository (making it permanently read-only) is a more direct abandonment signal than anything inferred from release recency or maintainer count alone.

This is honestly partial coverage, not a guess dressed up as one:

| Ecosystem | Repository URL source |
|---|---|
| JavaScript (npm) | Registry metadata's `repository` field |
| Python (PyPI) | `info.project_urls` values (scanned for a `github.com` match), falling back to `info.home_page` |
| Go | The module path itself, when it starts with `github.com/` |
| Rust (crates.io) | The crate metadata's `repository` field |
| Ruby (RubyGems) | `source_code_uri`, falling back to `homepage_uri` |
| PHP (Packagist) | The package-info endpoint's `repository` field |
| Java (Maven, Gradle, Ivy) | Not resolved; Maven Central's search API has no source-URL field without an extra POM fetch this tool doesn't make |
| .NET (NuGet, Paket) | The latest catalog entry's `projectUrl`, when NuGet has one on file |
| Dart (pub.dev) | The latest version's pubspec `repository`, falling back to `homepage` |
| C/C++ (Conan, vcpkg) | Not resolved; no registry metadata API exists here at all |

A package hosted on GitLab, Bitbucket, or a self-hosted git server, or one whose registry metadata simply doesn't list a repository URL, reports `"archived": null` honestly rather than a guess, this check is GitHub-only by design. GitHub's unauthenticated API is rate-limited to 60 requests/hour, so this call is only made for the already-bounded set of packages a skill passes to `run_health()`, never once per every dependency in a repo.

`archived` is **not** factored into `health_tier` below; that computation is unchanged and shared with `patch-for-the-high-score`. `dead-weight-detector` uses the raw `archived` field on its own for its Status classification, see its own `SKILL.md`.

## Health tier thresholds

- **Healthy**: last release under 3 months old AND (2+ maintainers OR 10,000+ monthly downloads) AND no version-scoped OSV match.
- **Slowing**: last release 3-12 months old, or only 1 maintainer, or under 10,000 monthly downloads but still active. Also where unscoped OSV history exists but nothing version-scoped forces At Risk.
- **At Risk**: last release over 12 months old, or 0 maintainers found, or any version-scoped OSV vulnerability match, or a maintainer-declared deprecation (npm `deprecated` / PyPI fully-yanked release), or a hit in the curated abandoned-package list. Any of these overrides everything else, an unpatched known vulnerability or a declared/curated abandonment makes it At Risk regardless of how active the project otherwise looks.
- **Unknown**: the lookup failed, or every signal for that ecosystem came back N/A. Never guess a tier from missing data. The report layer should still distinguish *why* it's unknown using the `registry_status` field (`"not_found"`: the registry returned HTTP 404, a confirmed absence worth flagging as likely a private/internal package or a typo, vs. `"failed"`: a network/timeout/parse error, genuinely transient and worth retrying) even though both collapse to the same `unknown` tier.
