# Registry Health Signals

Lookup table for `dead-weight-detector`'s health check (`dead_weight_scan.py health`). Documents which signal comes from where per ecosystem, since coverage is genuinely uneven, some registries expose a real maintainer list and download count, others expose neither. Better an honest gap here than a guessed number in a report.

## Per-ecosystem signal availability

| Ecosystem | Release recency | Maintainer count | Monthly downloads | Source |
|---|---|---|---|---|
| npm | Yes | Yes (`maintainers[]`) | Yes | `registry.npmjs.org/<pkg>`, `api.npmjs.org/downloads/point/last-month/<pkg>` |
| Python (PyPI) | Yes | N/A, PyPI's API has no reliable maintainer list | Best-effort, third-party service | `pypi.org/pypi/<pkg>/json`, `pypistats.org/api/packages/<pkg>/recent` |
| Go | Yes | N/A, no registry concept of a maintainer | N/A, no registry concept of downloads | `proxy.golang.org/<module>/@latest` |
| Rust (crates.io) | Yes | Yes (owners endpoint) | Yes | `crates.io/api/v1/crates/<pkg>`, `.../owners` (requires a descriptive User-Agent header per crates.io policy) |
| Ruby (RubyGems) | Yes | Approximate, `authors` is a free-text string, not a real count | Yes | `rubygems.org/api/v1/gems/<pkg>.json` |
| PHP (Packagist) | Yes | Yes (`maintainers[]`) | N/A | `repo.packagist.org/p2/<vendor>/<pkg>.json`, `packagist.org/packages/<vendor>/<pkg>.json` |
| Java (Maven) | Yes, via Maven Central search | N/A | N/A | `search.maven.org/solrsearch/select` |
| .NET (NuGet) | Yes, via the registration API | N/A | N/A, total-download parsing is inconsistent across the API, skipped rather than guessed | `api.nuget.org/v3/registration5-semver1/<id>/index.json` |
| Dart (pub.dev) | Yes | Approximate, `publisher` is a single identity, not a count | N/A, pub.dev exposes no download metric | `pub.dev/api/packages/<pkg>` |

## Vulnerability check: every ecosystem, one API

[OSV.dev](https://osv.dev) covers every ecosystem above through one query shape, and is the strongest signal in this report: a known unpatched vulnerability in the version actually pinned is a concrete problem, not a heuristic. `POST api.osv.dev/v1/query` with `{"package": {"name": ..., "ecosystem": osv_name}, "version": pinned_version}`.

OSV ecosystem-name mapping (the string OSV expects, not always the same as the name used elsewhere in this table):

| Ecosystem | OSV name |
|---|---|
| npm | `npm` |
| Python | `PyPI` |
| Go | `Go` |
| Rust | `crates.io` |
| Ruby | `RubyGems` |
| PHP | `Packagist` |
| Java | `Maven` |
| .NET | `NuGet` |
| Dart | `Pub` |

**Version scoping matters.** Querying OSV without a version returns every vulnerability ever reported against the package, across its entire release history, not just ones affecting the version actually pinned in the lockfile. `dead_weight_scan.py` resolves the pinned version from the local lockfile before querying whenever it can; when it can't, the result is reported for awareness only and is marked `"version_scoped": false`, it does not by itself push a dependency to the At Risk tier.

## Health tier thresholds

- **Healthy**: last release under 3 months old AND (2+ maintainers OR 10,000+ monthly downloads) AND no version-scoped OSV match.
- **Slowing**: last release 3-12 months old, or only 1 maintainer, or under 10,000 monthly downloads but still active. Also where unscoped OSV history exists but nothing version-scoped forces At Risk.
- **At Risk**: last release over 12 months old, or 0 maintainers found, or any version-scoped OSV vulnerability match. The OSV match overrides everything else, an unpatched known vulnerability in what's actually pinned makes it At Risk regardless of how active the project otherwise looks.
- **Unknown**: the lookup failed, or every signal for that ecosystem came back N/A. Never guess a tier from missing data.
