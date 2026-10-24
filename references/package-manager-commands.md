# Package Manager Commands

Static reference for [`trim-reaper`](../skills/trim-reaper). Every real package-manager command trim-reaper's phases need (install, remove, show dependency tree, show why a package is installed, production-only install) per ecosystem, plus the real unused-dependency-detection CLI tool for that ecosystem where one exists. This is what the skill's own `SKILL.md` points to instead of hand-inventing ecosystem commands in prose.

Ecosystem keys match `cartridge_scan.py`'s own `package_managers[].ecosystem` values, so a dependency count or manifest list from a cartridge-scanner run tells trim-reaper exactly which section below applies.

## JavaScript (npm / yarn / pnpm)

| Action | npm | yarn | pnpm |
|---|---|---|---|
| Install a package | `npm install <pkg>` | `yarn add <pkg>` | `pnpm add <pkg>` |
| Remove a package (prunes orphaned transitives) | `npm uninstall <pkg>` | `yarn remove <pkg>` | `pnpm remove <pkg>` |
| Show dependency tree | `npm ls <pkg>` | `yarn why <pkg>` | `pnpm why <pkg>` |
| Why is this installed | `npm explain <pkg>` | `yarn why <pkg>` | `pnpm why <pkg>` |
| Production-only install | `npm ci --omit=dev` | `yarn install --production` | `pnpm install --prod` |

**Unused-dependency detection tool:** `depcheck` (community tool, not bundled with npm/yarn/pnpm).

## Python (pip / Poetry / Pipenv)

| Action | pip | Poetry | Pipenv |
|---|---|---|---|
| Install a package | `pip install <pkg>` | `poetry add <pkg>` | `pipenv install <pkg>` |
| Remove a package | `pip uninstall <pkg>` | `poetry remove <pkg>` | `pipenv uninstall <pkg>` |
| Show dependency tree | `pipdeptree` (separate install) | `poetry show --tree` | `pipenv graph` |
| Why is this installed | `pipdeptree --reverse --packages <pkg>` | `poetry show <pkg>` | `pipenv graph` (read manually) |
| Production-only install | `pip install --no-deps -r requirements.txt` (no dev extras in the file) | `poetry install --only main` | `pipenv install --deploy --ignore-pipfile` |

**Unused-dependency detection tool:** `deptry`. `pipdeptree`/`pip-extra-reqs` can show the tree but don't themselves flag unused packages the way `deptry` does.

## Go

| Action | Command |
|---|---|
| Install a package | `go get <module>` |
| Remove a package | `go get <module>@none` followed by `go mod tidy` |
| Show dependency tree | `go mod graph` |
| Why is this installed | `go mod why <module>` |
| Production-only install | Not applicable; Go has no dev/prod dependency split, `go mod download` fetches everything `go.mod` declares. |

**Unused-dependency detection tool:** `go mod why` combined with `go mod tidy` (which removes any module no longer `require`d by anything reachable from the build). There is no separate "unused dependency" linter beyond this.

## Java (Maven)

| Action | Command |
|---|---|
| Install a package | Add a `<dependency>` to `pom.xml`, then `mvn install` |
| Remove a package | Remove the `<dependency>` entry, then `mvn install` |
| Show dependency tree | `mvn dependency:tree` |
| Why is this installed | `mvn dependency:tree -Dincludes=<groupId>:<artifactId>` |
| Production-only install | `mvn package -P production` (scope-dependent; exclude `test`-scoped dependencies via `<scope>test</scope>` rather than a separate install mode) |

**Unused-dependency detection tool:** `mvn dependency:analyze` (reports both "used but undeclared" and "unused but declared").

## Java (Gradle)

| Action | Command |
|---|---|
| Install a package | Add an `implementation`/`api` line to `build.gradle`, then `gradle build` |
| Remove a package | Remove the line, then `gradle build` |
| Show dependency tree | `gradle dependencies` |
| Why is this installed | `gradle dependencyInsight --dependency <name>` |
| Production-only install | Gradle configurations (`implementation` vs. `testImplementation`) already separate this; no separate install mode needed. |

**Unused-dependency detection tool:** none bundled. State this plainly rather than guessing at a third-party plugin's current maintenance status.

## Ruby (Bundler)

| Action | Command |
|---|---|
| Install a package | `bundle add <gem>` |
| Remove a package | `bundle remove <gem>` |
| Show dependency tree | `bundle list --tree` (via `bundle viz` for a graphical version, requires graphviz) |
| Why is this installed | `bundle why <gem>` (via the `bundler-leak` plugin) or `bundle list --tree` read manually if that plugin isn't installed |
| Production-only install | `bundle install --without development test` |

**Unused-dependency detection tool:** none reliable. `bundle-leak` exists but is not actively maintained; flag this as "no reliable tool, manual search only" rather than recommending it.

## PHP (Composer)

| Action | Command |
|---|---|
| Install a package | `composer require <vendor/package>` |
| Remove a package | `composer remove <vendor/package>` |
| Show dependency tree | `composer show --tree` |
| Why is this installed | `composer why <vendor/package>` (also `composer depends <vendor/package>`) |
| Production-only install | `composer install --no-dev` |

**Unused-dependency detection tool:** `composer-unused`.

## Rust (Cargo)

| Action | Command |
|---|---|
| Install a package | `cargo add <crate>` |
| Remove a package | `cargo remove <crate>` |
| Show dependency tree | `cargo tree` |
| Why is this installed | `cargo tree -i <crate>` (inverted tree, shows what depends on it) |
| Production-only install | Not applicable in the npm sense; `dev-dependencies` are already excluded from a normal `cargo build --release`. |

**Unused-dependency detection tool:** `cargo-udeps`. Requires a nightly Rust toolchain to run (`cargo +nightly udeps`), note this caveat whenever recommending it.

## .NET (NuGet)

| Action | Command |
|---|---|
| Install a package | `dotnet add package <PackageId>` |
| Remove a package | `dotnet remove package <PackageId>` |
| Show dependency tree | `dotnet list package --include-transitive` |
| Why is this installed | `dotnet nuget why <PackageId>` (.NET 8+) or `dotnet list package --include-transitive` read manually on older SDKs |
| Production-only install | Not applicable the npm/pip way; .NET has no separate dev-dependency manifest section, a `Release` build configuration is the closer equivalent. |

**Unused-dependency detection tool:** none standard. `dotnet list package` shows what's installed, not what's actually used; state this gap plainly.

## Dart (pub.dev)

| Action | Command |
|---|---|
| Install a package | `dart pub add <package>` (or `flutter pub add <package>`) |
| Remove a package | `dart pub remove <package>` |
| Show dependency tree | `dart pub deps` |
| Why is this installed | `dart pub deps` read manually (no dedicated "why" flag) |
| Production-only install | Not applicable; `dev_dependencies` are already excluded from a release build automatically. |

**Unused-dependency detection tool:** none standard. `dart analyze` catches unused *imports* in first-party code, not unused *dependencies* in `pubspec.yaml`; don't conflate the two.

## C/C++ (Conan / vcpkg)

| Action | Conan | vcpkg |
|---|---|---|
| Install a package | Add a `requires` entry to `conanfile.txt`/`conanfile.py`, then `conan install .` | `vcpkg install <port>` |
| Remove a package | Remove the entry, then `conan install .` | `vcpkg remove <port>` |
| Show dependency tree | `conan graph info .` | `vcpkg depend-info <port>` |
| Why is this installed | `conan graph info . --filter requires` read manually | `vcpkg depend-info <port>` read manually |
| Production-only install | Not applicable; neither tool has a dev/prod dependency split, `build_requires`/`tool_requires` in Conan are the closer (build-time-only) equivalent. |

**Unused-dependency detection tool:** none. Neither Conan nor vcpkg has an "unused dependency" command; C/C++ has no single ecosystem-wide dependency manager to check usage against in the first place.
