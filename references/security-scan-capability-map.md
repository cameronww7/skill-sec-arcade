# Security Scan Capability Map

Lookup table for `cartridge-scanner`'s "Scanning coverage recommendations" step. Each row maps a signal the scan can actually detect (a language, a manifest file, a file type) to the *capability* a security tool needs in order to cover it.

Deliberately has no tool or vendor names. The landscape of open-source and commercial scanners changes constantly, and naming one product implies an endorsement this project isn't making. The goal is to tell the reader what kind of coverage they're missing, not which product to buy. If a row here doesn't have real supporting evidence from the scan (e.g. no `.tf` files found), don't surface it, exactly like `language-attack-vectors.md` is only cited when there's real supporting code.

## SAST

| Signal | Capability needed |
|---|---|
| Any language present in the LOC breakdown | A static analysis engine with rule coverage for the detected language(s), capable of tracing tainted input from an entry point to a dangerous sink. |

## SCA (Software Composition Analysis)

| Signal | Capability needed |
|---|---|
| `package.json` + npm/yarn/pnpm lockfile | A dependency-vulnerability scanner that reads npm lockfiles and checks resolved packages, direct and transitive, against a known-vulnerability database. |
| `requirements*.txt` / `pyproject.toml` / `Pipfile` / `setup.py` / `setup.cfg` / `poetry.lock` / `uv.lock` | A Python-aware dependency scanner that checks pinned versions in the lockfile or requirements file against a vulnerability database. |
| `go.mod` / `go.sum` | A Go module scanner that cross-references `go.sum` entries against a vulnerability database and can confirm whether the vulnerable symbol is actually imported. |
| `pom.xml` / `build.gradle` / `ivy.xml` | A JVM dependency scanner that resolves the full Maven/Gradle/Ivy tree, including transitives, against a CVE database. |
| `Gemfile` / `Gemfile.lock` | A Bundler-aware scanner checking `Gemfile.lock` entries against a Ruby-specific advisory database. |
| `composer.json` / `composer.lock` | A Composer-aware scanner checking `composer.lock` entries against a PHP-specific advisory database. |
| `Cargo.toml` / `Cargo.lock` | A Cargo-aware scanner reading `Cargo.lock` against a Rust-specific advisory database. |
| `*.csproj` / `packages.lock.json` / `paket.dependencies` / `paket.lock` | A NuGet-aware scanner (with Paket-lock support if the repo uses Paket instead of the NuGet CLI) checking resolved package versions against a vulnerability database. |
| `pubspec.yaml` / `pubspec.lock` | A Dart/Flutter-aware scanner checking resolved package versions against a vulnerability database. |
| `conanfile.txt` / `conanfile.py` / `conan.lock` / `vcpkg.json` | A C/C++-aware dependency scanner covering both Conan (ConanCenter advisories) and vcpkg; CVE matching for this ecosystem still leans heavily on CPEs, expect more false positives/negatives than the registry-backed ecosystems above. Vendored/copy-pasted source, `find_package()`/`FetchContent_Declare()`-only dependencies, and statically-linked binaries need source-fingerprinting or build-image-scanning capability this row doesn't cover. |

## Secrets

| Signal | Capability needed |
|---|---|
| Any repo, always | A git-history-aware secrets scanner that flags hardcoded credentials and tokens, including ones that were committed and later removed. |

## IaC

| Signal | Capability needed |
|---|---|
| `*.tf` / `*.tfvars` | A Terraform-aware misconfiguration scanner checking provider resources against a cloud security benchmark. |
| CloudFormation templates | A CloudFormation-aware misconfiguration scanner checking resource definitions against a cloud security benchmark. |
| Kubernetes manifests / Helm charts | A Kubernetes manifest scanner checking for missing resource limits, privileged containers, and over-broad RBAC. |
| Ansible playbooks | An Ansible-aware linter/scanner checking task definitions for insecure defaults (e.g. disabled host key checking, world-writable files). |
| Pulumi / CDK / Serverless Framework configs | A general-purpose IaC misconfiguration scanner with support for the framework's synthesized output, not just raw Terraform/CloudFormation. |

## Containers

| Signal | Capability needed |
|---|---|
| `Dockerfile*` | A Dockerfile linter checking for insecure base images, missing least-privilege `USER` directives, and build-time secret leakage, plus an image vulnerability scanner for the built layers. |
| `docker-compose*.yml` | The same image vulnerability scanning applied to every service image referenced, plus a check for containers running with excessive host privileges or exposed ports. |

## SBOM (ground truth for the counts above)

| Signal | Capability needed |
|---|---|
| Any dependency manifests found, always | An SBOM generator producing a standards-based (CycloneDX/SPDX) inventory of the full dependency tree. Every dependency count in the cartridge scan report is a static approximation, not a resolved install; treat it as a lower bound, not a ground truth. |

## Private/internal registries

| Signal | Capability needed |
|---|---|
| A `private_registries` entry for any ecosystem | Before trusting SCA coverage for that ecosystem, confirm the scanning tool is actually configured with network reachability and authentication to the internal registry host. Many SCA tools fail silently on unresolvable packages, skipping them with no error, rather than surfacing a coverage gap. A clean scan result is not proof of coverage here. |
