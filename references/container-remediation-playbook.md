# Container Remediation Playbook

Static reference for [`cargo-hold-cleanup`](../skills/cargo-hold-cleanup). This is the classification table, remediation templates, and checklists that skill's `SKILL.md` cites by name instead of restating inline. Nothing here is a workflow step, that lives in the skill itself.

## Ownership resolution table

Every container finding resolves to exactly one layer before any fix is proposed. This determines the fix target and whether `cargo-hold-cleanup` acts at all.

| Layer | How to identify it | Fix target | Skill action |
|---|---|---|---|
| Base image OS package | Package manager is apt/apk/yum/rpm, `introducedThrough` bottoms out at the base image, not a language manifest | `FROM` tag or digest | Produce patched tag or pinned inline upgrade |
| App dependency | Package manager is npm/pip/maven/go/gem/cargo, `introducedThrough` names a manifest/lockfile (package.json, requirements.txt, pom.xml, go.mod, Gemfile, Cargo.toml) | Manifest + lockfile | Hand off, do not remediate |
| Build-installed binary | Introduced by a `RUN curl`/`wget`/`COPY` step pulling a standalone binary, not a package manager | Dockerfile `RUN` step | Version and checksum bump |
| Buildpack / Jib / ko / apko / Bazel | No Dockerfile in repo, image built from build tool config | Builder or build config version | Builder bump, explicitly not a Dockerfile edit |
| Vendor or third-party image | Image not built by this org (no Dockerfile, no build config, user confirms it's pulled as-is) | No repo target | Upgrade path, vendor escalation, compensating control |
| Injected sidecar | Added at deploy time by a mesh, operator, or chart, not in the app's own Dockerfile | Chart or operator version | Version bump recommendation |
| Image config finding | Not a package CVE, e.g. running as root, privileged mode, writable root filesystem | Dockerfile directive or admission policy | `USER` directive, capability drop, or policy recommendation |

Ownership resolution runs before any remediation attempt. State the resolved layer in the output so the user can verify the routing before anything else happens.

## Pre-triage checks

Run both before proposing any change, regardless of layer:

1. **Rebuild cadence.** If the image build date is more than roughly 30 days old, or the base digest currently pulled is not the current digest for its tag, the correct first output is "rebuild and rescan," not a proposed edit. State this plainly and stop until the user confirms the image under test is current. A large share of findings clear here with zero code change, the base image already shipped a fix.
2. **Presence and necessity.** Before proposing an upgrade, ask whether the vulnerable package is needed in the final image at all. Removal via a multi-stage build, or a smaller base image that never installs it, is a valid and preferred fix over bumping a version. This check comes before the remediation templates below, not after.

## Remediation templates

### Base image bump

Patched tag published:

```
- FROM node:20.11.0-bookworm-slim
+ FROM node:20.11.1-bookworm-slim@sha256:<new-digest>
```

Pin by digest, not just tag. A tag can move underneath you, a digest can't.

No patched tag published yet, inline pinned upgrade instead. Unpinned `apt-get upgrade` is not acceptable output, it breaks reproducibility, the exact same Dockerfile can produce a different image tomorrow.

```dockerfile
# apt/deb
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl=3.0.11-1~deb12u2 \
    && rm -rf /var/lib/apt/lists/*

# apk/alpine
RUN apk add --no-cache openssl=3.1.4-r5

# yum/rpm
RUN yum install -y openssl-1.1.1k-9.el8_9 && yum clean all
```

### Build-installed binary

Bump the version and the checksum together, a version bump with a stale checksum either silently skips verification or breaks the build, both are worse than not fixing it.

```dockerfile
- ARG YQ_VERSION=4.35.1
- ARG YQ_SHA256=abc123...
+ ARG YQ_VERSION=4.44.3
+ ARG YQ_SHA256=def456...
  RUN curl -sSL -o /usr/local/bin/yq \
      "https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/yq_linux_amd64" \
      && echo "${YQ_SHA256}  /usr/local/bin/yq" | sha256sum -c - \
      && chmod +x /usr/local/bin/yq
```

### Distro switch

Moving from a full base (`debian`, `ubuntu`) to `slim`, `distroless`, or another minimal image removes a whole class of package-level CVEs at once, but trades them for breakage risk. Always pair this proposal with the breakage warning list below, and treat it as a complexity-gated change, not a trivial one.

### Image config

```dockerfile
+ RUN groupadd -r app && useradd -r -g app app
+ USER app
```

Capability drop, same finding class:

```yaml
securityContext:
  capabilities:
    drop: ["ALL"]
    add: ["NET_BIND_SERVICE"]
  runAsNonRoot: true
  readOnlyRootFilesystem: true
```

When there's no Dockerfile/chart access to make the change directly (vendor image, no repo target), the equivalent admission policy control (Kyverno, OPA Gatekeeper, Pod Security Admission) is the fallback recommendation, not a shrug.

## Breakage warning list

Warn proactively when a base image change is proposed, don't wait for the user to hit these after rebuilding:

- Language minor version shift (Python 3.11 to 3.12, Node 18 to 20), can change stdlib behavior or drop a deprecated API
- glibc to musl on Alpine moves, native extensions and prebuilt binaries compiled against glibc can fail silently or segfault
- Default user changes from root to non-root, breaks writes to paths that were only writable as root (`/var/run`, `/tmp` ownership, bind-mounted volumes)
- Removed shell and coreutils on distroless, breaks entrypoint scripts, healthchecks, and any `docker exec sh` debugging workflow
- Certificate bundle location changes between distros, breaks anything hardcoding a CA path
- Removed package manager, breaks any runtime `apt-get install` step still present in an entrypoint or init script

## No-fix-available decision order

When the scanner reports no fixed version exists, work this order, don't jump straight to an exception:

1. Remove the package if it's unused in the final image (see Presence and necessity above)
2. Switch to a base image that doesn't ship it at all
3. Assess reachability: is the vulnerable function called, is the component exposed to untrusted input, is it network-facing
4. Apply a compensating control: network policy, seccomp/AppArmor profile, dropped capability, WAF rule
5. Time-bound exception, only after 1 through 4 are genuinely exhausted

### Exception required fields

Every exception draft needs all of these, don't produce a partial one:

- Vulnerability ID (CVE/GHSA)
- Image and digest it applies to
- Justification (why 1-4 above don't apply here)
- Compensating control currently in place, if any
- Named owner (a person or team, not "the team")
- Expiry date, maximum 90 days out from creation
- Re-check trigger (next scheduled rescan, next base image release, or a specific event)

## Verification steps

In order, all of them, not a subset:

1. Rebuild the image from the changed Dockerfile/build config
2. Rescan the rebuilt image, not the local build layer cache, a stale cached layer can hide the fix
3. Confirm the specific target vulnerability ID cleared
4. Diff the full result set against the pre-fix scan: resolved, introduced, unchanged. A base image bump routinely trades one CVE for several others, confirming only the target ID cleared misses that trade entirely
5. Run the existing test suite against the rebuilt image
6. Confirm both the pushed registry artifact and the running workload report clean, a local build passing is not sufficient evidence, the artifact that actually deploys is the one that matters

## Edge cases

- **No Dockerfile, no build config, image not built by this org**: route to vendor escalation, not a proposed edit. Don't guess at a Dockerfile that doesn't exist.
- **Same CVE in both a container scan and an SCA scan**: state the overlap explicitly and defer to the SCA/dependency remediation flow, don't produce two competing fixes for one root cause.
- **Multi-arch image, vulnerability affects only one architecture**: say so, and scope the fix (or the decision to skip it) to that architecture rather than treating the whole manifest list as affected.
- **Finding in a discarded multi-stage build stage**: if the vulnerable layer never reaches the final `FROM` stage that ships, this is a false positive at the image level, say so plainly and don't propose a fix for a stage nothing runs.
- **Scratch or distroless base, no package manager present**: there is nothing to `apt-get upgrade`, the only available fixes are a base image swap, a build-installed binary bump, or removing the vulnerable file directly in a build stage.
