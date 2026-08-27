# Renderer bootstrap (v2 intake disabled)

This directory is the auditable bootstrap for the future Scientific Figure
Library 0.7 Archive renderers. It is not the renderer used by the current v1
Archive PR intake.

The checked-in `pixi.toml` and Pixi v7 lock resolve the joint Linux x86-64
environment to 222 direct/transitive conda-forge artifacts; every artifact has
an exact HTTPS URL and SHA-256. The builder and final linux/amd64 base manifests
are digest-pinned. After this policy is reviewed and merged, trusted `main`
builds, audits, and pushes exactly the same local image instance for each of:

```text
ghcr.io/jarxunlai/sfl-archive-renderer-r
ghcr.io/jarxunlai/sfl-archive-renderer-python
```

Both contexts are intended to use the same fixed R and Python runtime family.
The `r` runner declares `payload/code/render.R`; the `python` runner declares
`payload/code/render.py`. Both currently reject every render request. A later
policy phase will add the v2 schema,
cross-language helper allowlist and hardened invocation contract before either
image may process untrusted submissions.

`renderer-lock.json` separates **bootstrap publication** from **Archive
intake**. `publishBootstrapImages=true` authorizes only the trusted-main
build/audit/push workflow. `trustedLinuxBuildVerified=false` and
`v2IntakeEnabled=false` remain fail-closed source claims until evidence from a
real trusted Linux run is reviewed in a later policy PR. Publishing the disabled
images does not make them an Archive dependency.

The current Windows machine has no running Docker daemon, so it has not built
or executed these Linux images. Trusted `main` must perform the frozen build,
verify both runtimes/packages, run a product-neutral negative render canary,
export and audit the exact image rootfs, and only then push that same local image
instance. The audit inventories every executable by streamed SHA-256 and rejects
ordinary shells, package/install/download/build tools, special files, privilege
bits, and symlink/hard-link aliases to forbidden tools. A real GHCR digest is
reported as build evidence. Unknown digests are never represented by
placeholders: `publishedImageDigest` remains JSON `null` until those real
digests are reviewed and pinned in a later policy PR.

The bootstrap workflow has explicit timeouts and serializes trusted-main runs.
It does not modify this repository and never runs for pull requests. Only a
later reviewed activation change may add the v2 schema, mixed helper runner,
digest-pinned intake, and positive untrusted-render canaries.
