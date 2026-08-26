# Renderer bootstrap (v2 intake disabled)

This directory is the auditable bootstrap for the future Scientific Figure
Library 0.7 Archive renderers. It is not the renderer used by the current v1
Archive PR intake.

The checked-in `pixi.toml` and Pixi v7 lock resolve the joint Linux x86-64
environment to 222 direct/transitive conda-forge artifacts; every artifact has
an exact HTTPS URL and SHA-256. The build and final linux/amd64 OCI manifests are also
digest-pinned. Two images may be verified and, only after a separate reviewed
readiness change, published from trusted `main`:

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

`renderer-lock.json` is deliberately not publish-ready even though its artifact
graph is resolved. `publishReady=false`, `trustedLinuxBuildVerified=false`, and
`v2IntakeEnabled=false` remain independent gates. The current Windows machine
has no running Docker daemon, so it has not built or executed these Linux
images. Trusted `main` must perform the frozen Linux build, verify both
runtimes/packages, confirm the final rootfs does not expose Pixi, apt/dpkg,
curl/wget/git, pip, or an ordinary shell, and prove that the runner still
rejects render requests. Only a later reviewed change may set publish readiness
and obtain real GHCR digests. Unknown GHCR digests are never represented by
placeholders: `publishedImageDigest` remains JSON `null` until a real pushed
manifest digest is reviewed and committed in a later policy PR.

The bootstrap workflow emits lock and trusted-Linux build evidence. It cannot
publish while the lock says `publishReady=false`, it does not modify this
repository, and it never runs for pull requests.
