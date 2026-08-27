# Scientific Figure Library Community Archives

Immutable, content-addressed public-template ZIP archives for Scientific Figure Library Community.

Every normal pull request adds exactly one new path:

```text
archives/<templateId>/<releaseVersion>/<templateId>-<releaseVersion>.zip
```

Existing releases are never overwritten. A GitHub-hosted runner validates the ZIP structure and rights manifest, then executes only its fixed R render entrypoint inside a reviewed, non-root, network-disabled, read-only container. The generated PNG must match the archived preview and its canonical RGBA digest. A maintainer reviews and manually merges the PR. Automation never merges it.

The archive tree is strictly append-only: every committed path and blob identity must remain unchanged. A release that is withdrawn or redacted from discovery is represented by Catalog lifecycle metadata; its immutable Archive ZIP is retained here for audit. There is no physical-deletion route in the Archive pull-request policy.

The current pull-request intake remains the reviewed `figure-library.publication-submission.v1` fixed-R contract. A separate trusted-`main` workflow builds, audits, and publishes two disabled-for-intake future mixed-runtime renderer images for the 0.7 protocol from a 222-artifact exact URL/SHA-256 lock and digest-pinned OCI foundations. The exact image instance is config- and runtime-tested as UID/GID 65532 under the hardened container envelope, given an exact-output product-neutral negative-render canary, exported for a streamed executable/rootfs inventory, and only then pushed. The pushed raw single-image manifest must hash to the reported digest, bind the audited local config, and remain anonymously inspectable and pullable by exact digest after logout; a newly private GHCR package therefore fails closed until its owner deliberately makes it public. These images have not been built on this Windows development machine and do not enter Archive intake until trusted-Linux evidence, real GHCR digests, validator support, and a later reviewed digest-pin policy change are all available. Pull-request workflows never receive `packages: write`.

Catalog metadata is submitted separately, after the Archive PR has merged, to [`jarxunlai/ScientificFigureLibrary-community`](https://github.com/jarxunlai/ScientificFigureLibrary-community).

Repository tooling and schemas are MIT-licensed. Each archive contains explicit per-asset license declarations.
