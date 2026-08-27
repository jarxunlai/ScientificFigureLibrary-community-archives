# Archive submission policy

## One immutable release per PR

A template PR may add exactly one ZIP at:

```text
archives/<templateId>/<releaseVersion>/<templateId>-<releaseVersion>.zip
```

It may not modify or delete an existing path, workflow, validator, container, schema, policy, or license. Policy changes require a separate maintainer-authored PR.

## No physical archive withdrawal

Archive paths are append-only without exceptions. Once committed, neither the
ZIP nor any other base-tree blob may be modified or deleted by an Archive
submission. Community withdrawal and redaction are Catalog lifecycle actions;
they do not remove an immutable ZIP from this repository.

## Publication content

The ZIP must be a `figure-library.publication-submission.v1` export containing only specifically selected, redistributable code, synthetic data, generated preview, and documentation. It must not contain third-party screenshots or cropped panels, PDFs, patient data, source-reference media, a Local Library, locator, operation history, receipts, imports, quarantine, absolute paths, credentials, or private signing keys.

R code requires an explicit license. Synthetic data, generated preview, and documentation require explicit content licenses. The first Community seeds use MIT for R code and CC BY 4.0 for synthetic data, preview, and documentation.

## Render contract

The archive provides:

```text
payload/code/render.R
payload/data/**
payload/preview/preview.png
render-receipt.json
```

`render.R` accepts:

```text
--input-dir <read-only-directory> --output <new-png-path>
```

CI runs this entrypoint as a non-root user with no network, a read-only root filesystem, no Linux capabilities, `no-new-privileges`, bounded CPU/memory/PIDs/files, a timeout, read-only submission mount, and only a temporary output mount writable. The client never executes this code when materializing a template.

## Future 0.7 renderer bootstrap

The `renderer/` directory contains two auditable, disabled-for-intake build
contexts for future R-entry and Python-entry submissions. Both contexts are
intended to contain the fixed R and Python runtimes, but each runner permits
only its own trusted entrypoint. `renderer/pixi.lock` pins the shared Linux
environment to 222 exact conda-forge artifact URLs and SHA-256 values.
`renderer/renderer-lock.json` records the package contract and digest-pinned
build/final OCI foundations. Bootstrap publication is explicitly enabled only
for trusted `main`, while `trustedLinuxBuildVerified=false`,
`v2IntakeEnabled=false`, and null source-pinned image digests remain fail closed
until the resulting evidence is reviewed.

Only `.github/workflows/publish-renderer-bootstrap.yml`, running from trusted
`main`, may request `packages: write`. It builds, verifies exact non-root image
configuration and hardened runtime behavior, inventories every committed
rootfs tree including `/run` and `/tmp`, and pushes the same image instance.
It then verifies the raw single-image manifest/config binding and requires an
anonymous exact-digest inspect and pull after logout before recording the real
GHCR digest. A private first-publish package fails this gate until its owner
deliberately changes its visibility to public. It never writes an unknown or
placeholder digest into the repository. Archive
pull-request validation remains on the v1 fixed-R container until a later
reviewed policy change pins those digests and enables v2 intake.

## Human visual and rights review remains mandatory

CI verifies the committed tree, archive structure and identity, declared asset
inventory, rights-attestation fields, isolated re-render, PNG dimensions, and
the byte-exact and canonical-RGBA digests. Those mechanical checks do **not**
prove that a preview is free of watermarks, third-party visual material, or
misstated semantic copyright ownership. A maintainer must inspect the preview,
code, synthetic data, documentation, provenance, and license claims before
manually merging an Archive PR. A green CI run is evidence for that review, not
an automated copyright clearance.
