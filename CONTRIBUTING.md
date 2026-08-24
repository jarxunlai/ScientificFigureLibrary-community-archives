# Archive submission policy

## One immutable release per PR

A template PR may add exactly one ZIP at:

```text
archives/<templateId>/<releaseVersion>/<templateId>-<releaseVersion>.zip
```

It may not modify or delete an existing path, workflow, validator, container, schema, policy, or license. Policy changes require a separate maintainer-authored PR.

## Restricted invalid-seed withdrawal

The trusted validator has one closed maintenance exception for atomically
withdrawing these exact releases:

```text
archives/ggsankeyfier-layout-color-combo/1.0.0/ggsankeyfier-layout-color-combo-1.0.0.zip
archives/single-cell-enrichment-bar-pathway-genes/1.0.0/single-cell-enrichment-bar-pathway-genes-1.0.0.zip
archives/umap-unchull-main-type-circles/1.0.0/umap-unchull-main-type-circles-1.0.0.zip
```

All three paths must disappear in one candidate commit, their base blob OIDs
must match the validator's reviewed allowlist, and no other path may be added,
modified, or deleted. The exception cannot withdraw a different version or
template and cannot be used for a partial removal. Because a withdrawal has no
candidate archive to extract, its CI mode performs only the exact trusted-tree
and OID validation; normal archive additions continue through full extraction
and fixed-R re-rendering. After withdrawal, the three exact identities are
retired and the normal add gate will reject attempts to restore those paths. A
maintainer must review and manually merge the withdrawal. The commits and blobs
remain in Git history for audit.

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
## Human visual and rights review remains mandatory

CI verifies the committed tree, archive structure and identity, declared asset
inventory, rights-attestation fields, isolated re-render, PNG dimensions, and
the byte-exact and canonical-RGBA digests. Those mechanical checks do **not**
prove that a preview is free of watermarks, third-party visual material, or
misstated semantic copyright ownership. A maintainer must inspect the preview,
code, synthetic data, documentation, provenance, and license claims before
manually merging an Archive PR. A green CI run is evidence for that review, not
an automated copyright clearance.
