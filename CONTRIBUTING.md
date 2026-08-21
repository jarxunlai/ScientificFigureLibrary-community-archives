# Archive submission policy

## One immutable release per PR

A template PR may add exactly one ZIP at:

```text
archives/<templateId>/<releaseVersion>/<templateId>-<releaseVersion>.zip
```

It may not modify or delete an existing path, workflow, validator, container, schema, policy, or license. Policy changes require a separate maintainer-authored PR.

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
