# Scientific Figure Library Community Archives

Immutable, content-addressed public-template ZIP archives for Scientific Figure Library Community.

Every normal pull request adds exactly one new path:

```text
archives/<templateId>/<releaseVersion>/<templateId>-<releaseVersion>.zip
```

Existing releases are never overwritten. A GitHub-hosted runner validates the ZIP structure and rights manifest, then executes only its fixed R render entrypoint inside a reviewed, non-root, network-disabled, read-only container. The generated PNG must match the archived preview and its canonical RGBA digest. A maintainer reviews and manually merges the PR. Automation never merges it.

The repository also contains a deliberately closed emergency-withdrawal rule for three exact `1.0.0` test-seed blobs whose provenance did not match the library owner's publication intent. That rule requires all three allowlisted paths to be deleted atomically, binds each deletion to its reviewed base blob OID, and rejects every addition, modification, partial deletion, or unrelated deletion. The three withdrawn identities are retired and cannot be re-added. This is not a general deletion interface and does not weaken the normal one-new-archive gate for any other identity. Withdrawal CI validates only that exact committed-tree transition; it does not run a renderer for ZIPs that are absent from the candidate tree. Git history remains available for audit.

Catalog metadata is submitted separately, after the Archive PR has merged, to [`jarxunlai/ScientificFigureLibrary-community`](https://github.com/jarxunlai/ScientificFigureLibrary-community).

Repository tooling and schemas are MIT-licensed. Each archive contains explicit per-asset license declarations.
