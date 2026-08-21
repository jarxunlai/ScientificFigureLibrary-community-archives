# Scientific Figure Library Community Archives

Immutable, content-addressed public-template ZIP archives for Scientific Figure Library Community.

Every normal pull request adds exactly one new path:

```text
archives/<templateId>/<releaseVersion>/<templateId>-<releaseVersion>.zip
```

Existing releases are never overwritten. A GitHub-hosted runner validates the ZIP structure and rights manifest, then executes only its fixed R render entrypoint inside a reviewed, non-root, network-disabled, read-only container. The generated PNG must match the archived preview and its canonical RGBA digest. A maintainer reviews and manually merges the PR. Automation never merges it.

Catalog metadata is submitted separately, after the Archive PR has merged, to [`jarxunlai/ScientificFigureLibrary-community`](https://github.com/jarxunlai/ScientificFigureLibrary-community).

Repository tooling and schemas are MIT-licensed. Each archive contains explicit per-asset license declarations.
