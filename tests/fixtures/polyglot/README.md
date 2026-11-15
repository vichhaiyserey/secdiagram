# Polyglot analyzer fixtures

Small C#/.NET, JavaScript/TypeScript, PHP and Go applications used by
`tests/test_polyglot.py`. Each file pairs deliberately **vulnerable** code with a
**safe** variant (bound parameters, numeric casts, escaping, local redirects) so
the tests assert both detections and the absence of false positives.

These files are test data only: they are never built, installed or executed.

Dependency versions in `package.json`, `composer.json` and `go.mod` are
intentionally the non-existent `99.0.0`. The analyzers only need the package
names (framework and data-store detection); a version above every published
release keeps dependency scanners (GitHub dependency review, Dependabot,
Trivy) from reporting advisories against fixture manifests.
