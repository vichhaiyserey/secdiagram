# Test contracts and validation

Issue #82 refactored the suite from 653 to **623 test methods in 45 files** at
merge commit `58aa51c`. This is a historical baseline, not the current suite size:
subsequent Studio and Rust changes add regression tests.
Distinct conditions remain named `unittest.subTest` cases. Method count measures
inventory, not correctness: tests are retained for observable behavior, meaningful
failure conditions, source evidence or a documented regression.

This builds on the assertion/isolation audit in issue #71 / PR #72 and the threat
evidence tests in issue #73 / PR #74. That review checked every test file
structurally and reviewed candidate consolidations, mocks, positive controls,
expected failures, environment isolation and cached fixtures.

## What remains covered

| Area | Important contracts |
| --- | --- |
| Parsing and resolution | Definitions, routes, imports, lexical exclusions, exact locations, recovery, ambiguous and unresolved symbols |
| Graphs and discovery | Stable IDs, exact filtering, node caps, priority retention, containment, actual successful workers and serial fallback |
| SAST and infrastructure | Unsafe/safe counterparts, source-to-sink traces, sanitizers, custom rules, CWE/evidence, existing out-of-root inputs |
| Security policy | Severity/confidence/exposure, positive and negative gates, baselines, expiry, reachability, STRIDE and ATT&CK |
| CLI and outputs | Exit codes, real artifacts, full serialization, determinism, offline transport guards and input preservation |
| Platform and Studio | Authentication, permissions, limits, state transitions, evidence bounds, installer hashes, HTTP response bodies and markup relationships |
| External integrations | Provider/import provenance, plugin rollback, LLM transport/key boundaries and renderer error handling |
| Supply chain and governance | Version/digest pins, task linkage and vulnerability gates |

Small tests with distinct contracts remain separate. A security negative case is
not redundant with its positive counterpart. A fallback test is not evidence that
parallel workers succeeded. Coverage overlap alone is not grounds for deletion.

## Consolidations and corrected conditions

| Previous checks | Retained contract |
| --- | --- |
| Provider tokens embedded in `token=` / `key=` assignments | A provider matrix in neutral text, exact redaction, preserved surrounding text and identifier-boundary negatives. Generic assignment masking cannot satisfy provider recognition. |
| Separate quoted/unquoted/key-spelling redaction tests | Exact-output matrices covering all spellings, quoting, punctuation, benign token configuration and surrounding context. |
| Repeated role, layout, policy and path-glob cases | Named matrices with independent expected values, complete outputs and both slash spellings. |
| Repeated serialization counts and type checks | Full-content equality plus positive/negative queries for dict, file and text restoration. |
| Filter results merely smaller / above a threshold | Exact surviving edge/finding sets with fixtures that contain both retained and removed cases. |
| Node cap with an arbitrary allowance for IaC nodes | A direct five-node Python cap with exact retained endpoint identities. |
| Custom sanitizer yielding no findings | The same source must first produce a real finding before sanitizer registration; custom sink registration has the inverse control. |
| Traversal to a nonexistent Dockerfile | An existing unsafe file outside the root, plus the same detectable file inside the root. Missing files cannot stand in for containment. |
| Repeating one evidence item to test a size limit | Deduplication and a separate sequence of distinct items that must retain exactly the last bounded window. |
| Installer checksum length of 64 | Independent SHA-256 of actual bytes for every recorded file, with nonempty and complete manifest checks. |
| First available taint finding and field truthiness | A known command flow with exact source, sink, intermediate locations, severity/CWE and negative queries. |
| Empty/single-item lists satisfying sortedness | Multiple distinct risks are required before verifying priority order. |
| Unit rendering test accepting either 200 or 503 | Controlled successful SVG/PNG bytes and a separate controlled error requiring exactly 503; renderer settings and calls are checked. Real rendering stays in container smoke verification. |
| JavaScript keyword presence | Removed as evidence of keyboard/busy behavior. Asset HTTP bodies and reciprocal tab/panel markup relationships are checked directly. |

The old tab-indentation test raised `ValueError` for a malformed list, not for
tabs. Its stricter replacement exposed a production defect: indentation was
computed using spaces only, so the subsequent tab check could never detect a
leading tab. The one-line fix includes tabs in the prefix being validated.
Tests now distinguish tabbed/mixed mappings, malformed lines, orphan list items,
unknown values and out-of-range scores by their actual error messages. Valid
policy inputs and ATT&CK enforcement remain unchanged.

Configuration tests isolate `SECDIAGRAM_*` variables from the caller's environment.
Unexpected errors do not become successful early returns. Known platform
limitations remain explicit skips rather than hidden passes. No assertion
overrides, literal tautologies or duplicate discovered test definitions were found.

## Verification

### Dart and Flutter regression coverage

Run `python -m unittest tests.test_dart tests.test_flutter -v` for the focused
suite. Golden cases check exact callable/type names, kinds, owners and locations:
constructors/factories, getters/setters, operators, generic and nullable types,
records, function return/parameter types, annotations, async/generator methods,
mixins, extensions, aliases and common Flutter widget/state/repository classes.
Calls, provider expressions and widget callbacks must not create callable nodes.

Adversarial tests cover nested comments, raw/triple/unterminated strings,
Unicode, malformed groups, long lines, nested widget trees and route nesting.
The performance regression runs in a child process with a 20-second deadline so
a regex regression cannot hang the test runner. Input tests exercise the 2 MiB
UTF-8 cap before lexer allocation and file opening, a file growing after stat,
relative/absolute/symlink escapes and a sibling sharing the root's name prefix.
Execution and network functions are guarded during parsing, graph building and
Dart SAST, including instruction-like comments and command strings as input.

Dart declaration headers have a deterministic 4096-character / 512-token budget;
type nesting is limited to 32 levels. Route argument inspection has both a
4096-character window and a per-file aggregate work budget. Header/route scan
limits appear in `graph.meta.polyglot_diagnostics`, the CLI diagnostics and
`health.complete = false`; results with these diagnostics need review for omitted
declarations/routes. This is lexical analysis: function
bodies are skipped for declaration discovery, including nested local functions.
Unsupported syntax and type-resolution limitations remain possible even without
a scan-limit diagnostic; file-indexing health does not prove syntax completeness.

CI discovers these tests in every Ubuntu/Windows Python matrix job and uploads
branch-coverage XML from Python 3.12. The optional SonarQube Cloud job imports
`coverage.xml` using `sonar.python.coverage.reportPaths` once the repository's
`SONAR_TOKEN` Actions secret and `SONAR_CI_ANALYSIS_ENABLED=true` Actions variable
are set. The CI scanner is off by default so existing Automatic Analysis remains
enabled. Disable SonarCloud automatic analysis before opting into CI-based
analysis; automatic analysis cannot import test coverage. Fork PRs
without secrets retain test/coverage artifact checks and skip the Sonar upload.
No token is stored in the repository.

### Full verification

Python 3.15 joins the Windows/Ubuntu matrix for the container runtime upgrade.
Studio tests create a real private environment, assert pip/setuptools are absent,
execute the CLI using that interpreter and verify error propagation. The container
gate also checks UID 10001, absence of pip/ensurepip/setuptools, a real package-mode
Studio install and its generated launcher under `--network none`.

Rust release-readiness regressions in issue #87 cover lifetime and character
tokenization, deeply nested comments, raw-string exclusions, multiline routes,
module-qualified ownership, exact SAST evidence, trusted application state,
literal SQL/process arguments, cryptographic RNG exclusions and Cargo runtime
dependency evidence. See [Rust support](RUST_SUPPORT.md) for supported patterns
and gaps. Run `python -m unittest tests.test_rust -v` for the focused suite; the
full discovery command below remains the release gate. The counts and coverage
comparison later in this document describe the #82 refactor, not later commits.

The same review corrected an existing Windows CI blocker in the Studio installer
test: expected project-root paths are resolved before comparison, matching the
installer's documented normalization. This handles Windows 8.3 TEMP paths while
still requiring the exact target repository and launcher behavior.

```sh
python -m unittest discover -s tests -v
python -m coverage run --branch -m unittest discover -s tests -v
python -m coverage report
python scripts/verify_test_depth.py --output .secdiagram/test-depth.json
```

The full suite is also checked in shuffled class/method order with seed
`20261118`. On Windows this uses a real guarded script so multiprocessing
starts correctly; a stdin runner can accidentally exercise only serial fallback.
The Linux suite runs as UID 10001 in the verification container with networking
disabled and source inputs mounted read-only.

The test-depth audit contains **37 isolated fault cases**. Every unmodified
control must pass in its own process. A fault is detected only by actual assertion
failures; import/setup errors, skips and timeouts never earn credit. Production
files are not rewritten. Added cases target provider recognition masked by
assignment redaction, over-redaction, empty sanitizer analysis, ignored filters,
path escapes, evidence bounds, wrong installer digests, empty risk priorities,
corrupt taint sources, ignored image flags, accepted tab indentation, empty asset
bodies, crossed tab associations, dropped unowned findings and corrupt rendered
bytes. The original diagram, security, policy, serialization, fixture-isolation
and parallel-worker faults remain included.

The Windows before/after comparison uses exact executed production line and
branch sets, not only rounded coverage percentages. The baseline is the original
653-test suite on commit `5cb02f1`; the production tab fix preserves line numbers,
so the sets can be compared directly. Raw logs, coverage sets and fault reports
are kept as ignored local evidence and summarized in the tracking issue.

The final comparison loses **zero previously executed production lines or
branches**, and gains six lines and three branches. Statement coverage changes
from 88.122% to 88.163%; branch coverage from 79.194% to 79.239%. The 59 existing
excluded lines are unchanged. These measurements describe Python execution,
not browser behavior or exhaustive defect detection.

## Limits

Fault injection is a bounded regression audit, not an exhaustive mutation score.
Coverage is not proof of assertion quality or a substitute for positive/negative
controls. Existing defensive `pragma: no cover` and type-checking exclusions are
not expanded by this refactor.

Static Studio markup/asset tests do not execute JavaScript or certify browser
keyboard, focus or asynchronous interaction behavior. Those require browser-level
verification; keyword presence is not presented as a substitute. Optional image
engines are mocked at unit boundaries and exercised for real by the offline
Docker PNG/Mermaid smoke checks.

Container verification refreshes the named `runtime` build stage on each CI
build while retaining the locked Mermaid dependency cache. Otherwise inherited
build layers can skip `apk upgrade` and retain fixable OS vulnerabilities even
after local cache metadata has been invalidated. The vulnerability gate remains
blocking; no finding is suppressed to obtain a passing check.

Remaining Python coverage gaps include advisory/report format variants,
resolver/cache error branches, renderer transport failures, server paths and
workspace language detection. Passing tests do not certify those uncovered paths.
