# Rust, Axum and Actix support

Rust analysis uses the Python standard library to read `.rs` and `Cargo.toml`
files. It does not invoke Cargo, rustc, build scripts or procedural macros, and
does not download dependencies. No Rust toolchain is required.

## Run offline

```sh
python secdiagram.py --dir tests/fixtures/polyglot/rust_api --offline --dry-run --output json
python secdiagram.py --dir /path/to/rust-project --offline --format mermaid,json,sarif
```

The first command prints the scan summary without writing reports. The second
writes architecture, graph and security reports to the project's `.secdiagram/`
directory. Add `--image png --image-provider local` when a local Mermaid renderer
is available; the container bundles it. See the [CLI reference](CLI_REFERENCE.md)
for progress stages, filters, caches, limits and the `health.complete` field.

## Architecture coverage

- Structs, enums, traits, unions, functions and `impl` methods, including common
  generic signatures and lifetime annotations; trait implementation relationships.
- Axum `.route("/path", get(handler).post(other))` registrations, including
  multiline arguments. Explicit module-qualified handlers are matched by source
  path, so an unrelated same-named function is not selected. Unresolved or
  ambiguous registrations remain endpoint observations at the registration site.
- Actix `#[get("/path")]` and `#[actix_web::post("/path")]` style attributes
  with literal paths. Detected HTTP methods include GET, POST, PUT, DELETE, PATCH,
  HEAD and OPTIONS; Axum `any(handler)` is recorded as ANY.
- Comments, nested block comments, character/byte literals and raw strings are
  excluded from structural recognition while source line offsets are preserved.

Cargo inventory recognizes `[package]` names, runtime dependency keys and
dependency tables, including target-specific declarations and renamed packages.
Explicit `postgres`, `mysql` and `sqlite` features contribute data-store markers.
Descriptions, comments and development/build dependencies do not establish
runtime relationships. A virtual workspace manifest is not an application
subsystem. Framework dependencies such as Axum, Actix-web, Rocket, Warp and Poem
can label a subsystem; route extraction is scoped to the Axum/Actix forms above.

## Evidence-backed security rules

| Rule | Evidence required |
| --- | --- |
| `PG-RS-SQL` / CWE-89 | Request-controlled or dynamically constructed SQL passed to `sqlx::query` / `query_as`; bound literal queries are not findings. Untainted dynamic SQL is a lower-confidence review item. |
| `PG-RS-CMD` / CWE-78 | Tainted executable at `Command::new`, or tainted arguments connected to a detected shell/batch builder. Literal arguments to ordinary programs are not shell-injection evidence. |
| `PG-RS-PATH` / CWE-22 | Request input reaching recognized `fs::read`, `read_to_string`, `write`, removal calls or `File::open/create`. |
| `PG-RS-SSRF` / CWE-918 | Request input reaching recognized reqwest/client HTTP calls; verify URL and destination restrictions during review. |
| `PG-RS-TLS` / CWE-295 | Explicit `danger_accept_invalid_certs(true)` or `danger_accept_invalid_hostnames(true)`. |
| `CFG-RS-CORS` / CWE-942 | `CorsLayer::very_permissive()` or `.allow_any_origin()`; review intended origin and credential policy. |
| `CFG-RS-RANDOM` / CWE-338 | Recognized `fastrand` calls or `SmallRng` construction near security-value names. |

Recognized request extractors include Query, Json, Path, Form, HeaderMap, Bytes,
String and HttpRequest. State, Extension and Actix `web::Data` are application
state, not request sources. Ordinary `Query(...)` construction is not an input
source. Command-line arguments and stdin also have explicit source patterns.
Tainted findings include source-to-sink locations and graph ownership when
resolved. Static observations require human verification; they do not prove
exploitability. See [security analysis](SECURITY_AND_IAC.md) and
[threat modeling](THREAT_MODELING.md).

`unsafe { ... }` alone is not a memory-corruption finding: it permits operations
whose safety conditions require review, rather than proving those conditions
were violated. `rand::thread_rng()` and `rand::random()` are not classified as
non-cryptographic RNGs merely because they generate a token. These distinctions
follow the [Rust unsafe reference](https://doc.rust-lang.org/reference/unsafe-keyword.html),
[Command argument semantics](https://doc.rust-lang.org/std/process/struct.Command.html#method.arg),
[ThreadRng security documentation](https://docs.rs/rand/latest/rand/rngs/struct.ThreadRng.html#security),
[SmallRng documentation](https://docs.rs/rand/latest/rand/rngs/struct.SmallRng.html)
and [fastrand documentation](https://docs.rs/fastrand/latest/fastrand/).

## Limits and release checks

This is lexical analysis, not Rust compiler/type-system validation. It does not
expand macros, evaluate `cfg`/features, resolve Cargo workspace inheritance or
lockfiles, prove memory safety, or model arbitrary middleware and custom request
extractors. Aliases, complex generic signatures, nested modules, nonliteral route
paths, router nesting/prefix composition and builder reassignment may be
unresolved. Absence of a finding is not proof of safe code. The scan health
summary describes indexed files; it cannot measure every unsupported Rust
construct inside an indexed file.

`tests/test_rust.py` checks exact route ownership, source locations, complete
fixture findings, safe counterparts, tokenizer recovery, bounded hostile input,
Cargo evidence and deterministic graphs. The full suite runs on Windows and
Ubuntu with Python 3.10–3.14. Offline container verification exercises actual
Mermaid/PNG rendering as UID 10001 with networking disabled. See
[test validation](TEST_VALIDATION.md) for broader contracts and coverage limits.
