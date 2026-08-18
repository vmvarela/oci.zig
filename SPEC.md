# oci.zig — Project Specification

Status: draft / pre-implementation. No stable API yet.

## 1. Overview

`oci.zig` is a pure-Zig client library for the [OCI Distribution
Specification](https://github.com/opencontainers/distribution-spec) — the
protocol used by Docker Hub, GHCR, ACR, ECR, Docker Registry, and any other
OCI-conformant registry. It provides pull/push of manifests and blobs,
authentication, tag/catalog listing, and the referrers API.

It is a from-scratch reimplementation of the design and API surface of
[`oras-project/rust-oci-client`](https://github.com/oras-project/rust-oci-client),
built against Zig's standard library and the `std.Io` interface introduced
in Zig 0.16.

**Explicitly not in scope**: ORAS-style artifact packing (`oras push`/`oras
pull` semantics — local tar packing, `subject`/attach helpers, a local
content-addressable cache). That is a distinct, higher-level concern the
`oras-project` itself keeps in a separate library (`oras-rs`, still in
progress, on top of `oci-client`). If that layer is ever built here, it
belongs in a separate package on top of `oci.zig`, not inside it.

## 2. Reference implementation

- Upstream: <https://github.com/oras-project/rust-oci-client>
- Pinned reference version: **v0.17.0** (2026-05-19)
- License: Apache-2.0
- `oci.zig` is an independent reimplementation, not a code translation or a
  fork. It follows the same protocol behavior and, where idiomatic, the same
  module boundaries and function names as the Rust crate — but every line of
  Zig is original. When a design question is ambiguous, `client.rs` in the
  pinned version is the tie-breaker.

## 3. Goals

- Implement the client surface of OCI Distribution Spec v1.1: auth
  (anonymous/basic/bearer), manifest push/pull, blob push/pull (including
  streaming and partial/range pulls), tag listing, catalog listing,
  cross-repository blob mount, and the referrers API.
- No required C dependencies. Transport, TLS, JSON, and hashing come from
  Zig std only.
- Correctness parity with `rust-oci-client` where it matters most: canonical
  JSON manifest digests, auth token handling, error semantics.
- Reuse existing, well-scoped Zig libraries for spec-level types instead of
  redefining them (see §5) — but don't force a dependency where its scope
  doesn't actually match what the client needs (also §5).

## 4. Non-goals (for now)

- ORAS artifact packing/attach semantics (see §1).
- OCI Runtime Specification support — irrelevant to a registry client.
  `oci-spec-zig` ships a `runtime` submodule; `oci.zig` will not depend on
  it.
- Registry server or mirror implementation.
- Image signing/verification (cosign-style) — out of scope until there is a
  concrete driver for it.

## 5. Dependency strategy — what to reuse vs. what to write

I inventoried `rust-oci-client`'s actual source (not just `Cargo.toml`) and
cross-checked each piece against
[`navidys/oci-spec-zig`](https://github.com/navidys/oci-spec-zig) (MIT,
implements the OCI Image/Runtime/Distribution specs — the Zig analogue of
the `oci-spec` crate, **not** of `oci-client`). Two dependencies declared in
`rust-oci-client`'s `Cargo.toml` (`regex`, `unicase`) turned out to have zero
actual usage in `src/*.rs` — dropped, no Zig equivalent needed.

| Concern | Rust source | oci.zig plan | Notes |
|---|---|---|---|
| HTTP/1.1 transport + TLS | `reqwest` + `rustls` | `std.http.Client` + `std.crypto.tls` | Std only. Validate streaming/range-request behavior early — see §9. |
| Async I/O | `tokio` | `std.Io` (0.16), `std.Io.Threaded` backend | Functions take an `Io` param, colorless. The evented (io_uring) backend is still experimental in 0.16 — not targeted yet. |
| JSON (de)serialization | `serde`/`serde_json` | `std.json` | |
| SHA-256/384/512 | `sha2` | `std.crypto.hash.sha2` | |
| Hex encoding | `hex` | `std.fmt` | |
| OCI Image Configuration (`config.rs`: `ConfigFile`, `Config`, `Rootfs`, `History`) | own types, `type Architecture = oci_spec::image::Arch` | **fully covered by `ocispec.image.ImageConfiguration` / `Config` / `RootFS` / `History`** | Verified field-for-field. No `oci.zig`-specific file needed here — just consume `ocispec.image.*` directly. |
| Well-known annotation keys (`annotations.rs`) | `ORG_OPENCONTAINERS_IMAGE_*` consts | **`ocispec.image` annotation constants** | Verified identical key strings (`org.opencontainers.image.*`), just a different naming convention (`ANNOTATION_CREATED` vs `ORG_OPENCONTAINERS_IMAGE_CREATED`). Reuse. |
| Manifest/Index/Descriptor/Platform types + media-type constants (`manifest.rs`) | `OciManifest`, `OciImageManifest`, `OciImageIndex`, `OciDescriptor`, `Platform`, plus Docker-legacy (`application/vnd.docker.distribution.manifest.v2+json`) and WASM media type constants | **write from scratch** (`manifest.zig`) | `ocispec.image.MediaType` is pure-OCI only — verified it has no Docker Distribution v2 schema2 or WASM variants. `rust-oci-client` deliberately supports those for compatibility with real-world registries and OCI-artifact use cases. Internally it can still lean on `ocispec.image.Descriptor` for the pure-OCI cases, but the manifest/index union type and legacy media types need their own home. |
| Blob transport plumbing (`blob.rs`: `SizedStream`, `BlobResponse`) | internal | **write from scratch** (`blob.zig`) | Pure client plumbing, not spec-related. |
| Digest header handling + validation (`digest.rs`: `Digest<'a>`, `digest_header_value`, `validate_digest`) | internal | **write from scratch** (`digest.zig`) | Distinct from `ocispec`'s `Digest` (which only parses/formats the `algo:hex` string). This is the `Docker-Content-Digest` header extraction plus verifying a pulled blob's actual hash against the expected digest. |
| Registry error envelope + error set (`errors.rs`: `OciDistributionError`, `OciError`, `OciEnvelope`, `OciErrorCode`) | internal | **write from scratch** (`errors.zig`) | Confirmed not covered by `oci-spec-zig` (its only error type is a tiny digest-parsing error set in `image/errors.zig`). |
| Credential input type (`secrets.rs`: `RegistryAuth`) | internal | **write from scratch** (`secrets.zig`) | Small tagged union: anonymous / basic / bearer. |
| Token cache (`token_cache.rs`: `RegistryToken`, `TokenCache`, `RegistryOperation`) | internal, decodes JWT `exp` claim only — **no signature verification** | **write from scratch** (`token_cache.zig`) | Confirmed: the Rust side never verifies the JWT signature, it only base64-decodes the payload to read `exp`. No crypto beyond base64 + JSON needed. |
| `WWW-Authenticate` bearer challenge parsing | `http-auth` crate | **write from scratch** (`auth.zig`) | Small, well-defined grammar (`Bearer realm="...",service="...",scope="..."`). Not worth a dependency; none found in the Zig ecosystem anyway. |
| Canonical JSON for manifest digest | `olpc-cjson` | **write from scratch** (`canonical_json.zig`) | No existing Zig library found (checked Zigistry / awesome-zig). Small, well-defined surface — sorted object keys, no insignificant whitespace, specific escaping — but must be byte-exact: a wrong digest breaks every push. |
| Image reference parsing (`[registry[:port]/]repo[:tag][@digest]`) | `oci_spec::distribution::Reference`, re-exported | **write from scratch** (`reference.zig`) | Confirmed `oci-spec-zig`'s `distribution` submodule does *not* include this — it only has `RepositoryList`, `TagList`, and a version constant. Hand-written parser preferred over pulling in a regex engine (Zig std has none). |

## 6. Target environment

- Zig **0.16.0** (stable, released 2026-04-14) as the minimum and the
  pinned CI version.
- Track tagged releases, not `master`/`-dev` builds, on the main branch.
  `std.Io` is one release old; expect further churn toward 0.17
  (`std.Io.Evented` maturing, possible API adjustments). Re-evaluate the
  pin once 0.17 stabilizes.
- Platforms: Zig Tier 1 targets (Linux, macOS, Windows). No platform-specific
  code expected beyond what `std.http.Client` / `std.crypto.tls` already
  abstract.

## 7. Proposed module layout

```
src/
  root.zig             // public re-exports (lib.rs equivalent)
  client.zig            // Client struct, ClientConfig/ClientProtocol,
                         // pull/push manifest & blob, catalog, list_tags,
                         // mount_blob, referrers, platform resolvers
  auth.zig               // WWW-Authenticate challenge parsing + auth()/_auth()
  reference.zig           // Reference: parse/format registry/repo:tag@digest
  manifest.zig             // OciManifest/OciImageManifest/OciImageIndex/
                            // Platform + Docker-legacy & WASM media types
  blob.zig                  // SizedStream / BlobResponse transport plumbing
  digest.zig                 // Docker-Content-Digest header + blob validation
  canonical_json.zig          // olpc-cjson equivalent
  errors.zig                   // OciError set + registry JSON error envelope
  secrets.zig                   // RegistryAuth (anonymous/basic/bearer)
  token_cache.zig                 // RegistryToken, TokenCache, RegistryOperation
```

Single external dependency: `ocispec` ([oci-spec-zig](https://github.com/navidys/oci-spec-zig)),
imported for `image.ImageConfiguration`/`Config`/`RootFS`/`History` and
`image` annotation constants, and `distribution.RepositoryList`/`TagList`.
Not the `runtime` submodule (irrelevant here).

## 8. Public API surface (ported from `client.rs`)

Grouped into delivery tiers — see §12.

**Tier 1 — read path (MVP)** (implemented signatures; `creds` = `RegistryAuth`)
- `Client.init(allocator, config: ClientConfig) Client`
- `Client.auth(io, image: Reference, creds: RegistryAuth, op: RegistryOperation) !?[]const u8`
- `Client.listTags(io, image, creds, n: ?usize, last: ?[]const u8) ![]const []const u8`
- `Client.fetchManifestDigest(io, image, creds) ![]const u8`
- `Client.pullManifest(io, image, creds) !struct { manifest: OciManifest, digest: []const u8 }`
- `Client.pullManifestAndConfig(io, image, creds) !struct { manifest: OciImageManifest, config_digest: []const u8, config: []const u8 }`
- `Client.pullBlob(io, image, digest, writer) !void`
- `Client.pullBlobStream(io, image, digest) !BlobStreamResult` (stream + owning Request + container; `result.deinit()` after reads)
- `Client.pullBlobStreamPartial(io, image, digest, offset, length) !BlobResponseResult` (partial — no digest verification)
- `Client.pull(io, image, creds, accepted_media_types) !ImageData` (convenience wrapper)
- `Client.pullReferrers(io, image, creds, artifact_type) ![]OciDescriptor` (404 → tag-schema fallback)
- Platform resolvers: `linuxAmd64Resolver`, `windowsAmd64Resolver`, `currentPlatformResolver`

**Tier 2 — write path**
- `Client.pushManifest` / `pushManifestRaw` / `pushManifestList`
- `Client.pushBlob` / `pushBlobStream`
- `Client.push` (convenience wrapper)
- `Client.mountBlob`

**Tier 3 — admin/misc**
- `Client.catalog(io, image, creds, n: ?usize, last: ?[]const u8) ![]const []const u8`
- `Client.blobExists(io, image, creds, digest) !bool`
- `Client.storeAuthIfNeeded`

## 9. Known risk areas — validate before committing to the full port

1. **Streaming over `std.http.Client`.** Range requests (`Range` header) for
   partial blob pulls, and streamed/chunked uploads for `push_blob_stream`,
   against a real registry. This is the area most likely to surface bugs in
   Zig's still-young HTTP client, given its history of rough edges around
   chunked transfer. Spike this in isolation before porting the rest of
   `client.rs`.
2. **Canonical JSON byte-exactness.** A wrong serialization produces a wrong
   manifest digest — the registry either rejects the push or, worse, accepts
   a mismatched one. Build a golden-vector test suite sourced from
   `rust-oci-client`'s own test fixtures, not just hand-written examples.
3. **Zig 0.16 → 0.17 churn.** `std.Io` is one release old. Pin the required
   version in `build.zig.zon` and budget maintenance time for the next
   release cycle.

## 10. Testing strategy

- **Unit tests** (no network): canonical JSON, reference parsing, digest
  validation, `WWW-Authenticate` challenge parsing.
- **Integration tests**: run [zot](https://zotregistry.dev/) (single static
  binary, OCI-conformant registry) in CI instead of `rust-oci-client`'s
  `testcontainers` + Docker approach — lighter, no Docker-in-CI dependency.
- **Parity tests**: for canonical JSON and digest computation, assert
  against fixtures copied from `rust-oci-client/tests/`.

## 11. Relationship to oci-spec-zig

- Consume it as a normal dependency (`zig fetch --save`), not a fork.
- If a concrete gap blocks development (missing type, bug), open an
  issue/PR upstream first — the project has `CONTRIBUTING.md` and
  `MAINTAINERS.md`, and was last active 2026-06.
- Fork only as a last resort, if upstream is unresponsive or declines a
  needed change — and prefer contributing back over diverging silently.

## 12. Roadmap

- **v0.1** — Tier 1 (read path) complete, unit + integration tests, `zot`-based CI.
- **v0.2** — Tier 2 (write path) complete, canonical-JSON parity suite finalized.
- **v0.3** — Tier 3 (catalog, blobExists, storeAuthIfNeeded), referrers API polish, platform resolver coverage. (complete)
- **Post-v1.0 candidate** — evaluate `std.Io.Evented` once non-experimental.

## 13. Open questions

- License for `oci.zig`: MIT recommended for ecosystem consistency (matches
  `oci-spec-zig` and most Zigistry packages) — not yet decided.
- Module/package name in `build.zig.zon`: proposed `oci`.
- Whether pure-OCI manifest/descriptor handling should wrap
  `ocispec.image.Descriptor` internally or stay fully independent — decide
  once `manifest.zig` is underway and the Docker-legacy/WASM overlap is
  clearer in practice.

