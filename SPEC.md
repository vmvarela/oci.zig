# oci.zig — Project Specification

Status: **v0.6** — all three delivery tiers implemented plus manifest
deletion, zero external dependencies, zot-based CI. v0.4 was a breaking
cleanup pass on the 0.1.0 lib: dropped the never-imported `ocispec`
dependency and removed dead public API (`validateDigest`,
`digestHeaderValue`, `storeAuthIfNeeded`). v0.5 added `deleteManifest`.
v0.6 fixed an unbounded arena leak on manifest pulls: `PulledManifest`,
`ManifestAndConfig`, and `ImageData` now own their strings in an internal
arena and must be released with `deinit` (breaking).

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
- Zero external dependencies. Transport, TLS, JSON, hashing, and spec-level
  types all come from Zig std or this crate. `oci-spec-zig` was evaluated
  (see §5) but dropped in v0.4 — no source file ever imported it (see §11).

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

**Outcome (v0.4):** the `ocispec` dependency was dropped entirely — no source
file ever imported it. Everything below is now written from scratch in this
crate, std-only. The table records the original plan and the final call.

| Concern | Rust source | oci.zig plan | Notes |
|---|---|---|---|
| HTTP/1.1 transport + TLS | `reqwest` + `rustls` | `std.http.Client` + `std.crypto.tls` | Std only. Validate streaming/range-request behavior early — see §9. |
| Async I/O | `tokio` | `std.Io` (0.16), `std.Io.Threaded` backend | Functions take an `Io` param, colorless. The evented (io_uring) backend is still experimental in 0.16 — not targeted yet. |
| JSON (de)serialization | `serde`/`serde_json` | `std.json` | |
| SHA-256/384/512 | `sha2` | `std.crypto.hash.sha2` | |
| Hex encoding | `hex` | `std.fmt` | |
| OCI Image Configuration (`config.rs`: `ConfigFile`, `Config`, `Rootfs`, `History`) | own types, `type Architecture = oci_spec::image::Arch` | **raw config bytes** | Originally planned to consume `ocispec.image.*`; v0.4 dropped the dep. `pullManifestAndConfig` returns the config blob as raw bytes — no typed `ConfigFile` shipped. |
| Well-known annotation keys (`annotations.rs`) | `ORG_OPENCONTAINERS_IMAGE_*` consts | **write from scratch** (`manifest.zig`) | Originally planned to reuse `ocispec.image` annotation constants; v0.4 dropped the dep. `manifest.zig` carries `annotations` as `json.ArrayHashMap([]const u8)` — no named constants needed. |
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
  tls.zig                    // TLS certificate configuration (extra root CAs / certs-only)
```

Zero external dependencies. `ocispec` was evaluated and dropped in v0.4
(never imported); `image` config/annotation types are reimplemented
independently in `manifest.zig`.

## 8. Public API surface (ported from `client.rs`)

Grouped into delivery tiers — see §12.

**Tier 1 — read path (MVP)** (implemented signatures; `creds` = `RegistryAuth`)
- `Client.init(allocator, config: ClientConfig) Client`
- `Client.auth(io, image: Reference, creds: RegistryAuth, op: RegistryOperation) !?[]const u8`
- `Client.listTags(io, image, creds, n: ?usize, last: ?[]const u8) ![]const []const u8`
- `Client.fetchManifestDigest(io, image, creds) ![]const u8`
- `Client.pullManifest(io, image, creds) !PulledManifest` (has `deinit`)
- `Client.pullManifestAndConfig(io, image, creds) !ManifestAndConfig` (has `deinit`)
- `Client.pullBlob(io, image, digest, writer) !void`
- `Client.pullBlobStream(io, image, digest) !BlobStreamResult` (stream + owning Request + container; `result.deinit()` after reads)
- `Client.pullBlobStreamPartial(io, image, digest, offset, length) !BlobResponseResult` (partial — no digest verification)
- `Client.pull(io, image, creds, accepted_media_types) !ImageData` (convenience wrapper; has `deinit`)

`PulledManifest`, `ManifestAndConfig`, and `ImageData` each own their result
strings in an internal arena; results must be released with `deinit`.
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
- `Client.deleteManifest(io, image, creds) !void` (DELETE by tag/digest; 404 → `error.NotFound`)

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

Evaluated as a dependency, then dropped in v0.4 — no source file ever
imported it. The `image` config/annotation types it would have provided are
reimplemented independently in `manifest.zig` (config handled as raw bytes,
annotations as `json.ArrayHashMap`). If a future need for typed image-config
types arises, revisit `oci-spec-zig` as a normal dependency (`zig fetch
--save`), not a fork.

## 12. Roadmap

- **v0.1** — Tier 1 (read path) complete, unit + integration tests, `zot`-based CI.
- **v0.2** — Tier 2 (write path) complete, canonical-JSON parity suite finalized.
- **v0.3** — Tier 3 (catalog, blobExists, storeAuthIfNeeded), referrers API polish, platform resolver coverage. (complete)
- **v0.4** — breaking cleanup on the 0.1.0 lib: drop the never-imported
  `ocispec` dependency, remove dead public API (`validateDigest`,
  `digestHeaderValue`, `storeAuthIfNeeded`), internal shrink; TLS certificate
  support (custom root CAs via `extra_root_certificates` / `tls_certs_only`). (complete)
- **v0.5** — `Client.deleteManifest` (manifest deletion by tag/digest, OCI
  Distribution Spec "Deleting Manifests"/"Deleting tags"; bearer scope
  `repository:<name>:pull,delete`). (complete)
- **v0.6** — memory-lifecycle fix: `PulledManifest`, `ManifestAndConfig`,
  and `ImageData` own their strings in an internal arena released via
  `deinit`, fixing an unbounded arena leak on every manifest pull
  (issue #4). Breaking: callers must call `deinit` on these results.
  (complete)
- **Post-v1.0 candidate** — evaluate `std.Io.Evented` once non-experimental.

## 13. Open questions

- License for `oci.zig`: **MIT** (decided — `LICENSE` file in place; matches
  `oci-spec-zig` and most Zigistry packages).
- Module/package name in `build.zig.zon`: **`oci`** (decided — set in
  `build.zig.zon`).
- Whether pure-OCI manifest/descriptor handling should wrap
  `ocispec.image.Descriptor` internally or stay fully independent — **decided
  (v0.4): fully independent.** The `ocispec` dependency was dropped; `manifest.zig`
  defines its own string-media-type descriptors with no wrapping.

