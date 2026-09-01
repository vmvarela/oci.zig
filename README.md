# oci.zig

[![CI](https://github.com/vmvarela/oci.zig/actions/workflows/ci.yml/badge.svg)](https://github.com/vmvarela/oci.zig/actions/workflows/ci.yml)

Pure-Zig client library for the [OCI Distribution
Specification](https://github.com/opencontainers/distribution-spec) v1.1 —
the protocol used by Docker Hub, GHCR, ACR, ECR, and any OCI-conformant
registry. Pull/push of manifests and blobs (full, streaming, partial-range
pulls; monolithic and chunked-stream pushes), authentication, tag listing,
cross-repo blob mount, manifest deletion, and the referrers API.

A from-scratch reimplementation of the design and API surface of
[`oras-project/rust-oci-client`](https://github.com/oras-project/rust-oci-client)
(v0.17.0), built against Zig's standard library and the `std.Io` interface
introduced in Zig 0.16. No C dependencies.

See [SPEC.md](SPEC.md) for the full project specification.

## Status

**v0.4** — Tier 1 read path, Tier 2 write path, Tier 3 (catalog, blobExists), referrers API with tag-schema fallback, platform resolvers. Zero external dependencies (dropped `ocispec`); dead public API removed (`validateDigest`, `digestHeaderValue`, `storeAuthIfNeeded`); TLS certificate support (custom root CAs via `extra_root_certificates` / `tls_certs_only`).

**v0.5** — `Client.deleteManifest` (manifest deletion by tag/digest).

**v0.6** — `PulledManifest`, `ManifestAndConfig`, and `ImageData` own their result strings in an internal arena, released with `deinit` (breaking).

**v0.7** — anonymous bearer-token dance fixed (credential-less token request on 401 challenge, Docker Hub-style); `pullBlob`, `pullBlobStream`, and `pullBlobStreamPartial` now take `creds` (breaking).

## Requirements

- Zig 0.16.0 (pinned in `build.zig.zon`)
- No external dependencies (Zig std only)

## Usage

```zig
const std = @import("std");
const oci = @import("oci");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();

    var io = std.Io.Threaded.init(gpa.allocator(), .{});
    defer io.deinit();

    var client = oci.client.Client.init(gpa.allocator(), .{ .protocol = .https });
    defer client.deinit();

    const image = try oci.reference.parse("registry.example.com/team/app:v1");
    const auth = oci.secrets.RegistryAuth.anonymous;

    var result = try client.pullManifest(io.io(), image, auth);
    defer result.deinit();
    // result.manifest: oci.manifest.OciManifest
    // result.digest: []const u8 (owned by result; freed by deinit)
}
```

### Pushing

```zig
// Tier 2: push config + layers + manifest in one call (manifest auto-built)
const pushed = try client.push(
    io.io(), image, auth,
    null,                      // auto-build the manifest from config + layers
    config_bytes,              // OCI image config JSON
    &.{ layer_a_bytes, layer_b_bytes },
);
defer gpa.allocator().free(pushed.manifest_digest);
defer gpa.allocator().free(pushed.manifest_url);

// Lower-level: push a blob monolithically, or stream it chunked
const digest = try client.pushBlob(io.io(), image, auth, layer_bytes);
_ = try client.pushBlobStream(io.io(), image, auth, reader, size);

// Push a pre-serialized manifest verbatim
const loc = try client.pushManifestRaw(io.io(), image, auth, manifest_bytes, media_type);

// Cross-repo blob mount (no upload when the source repo has the blob)
try client.mountBlob(io.io(), target_image, auth, source_image, digest);
```

### Registry admin

```zig
// Tier 3: list repositories on the registry. Pagination: pass the last
// returned repository back as `last` on the next call; the response carries
// no pagination fields.
const repos = try client.catalog(io.io(), image, auth, 50, last_repo);
// The returned slice and each repo string are separate allocations — free
// the slice, then each repo string.

// Blob existence check (HEAD). Returns false when absent, errors otherwise.
const exists = try client.blobExists(io.io(), image, auth, digest);

// Delete a manifest by tag or digest. 404 -> error.NotFound (nothing to delete).
try client.deleteManifest(io.io(), image, auth);

// Referrers API, filtered to a specific artifact type (exact match)
const refs = try client.pullReferrers(io.io(), image, auth, "application/vnd.example.sbom.v1");
```

### Custom TLS certificates

Private registries with self-signed or private-CA certificates:

```zig
// ca_pem_bytes: PEM bytes of the CA certificate (caller-owned).
// .fromDer(der_bytes) also works for DER-encoded certificates.
var ca_certs = [_]oci.tls.Certificate{oci.tls.Certificate.fromPem(ca_pem_bytes)};

var client = oci.client.Client.init(gpa.allocator(), .{
    .protocol = .https,
    .extra_root_certificates = &ca_certs, // trust these in addition to system roots
    // .tls_certs_only = &ca_certs,       // trust ONLY these, no system roots
});
```

`accept_invalid_certificates` / `accept_invalid_hostnames` are NOT supported
(Zig's `std.http.Client` has no hook to disable verification). Workaround: use
`.protocol = .http` or a TLS-terminating reverse proxy.

## Development

```sh
zig build test          # unit tests (no network)
zig build integration-test  # integration tests against a local zot registry
```

Integration tests require a running [zot](https://zotregistry.dev/) registry
at `127.0.0.1:5000` with the test content pushed via `tests/setup.sh` (see
that script for the setup). Each run pushes timestamp-suffixed test repos, so
a long-lived local zot accumulates them — wipe the zot data directory to
reset.

## License

MIT — see [LICENSE](LICENSE).