# oci.zig

Pure-Zig client library for the [OCI Distribution
Specification](https://github.com/opencontainers/distribution-spec) v1.1 —
the protocol used by Docker Hub, GHCR, ACR, ECR, and any OCI-conformant
registry. Pull/push of manifests and blobs (full, streaming, partial-range
pulls; monolithic and chunked-stream pushes), authentication, tag listing,
cross-repo blob mount, and the referrers API.

A from-scratch reimplementation of the design and API surface of
[`oras-project/rust-oci-client`](https://github.com/oras-project/rust-oci-client)
(v0.17.0), built against Zig's standard library and the `std.Io` interface
introduced in Zig 0.16. No C dependencies.

See [SPEC.md](SPEC.md) for the full project specification.

## Status

**v0.2 (in progress)** — Tier 1 read path (auth, manifest/blob pull
streaming + partial/range, tag listing, referrers, platform resolvers) and
Tier 2 write path (push manifest/raw/list, push blob monolithic + streamed
chunked, push convenience wrapper, cross-repo blob mount).

## Requirements

- Zig 0.16.0 (pinned in `build.zig.zon`)
- Single dependency: [`ocispec`](https://github.com/navidys/oci-spec-zig) v0.5.0

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

    const result = try client.pullManifest(io.io(), image, auth);
    defer gpa.allocator().free(result.digest);
    // result.manifest: oci.manifest.OciManifest
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

## Development

```sh
zig build test          # unit tests (no network)
zig build integration-test  # integration tests against a local zot registry
```

Integration tests require a running [zot](https://zotregistry.dev/) registry
at `127.0.0.1:5000` with the test content pushed (see
`.slim/deepwork/zot/` for the local setup used during development).

## License

MIT — see [LICENSE](LICENSE).