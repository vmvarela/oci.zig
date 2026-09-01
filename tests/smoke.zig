//! Read-only "smoke" tests against a real public registry (Docker Hub,
//! anonymous). Purpose: prove the client performs real-world HTTPS pulls
//! against Docker Hub — real digests, CDN redirects, and blob ranges — the
//! biggest untested divergence from the local zot integration lane. No
//! writes are performed.
//!
//! These tests hit the network and are NOT part of `zig build test`; run
//! them with `zig build smoke-test`. OCI_SMOKE_REF overrides the pinned
//! reference (default: alpine:3.20 pinned by digest — immutable, so the
//! test is deterministic).
//!
//! Anonymous auth note: the client cannot yet fetch a token for
//! `RegistryAuth.anonymous` (tokenFromChallenge returns null, and Docker
//! Hub's token endpoint rejects every Basic credential variant — only a
//! credential-less GET succeeds). So these tests fetch the anonymous pull
//! token themselves and hand it to the client as `.bearer` creds. The
//! client's internal 401 -> challenge -> token -> retry dance therefore
//! remains untested here; enabling anonymous token fetch would be a src/
//! change.

const std = @import("std");
const oci = @import("oci");
const client = oci.client;
const manifest = oci.manifest;
const reference = oci.reference;
const secrets = oci.secrets;
const token_cache = oci.token_cache;

/// Pinned alpine:3.20 multi-arch index digest (immutable on Docker Hub).
const pinned_ref = "docker.io/library/alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc";

/// Reference string from OCI_SMOKE_REF, or the pinned default.
fn smokeRef(allocator: std.mem.Allocator) ![]const u8 {
    if (std.c.getenv("OCI_SMOKE_REF")) |ptr| {
        const len = std.mem.len(ptr);
        if (len > 0) return allocator.dupe(u8, ptr[0..len]);
    }
    return allocator.dupe(u8, pinned_ref);
}

/// Reference from OCI_SMOKE_REF or the pinned default, with the registry
/// normalized for direct API use: the client performs no docker.io ->
/// registry-1.docker.io mapping, and docker.io itself is the website host
/// (302 to www.docker.com), so rewrite it here.
fn smokeReference(allocator: std.mem.Allocator) !reference.Reference {
    const parsed = try reference.parse(try smokeRef(allocator));
    if (std.ascii.eqlIgnoreCase(parsed.registry, "docker.io")) {
        return .{
            .registry = "registry-1.docker.io",
            .repository = parsed.repository,
            .tag = parsed.tag,
            .digest = parsed.digest,
        };
    }
    return parsed;
}

/// Fetches an anonymous pull token from Docker Hub's token endpoint
/// (credential-less GET — see the module comment for why the client cannot
/// do this itself yet). Returned string is owned by `allocator`.
fn dockerHubToken(allocator: std.mem.Allocator, io: std.Io, repository: []const u8) ![]const u8 {
    var http: std.http.Client = .{ .allocator = allocator, .io = io };
    defer http.deinit();
    const url = try std.fmt.allocPrint(
        allocator,
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{s}:pull",
        .{repository},
    );
    defer allocator.free(url);
    const uri = try std.Uri.parse(url);

    var redirect_buf: [8192]u8 = undefined;
    var req = try http.request(.GET, uri, .{ .redirect_behavior = .unhandled });
    defer req.deinit();
    try req.sendBodiless();
    var resp = try req.receiveHead(&redirect_buf);
    if (resp.head.status != .ok) return error.UnexpectedStatus;

    var transfer_buf: [8192]u8 = undefined;
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    const reader = resp.reader(&transfer_buf);
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = try reader.readSliceShort(&chunk);
        if (n == 0) break;
        try body.appendSlice(allocator, chunk[0..n]);
    }
    const parsed = try std.json.parseFromSliceLeaky(
        struct { token: ?[]const u8 = null },
        allocator,
        body.items,
        .{ .ignore_unknown_fields = true },
    );
    return allocator.dupe(u8, parsed.token orelse return error.InvalidResponse);
}

/// Fetches the anonymous token, seeds the client's token cache (openBlob
/// only consults the cache — its auth header path hardcodes anonymous),
/// and returns `.bearer` creds for the direct-call APIs.
fn setupAuth(
    c: *client.Client,
    io: std.Io,
    allocator: std.mem.Allocator,
    ref: reference.Reference,
) !secrets.RegistryAuth {
    const token = try dockerHubToken(allocator, io, ref.repository);
    try c.token_cache.put(ref.registry, ref.repository, .pull, token);
    return .{ .bearer = token };
}

test "smoke: pull manifest by digest from Docker Hub" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();
    const a = arena.allocator();

    var threaded = std.Io.Threaded.init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var c = client.Client.init(a, .{ .protocol = .https });
    defer c.deinit();

    const ref = try smokeReference(a);
    const creds = try setupAuth(&c, io, a, ref);

    var pulled = try c.pullManifest(io, ref, creds);
    defer pulled.deinit();

    // The registry's Docker-Content-Digest must equal the pinned digest:
    // this is the real-world digest verification (zot tests only ever see
    // digests we computed ourselves).
    try std.testing.expectEqualStrings(ref.digest.?, pulled.digest);
    // Media type must be one of the OCI document types the client supports
    // (Docker Hub serves library/alpine as an OCI index).
    const mt = pulled.manifest.mediaType() orelse return error.TestUnexpectedResult;
    const supported = std.mem.eql(u8, mt, manifest.oci_manifest) or
        std.mem.eql(u8, mt, manifest.oci_index);
    try std.testing.expect(supported);
}

test "smoke: partial-range blob pull from Docker Hub" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();
    const a = arena.allocator();

    var threaded = std.Io.Threaded.init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var c = client.Client.init(a, .{ .protocol = .https });
    defer c.deinit();

    const ref = try smokeReference(a);
    const creds = try setupAuth(&c, io, a, ref);

    // Resolve to a leaf manifest: the default ref is a multi-arch index, so
    // its descriptors point at manifests, not blobs. Pull the first child.
    var pulled = try c.pullManifest(io, ref, creds);
    defer pulled.deinit();
    var leaf_pulled: ?client.PulledManifest = null;
    defer if (leaf_pulled) |*l| l.deinit();
    var leaf = &pulled;
    if (pulled.manifest.isIndex()) {
        const child_ref = reference.Reference{
            .registry = ref.registry,
            .repository = ref.repository,
            .digest = pulled.manifest.index.manifests[0].digest,
        };
        leaf_pulled = try c.pullManifest(io, child_ref, creds);
        leaf = &leaf_pulled.?;
    }

    // First 1024 bytes of the first layer (a few MB gzipped: the range is
    // guaranteed in-bounds).
    const layer = leaf.manifest.manifest.layers[0];
    var part = try c.pullBlobStreamPartial(io, ref, layer.digest, 0, 1024);
    defer part.deinit();
    try std.testing.expect(part.response == .partial);
    const pstream = part.response.partial;
    var pbuf: [1024]u8 = undefined;
    var got: usize = 0;
    while (got < pbuf.len) {
        const n = try pstream.reader.readSliceShort(pbuf[got..]);
        if (n == 0) break;
        got += n;
    }
    try std.testing.expectEqual(@as(usize, 1024), got);
}

test "smoke: list tags for library/alpine on Docker Hub" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    var arena = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena.deinit();
    const a = arena.allocator();

    var threaded = std.Io.Threaded.init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var c = client.Client.init(a, .{ .protocol = .https });
    defer c.deinit();

    // listTags uses only the reference's registry + repository (the digest
    // on the pinned ref is irrelevant to tags/list).
    const ref = try smokeReference(a);
    const creds = try setupAuth(&c, io, a, ref);
    const tags = try c.listTags(io, ref, creds, null, null);
    // listTags allocates from the Client's allocator — here an arena — so
    // the returned slice and tag strings die with the arena (no explicit
    // free, mirroring the integration-test usage).

    var has_320 = false;
    for (tags) |t| {
        if (std.mem.eql(u8, t, "3.20")) has_320 = true;
    }
    try std.testing.expect(tags.len > 0);
    try std.testing.expect(has_320);
}
