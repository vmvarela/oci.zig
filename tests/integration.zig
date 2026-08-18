//! Integration tests for the Tier 1 OCI client against a running zot
//! registry. Requires test content pushed by tests/setup.sh. The registry
//! URL comes from OCI_TEST_REGISTRY (default http://127.0.0.1:5000).
//!
//! These tests hit the network and are NOT part of `zig build test`; run
//! them with `zig build integration-test`.

const std = @import("std");
const oci = @import("oci");
const client = oci.client;
const manifest = oci.manifest;
const reference = oci.reference;
const secrets = oci.secrets;
const token_cache = oci.token_cache;
const canonical_json = oci.canonical_json;
const blob = oci.blob;

const config_fixture = @embedFile("fixtures/config.json");

/// Deterministic: config.json is a fixed fixture.
const config_digest = "sha256:3f57d9401f8d42f986df300f0c69192fc41da28ccc8d797829467780db3dd741";
const layer_size: u64 = 1048576;

/// Registry host:port (no scheme) from OCI_TEST_REGISTRY, or the default.
fn registryHost(allocator: std.mem.Allocator) ![]const u8 {
    const env = if (std.c.getenv("OCI_TEST_REGISTRY")) |ptr| blk: {
        const len = std.mem.len(ptr);
        break :blk ptr[0..len];
    } else "127.0.0.1:5000";
    if (std.mem.indexOf(u8, env, "://")) |i| {
        return allocator.dupe(u8, env[i + 3 ..]);
    }
    return allocator.dupe(u8, env);
}

/// Builds the canonical-form std.json.Value of a single-platform manifest
/// (config, layers, mediaType, schemaVersion) for the canonical-JSON parity
/// check.
fn manifestToValue(allocator: std.mem.Allocator, man: manifest.OciImageManifest) !std.json.Value {
    var obj = std.json.ObjectMap.empty;
    var cfg = std.json.ObjectMap.empty;
    try cfg.put(allocator, "digest", .{ .string = man.config.?.digest });
    try cfg.put(allocator, "mediaType", .{ .string = man.config.?.media_type });
    try cfg.put(allocator, "size", .{ .integer = @intCast(man.config.?.size) });
    try obj.put(allocator, "config", .{ .object = cfg });
    var layers = std.json.Array.init(allocator);
    for (man.layers) |l| {
        var ld = std.json.ObjectMap.empty;
        try ld.put(allocator, "digest", .{ .string = l.digest });
        try ld.put(allocator, "mediaType", .{ .string = l.media_type });
        try ld.put(allocator, "size", .{ .integer = @intCast(l.size) });
        try layers.append(.{ .object = ld });
    }
    try obj.put(allocator, "layers", .{ .array = layers });
    try obj.put(allocator, "mediaType", .{ .string = man.media_type.? });
    try obj.put(allocator, "schemaVersion", .{ .integer = man.schema_version });
    return .{ .object = obj };
}

test "Tier 1 client against zot" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    var threaded = std.Io.Threaded.init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const registry = try registryHost(a);
    var c = client.Client.init(a, .{ .protocol = .http });
    defer c.deinit();

    const v1_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/testrepo:v1", .{registry}));
    const canonical_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/testrepo:canonical", .{registry}));

    // --- pullManifest(v1): structure + deterministic config digest ---
    const v1 = try c.pullManifest(io, v1_ref, .anonymous);
    try std.testing.expectEqualStrings(manifest.oci_manifest, v1.manifest.mediaType().?);
    const v1man = v1.manifest.manifest;
    try std.testing.expectEqualStrings(config_digest, v1man.config.?.digest);
    try std.testing.expectEqual(layer_size, v1man.layers[0].size);

    // --- pullManifest(canonical) + canonical-JSON parity ---
    // zot's Docker-Content-Digest is over the exact bytes we pushed; our
    // canonical re-serialization of the parsed manifest must hash to the same
    // value. This proves canonical_json matches what a real registry hashed.
    const canonical = try c.pullManifest(io, canonical_ref, .anonymous);
    try std.testing.expectEqualStrings(manifest.oci_manifest, canonical.manifest.mediaType().?);
    const value = try manifestToValue(a, canonical.manifest.manifest);
    const re_digest = try canonical_json.digestString(a, value);
    try std.testing.expectEqualStrings(canonical.digest, re_digest);

    // --- fetchManifestDigest(canonical) ---
    const fetched = try c.fetchManifestDigest(io, canonical_ref, .anonymous);
    try std.testing.expectEqualStrings(canonical.digest, fetched);

    // --- pullManifestAndConfig(v1) ---
    const mc = try c.pullManifestAndConfig(io, v1_ref, .anonymous);
    try std.testing.expectEqualStrings(config_digest, mc.config_digest);
    try std.testing.expectEqualSlices(u8, config_fixture, mc.config);

    // --- pullBlob(layer): written bytes hash to the layer digest ---
    var aw = std.Io.Writer.Allocating.init(a);
    defer aw.deinit();
    try c.pullBlob(io, v1_ref, v1man.layers[0].digest, &aw.writer);
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(aw.written(), &h, .{});
    const hex = std.fmt.bytesToHex(h, .lower);
    const full = try std.fmt.allocPrint(a, "sha256:{s}", .{&hex});
    try std.testing.expectEqualStrings(v1man.layers[0].digest, full);

    // --- pullBlobStream(layer): read to EOF + finish() passes ---
    var bs = try c.pullBlobStream(io, v1_ref, v1man.layers[0].digest);
    defer bs.deinit();
    var buf: [32 * 1024]u8 = undefined;
    var total: usize = 0;
    while (true) {
        const n = try bs.stream.read(&buf);
        if (n == 0) break;
        total += n;
    }
    try std.testing.expectEqual(@as(usize, layer_size), total);
    try bs.stream.finish();

    // --- pullBlobStreamPartial(layer, 0, 1024): 206, 1024 bytes, full size ---
    var part = try c.pullBlobStreamPartial(io, v1_ref, v1man.layers[0].digest, 0, 1024);
    defer part.deinit();
    try std.testing.expect(part.response == .partial);
    const pstream = part.response.partial;
    try std.testing.expectEqual(layer_size, pstream.size);
    var pbuf: [1024]u8 = undefined;
    var got: usize = 0;
    while (true) {
        const n = try pstream.reader.readSliceShort(pbuf[got..]);
        if (n == 0) break;
        got += n;
    }
    try std.testing.expectEqual(@as(usize, 1024), got);

    // --- listTags: contains v1 and canonical ---
    const tags = try c.listTags(io, v1_ref, .anonymous, null, null);
    var has_v1 = false;
    var has_canonical = false;
    for (tags) |t| {
        if (std.mem.eql(u8, t, "v1")) has_v1 = true;
        if (std.mem.eql(u8, t, "canonical")) has_canonical = true;
    }
    try std.testing.expect(has_v1);
    try std.testing.expect(has_canonical);

    // --- pullReferrers(canonical): 1 sbom referrer whose subject is canonical ---
    const canonical_digest_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/testrepo@{s}", .{ registry, canonical.digest }));
    const refs = try c.pullReferrers(io, canonical_digest_ref, .anonymous, null);
    try std.testing.expectEqual(@as(usize, 1), refs.len);
    try std.testing.expectEqualStrings("application/vnd.example.sbom.v1", refs[0].artifact_type.?);
    const referrer_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/testrepo@{s}", .{ registry, refs[0].digest }));
    const referrer = try c.pullManifest(io, referrer_ref, .anonymous);
    try std.testing.expectEqualStrings(canonical.digest, referrer.manifest.manifest.subject.?.digest);

    // --- pull(v1): config content + 1 layer descriptor ---
    const accepted = [_][]const u8{ manifest.oci_manifest, manifest.oci_index };
    const data = try c.pull(io, v1_ref, .anonymous, &accepted);
    try std.testing.expectEqualSlices(u8, config_fixture, data.config.?);
    try std.testing.expectEqual(@as(usize, 1), data.layers.len);

    // --- auth() -> null (no auth configured on zot) ---
    const tok = try c.auth(io, v1_ref, .anonymous, .pull);
    try std.testing.expectEqual(@as(?[]const u8, null), tok);

    // --- resolvers ---
    try std.testing.expectEqual(@as(?[]const u8, null), client.linuxAmd64Resolver(refs));
    const synthetic = [_]manifest.OciDescriptor{
        .{ .media_type = manifest.oci_manifest, .digest = "sha256:amd", .size = 1, .platform = .{ .architecture = "amd64", .os = "linux" } },
    };
    try std.testing.expectEqualStrings("sha256:amd", client.linuxAmd64Resolver(&synthetic).?);

    // --- 404 path ---
    const missing_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/testrepo:nonexistent", .{registry}));
    try std.testing.expectError(error.NotFound, c.pullManifest(io, missing_ref, .anonymous));
}
