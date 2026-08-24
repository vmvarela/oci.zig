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

test "Tier 2 write path against zot" {
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

    // Unique suffix per run so re-runs never collide with prior content.
    const ts = std.Io.Timestamp.toSeconds(std.Io.Clock.real.now(io));
    var prng = std.Random.DefaultPrng.init(@intCast(ts));

    // --- pushBlob round-trip: 1 MiB random ---
    {
        const ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/wblob-{d}", .{ registry, ts }));
        const data = try a.alloc(u8, 1_048_576);
        prng.random().bytes(data);
        const digest = try c.pushBlob(io, ref, .anonymous, data);
        var aw = std.Io.Writer.Allocating.init(a);
        defer aw.deinit();
        try c.pullBlob(io, ref, digest, &aw.writer);
        try std.testing.expectEqualSlices(u8, data, aw.written());
        var h: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data, &h, .{});
        const hex = std.fmt.bytesToHex(h, .lower);
        try std.testing.expectEqualStrings(try std.fmt.allocPrint(a, "sha256:{s}", .{&hex}), digest);
    }

    // --- pushBlobStream: 5 MiB (forces >=2 PATCH chunks) + empty blob ---
    {
        const ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/wstream-{d}", .{ registry, ts }));
        const data5 = try a.alloc(u8, 5 * 1_048_576);
        prng.random().bytes(data5);
        const d5 = try c.pushBlobStream(io, ref, .anonymous, std.Io.Reader.fixed(data5), data5.len);
        var aw = std.Io.Writer.Allocating.init(a);
        defer aw.deinit();
        try c.pullBlob(io, ref, d5, &aw.writer);
        try std.testing.expectEqualSlices(u8, data5, aw.written());

        // Empty blob: no PATCHes, finalize only.
        const empty = try c.pushBlobStream(io, ref, .anonymous, std.Io.Reader.fixed(&.{}), 0);
        try std.testing.expectEqualStrings("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", empty);
        var aw2 = std.Io.Writer.Allocating.init(a);
        defer aw2.deinit();
        try c.pullBlob(io, ref, empty, &aw2.writer);
        try std.testing.expectEqual(@as(usize, 0), aw2.written().len);
    }

    // --- pushManifest + write-parity: DCD == our canonical digest ---
    // zot validates that referenced blobs exist IN the manifest's repo, so
    // config + layer are pushed into the same repository as the manifest.
    const man_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/wman-{d}:write-{d}", .{ registry, ts, ts }));
    const cfg_digest = try c.pushBlob(io, man_ref, .anonymous, config_fixture);
    const layer_small = try a.alloc(u8, 64 * 1024);
    prng.random().bytes(layer_small);
    const layer_digest = try c.pushBlob(io, man_ref, .anonymous, layer_small);

    const man_layers = try a.alloc(manifest.OciDescriptor, 1);
    man_layers[0] = .{ .media_type = manifest.oci_layer, .digest = layer_digest, .size = layer_small.len };
    const man = manifest.OciImageManifest{
        .schema_version = 2,
        .media_type = manifest.oci_manifest,
        .config = .{ .media_type = manifest.oci_config, .digest = cfg_digest, .size = config_fixture.len },
        .layers = man_layers,
    };
    const pushed = try c.pushManifest(io, man_ref, .anonymous, &.{ .manifest = man });
    const dcd = try c.fetchManifestDigest(io, man_ref, .anonymous);
    // Parity proof: zot's Docker-Content-Digest is the sha256 of the exact
    // canonical bytes we sent; our locally computed canonical digest must
    // equal it. pushManifest's returned value is the registry Location,
    // which carries that digest as its final path component.
    const local_value = try manifestToValue(a, man);
    const local_digest = try canonical_json.digestString(a, local_value);
    try std.testing.expectEqualStrings(local_digest, dcd);
    try std.testing.expect(std.mem.endsWith(u8, pushed, dcd));
    const back = try c.pullManifest(io, man_ref, .anonymous);
    try std.testing.expectEqualStrings(cfg_digest, back.manifest.manifest.config.?.digest);
    try std.testing.expectEqualStrings(layer_digest, back.manifest.manifest.layers[0].digest);

    // --- pushManifestRaw: same canonical bytes, raw content-type ---
    const raw_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/wman-{d}:raw-{d}", .{ registry, ts, ts }));
    const canonical_body = try canonical_json.stringify(a, local_value);
    const raw_pushed = try c.pushManifestRaw(io, raw_ref, .anonymous, canonical_body, manifest.oci_manifest);
    const raw_dcd = try c.fetchManifestDigest(io, raw_ref, .anonymous);
    try std.testing.expectEqualStrings(dcd, raw_dcd);
    try std.testing.expect(std.mem.endsWith(u8, raw_pushed, raw_dcd));

    // --- pushManifestList: index referencing the pushed manifest ---
    const idx_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/wman-{d}:idx-{d}", .{ registry, ts, ts }));
    const idx_manifests = try a.alloc(manifest.OciDescriptor, 1);
    idx_manifests[0] = .{ .media_type = manifest.oci_manifest, .digest = dcd, .size = canonical_body.len };
    const index = manifest.OciImageIndex{
        .schema_version = 2,
        .media_type = manifest.oci_index,
        .manifests = idx_manifests,
    };
    const idx_pushed = try c.pushManifestList(io, idx_ref, .anonymous, &index);
    const idx_back = try c.pullManifest(io, idx_ref, .anonymous);
    try std.testing.expect(idx_back.manifest.isIndex());
    try std.testing.expectEqualStrings(manifest.oci_index, idx_back.manifest.mediaType().?);
    try std.testing.expectEqualStrings(dcd, idx_back.manifest.index.manifests[0].digest);
    try std.testing.expect(std.mem.endsWith(u8, idx_pushed, idx_back.digest));

    // --- push wrapper: build manifest from config + two layers ---
    {
        const push_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/wpush-{d}:write-{d}", .{ registry, ts, ts }));
        const lay_a = try a.alloc(u8, 32 * 1024);
        prng.random().bytes(lay_a);
        const lay_b = try a.alloc(u8, 64 * 1024);
        prng.random().bytes(lay_b);
        const res = try c.push(io, push_ref, .anonymous, null, config_fixture, &.{ lay_a, lay_b });
        const push_dcd = try c.fetchManifestDigest(io, push_ref, .anonymous);
        try std.testing.expect(std.mem.endsWith(u8, res.manifest_digest, push_dcd));
        const mc = try c.pullManifestAndConfig(io, push_ref, .anonymous);
        try std.testing.expectEqualStrings(config_digest, mc.config_digest);
        try std.testing.expectEqualSlices(u8, config_fixture, mc.config);
        try std.testing.expectEqual(@as(usize, 2), mc.manifest.layers.len);
    }

    // --- mountBlob: push to source repo, mount into target repo ---
    {
        const src_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/wsrc-{d}", .{ registry, ts }));
        const dst_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/wdst-{d}", .{ registry, ts }));
        const data = try a.alloc(u8, 128 * 1024);
        prng.random().bytes(data);
        const digest = try c.pushBlob(io, src_ref, .anonymous, data);
        try c.mountBlob(io, dst_ref, .anonymous, src_ref, digest);
        var aw = std.Io.Writer.Allocating.init(a);
        defer aw.deinit();
        try c.pullBlob(io, dst_ref, digest, &aw.writer);
        try std.testing.expectEqualSlices(u8, data, aw.written());
    }

    // --- error paths: no crash ---
    {
        // mountBlob with a never-pushed digest: any error is acceptable.
        const ghost = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        const dst_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/wdst-{d}", .{ registry, ts }));
        const src_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/wsrc-{d}", .{ registry, ts }));
        if (c.mountBlob(io, dst_ref, .anonymous, src_ref, ghost)) |_| {
            return error.TestUnexpectedResult;
        } else |_| {}

        // docker-schema2 media type: zot 415s -> MANIFEST_INVALID -> InvalidManifest.
        const bad_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/wman-{d}:bad-{d}", .{ registry, ts, ts }));
        const bad_layers = try a.alloc(manifest.OciDescriptor, 1);
        bad_layers[0] = .{ .media_type = manifest.docker_layer_gzip, .digest = layer_digest, .size = layer_small.len };
        const bad_man = manifest.OciImageManifest{
            .schema_version = 2,
            .media_type = manifest.docker_manifest_v2,
            .config = .{ .media_type = manifest.docker_config, .digest = cfg_digest, .size = config_fixture.len },
            .layers = bad_layers,
        };
        try std.testing.expectError(error.InvalidManifest, c.pushManifest(io, bad_ref, .anonymous, &.{ .manifest = bad_man }));
    }
}

test "Tier 3 admin/misc against zot" {
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

    // Unique suffix per run so re-runs never collide with prior content.
    const ts = std.Io.Timestamp.toSeconds(std.Io.Clock.real.now(io));
    var prng = std.Random.DefaultPrng.init(@intCast(ts));

    // --- catalog: full listing contains testrepo + this run's repo ---
    {
        const cat_repo = try std.fmt.allocPrint(a, "wcat-{d}", .{ts});
        const cat_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/{s}:x", .{ registry, cat_repo }));
        // Deterministic membership: push a blob so the repo exists in this run.
        const seed = try a.alloc(u8, 4096);
        prng.random().bytes(seed);
        _ = try c.pushBlob(io, cat_ref, .anonymous, seed);

        const test_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/testrepo:v1", .{registry}));
        const repos = try c.catalog(io, test_ref, .anonymous, null, null);
        var has_testrepo = false;
        var has_cat_repo = false;
        for (repos) |r| {
            if (std.mem.eql(u8, r, "testrepo")) has_testrepo = true;
            if (std.mem.eql(u8, r, cat_repo)) has_cat_repo = true;
        }
        try std.testing.expect(has_testrepo);
        try std.testing.expect(has_cat_repo);

        // --- catalog pagination walk: n=1, resume via last, bounded ---
        // Termination: at most one page per repo plus one final empty page;
        // a duplicate would mean the registry ignored `last`.
        const max_pages = repos.len + 2;
        var seen = std.StringHashMap(void).init(a);
        var last: ?[]const u8 = null;
        var pages: usize = 0;
        while (pages < max_pages) : (pages += 1) {
            const page = try c.catalog(io, test_ref, .anonymous, 1, last);
            if (page.len == 0) break;
            if (seen.contains(page[0])) return error.TestUnexpectedResult; // dup = bad pagination
            try seen.put(page[0], {});
            last = page[0];
        }
        try std.testing.expect(pages < max_pages); // terminated via empty page, not the cap
        // The walk's union covers the full listing.
        for (repos) |r| try std.testing.expect(seen.contains(r));
    }

    // --- blobExists: present blob true, never-pushed digest false ---
    {
        const ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/wexist-{d}", .{ registry, ts }));
        const data = try a.alloc(u8, 128 * 1024);
        prng.random().bytes(data);
        const digest = try c.pushBlob(io, ref, .anonymous, data);
        try std.testing.expect(try c.blobExists(io, ref, .anonymous, digest));
        const ghost = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        try std.testing.expect(!try c.blobExists(io, ref, .anonymous, ghost));
    }

    // --- referrers native path with artifactType filter ---
    {
        const man_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/wref-{d}:main-{d}", .{ registry, ts, ts }));
        const cfg_digest = try c.pushBlob(io, man_ref, .anonymous, config_fixture);
        const layer = try a.alloc(u8, 64 * 1024);
        prng.random().bytes(layer);
        const layer_digest = try c.pushBlob(io, man_ref, .anonymous, layer);
        const man_layers = try a.alloc(manifest.OciDescriptor, 1);
        man_layers[0] = .{ .media_type = manifest.oci_layer, .digest = layer_digest, .size = layer.len };
        const man = manifest.OciImageManifest{
            .schema_version = 2,
            .media_type = manifest.oci_manifest,
            .config = .{ .media_type = manifest.oci_config, .digest = cfg_digest, .size = config_fixture.len },
            .layers = man_layers,
        };
        const main_value = try manifestToValue(a, man);
        const main_body = try canonical_json.stringify(a, main_value);
        const main_digest = try canonical_json.digestString(a, main_value);
        _ = try c.pushManifest(io, man_ref, .anonymous, &.{ .manifest = man });
        try std.testing.expectEqualStrings(main_digest, try c.fetchManifestDigest(io, man_ref, .anonymous));

        // Referrer: artifact manifest (empty '{}' config, zero layers) with
        // artifactType + subject = the pushed manifest's digest. Built as a
        // real OciImageManifest so pushManifest's canonical serialization
        // (jsonStringify emits artifactType/subject) is what zot hashes.
        const empty_blob = "{}";
        const empty_digest = try c.pushBlob(io, man_ref, .anonymous, empty_blob);
        const ref_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/wref-{d}:ref-{d}", .{ registry, ts, ts }));
        const referrer = manifest.OciImageManifest{
            .schema_version = 2,
            .media_type = manifest.oci_manifest,
            .artifact_type = "application/vnd.example.sbom.v1",
            .config = .{ .media_type = manifest.oci_config, .digest = empty_digest, .size = empty_blob.len },
            .layers = &.{},
            .subject = .{ .media_type = manifest.oci_manifest, .digest = main_digest, .size = main_body.len },
        };
        _ = try c.pushManifest(io, ref_ref, .anonymous, &.{ .manifest = referrer });
        const referrer_digest = try c.fetchManifestDigest(io, ref_ref, .anonymous);

        const digest_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/wref-{d}@{s}", .{ registry, ts, main_digest }));
        const sbom_refs = try c.pullReferrers(io, digest_ref, .anonymous, "application/vnd.example.sbom.v1");
        try std.testing.expectEqual(@as(usize, 1), sbom_refs.len);
        try std.testing.expectEqualStrings("application/vnd.example.sbom.v1", sbom_refs[0].artifact_type orelse return error.TestUnexpectedResult);
        try std.testing.expectEqualStrings(referrer_digest, sbom_refs[0].digest);
        // Server-side filter for a media type that is not the referrer's.
        // Pins zot's SERVER-SIDE artifactType filtering (ci.yml pins zot
        // v2.1.20). The client's native path does not client-filter (upstream
        // parity); on a zot upgrade, re-verify server-side filtering before
        // trusting green.
        const image_refs = try c.pullReferrers(io, digest_ref, .anonymous, "application/vnd.oci.image.manifest.v1+json");
        try std.testing.expectEqual(@as(usize, 0), image_refs.len);
    }

    // --- platform resolution via pull(): index -> linux/amd64 child ---
    {
        // The pull() default resolver (linuxAmd64Resolver) is pinned at
        // client.zig via `orelse`; CI is linux/amd64, so a future default
        // change would otherwise pass CI silently.
        try std.testing.expectEqual(@as(?*const fn ([]const manifest.OciDescriptor) ?[]const u8, null), c.config.platform_resolver);

        // Manifest A: linux/amd64 (config_fixture). Manifest B: windows/amd64
        // (distinct empty config so the resolved config digest is unambiguous).
        const plat_ref_a = try reference.parse(try std.fmt.allocPrint(a, "{s}/wplat-{d}:a-{d}", .{ registry, ts, ts }));
        const cfg_digest_a = try c.pushBlob(io, plat_ref_a, .anonymous, config_fixture);
        const lay_a = try a.alloc(u8, 64 * 1024);
        prng.random().bytes(lay_a);
        const lay_a_digest = try c.pushBlob(io, plat_ref_a, .anonymous, lay_a);
        const man_a_layers = try a.alloc(manifest.OciDescriptor, 1);
        man_a_layers[0] = .{ .media_type = manifest.oci_layer, .digest = lay_a_digest, .size = lay_a.len };
        const man_a = manifest.OciImageManifest{
            .schema_version = 2,
            .media_type = manifest.oci_manifest,
            .config = .{ .media_type = manifest.oci_config, .digest = cfg_digest_a, .size = config_fixture.len },
            .layers = man_a_layers,
        };
        _ = try c.pushManifest(io, plat_ref_a, .anonymous, &.{ .manifest = man_a });
        const digest_a = try c.fetchManifestDigest(io, plat_ref_a, .anonymous);
        const body_a = try canonical_json.stringify(a, try manifestToValue(a, man_a));

        const plat_ref_b = try reference.parse(try std.fmt.allocPrint(a, "{s}/wplat-{d}:b-{d}", .{ registry, ts, ts }));
        const cfg_b = "{}";
        const cfg_digest_b = try c.pushBlob(io, plat_ref_b, .anonymous, cfg_b);
        const lay_b = try a.alloc(u8, 64 * 1024);
        prng.random().bytes(lay_b);
        const lay_b_digest = try c.pushBlob(io, plat_ref_b, .anonymous, lay_b);
        const man_b_layers = try a.alloc(manifest.OciDescriptor, 1);
        man_b_layers[0] = .{ .media_type = manifest.oci_layer, .digest = lay_b_digest, .size = lay_b.len };
        const man_b = manifest.OciImageManifest{
            .schema_version = 2,
            .media_type = manifest.oci_manifest,
            .config = .{ .media_type = manifest.oci_config, .digest = cfg_digest_b, .size = cfg_b.len },
            .layers = man_b_layers,
        };
        _ = try c.pushManifest(io, plat_ref_b, .anonymous, &.{ .manifest = man_b });
        const digest_b = try c.fetchManifestDigest(io, plat_ref_b, .anonymous);
        const body_b = try canonical_json.stringify(a, try manifestToValue(a, man_b));

        const idx_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/wplat-{d}:idx-{d}", .{ registry, ts, ts }));
        const idx_manifests = try a.alloc(manifest.OciDescriptor, 2);
        idx_manifests[0] = .{ .media_type = manifest.oci_manifest, .digest = digest_a, .size = body_a.len, .platform = .{ .architecture = "amd64", .os = "linux" } };
        idx_manifests[1] = .{ .media_type = manifest.oci_manifest, .digest = digest_b, .size = body_b.len, .platform = .{ .architecture = "amd64", .os = "windows" } };
        const index = manifest.OciImageIndex{
            .schema_version = 2,
            .media_type = manifest.oci_index,
            .manifests = idx_manifests,
        };
        _ = try c.pushManifestList(io, idx_ref, .anonymous, &index);

        // Default resolver (linuxAmd64Resolver) must pick manifest A.
        const accepted = [_][]const u8{ manifest.oci_manifest, manifest.oci_index };
        const data = try c.pull(io, idx_ref, .anonymous, &accepted);
        try std.testing.expectEqualStrings(manifest.oci_manifest, data.manifest.mediaType() orelse return error.TestUnexpectedResult);
        try std.testing.expectEqualStrings(cfg_digest_a, (data.manifest.manifest.config orelse return error.TestUnexpectedResult).digest);
        try std.testing.expectEqualStrings(lay_a_digest, data.manifest.manifest.layers[0].digest);
        try std.testing.expectEqualSlices(u8, config_fixture, data.config orelse return error.TestUnexpectedResult);
    }
}

test "deleteManifest against zot" {
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

    const ts = std.Io.Timestamp.toSeconds(std.Io.Clock.real.now(io));
    var prng = std.Random.DefaultPrng.init(@intCast(ts));

    // Push a manifest under a unique tag, then delete it by tag.
    const man_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/wdel-{d}:del-{d}", .{ registry, ts, ts }));
    const cfg_digest = try c.pushBlob(io, man_ref, .anonymous, config_fixture);
    const layer = try a.alloc(u8, 64 * 1024);
    prng.random().bytes(layer);
    const layer_digest = try c.pushBlob(io, man_ref, .anonymous, layer);
    const man_layers = try a.alloc(manifest.OciDescriptor, 1);
    man_layers[0] = .{ .media_type = manifest.oci_layer, .digest = layer_digest, .size = layer.len };
    const man = manifest.OciImageManifest{
        .schema_version = 2,
        .media_type = manifest.oci_manifest,
        .config = .{ .media_type = manifest.oci_config, .digest = cfg_digest, .size = config_fixture.len },
        .layers = man_layers,
    };
    _ = try c.pushManifest(io, man_ref, .anonymous, &.{ .manifest = man });
    try std.testing.expectEqualStrings(cfg_digest, (try c.pullManifest(io, man_ref, .anonymous)).manifest.manifest.config.?.digest);

    // Delete by tag: succeeds, then the manifest is gone (404).
    try c.deleteManifest(io, man_ref, .anonymous);
    try std.testing.expectError(error.NotFound, c.pullManifest(io, man_ref, .anonymous));
    // Deleting again is idempotent: 404, not a hard failure.
    try std.testing.expectError(error.NotFound, c.deleteManifest(io, man_ref, .anonymous));

    // Delete by digest: push a second manifest, resolve its digest, delete it.
    const dig_ref = try reference.parse(try std.fmt.allocPrint(a, "{s}/wdel-{d}:dig-{d}", .{ registry, ts, ts }));
    _ = try c.pushManifest(io, dig_ref, .anonymous, &.{ .manifest = man });
    const digest = try c.fetchManifestDigest(io, dig_ref, .anonymous);
    const by_digest = try reference.parse(try std.fmt.allocPrint(a, "{s}/wdel-{d}@{s}", .{ registry, ts, digest }));
    try c.deleteManifest(io, by_digest, .anonymous);
    try std.testing.expectError(error.NotFound, c.pullManifest(io, by_digest, .anonymous));
}
