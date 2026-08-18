//! OCI manifest / index types and parsing.
//!
//! This module is deliberately independent of ocispec's enum-typed
//! `image.MediaType` / `image.Descriptor` (research decision, SPEC §13):
//! media types are plain `[]const u8` strings so Docker legacy (schema2,
//! container config, layer gzip) and WASM variants survive. ocispec's
//! MediaType maps those to `.Other`, which would lose the original string.
//! `digest` is likewise a plain string, matching the client's string-based
//! digests.
//!
//! JSON wire names are camelCase (mediaType, schemaVersion, ...) per the OCI
//! spec; Zig fields are snake_case. std.json 0.16 matches JSON keys to Zig
//! field names verbatim (no auto-rename), so parsing goes through private
//! camelCase "wire" mirror structs that std.json handles natively, and the
//! public snake_case structs convert to/from them. Public structs serialize
//! via `jsonStringify`; JSON documents are parsed with `OciManifest.parse`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const json = std.json;

// ---- media type constants ----

/// OCI image manifest (image-spec).
pub const oci_manifest = "application/vnd.oci.image.manifest.v1+json";
/// OCI image index (image-spec).
pub const oci_index = "application/vnd.oci.image.index.v1+json";
/// OCI image configuration.
pub const oci_config = "application/vnd.oci.image.config.v1+json";
/// OCI uncompressed layer.
pub const oci_layer = "application/vnd.oci.image.layer.v1.tar";
/// OCI gzip-compressed layer.
pub const oci_layer_gzip = "application/vnd.oci.image.layer.v1.tar+gzip";
/// OCI zstd-compressed layer.
pub const oci_layer_zstd = "application/vnd.oci.image.layer.v1.tar+zstd";
/// OCI artifact manifest.
pub const oci_artifact = "application/vnd.oci.artifact.manifest.v1+json";

/// Docker Distribution schema2 manifest.
pub const docker_manifest_v2 = "application/vnd.docker.distribution.manifest.v2+json";
/// Docker manifest list (schema2).
pub const docker_manifest_list = "application/vnd.docker.distribution.manifest.list.v2+json";
/// Docker container image configuration.
pub const docker_config = "application/vnd.docker.container.image.v1+json";
/// Docker gzip-compressed layer.
pub const docker_layer_gzip = "application/vnd.docker.image.rootfs.diff.tar.gzip";
/// Docker foreign (non-distributable) layer.
pub const docker_foreign_layer = "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip";

/// WASM image configuration.
pub const wasm_config = "application/vnd.wasm.config.v1+json";
/// WASM content layer.
pub const wasm_layer = "application/vnd.wasm.content.layer.v1+wasm";

// ---- wire mirror structs (camelCase JSON shape, std.json default handling) ----

const WirePlatform = struct {
    architecture: []const u8,
    os: []const u8,
    osVersion: ?[]const u8 = null,
    osFeatures: ?[][]const u8 = null,
    variant: ?[]const u8 = null,
    features: ?[][]const u8 = null,
};

const WireDescriptor = struct {
    mediaType: []const u8,
    digest: []const u8,
    size: u64,
    urls: ?[][]const u8 = null,
    annotations: ?json.ArrayHashMap([]const u8) = null,
    platform: ?WirePlatform = null,
    artifactType: ?[]const u8 = null,
};

const WireManifest = struct {
    schemaVersion: u32 = 2,
    mediaType: ?[]const u8 = null,
    artifactType: ?[]const u8 = null,
    config: ?WireDescriptor = null,
    layers: ?[]WireDescriptor = null,
    subject: ?WireDescriptor = null,
    annotations: ?json.ArrayHashMap([]const u8) = null,
};

const WireIndex = struct {
    schemaVersion: u32 = 2,
    mediaType: ?[]const u8 = null,
    artifactType: ?[]const u8 = null,
    manifests: []WireDescriptor,
    subject: ?WireDescriptor = null,
    annotations: ?json.ArrayHashMap([]const u8) = null,
};

// ---- public types ----

/// Minimum runtime requirements of an image. Architecture and OS are plain
/// strings: Docker uses "arm64"/"linux" while ocispec's `image.Arch` is an
/// enum that would reject unknown values.
pub const OciPlatform = struct {
    architecture: []const u8,
    os: []const u8,
    os_version: ?[]const u8 = null,
    os_features: ?[][]const u8 = null,
    variant: ?[]const u8 = null,
    features: ?[][]const u8 = null,

    pub fn jsonStringify(self: *const OciPlatform, jws: anytype) !void {
        try jws.beginObject();
        try jws.objectField("architecture");
        try jws.write(self.architecture);
        try jws.objectField("os");
        try jws.write(self.os);
        try jws.objectField("osVersion");
        try jws.write(self.os_version);
        try jws.objectField("osFeatures");
        try jws.write(self.os_features);
        try jws.objectField("variant");
        try jws.write(self.variant);
        try jws.objectField("features");
        try jws.write(self.features);
        try jws.endObject();
    }
};

/// Content descriptor. String media types (not ocispec enum) so Docker and
/// WASM values survive parsing.
pub const OciDescriptor = struct {
    media_type: []const u8,
    digest: []const u8,
    size: u64,
    urls: ?[][]const u8 = null,
    annotations: ?json.ArrayHashMap([]const u8) = null,
    platform: ?OciPlatform = null,
    artifact_type: ?[]const u8 = null,

    pub fn jsonStringify(self: *const OciDescriptor, jws: anytype) !void {
        try jws.beginObject();
        try jws.objectField("mediaType");
        try jws.write(self.media_type);
        try jws.objectField("digest");
        try jws.write(self.digest);
        try jws.objectField("size");
        try jws.write(self.size);
        try jws.objectField("urls");
        try jws.write(self.urls);
        try jws.objectField("annotations");
        try jws.write(self.annotations);
        try jws.objectField("platform");
        try jws.write(self.platform);
        try jws.objectField("artifactType");
        try jws.write(self.artifact_type);
        try jws.endObject();
    }
};

/// Single-platform image manifest. `config` is optional because OCI 1.1
/// artifact manifests may omit it; `layers` stays required.
pub const OciImageManifest = struct {
    schema_version: u32 = 2,
    media_type: ?[]const u8 = null,
    artifact_type: ?[]const u8 = null,
    config: ?OciDescriptor = null,
    layers: []OciDescriptor,
    subject: ?OciDescriptor = null,
    annotations: ?json.ArrayHashMap([]const u8) = null,

    pub fn jsonStringify(self: *const OciImageManifest, jws: anytype) !void {
        try jws.beginObject();
        try jws.objectField("schemaVersion");
        try jws.write(self.schema_version);
        try jws.objectField("mediaType");
        try jws.write(self.media_type);
        try jws.objectField("artifactType");
        try jws.write(self.artifact_type);
        try jws.objectField("config");
        try jws.write(self.config);
        try jws.objectField("layers");
        try jws.write(self.layers);
        try jws.objectField("subject");
        try jws.write(self.subject);
        try jws.objectField("annotations");
        try jws.write(self.annotations);
        try jws.endObject();
    }
};

/// Multi-platform image index.
pub const OciImageIndex = struct {
    schema_version: u32 = 2,
    media_type: ?[]const u8 = null,
    artifact_type: ?[]const u8 = null,
    manifests: []OciDescriptor,
    subject: ?OciDescriptor = null,
    annotations: ?json.ArrayHashMap([]const u8) = null,

    pub fn jsonStringify(self: *const OciImageIndex, jws: anytype) !void {
        try jws.beginObject();
        try jws.objectField("schemaVersion");
        try jws.write(self.schema_version);
        try jws.objectField("mediaType");
        try jws.write(self.media_type);
        try jws.objectField("artifactType");
        try jws.write(self.artifact_type);
        try jws.objectField("manifests");
        try jws.write(self.manifests);
        try jws.objectField("subject");
        try jws.write(self.subject);
        try jws.objectField("annotations");
        try jws.write(self.annotations);
        try jws.endObject();
    }
};

/// Parsed manifest document: either a single-platform manifest or an index.
pub const OciManifest = union(enum) {
    manifest: OciImageManifest,
    index: OciImageIndex,

    /// Parses a manifest or index document. Media type is used to pick the
    /// branch; when absent (some registries omit it) the structure decides:
    /// a document with a "manifests" array is an index, anything else parses
    /// as a manifest (config/layers may be absent for OCI 1.1 artifact
    /// manifests). All strings and slices in the result are owned by
    /// `allocator` — pass an arena whose lifetime covers the result.
    pub fn parse(allocator: Allocator, bytes: []const u8) !OciManifest {
        const opts = json.ParseOptions{ .allocate = .alloc_always, .ignore_unknown_fields = true };
        const peek = try json.parseFromSliceLeaky(
            struct { mediaType: ?[]const u8 = null },
            allocator,
            bytes,
            .{ .ignore_unknown_fields = true },
        );
        switch (classify(peek.mediaType orelse "")) {
            .manifest => return .{ .manifest = try manifestFromWire(allocator, try json.parseFromSliceLeaky(WireManifest, allocator, bytes, opts)) },
            .index => return .{ .index = try indexFromWire(allocator, try json.parseFromSliceLeaky(WireIndex, allocator, bytes, opts)) },
            .unknown => {
                // No recognizable media type: the "manifests" key is the only
                // reliable structural discriminator left.
                if (json.parseFromSliceLeaky(WireIndex, allocator, bytes, opts)) |w| {
                    return .{ .index = try indexFromWire(allocator, w) };
                } else |err| switch (err) {
                    error.MissingField => {},
                    else => return err,
                }
                return .{ .manifest = try manifestFromWire(allocator, try json.parseFromSliceLeaky(WireManifest, allocator, bytes, opts)) };
            },
        }
    }

    /// Media type of the document (null if the registry omitted it).
    pub fn mediaType(m: OciManifest) ?[]const u8 {
        return switch (m) {
            .manifest => |v| v.media_type,
            .index => |v| v.media_type,
        };
    }

    pub fn isIndex(m: OciManifest) bool {
        return std.meta.activeTag(m) == .index;
    }

    pub fn jsonStringify(self: *const OciManifest, jws: anytype) !void {
        switch (self.*) {
            .manifest => |v| try jws.write(v),
            .index => |v| try jws.write(v),
        }
    }
};

// ---- wire <-> public conversion ----

fn platformFromWire(w: WirePlatform) OciPlatform {
    return .{
        .architecture = w.architecture,
        .os = w.os,
        .os_version = w.osVersion,
        .os_features = w.osFeatures,
        .variant = w.variant,
        .features = w.features,
    };
}

fn descriptorFromWire(w: WireDescriptor) OciDescriptor {
    return .{
        .media_type = w.mediaType,
        .digest = w.digest,
        .size = w.size,
        .urls = w.urls,
        .annotations = w.annotations,
        .platform = if (w.platform) |p| platformFromWire(p) else null,
        .artifact_type = w.artifactType,
    };
}

fn manifestFromWire(allocator: Allocator, w: WireManifest) !OciImageManifest {
    const wire_layers = w.layers orelse &[_]WireDescriptor{};
    const layers = try allocator.alloc(OciDescriptor, wire_layers.len);
    for (wire_layers, 0..) |l, i| layers[i] = descriptorFromWire(l);
    return .{
        .schema_version = w.schemaVersion,
        .media_type = w.mediaType,
        .artifact_type = w.artifactType,
        .config = if (w.config) |c| descriptorFromWire(c) else null,
        .layers = layers,
        .subject = if (w.subject) |s| descriptorFromWire(s) else null,
        .annotations = w.annotations,
    };
}

fn indexFromWire(allocator: Allocator, w: WireIndex) !OciImageIndex {
    const manifests = try allocator.alloc(OciDescriptor, w.manifests.len);
    for (w.manifests, 0..) |m, i| manifests[i] = descriptorFromWire(m);
    return .{
        .schema_version = w.schemaVersion,
        .media_type = w.mediaType,
        .artifact_type = w.artifactType,
        .manifests = manifests,
        .subject = if (w.subject) |s| descriptorFromWire(s) else null,
        .annotations = w.annotations,
    };
}

const Kind = enum { manifest, index, unknown };

fn classify(media_type: []const u8) Kind {
    if (std.mem.indexOf(u8, media_type, "index") != null or
        std.mem.indexOf(u8, media_type, "manifest.list") != null)
    {
        return .index;
    }
    if (std.mem.startsWith(u8, media_type, "application/vnd.oci.image.manifest") or
        std.mem.startsWith(u8, media_type, "application/vnd.docker.distribution.manifest.v2"))
    {
        return .manifest;
    }
    return .unknown;
}

// ---- tests ----

test {
    @import("std").testing.refAllDecls(@This());
}

/// tests/ lives outside the package path but src/fixtures symlinks to it,
/// so @embedFile resolves relative to this file.
const fixture_manifest = @embedFile("fixtures/manifest.json");

test "parse docker schema2 manifest fixture" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const m = try OciManifest.parse(a, fixture_manifest);
    try std.testing.expectEqual(Kind.manifest, classify(m.mediaType().?));
    try std.testing.expect(m.isIndex() == false);
    try std.testing.expectEqualStrings(docker_manifest_v2, m.mediaType().?);

    const man = m.manifest;
    try std.testing.expectEqual(@as(u32, 2), man.schema_version);
    try std.testing.expectEqualStrings(docker_config, man.config.?.media_type);
    try std.testing.expectEqualStrings("sha256:3f57d9401f8d42f986df300f0c69192fc41da28ccc8d797829467780db3dd741", man.config.?.digest);
    try std.testing.expectEqual(@as(u64, 581), man.config.?.size);
    try std.testing.expectEqual(@as(usize, 1), man.layers.len);
    try std.testing.expectEqualStrings(docker_layer_gzip, man.layers[0].media_type);
    try std.testing.expectEqualStrings("sha256:9ad63333ebc97e32b987ae66aa3cff81300e4c2e6d2f2395cef8a3ae18b249fe", man.layers[0].digest);
    try std.testing.expectEqual(@as(u64, 2220094), man.layers[0].size);
}

test "parse oci image index" {
    const doc =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.index.v1+json",
        \\  "manifests": [
        \\    {
        \\      "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\      "digest": "sha256:abc",
        \\      "size": 123,
        \\      "platform": { "architecture": "amd64", "os": "linux" }
        \\    }
        \\  ]
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const m = try OciManifest.parse(arena.allocator(), doc);
    try std.testing.expect(m.isIndex());
    try std.testing.expectEqualStrings(oci_index, m.mediaType().?);

    const idx = m.index;
    try std.testing.expectEqual(@as(usize, 1), idx.manifests.len);
    const d = idx.manifests[0];
    try std.testing.expectEqualStrings(oci_manifest, d.media_type);
    try std.testing.expectEqualStrings("sha256:abc", d.digest);
    try std.testing.expectEqual(@as(u64, 123), d.size);
    const plat = d.platform.?;
    try std.testing.expectEqualStrings("amd64", plat.architecture);
    try std.testing.expectEqualStrings("linux", plat.os);
}

test "parse oci image manifest" {
    const doc =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.oci.image.config.v1+json",
        \\    "digest": "sha256:config",
        \\    "size": 1
        \\  },
        \\  "layers": [
        \\    { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:layer", "size": 2 }
        \\  ]
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const m = try OciManifest.parse(arena.allocator(), doc);
    try std.testing.expect(m.isIndex() == false);
    try std.testing.expectEqualStrings(oci_manifest, m.mediaType().?);
    try std.testing.expectEqualStrings("sha256:config", m.manifest.config.?.digest);
    try std.testing.expectEqualStrings(oci_layer_gzip, m.manifest.layers[0].media_type);
}

test "parse oci artifact manifest without config" {
    const doc =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.artifact.manifest.v1+json",
        \\  "blobs": [
        \\    { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:blob", "size": 42 }
        \\  ]
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const m = try OciManifest.parse(arena.allocator(), doc);
    try std.testing.expect(m.isIndex() == false);
    try std.testing.expectEqualStrings(oci_artifact, m.mediaType().?);
    try std.testing.expect(m.manifest.config == null);
    try std.testing.expectEqual(@as(usize, 0), m.manifest.layers.len);
}

test "parse with media type absent falls back to structure" {
    const index_doc =
        \\{
        \\  "schemaVersion": 2,
        \\  "manifests": [
        \\    { "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:x", "size": 1 }
        \\  ]
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const m = try OciManifest.parse(a, index_doc);
    try std.testing.expect(m.isIndex());
    try std.testing.expect(m.mediaType() == null);

    const manifest_doc =
        \\{
        \\  "schemaVersion": 2,
        \\  "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:c", "size": 1 },
        \\  "layers": []
        \\}
    ;
    const m2 = try OciManifest.parse(a, manifest_doc);
    try std.testing.expect(m2.isIndex() == false);
    try std.testing.expect(m2.mediaType() == null);
}

test "round-trip stringify and re-parse" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const m = try OciManifest.parse(a, fixture_manifest);
    const s = try json.Stringify.valueAlloc(a, m, .{});
    const m2 = try OciManifest.parse(a, s);

    try std.testing.expectEqualStrings(m.mediaType().?, m2.mediaType().?);
    try std.testing.expectEqualStrings(m.manifest.config.?.digest, m2.manifest.config.?.digest);
    try std.testing.expectEqual(m.manifest.config.?.size, m2.manifest.config.?.size);
    try std.testing.expectEqualStrings(m.manifest.layers[0].digest, m2.manifest.layers[0].digest);
}
