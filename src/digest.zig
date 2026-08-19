//! OCI digest type, digest response-header extraction, and digest validation
//! (mirror of rust-oci-client src/digest.rs: Digest, digest_header_value,
//! validate_digest).

const std = @import("std");

/// Supported digest algorithms.
pub const Algorithm = enum { sha256, sha384, sha512 };

/// Number of digest bytes produced by `a` (32/48/64).
pub fn digestLength(a: Algorithm) usize {
    return switch (a) {
        .sha256 => 32,
        .sha384 => 48,
        .sha512 => 64,
    };
}

/// A parsed digest: algorithm plus the raw (decoded) hash value held in a
/// fixed buffer to avoid allocation.
pub const Digest = struct {
    algorithm: Algorithm,
    value: [64]u8,
    len: usize,

    /// Builds a digest from a hex string of the exact expected length for
    /// `algorithm` (2 * digestLength characters).
    pub fn init(algorithm: Algorithm, hex_value: []const u8) error{InvalidDigest}!Digest {
        const want = digestLength(algorithm);
        if (hex_value.len != want * 2) return error.InvalidDigest;
        var value = [_]u8{0} ** 64;
        _ = std.fmt.hexToBytes(value[0..want], hex_value) catch return error.InvalidDigest;
        return .{ .algorithm = algorithm, .value = value, .len = want };
    }

    /// Writes "algo:hex" (e.g. "sha256:3f57...") to `writer`.
    pub fn format(self: Digest, writer: anytype) !void {
        const hex = std.fmt.bytesToHex(self.value, .lower);
        try writer.print("{s}:{s}", .{ @tagName(self.algorithm), hex[0 .. self.len * 2] });
    }

    /// Constant-time equality (algorithm + digest bytes).
    pub fn eql(a: Digest, b: Digest) bool {
        if (a.algorithm != b.algorithm or a.len != b.len) return false;
        return timingSafeEqlBytes(a.value[0..a.len], b.value[0..b.len]);
    }
};

/// Parses "algo:hex" (e.g. "sha256:3f57...") into a `Digest`.
pub fn parse(s: []const u8) error{InvalidDigest}!Digest {
    const colon = std.mem.indexOfScalar(u8, s, ':') orelse return error.InvalidDigest;
    const algorithm = std.meta.stringToEnum(Algorithm, s[0..colon]) orelse return error.InvalidDigest;
    return Digest.init(algorithm, s[colon + 1 ..]);
}

/// Extracts the `Docker-Content-Digest` header value (case-insensitive name
/// match), or null if absent.
pub fn digestHeaderValue(headers: []const std.http.Header) ?[]const u8 {
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "docker-content-digest")) return h.value;
    }
    return null;
}

/// Computes the digest of `data` with `algo` and compares it (constant-time)
/// against the expected hex string. Returns false on any length mismatch.
pub fn validateDigest(expected: []const u8, data: []const u8, algo: Algorithm) bool {
    var digest_buf: [64]u8 = undefined;
    switch (algo) {
        .sha256 => std.crypto.hash.sha2.Sha256.hash(data, digest_buf[0..32], .{}),
        .sha384 => std.crypto.hash.sha2.Sha384.hash(data, digest_buf[0..48], .{}),
        .sha512 => std.crypto.hash.sha2.Sha512.hash(data, digest_buf[0..64], .{}),
    }
    const hex = std.fmt.bytesToHex(digest_buf, .lower);
    const computed = hex[0 .. digestLength(algo) * 2];
    if (expected.len != computed.len) return false;
    return timingSafeEqlBytes(expected, computed);
}

/// Constant-time byte comparison for equal-length slices.
fn timingSafeEqlBytes(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var acc: u8 = 0;
    for (a, b) |x, y| acc |= x ^ y;
    return acc == 0;
}

const config_json = @embedFile("fixtures/config.json");
const manifest_json = @embedFile("fixtures/manifest.json");

/// Minimal `anytype` writer for `format` tests (std.Io has no fixed-buffer writer).
pub const TestWriter = struct {
    buf: []u8,
    len: usize = 0,

    pub fn print(self: *TestWriter, comptime fmt: []const u8, args: anytype) !void {
        const s = try std.fmt.bufPrint(self.buf[self.len..], fmt, args);
        self.len += s.len;
    }
};

test "parity: config.json matches upstream golden digest" {
    try std.testing.expect(validateDigest(
        "3f57d9401f8d42f986df300f0c69192fc41da28ccc8d797829467780db3dd741",
        config_json,
        .sha256,
    ));
}

test "parity: manifest.json matches upstream golden digest" {
    try std.testing.expect(validateDigest(
        "d319b0e3e1745e504544e931cde012fc5470eba649acc8a7b3607402942e5db7",
        manifest_json,
        .sha256,
    ));
}

test "tampered bytes fail validation" {
    var tampered: [config_json.len]u8 = undefined;
    @memcpy(&tampered, config_json);
    tampered[config_json.len / 2] ^= 0x01;
    try std.testing.expect(!validateDigest(
        "3f57d9401f8d42f986df300f0c69192fc41da28ccc8d797829467780db3dd741",
        &tampered,
        .sha256,
    ));
}

test "wrong expected length fails validation" {
    try std.testing.expect(!validateDigest("3f57", config_json, .sha256));
    try std.testing.expect(!validateDigest(
        "3f57d9401f8d42f986df300f0c69192fc41da28ccc8d797829467780db3dd74100",
        config_json,
        .sha256,
    ));
}

test "validateDigest sha384 and sha512" {
    // Cross-check against the std hash directly.
    var out384: [48]u8 = undefined;
    std.crypto.hash.sha2.Sha384.hash(config_json, &out384, .{});
    const hex384 = std.fmt.bytesToHex(out384, .lower);
    try std.testing.expect(validateDigest(&hex384, config_json, .sha384));

    var out512: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(config_json, &out512, .{});
    const hex512 = std.fmt.bytesToHex(out512, .lower);
    try std.testing.expect(validateDigest(&hex512, config_json, .sha512));
}

test "digestLength" {
    try std.testing.expectEqual(@as(usize, 32), digestLength(.sha256));
    try std.testing.expectEqual(@as(usize, 48), digestLength(.sha384));
    try std.testing.expectEqual(@as(usize, 64), digestLength(.sha512));
}

test "digest parse and format round-trip" {
    const s = "sha256:3f57d9401f8d42f986df300f0c69192fc41da28ccc8d797829467780db3dd741";
    const d = try parse(s);
    var buf: [128]u8 = undefined;
    var tw = TestWriter{ .buf = &buf };
    try d.format(&tw);
    try std.testing.expectEqualStrings(s, buf[0..tw.len]);

    const d2 = try parse("sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    try std.testing.expectEqual(@as(usize, 64), d2.len);
    try std.testing.expectEqual(Algorithm.sha512, d2.algorithm);
}

test "digest parse rejects bad input" {
    try std.testing.expectError(error.InvalidDigest, parse("sha256:zzz"));
    try std.testing.expectError(error.InvalidDigest, parse("sha256:3f57")); // too short
    try std.testing.expectError(error.InvalidDigest, parse("md5:3f57d9401f8d42f986df300f0c69192f")); // unknown algo
    try std.testing.expectError(error.InvalidDigest, parse("sha256"));
    try std.testing.expectError(error.InvalidDigest, parse(""));
}

test "digest init validates length and hex" {
    const d = try Digest.init(.sha256, "3f57d9401f8d42f986df300f0c69192fc41da28ccc8d797829467780db3dd741");
    try std.testing.expectEqual(@as(usize, 32), d.len);
    try std.testing.expectError(error.InvalidDigest, Digest.init(.sha256, "3f57"));
    try std.testing.expectError(error.InvalidDigest, Digest.init(.sha256, "zz57d9401f8d42f986df300f0c69192fc41da28ccc8d797829467780db3dd741"));
    try std.testing.expectError(error.InvalidDigest, Digest.init(.sha512, "3f57d9401f8d42f986df300f0c69192fc41da28ccc8d797829467780db3dd741"));
}

test "digest eql" {
    const a = try parse("sha256:3f57d9401f8d42f986df300f0c69192fc41da28ccc8d797829467780db3dd741");
    const b = try parse("sha256:3f57d9401f8d42f986df300f0c69192fc41da28ccc8d797829467780db3dd741");
    const c = try parse("sha256:d319b0e3e1745e504544e931cde012fc5470eba649acc8a7b3607402942e5db7");
    try std.testing.expect(Digest.eql(a, b));
    try std.testing.expect(!Digest.eql(a, c));
}

test "digestHeaderValue extraction" {
    const headers = [_]std.http.Header{
        .{ .name = "Content-Type", .value = "application/vnd.oci.image.manifest.v1+json" },
        .{ .name = "docker-content-digest", .value = "sha256:abc" },
        .{ .name = "Content-Length", .value = "123" },
    };
    try std.testing.expectEqualStrings("sha256:abc", digestHeaderValue(&headers).?);

    const none = [_]std.http.Header{
        .{ .name = "Content-Type", .value = "application/json" },
    };
    try std.testing.expectEqual(@as(?[]const u8, null), digestHeaderValue(&none));
}
