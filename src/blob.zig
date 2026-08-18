//! Blob transport plumbing: SizedStream, BlobResponse, BlobStream
//! (mirror of rust-oci-client src/blob.rs). Pure types — the HTTP request
//! logic that produces these lives in client.zig.
//!
//! Shape validated by the Phase B spike against a local zot registry:
//! * `SizedStream.reader` is a `*std.Io.Reader`, not a value. The body reader
//!   returned by `std.http.Client.Response.reader()` is NOT copy-safe: its
//!   vtable recovers the owning `http.Reader` via `@fieldParentPtr`, so a
//!   copied value silently reads 0 bytes (spike-proven). The pointer aliases
//!   the Response's transfer buffer, which must outlive the reads.
//! * Range responses (206) must NOT be digest-verified (upstream parity).

const std = @import("std");
const digest = @import("digest.zig");

/// A streamed response body whose total size is known in advance (from
/// Content-Length, or the `/total` of a Content-Range header).
pub const SizedStream = struct {
    /// Body reader. Aliases caller-owned memory; the underlying Request (and
    /// its transfer buffer) must outlive reads.
    reader: *std.Io.Reader,
    size: u64,
};

/// The response to a blob GET.
/// `full` = complete blob (digest verification applies); `partial` = range
/// response (NO digest verification — upstream parity).
///
/// Producer/consumer contract: the producer (client.zig) MUST return this
/// together with the owning `std.http.Client.Request` (e.g. as a pair struct),
/// because `SizedStream.reader` aliases the Request's reader and transfer
/// buffer. The consumer reads to EOF, then calls `req.deinit()` (which drains
/// the body and returns the connection to the pool). Only the `.full` variant
/// may be wrapped in a `BlobStream`; `.partial` consumers use `SizedStream`
/// directly and never call `finish()` (the hash of range bytes never matches
/// the full-blob digest).
pub const BlobResponse = union(enum) {
    full: SizedStream,
    partial: SizedStream,
};

/// Streaming reader over a blob body that hashes bytes incrementally (sha256)
/// and verifies the digest on `finish`. The digest algorithm is hardcoded to
/// sha256 — upstream parity (rust-oci-client's BlobStream uses Sha256
/// unconditionally); a non-sha256 expected digest would fail at `finish`.
pub const BlobStream = struct {
    stream: SizedStream,
    expected_digest: digest.Digest,
    hasher: std.crypto.hash.sha2.Sha256,

    pub fn init(stream: SizedStream, expected_digest: digest.Digest) BlobStream {
        return .{
            .stream = stream,
            .expected_digest = expected_digest,
            .hasher = std.crypto.hash.sha2.Sha256.init(.{}),
        };
    }

    /// Total blob size in bytes. For a `.partial` stream this is the FULL blob
    /// size (the `/total` of the Content-Range header), NOT the readable byte
    /// count — do not use it to size a buffer for a partial fetch.
    pub fn size(self: *const BlobStream) u64 {
        return self.stream.size;
    }

    /// Reads up to `buf.len` bytes, feeding them into the running sha256.
    /// Returns 0 at end of stream (like std.Io.Reader.readSliceShort).
    pub fn read(self: *BlobStream, buf: []u8) !usize {
        const n = try self.stream.reader.readSliceShort(buf);
        if (n > 0) self.hasher.update(buf[0..n]);
        return n;
    }

    /// Finalizes the hash and compares it (constant-time) against the expected
    /// digest. Returns error.DigestMismatch on any mismatch. Calling `finish`
    /// after an incomplete read (fewer than `size` bytes) therefore also
    /// errors with DigestMismatch.
    pub fn finish(self: *BlobStream) !void {
        var out: [32]u8 = undefined;
        self.hasher.final(&out);
        var computed = digest.Digest{ .algorithm = .sha256, .value = undefined, .len = 32 };
        @memcpy(computed.value[0..32], &out);
        if (!digest.Digest.eql(computed, self.expected_digest)) return error.DigestMismatch;
    }
};

const test_data = "the quick brown fox jumps over the lazy dog, and the blob is slightly longer than a single read";

fn expectedDigest(data: []const u8) digest.Digest {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &out, .{});
    const hex = std.fmt.bytesToHex(out, .lower);
    return digest.Digest.init(.sha256, &hex) catch unreachable;
}

test "BlobStream: correct digest passes" {
    var reader = std.Io.Reader.fixed(test_data);
    var bs = BlobStream.init(.{ .reader = &reader, .size = test_data.len }, expectedDigest(test_data));
    var buf: [16]u8 = undefined;
    var total: usize = 0;
    while (true) {
        const n = try bs.read(&buf);
        if (n == 0) break;
        total += n;
    }
    try std.testing.expectEqual(test_data.len, total);
    try bs.finish(); // must not error
}

test "BlobStream: wrong digest errors with DigestMismatch" {
    var reader = std.Io.Reader.fixed(test_data);
    var bs = BlobStream.init(.{ .reader = &reader, .size = test_data.len }, expectedDigest("some other bytes"));
    var buf: [64]u8 = undefined;
    while (true) {
        const n = try bs.read(&buf);
        if (n == 0) break;
    }
    try std.testing.expectError(error.DigestMismatch, bs.finish());
}

test "BlobStream: partial read sizes and finish after full read" {
    var reader = std.Io.Reader.fixed(test_data);
    var bs = BlobStream.init(.{ .reader = &reader, .size = test_data.len }, expectedDigest(test_data));
    var buf: [7]u8 = undefined;
    var total: usize = 0;
    var count: usize = 0;
    while (true) {
        const n = try bs.read(&buf);
        if (n == 0) break;
        try std.testing.expect(n <= 7 and n > 0);
        total += n;
        count += 1;
    }
    try std.testing.expectEqual(test_data.len, total);
    try std.testing.expect(count > 1); // genuinely partial reads happened
    try bs.finish();
}

test "BlobStream: finish before full read errors cleanly" {
    var reader = std.Io.Reader.fixed(test_data);
    var bs = BlobStream.init(.{ .reader = &reader, .size = test_data.len }, expectedDigest(test_data));
    var buf: [8]u8 = undefined;
    _ = try bs.read(&buf); // read a prefix only
    try std.testing.expectError(error.DigestMismatch, bs.finish());
}

test "BlobStream: size accessor" {
    var reader = std.Io.Reader.fixed(test_data);
    var bs = BlobStream.init(.{ .reader = &reader, .size = test_data.len }, expectedDigest(test_data));
    try std.testing.expectEqual(@as(u64, test_data.len), bs.size());
}

test "BlobResponse holds both variants" {
    var reader = std.Io.Reader.fixed(test_data);
    const full: BlobResponse = .{ .full = .{ .reader = &reader, .size = test_data.len } };
    const partial: BlobResponse = .{ .partial = .{ .reader = &reader, .size = 4 } };
    try std.testing.expect(full == .full);
    try std.testing.expect(partial == .partial);
    // The pointer variant actually reads through the stored reader.
    var buf: [4]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 4), try full.full.reader.readSliceShort(&buf));
}
