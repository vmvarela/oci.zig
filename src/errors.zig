//! OCI registry error model: client error set, registry error codes, and the
//! registry error envelope (mirror of rust-oci-client src/errors.rs).

const std = @import("std");

/// Client-side errors surfaced by the OCI client.
///
/// `OutOfMemory` merges with `std.mem.Allocator.Error` so allocator calls
/// coerce into this set directly. `OciError` is the generic transport/other
/// failure, mirroring `Error::OciError` upstream.
pub const OciError = error{
    /// HTTP 401: credentials missing or rejected.
    Unauthorized,
    /// HTTP 403: authenticated but not permitted.
    Forbidden,
    /// HTTP 404: resource does not exist.
    NotFound,
    /// HTTP status outside the expected range.
    UnexpectedStatus,
    /// A digest string failed to parse.
    InvalidDigest,
    /// An image reference failed to parse.
    InvalidReference,
    /// The registry response body was malformed.
    InvalidResponse,
    /// Received content does not match its declared digest.
    DigestMismatch,
    /// Allocation failure (part of `std.mem.Allocator.Error`).
    OutOfMemory,
    /// Generic transport or other failure.
    OciError,
};

/// Registry error codes from the OCI distribution spec
/// (https://github.com/opencontainers/distribution-spec/blob/main/spec.md#error-codes).
/// Wire values are UPPER_SNAKE strings such as "BLOB_UNKNOWN"; the enum tags
/// use the Zig-conventional lower_snake spelling.
pub const OciErrorCode = enum {
    blob_unknown,
    blob_upload_invalid,
    blob_upload_unknown,
    digest_invalid,
    manifest_blob_unknown,
    manifest_invalid,
    manifest_unknown,
    manifest_verification_failed,
    name_invalid,
    name_unknown,
    size_invalid,
    tag_invalid,
    unauthorized,
    denied,
    unsupported,

    /// Matches a registry error code string (e.g. "BLOB_UNKNOWN") against the
    /// canonical codes, case-insensitively. Returns null for unknown strings.
    pub fn fromString(s: []const u8) ?OciErrorCode {
        inline for (@typeInfo(OciErrorCode).@"enum".fields) |f| {
            if (std.ascii.eqlIgnoreCase(f.name, s)) return @enumFromInt(f.value);
        }
        return null;
    }

    /// std.json hook: registry codes arrive as UPPER_SNAKE strings while the
    /// enum tags are lower_snake, so parse via `fromString`.
    pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) !OciErrorCode {
        const token = try source.nextAllocMax(allocator, .alloc_if_needed, options.max_value_len.?);
        defer switch (token) {
            .allocated_string => |s| allocator.free(s),
            else => {},
        };
        const slice = switch (token) {
            .allocated_string, .string => |s| s,
            else => return error.InvalidEnumTag,
        };
        return fromString(slice) orelse error.InvalidEnumTag;
    }
};

/// A single error entry of a registry error envelope.
pub const OciEnvelopeError = struct {
    code: OciErrorCode,
    message: ?[]const u8 = null,
    detail: ?std.json.Value = null,
};

/// Registry error envelope: `{"errors": [{"code": "...", "message": "...", "detail": ...}]}`
/// (https://github.com/opencontainers/distribution-spec/blob/main/spec.md#error-response).
/// Parse with `std.json.parseFromSlice(OciEnvelope, allocator, body, .{ .ignore_unknown_fields = true })`;
/// the returned `Parsed(OciEnvelope)` owns its allocations — call `deinit()`.
pub const OciEnvelope = struct {
    errors: []const OciEnvelopeError,
};

test "fromString matches canonical registry codes case-insensitively" {
    try std.testing.expectEqual(OciErrorCode.blob_unknown, OciErrorCode.fromString("BLOB_UNKNOWN").?);
    try std.testing.expectEqual(OciErrorCode.digest_invalid, OciErrorCode.fromString("DIGEST_INVALID").?);
    try std.testing.expectEqual(OciErrorCode.manifest_unknown, OciErrorCode.fromString("MANIFEST_UNKNOWN").?);
    try std.testing.expectEqual(OciErrorCode.unsupported, OciErrorCode.fromString("unsupported").?);
    try std.testing.expectEqual(OciErrorCode.denied, OciErrorCode.fromString("Denied").?);
}

test "fromString unknown code falls back to null" {
    try std.testing.expectEqual(@as(?OciErrorCode, null), OciErrorCode.fromString("FOO_BAR"));
    try std.testing.expectEqual(@as(?OciErrorCode, null), OciErrorCode.fromString(""));
}

test "envelope parse from a real registry error body" {
    const body = "{\"errors\":[{\"code\":\"MANIFEST_UNKNOWN\",\"message\":\"manifest unknown\",\"detail\":{}}]}";
    const parsed = try std.json.parseFromSlice(OciEnvelope, std.testing.allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    try std.testing.expectEqual(@as(usize, 1), parsed.value.errors.len);
    try std.testing.expectEqual(OciErrorCode.manifest_unknown, parsed.value.errors[0].code);
    try std.testing.expectEqualStrings("manifest unknown", parsed.value.errors[0].message.?);
    try std.testing.expectEqual(std.json.Value.object, std.meta.activeTag(parsed.value.errors[0].detail.?));
}

test "envelope parse tolerates missing optional fields and unknown fields" {
    const body = "{\"errors\":[{\"code\":\"BLOB_UNKNOWN\"}],\"extra\":true}";
    const parsed = try std.json.parseFromSlice(OciEnvelope, std.testing.allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    try std.testing.expectEqual(@as(usize, 1), parsed.value.errors.len);
    try std.testing.expectEqual(OciErrorCode.blob_unknown, parsed.value.errors[0].code);
    try std.testing.expectEqual(@as(?[]const u8, null), parsed.value.errors[0].message);
    try std.testing.expectEqual(@as(?std.json.Value, null), parsed.value.errors[0].detail);
}

test "malformed envelope body errors cleanly" {
    const body = "{\"errors\": [}";
    if (std.json.parseFromSlice(OciEnvelope, std.testing.allocator, body, .{ .ignore_unknown_fields = true })) |parsed| {
        parsed.deinit();
        return error.TestExpectedError;
    } else |_| {}
}

test "envelope with unknown code errors cleanly" {
    const body = "{\"errors\":[{\"code\":\"NOT_A_REAL_CODE\"}]}";
    if (std.json.parseFromSlice(OciEnvelope, std.testing.allocator, body, .{ .ignore_unknown_fields = true })) |parsed| {
        parsed.deinit();
        return error.TestExpectedError;
    } else |_| {}
}
