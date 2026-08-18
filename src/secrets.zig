//! Registry credentials (mirror of rust-oci-client src/secrets.rs RegistryAuth).

const std = @import("std");

/// Username/password pair for registry basic auth.
pub const Basic = struct {
    username: []const u8,
    password: []const u8,
};

/// Registry authentication strategy.
pub const RegistryAuth = union(enum) {
    /// No credentials; requests are sent unauthenticated.
    anonymous,
    /// HTTP Basic auth (`Authorization: Basic <base64 user:pass>`).
    basic: Basic,
    /// Bearer token (`Authorization: Bearer <token>`).
    bearer: []const u8,
};

/// Builds the `Authorization` header value for `auth`, or null for anonymous.
///
/// - basic   -> "Basic <base64(username:password)>"
/// - bearer  -> "Bearer <token>"
/// - anonymous -> null
///
/// Return ownership: caller frees with `allocator.free`.
pub fn basicAuthHeader(auth: RegistryAuth, allocator: std.mem.Allocator) !?[]const u8 {
    return switch (auth) {
        .anonymous => null,
        .bearer => |token| try std.fmt.allocPrint(allocator, "Bearer {s}", .{token}),
        .basic => |b| blk: {
            const joined = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ b.username, b.password });
            defer allocator.free(joined);
            const enc = std.base64.standard.Encoder;
            const b64_len = enc.calcSize(joined.len);
            const out = try allocator.alloc(u8, "Basic ".len + b64_len);
            @memcpy(out[0.."Basic ".len], "Basic ");
            _ = enc.encode(out["Basic ".len..], joined);
            break :blk out;
        },
    };
}

test "basic auth header" {
    const auth = RegistryAuth{ .basic = .{ .username = "user", .password = "pass" } };
    const hdr = (try basicAuthHeader(auth, std.testing.allocator)).?;
    defer std.testing.allocator.free(hdr);
    try std.testing.expectEqualStrings("Basic dXNlcjpwYXNz", hdr);
}

test "basic auth header with empty password" {
    const auth = RegistryAuth{ .basic = .{ .username = "user", .password = "" } };
    const hdr = (try basicAuthHeader(auth, std.testing.allocator)).?;
    defer std.testing.allocator.free(hdr);
    try std.testing.expectEqualStrings("Basic dXNlcjo=", hdr);
}

test "bearer auth header" {
    const auth = RegistryAuth{ .bearer = "tok123" };
    const hdr = (try basicAuthHeader(auth, std.testing.allocator)).?;
    defer std.testing.allocator.free(hdr);
    try std.testing.expectEqualStrings("Bearer tok123", hdr);
}

test "anonymous produces no header" {
    try std.testing.expectEqual(@as(?[]const u8, null), try basicAuthHeader(.anonymous, std.testing.allocator));
}
