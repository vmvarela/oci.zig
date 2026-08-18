//! Bearer token cache: (registry, repo, operation) -> RegistryToken, plus
//! JWT `exp` extraction (without signature verification) for expiry checks.
//!
//! Analog of src/token_cache.rs in rust-oci-client: RegistryOperation,
//! RegistryToken and TokenCache, where TokenCache::put decodes the JWT
//! expiration claim from the token itself.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Registry operation, used to build the token request scope string.
pub const RegistryOperation = enum {
    pull,
    push,
    delete,
    mount,

    /// The OCI scope component for this operation ("pull", "push", ...).
    pub fn scopeString(self: RegistryOperation) []const u8 {
        return switch (self) {
            .pull => "pull",
            .push => "push",
            .delete => "delete",
            .mount => "mount",
        };
    }
};

/// A cached bearer token with an optional expiry (Unix seconds).
pub const RegistryToken = struct {
    token: []const u8,
    expiration: ?i64 = null,
};

/// Decodes the `exp` claim (Unix seconds) from a JWT *payload* segment
/// (base64url, unpadded). Returns null when the claim is absent.
/// Invalid base64 or non-JSON input returns an error.
pub fn decodeJwtExp(payload_b64: []const u8, allocator: Allocator) !?i64 {
    // url_safe_no_pad rejects padding; tolerate it by stripping '='.
    var s = payload_b64;
    while (s.len > 0 and s[s.len - 1] == '=') s = s[0 .. s.len - 1];

    const decoder = std.base64.url_safe_no_pad.Decoder;
    const size = try decoder.calcSizeForSlice(s);
    const buf = try allocator.alloc(u8, size);
    defer allocator.free(buf);
    try decoder.decode(buf, s);

    const JwtPayload = struct {
        exp: ?i64 = null,
    };
    const parsed = try std.json.parseFromSlice(JwtPayload, allocator, buf, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    return parsed.value.exp;
}

/// Keyed map of (registry, repo, operation) -> RegistryToken, using a
/// composite string key "registry/repo/op".
pub const TokenCache = struct {
    tokens: std.StringHashMap(RegistryToken),

    pub fn init(allocator: Allocator) TokenCache {
        return .{ .tokens = std.StringHashMap(RegistryToken).init(allocator) };
    }

    /// Frees the map and all owned keys/tokens.
    pub fn deinit(self: *TokenCache) void {
        var it = self.tokens.iterator();
        while (it.next()) |entry| {
            const a = self.tokens.allocator;
            a.free(entry.key_ptr.*);
            a.free(entry.value_ptr.token);
        }
        self.tokens.deinit();
    }

    /// Returns the cached token if present and not expired
    /// (expiration absent or > now_secs); otherwise null.
    pub fn get(self: *TokenCache, registry: []const u8, repo: []const u8, op: RegistryOperation, now_secs: i64) ?RegistryToken {
        var buf: [512]u8 = undefined;
        const key_str = std.fmt.bufPrint(&buf, "{s}/{s}/{s}", .{ registry, repo, op.scopeString() }) catch return null;
        const token = self.tokens.get(key_str) orelse return null;
        if (token.expiration) |exp| {
            if (exp <= now_secs) return null; // expired
        }
        return token;
    }

    /// Stores a token under (registry, repo, op), deriving its expiration
    /// from the JWT `exp` claim (null when not decodable). Expired tokens are
    /// stored too; `get` drops them. `now_secs` is unused (get filters).
    pub fn put(self: *TokenCache, registry: []const u8, repo: []const u8, op: RegistryOperation, token: []const u8, now_secs: i64) !void {
        _ = now_secs;
        const allocator = self.tokens.allocator;
        const key_str = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{ registry, repo, op.scopeString() });
        errdefer allocator.free(key_str);
        const token_owned = try allocator.dupe(u8, token);
        errdefer allocator.free(token_owned);
        const expiration = decodeJwtExp(jwtPayloadSegment(token), allocator) catch null;
        try self.tokens.put(key_str, .{ .token = token_owned, .expiration = expiration });
    }
};

/// Extracts the payload segment of a JWT ("header.payload.signature").
/// Non-JWT tokens fall back to the whole string (decode will fail -> null exp).
fn jwtPayloadSegment(token: []const u8) []const u8 {
    const first = std.mem.indexOfScalar(u8, token, '.') orelse return token;
    const rest = token[first + 1 ..];
    const second = std.mem.indexOfScalar(u8, rest, '.') orelse return rest;
    return rest[0..second];
}

test "decodeJwtExp hand-built payload" {
    const a = std.testing.allocator;
    // {"exp":1234567890} base64url-unpadded
    try std.testing.expectEqual(@as(?i64, 1234567890), try decodeJwtExp("eyJleHAiOjEyMzQ1Njc4OTB9", a));
    // {"exp":100}
    try std.testing.expectEqual(@as(?i64, 100), try decodeJwtExp("eyJleHAiOjEwMH0", a));
}

test "decodeJwtExp tolerates padding" {
    const a = std.testing.allocator;
    // {} -> "e30=" (padded); stripped before decode, exp absent -> null.
    try std.testing.expectEqual(@as(?i64, null), try decodeJwtExp("e30=", a));
}

test "decodeJwtExp missing exp returns null" {
    const a = std.testing.allocator;
    // {"sub":"x"} has no exp claim.
    try std.testing.expectEqual(@as(?i64, null), try decodeJwtExp("eyJzdWIiOiJ4In0", a));
}

test "decodeJwtExp garbage payload errors" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.InvalidCharacter, decodeJwtExp("!!!notbase64!!!", a));
}

test "op scope strings" {
    try std.testing.expectEqualStrings("pull", RegistryOperation.pull.scopeString());
    try std.testing.expectEqualStrings("push", RegistryOperation.push.scopeString());
    try std.testing.expectEqualStrings("delete", RegistryOperation.delete.scopeString());
    try std.testing.expectEqualStrings("mount", RegistryOperation.mount.scopeString());
}

test "token cache get/put round-trip" {
    const a = std.testing.allocator;
    var cache = TokenCache.init(a);
    defer cache.deinit();

    const token = "eyJhbGciOiJub25lIn0.eyJleHAiOjQxMDI0NDQ4MDB9.sig"; // exp 4102444800 (year 2100)
    try cache.put("registry.example.com", "org/repo", .pull, token, 0);

    const got = cache.get("registry.example.com", "org/repo", .pull, 1_700_000_000) orelse
        @panic("expected cached token");
    try std.testing.expectEqualStrings(token, got.token);
    try std.testing.expectEqual(@as(?i64, 4102444800), got.expiration);

    // Same repo, different operation -> separate entry (not found yet).
    try std.testing.expectEqual(@as(?RegistryToken, null), cache.get("registry.example.com", "org/repo", .push, 1_700_000_000));
}

test "expired token dropped by get" {
    const a = std.testing.allocator;
    var cache = TokenCache.init(a);
    defer cache.deinit();

    const token = "eyJhbGciOiJub25lIn0.eyJleHAiOjEwMH0.sig"; // exp 100
    try cache.put("reg", "repo", .pull, token, 0);

    // Before expiry: returned.
    try std.testing.expect(cache.get("reg", "repo", .pull, 50) != null);
    // Exactly at expiry: dropped.
    try std.testing.expectEqual(@as(?RegistryToken, null), cache.get("reg", "repo", .pull, 100));
    // After expiry: dropped.
    try std.testing.expectEqual(@as(?RegistryToken, null), cache.get("reg", "repo", .pull, 200));
}

test "token without decodable exp stored as valid" {
    const a = std.testing.allocator;
    var cache = TokenCache.init(a);
    defer cache.deinit();

    // Opaque token (no JWT structure): decode fails -> expiration null -> never expires.
    try cache.put("reg", "repo", .pull, "plain-opaque-token", 0);
    const got = cache.get("reg", "repo", .pull, 9_999_999_999) orelse
        @panic("expected non-expiring token");
    try std.testing.expectEqualStrings("plain-opaque-token", got.token);
    try std.testing.expectEqual(@as(?i64, null), got.expiration);
}
