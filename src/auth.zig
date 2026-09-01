//! WWW-Authenticate Bearer challenge parsing (RFC 7235 auth-param).
//!
//! Analog of the `http-auth` crate usage in rust-oci-client: a registry 401
//! response carries `WWW-Authenticate: Bearer realm="...",service="...",
//! scope="..."`, and the client uses these parameters to fetch a token.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// A parsed Bearer challenge from a `WWW-Authenticate` header value.
///
/// The slices are owned by the Challenge (allocated by `parseBearerChallenge`
/// from the provided allocator) and must be released with `deinit` using the
/// same allocator.
pub const Challenge = struct {
    realm: []const u8,
    service: ?[]const u8 = null,
    scope: ?[]const u8 = null,

    /// Frees the parameter storage allocated by `parseBearerChallenge`.
    pub fn deinit(self: Challenge, allocator: Allocator) void {
        if (self.service) |s| allocator.free(s);
        if (self.scope) |s| allocator.free(s);
        allocator.free(self.realm);
    }
};

/// Parses a `Bearer` challenge per RFC 7235: scheme token (case-insensitive)
/// followed by comma-separated auth-params with quoted-string values
/// (`\"` and `\\` escapes). Unknown params are skipped; `realm` is required.
/// Values are unescaped into freshly allocated storage owned by the returned
/// `Challenge` (see `Challenge.deinit`).
pub fn parseBearerChallenge(allocator: Allocator, header_value: []const u8) !Challenge {
    const trimmed = std.mem.trim(u8, header_value, " \t\r\n");
    const space = std.mem.indexOfAny(u8, trimmed, " \t") orelse trimmed.len;
    const scheme = trimmed[0..space];
    if (!std.ascii.eqlIgnoreCase(scheme, "Bearer")) return error.InvalidHeader;

    var ch = Challenge{ .realm = "" };
    errdefer ch.deinit(allocator);

    const params = trimmed[space..];
    var i: usize = 0;
    var realm_set = false;
    while (i < params.len) {
        // Skip separators between params.
        while (i < params.len and (params[i] == ',' or params[i] == ' ' or params[i] == '\t')) i += 1;
        if (i >= params.len) break;

        // Key: up to '=' (or a separator, which is malformed).
        const key_start = i;
        while (i < params.len and params[i] != '=' and params[i] != ',' and params[i] != ' ' and params[i] != '\t') i += 1;
        if (i >= params.len or params[i] != '=') return error.InvalidHeader;
        const key = params[key_start..i];
        i += 1;

        // Value: quoted string (commas inside quotes do not split params).
        while (i < params.len and (params[i] == ' ' or params[i] == '\t')) i += 1;
        if (i >= params.len or params[i] != '"') return error.InvalidHeader;
        var j = i + 1;
        var closed = false;
        while (j < params.len) : (j += 1) {
            if (params[j] == '\\') {
                j += 1; // skip the escaped character ('"' or '\')
                continue;
            }
            if (params[j] == '"') {
                closed = true;
                break;
            }
        }
        if (!closed) return error.InvalidHeader;
        const value = try unescape(allocator, params[i + 1 .. j]);

        if (std.ascii.eqlIgnoreCase(key, "realm")) {
            if (realm_set) {
                allocator.free(value);
            } else {
                ch.realm = value;
                realm_set = true;
            }
        } else if (std.ascii.eqlIgnoreCase(key, "service")) {
            if (ch.service != null) allocator.free(value) else ch.service = value;
        } else if (std.ascii.eqlIgnoreCase(key, "scope")) {
            if (ch.scope != null) allocator.free(value) else ch.scope = value;
        } else {
            allocator.free(value); // unknown param: tolerate and skip
        }
        i = j + 1;
    }

    if (!realm_set) return error.InvalidHeader;
    return ch;
}

/// Decodes a quoted-string body: `\"` -> `"`, `\\` -> `\`; other backslash
/// sequences are kept verbatim (lenient). Allocates via `allocator`.
fn unescape(allocator: Allocator, raw: []const u8) ![]const u8 {
    // Worst case (no escapes) needs raw.len bytes.
    const buf = try allocator.alloc(u8, raw.len);
    errdefer allocator.free(buf);
    var n: usize = 0;
    var i: usize = 0;
    while (i < raw.len) : (i += 1) {
        if (raw[i] == '\\' and i + 1 < raw.len) {
            switch (raw[i + 1]) {
                '"', '\\' => {
                    buf[n] = raw[i + 1];
                    n += 1;
                    i += 1;
                },
                else => {
                    buf[n] = raw[i]; // lenient: keep the backslash
                    n += 1;
                },
            }
        } else {
            buf[n] = raw[i];
            n += 1;
        }
    }
    return allocator.realloc(buf, n);
}

test "full header with all three params" {
    const a = std.testing.allocator;
    const ch = try parseBearerChallenge(
        a,
        "Bearer realm=\"https://registry.example.com\",service=\"registry.example.com\",scope=\"repository:foo:pull,push\"",
    );
    defer ch.deinit(a);
    try std.testing.expectEqualStrings("https://registry.example.com", ch.realm);
    try std.testing.expectEqualStrings("registry.example.com", ch.service.?);
    // Comma inside the quoted scope must not split the param.
    try std.testing.expectEqualStrings("repository:foo:pull,push", ch.scope.?);
}

test "realm only" {
    const a = std.testing.allocator;
    const ch = try parseBearerChallenge(a, "Bearer realm=\"https://x\"");
    defer ch.deinit(a);
    try std.testing.expectEqualStrings("https://x", ch.realm);
    try std.testing.expectEqual(null, ch.service);
    try std.testing.expectEqual(null, ch.scope);
}

test "lowercase scheme accepted" {
    const a = std.testing.allocator;
    const ch = try parseBearerChallenge(a, "bearer realm=\"https://x\"");
    defer ch.deinit(a);
    try std.testing.expectEqualStrings("https://x", ch.realm);
}

test "unknown extra param skipped" {
    const a = std.testing.allocator;
    const ch = try parseBearerChallenge(a, "Bearer realm=\"r\",foo=\"bar\",service=\"s\"");
    defer ch.deinit(a);
    try std.testing.expectEqualStrings("r", ch.realm);
    try std.testing.expectEqualStrings("s", ch.service.?);
}

test "param keys case-insensitive" {
    const a = std.testing.allocator;
    const ch = try parseBearerChallenge(a, "Bearer REALM=\"r\",Service=\"s\"");
    defer ch.deinit(a);
    try std.testing.expectEqualStrings("r", ch.realm);
    try std.testing.expectEqualStrings("s", ch.service.?);
}

test "unquoted value rejected" {
    try std.testing.expectError(error.InvalidHeader, parseBearerChallenge(std.testing.allocator, "Bearer realm=foo"));
}

test "missing realm rejected" {
    try std.testing.expectError(error.InvalidHeader, parseBearerChallenge(std.testing.allocator, "Bearer service=\"s\""));
}

test "non-Bearer scheme rejected" {
    try std.testing.expectError(error.InvalidHeader, parseBearerChallenge(std.testing.allocator, "Basic realm=\"https://x\""));
}

test "unterminated quoted string rejected" {
    try std.testing.expectError(error.InvalidHeader, parseBearerChallenge(std.testing.allocator, "Bearer realm=\"oops"));
}

test "escaped quote inside realm" {
    const a = std.testing.allocator;
    const ch = try parseBearerChallenge(a, "Bearer realm=\"foo\\\"bar\"");
    defer ch.deinit(a);
    try std.testing.expectEqualStrings("foo\"bar", ch.realm);
}

test "escaped backslash inside realm" {
    const a = std.testing.allocator;
    const ch = try parseBearerChallenge(a, "Bearer realm=\"a\\\\b\"");
    defer ch.deinit(a);
    try std.testing.expectEqualStrings("a\\b", ch.realm);
}
