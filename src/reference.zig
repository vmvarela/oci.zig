//! Image reference parsing and formatting (hand-written parser for the
//! OCI distribution reference grammar, mirror of
//! `oci_spec::distribution::Reference`).
//!
//! Grammar: `[registry[:port]/]repository[:tag][@digest]`. The registry is
//! REQUIRED: the first path component is treated as a registry only if it
//! contains "." or ":" or equals "localhost"; otherwise the reference is
//! rejected (so "ubuntu:latest" is an error).
//!
//! All returned slices point into the original input string; no allocation.

const std = @import("std");
const digest = @import("digest.zig");

/// A parsed image reference. All fields are slices into the parsed input.
pub const Reference = struct {
    registry: []const u8,
    repository: []const u8,
    tag: ?[]const u8 = null,
    digest: ?[]const u8 = null,

    /// Writes `registry/repository[:tag][@digest]` (no scheme) to `writer`.
    pub fn format(self: *const Reference, writer: anytype) !void {
        try writer.print("{s}/{s}", .{ self.registry, self.repository });
        if (self.tag) |t| try writer.print(":{s}", .{t});
        if (self.digest) |d| try writer.print("@{s}", .{d});
    }
};

pub const ParseError = error{
    InvalidReference,
    MissingRegistry,
    InvalidRepository,
    InvalidTag,
    InvalidDigest,
};

/// Parses `[registry[:port]/]repository[:tag][@digest]`.
///
/// Split order (matching oci-spec): "@" first (digest), then the last ":"
/// in the final path component (tag) — repository components never contain
/// ":", so any ":" past the registry is the tag separator.
pub fn parse(s: []const u8) ParseError!Reference {
    if (s.len == 0) return error.InvalidReference;

    // Digest: everything after the first "@".
    var rest = s;
    var digest_str: ?[]const u8 = null;
    if (std.mem.indexOfScalar(u8, s, '@')) |at| {
        digest_str = s[at + 1 ..];
        rest = s[0..at];
        _ = try digest.parse(digest_str.?);
    }

    // Registry: first path component.
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return error.MissingRegistry;
    const registry = rest[0..slash];
    if (registry.len == 0 or !isRegistry(registry)) return error.MissingRegistry;

    // Repository + optional tag.
    const repo_and_tag = rest[slash + 1 ..];
    if (repo_and_tag.len == 0) return error.InvalidRepository;
    var repository = repo_and_tag;
    var tag: ?[]const u8 = null;
    if (std.mem.lastIndexOfScalar(u8, repo_and_tag, ':')) |colon| {
        tag = repo_and_tag[colon + 1 ..];
        repository = repo_and_tag[0..colon];
    }

    try validateRepository(repository);
    if (tag) |t| try validateTag(t);

    return Reference{
        .registry = registry,
        .repository = repository,
        .tag = tag,
        .digest = digest_str,
    };
}

fn isRegistry(component: []const u8) bool {
    if (std.mem.indexOfScalar(u8, component, '.')) |_| return true;
    if (std.mem.indexOfScalar(u8, component, ':')) |_| return true;
    return std.ascii.eqlIgnoreCase(component, "localhost");
}

fn validateRepository(repository: []const u8) ParseError!void {
    // Components separated by "/", each lowercase alphanumeric plus
    // ".", "_", "-"; must not begin or end with a separator.
    var it = std.mem.splitScalar(u8, repository, '/');
    while (it.next()) |component| {
        if (component.len == 0) return error.InvalidRepository;
        const first = component[0];
        const last = component[component.len - 1];
        if (!isLowerAlnum(first) or !isLowerAlnum(last)) return error.InvalidRepository;
        for (component) |c| {
            if (!isLowerAlnum(c) and c != '.' and c != '_' and c != '-') return error.InvalidRepository;
        }
    }
}

fn validateTag(tag: []const u8) ParseError!void {
    // ^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$
    if (tag.len == 0 or tag.len > 128) return error.InvalidTag;
    if (!(std.ascii.isAlphanumeric(tag[0]) or tag[0] == '_')) return error.InvalidTag;
    for (tag[1..]) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '.' and c != '_' and c != '-') return error.InvalidTag;
    }
}

fn isLowerAlnum(c: u8) bool {
    return std.ascii.isLower(c) or std.ascii.isDigit(c);
}

test "parse valid references" {
    const r1 = try parse("registry.example.com/foo/bar");
    try std.testing.expectEqualStrings("registry.example.com", r1.registry);
    try std.testing.expectEqualStrings("foo/bar", r1.repository);
    try std.testing.expectEqual(@as(?[]const u8, null), r1.tag);
    try std.testing.expectEqual(@as(?[]const u8, null), r1.digest);

    const r2 = try parse("localhost:5000/foo/bar:v1");
    try std.testing.expectEqualStrings("localhost:5000", r2.registry);
    try std.testing.expectEqualStrings("foo/bar", r2.repository);
    try std.testing.expectEqualStrings("v1", r2.tag.?);

    const d = "sha256:3f57d9401f8d42f986df300f0c69192fc41da28ccc8d797829467780db3dd741";
    const r3 = try parse("registry.example.com/repo:tag@" ++ d);
    try std.testing.expectEqualStrings("repo", r3.repository);
    try std.testing.expectEqualStrings("tag", r3.tag.?);
    try std.testing.expectEqualStrings(d, r3.digest.?);

    const r4 = try parse("registry.example.com/repo@" ++ d);
    try std.testing.expectEqual(@as(?[]const u8, null), r4.tag);
    try std.testing.expectEqualStrings(d, r4.digest.?);

    const r5 = try parse("registry.example.com/repo:v1.2.3-rc_1");
    try std.testing.expectEqualStrings("v1.2.3-rc_1", r5.tag.?);
}

test "parse tag length limits" {
    var big: [128]u8 = undefined;
    @memset(&big, 'a');
    const tag128 = big[0..];
    const r = try parse("registry.example.com/repo:" ++ tag128);
    try std.testing.expectEqualStrings(tag128, r.tag.?);

    var too_big: [129]u8 = undefined;
    @memset(&too_big, 'a');
    try std.testing.expectError(error.InvalidTag, parse("registry.example.com/repo:" ++ too_big[0..]));
}

test "parse rejects missing registry" {
    try std.testing.expectError(error.MissingRegistry, parse("ubuntu:latest"));
    try std.testing.expectError(error.MissingRegistry, parse("ubuntu"));
    try std.testing.expectError(error.MissingRegistry, parse("/repo"));
}

test "parse rejects invalid repository" {
    try std.testing.expectError(error.InvalidRepository, parse("registry.example.com/"));
    try std.testing.expectError(error.InvalidRepository, parse("registry.example.com/REPO"));
    try std.testing.expectError(error.InvalidRepository, parse("registry.example.com//repo"));
    try std.testing.expectError(error.InvalidRepository, parse("registry.example.com/repo/"));
    try std.testing.expectError(error.InvalidRepository, parse("registry.example.com/-repo"));
}

test "parse rejects invalid tag" {
    try std.testing.expectError(error.InvalidTag, parse("registry.example.com/repo:bad tag!"));
    try std.testing.expectError(error.InvalidTag, parse("registry.example.com/repo:"));
    try std.testing.expectError(error.InvalidTag, parse("registry.example.com/repo:-lead"));
}

test "parse rejects invalid digest" {
    try std.testing.expectError(error.InvalidDigest, parse("registry.example.com/repo@sha256:nothex"));
    try std.testing.expectError(error.InvalidDigest, parse("registry.example.com/repo@md5:abcdef"));
    try std.testing.expectError(error.InvalidDigest, parse("registry.example.com/repo@sha256:3f57"));
    try std.testing.expectError(error.InvalidDigest, parse("registry.example.com/repo@sha512:abcd"));
}

test "format round-trips" {
    const cases = [_][]const u8{
        "registry.example.com/foo/bar",
        "localhost:5000/foo/bar:v1",
        "registry.example.com/repo:tag@sha256:3f57d9401f8d42f986df300f0c69192fc41da28ccc8d797829467780db3dd741",
    };
    for (cases) |c| {
        const ref = try parse(c);
        var buf: [256]u8 = undefined;
        var w = std.Io.Writer.fixed(&buf);
        try ref.format(&w);
        try std.testing.expectEqualStrings(c, w.buffered());
    }
}
