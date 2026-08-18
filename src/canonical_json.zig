//! Canonical JSON serialization (RFC 8785 / OCI image-spec canonical form,
//! analogous to olpc-cjson used by rust-oci-client for manifest digests).
//!
//! Byte-exact and deterministic: object keys sorted lexicographically by
//! UTF-8 byte order (recursively), compact output (no whitespace), minimal
//! string escaping, non-ASCII emitted verbatim as UTF-8. The same
//! `std.json.Value` always produces identical bytes — this is what gets
//! hashed for manifest digests.
//!
//! Golden vectors in the tests were computed independently via
//! `printf '%s' '<canonical-json>' | shasum -a 256`.

const std = @import("std");
const Allocator = std.mem.Allocator;

const hex_digits = "0123456789abcdef";

const Entry = struct {
    key: []const u8,
    value: std.json.Value,
};

fn keyLessThan(_: void, a: Entry, b: Entry) bool {
    return std.mem.order(u8, a.key, b.key) == .lt;
}

/// Serializes `value` in canonical form to a `std.Io.Writer`.
/// Accepts a `std.Io.Writer` by value or by pointer (`&writer`).
pub fn writeValue(writer: anytype, value: std.json.Value) !void {
    // Scratch for sorted object keys; the caller's Value tree is never mutated.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    switch (@TypeOf(writer)) {
        std.Io.Writer => {
            // By value: only safe for writers whose state lives inline
            // (e.g. std.Io.Writer.fixed); the copy is the whole state.
            var w = writer;
            try writeValueInner(&w, arena.allocator(), value);
        },
        *std.Io.Writer => {
            // By pointer: must not copy the struct — Allocating.drain
            // recovers its parent via @fieldParentPtr("writer", w), which
            // breaks if w is a copy.
            try writeValueInner(writer, arena.allocator(), value);
        },
        else => @compileError("writeValue expects a std.Io.Writer or *std.Io.Writer"),
    }
}

/// Serializes `value` to canonical JSON bytes. Caller owns the result.
pub fn stringify(allocator: Allocator, value: std.json.Value) ![]u8 {
    var aw = std.Io.Writer.Allocating.init(allocator);
    defer aw.deinit();
    try writeValue(&aw.writer, value);
    return allocator.dupe(u8, aw.written());
}

/// Returns "sha256:<hex>" of the canonical JSON bytes of `value`
/// (the digest pushed to and verified against a registry).
pub fn digestString(allocator: Allocator, value: std.json.Value) ![]const u8 {
    const bytes = try stringify(allocator, value);
    defer allocator.free(bytes);
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const hex = std.fmt.bytesToHex(&digest, std.fmt.Case.lower);
    return std.fmt.allocPrint(allocator, "sha256:{s}", .{&hex});
}

fn writeValueInner(w: *std.Io.Writer, allocator: Allocator, value: std.json.Value) !void {
    switch (value) {
        .null => try w.writeAll("null"),
        .bool => |b| try w.writeAll(if (b) "true" else "false"),
        .integer => |i| try w.print("{d}", .{i}),
        // ponytail: {d} routes floats through std.fmt.printFloat (ryu,
        // shortest round-trip: 1.5 -> "1.5", 0.0 -> "0"). The {f} specifier
        // is broken in Zig 0.16 (calls a nonexistent value.format); upgrade
        // when std fixes it. Manifests rarely carry floats.
        .float => |f| try w.print("{d}", .{f}),
        .number_string => |s| try w.writeAll(s),
        .string => |s| try writeString(w, s),
        .array => |arr| {
            try w.writeByte('[');
            for (arr.items, 0..) |item, i| {
                if (i != 0) try w.writeByte(',');
                try writeValueInner(w, allocator, item);
            }
            try w.writeByte(']');
        },
        .object => |obj| {
            try w.writeByte('{');
            // Keys must be emitted sorted by UTF-8 byte order; collect a
            // scratch array (sorted copy), never mutate the caller's map.
            const entries = try allocator.alloc(Entry, obj.count());
            defer allocator.free(entries);
            var n: usize = 0;
            var it = obj.iterator();
            while (it.next()) |entry| : (n += 1) {
                entries[n] = .{ .key = entry.key_ptr.*, .value = entry.value_ptr.* };
            }
            std.mem.sort(Entry, entries[0..n], {}, keyLessThan);
            for (entries[0..n], 0..) |e, i| {
                if (i != 0) try w.writeByte(',');
                try writeString(w, e.key);
                try w.writeByte(':');
                try writeValueInner(w, allocator, e.value);
            }
            try w.writeByte('}');
        },
    }
}

/// Writes a JSON string with minimal RFC 7159 escaping: `"` and `\` escaped,
/// control chars U+0000..U+001F as short forms (\b \f \n \r \t) or \u00XX
/// with lowercase hex; all other bytes (including non-ASCII UTF-8) verbatim.
fn writeString(w: *std.Io.Writer, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            0x08 => try w.writeAll("\\b"),
            0x09 => try w.writeAll("\\t"),
            0x0A => try w.writeAll("\\n"),
            0x0C => try w.writeAll("\\f"),
            0x0D => try w.writeAll("\\r"),
            else => {
                if (c < 0x20) {
                    try w.writeAll("\\u00");
                    try w.writeByte(hex_digits[c >> 4]);
                    try w.writeByte(hex_digits[c & 0x0F]);
                } else {
                    try w.writeByte(c);
                }
            },
        }
    }
    try w.writeByte('"');
}

fn parseValue(allocator: Allocator, text: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, allocator, text, .{});
}

test "nested object with out-of-order keys" {
    const a = std.testing.allocator;
    const parsed = try parseValue(a, "{\"b\":2,\"a\":{\"d\":4,\"c\":3}}");
    defer parsed.deinit();
    const out = try stringify(a, parsed.value);
    defer a.free(out);
    try std.testing.expectEqualStrings("{\"a\":{\"c\":3,\"d\":4},\"b\":2}", out);
}

test "string escaping (quote, backslash, \\n, \\t, control, non-ASCII verbatim)" {
    const a = std.testing.allocator;
    // Parsed string value: q"b\l <LF> i <TAB> t <SOH> café
    const parsed = try parseValue(a, "{\"s\":\"q\\\"b\\\\l\\ni\\tt\\u0001caf\u{e9}\"}");
    defer parsed.deinit();
    const out = try stringify(a, parsed.value);
    defer a.free(out);
    try std.testing.expectEqualStrings("{\"s\":\"q\\\"b\\\\l\\ni\\tt\\u0001caf\u{e9}\"}", out);
}

test "numbers: integer, negative, float" {
    const a = std.testing.allocator;
    const parsed = try parseValue(a, "{\"neg\":-42,\"i\":0,\"float\":1.5}");
    defer parsed.deinit();
    const out = try stringify(a, parsed.value);
    defer a.free(out);
    try std.testing.expectEqualStrings("{\"float\":1.5,\"i\":0,\"neg\":-42}", out);
}

test "null, true, false" {
    const a = std.testing.allocator;
    const parsed = try parseValue(a, "{\"t\":true,\"f\":false,\"n\":null}");
    defer parsed.deinit();
    const out = try stringify(a, parsed.value);
    defer a.free(out);
    try std.testing.expectEqualStrings("{\"f\":false,\"n\":null,\"t\":true}", out);
}

test "nested arrays" {
    const a = std.testing.allocator;
    const parsed = try parseValue(a, "{\"a\":[[1,2],[3,4]]}");
    defer parsed.deinit();
    const out = try stringify(a, parsed.value);
    defer a.free(out);
    try std.testing.expectEqualStrings("{\"a\":[[1,2],[3,4]]}", out);
}

test "empty containers" {
    const a = std.testing.allocator;
    const parsed = try parseValue(a, "{\"obj\":{},\"arr\":[]}");
    defer parsed.deinit();
    const out = try stringify(a, parsed.value);
    defer a.free(out);
    try std.testing.expectEqualStrings("{\"arr\":[],\"obj\":{}}", out);
}

test "deterministic: stringify twice yields identical bytes" {
    const a = std.testing.allocator;
    const parsed = try parseValue(a, "{\"b\":[3,1,{\"y\":true,\"x\":null}],\"a\":\"s\"}");
    defer parsed.deinit();
    const out1 = try stringify(a, parsed.value);
    defer a.free(out1);
    const out2 = try stringify(a, parsed.value);
    defer a.free(out2);
    try std.testing.expectEqualSlices(u8, out1, out2);
}

test "golden vector 1: nested object" {
    const a = std.testing.allocator;
    const parsed = try parseValue(a, "{\"b\":2,\"a\":{\"d\":4,\"c\":3}}");
    defer parsed.deinit();
    const out = try stringify(a, parsed.value);
    defer a.free(out);
    // printf '%s' '{"a":{"c":3,"d":4},"b":2}' | shasum -a 256
    const hex = sha256Hex(out);
    try std.testing.expectEqualStrings(
        "c461c47a913352f1a21e3f2ea49e1fd34754c0dc12cb7366e4636d5e186c6c6e",
        &hex,
    );
}

test "golden vector 2: string escaping" {
    const a = std.testing.allocator;
    const parsed = try parseValue(a, "{\"s\":\"q\\\"b\\\\l\\ni\\tt\\u0001caf\u{e9}\"}");
    defer parsed.deinit();
    const out = try stringify(a, parsed.value);
    defer a.free(out);
    // printf '%s' '{"s":"q\"b\\l\ni\tt\u0001café"}' | shasum -a 256
    const hex = sha256Hex(out);
    try std.testing.expectEqualStrings(
        "fd5983d5512c5d1d02b62ff894894ac2db6f3f8d3ac9800781295193c0f907ca",
        &hex,
    );
}

test "golden vector 3: numbers" {
    const a = std.testing.allocator;
    const parsed = try parseValue(a, "{\"neg\":-42,\"i\":0,\"float\":1.5}");
    defer parsed.deinit();
    const out = try stringify(a, parsed.value);
    defer a.free(out);
    // printf '%s' '{"float":1.5,"i":0,"neg":-42}' | shasum -a 256
    const hex = sha256Hex(out);
    try std.testing.expectEqualStrings(
        "d1c8ed449c22e6d88e6641c07c3c349869e1bb5e5c721f4ec0c1c3cf46e8755f",
        &hex,
    );
}

test "golden vector 4: null, true, false" {
    const a = std.testing.allocator;
    const parsed = try parseValue(a, "{\"t\":true,\"f\":false,\"n\":null}");
    defer parsed.deinit();
    const out = try stringify(a, parsed.value);
    defer a.free(out);
    // printf '%s' '{"f":false,"n":null,"t":true}' | shasum -a 256
    const hex = sha256Hex(out);
    try std.testing.expectEqualStrings(
        "22e00dc2f7b01420f940fbdbfbdf34fa0667cc6500186495023ba37722cbd05e",
        &hex,
    );
}

test "golden vector 5: nested arrays" {
    const a = std.testing.allocator;
    const parsed = try parseValue(a, "{\"a\":[[1,2],[3,4]]}");
    defer parsed.deinit();
    const out = try stringify(a, parsed.value);
    defer a.free(out);
    // printf '%s' '{"a":[[1,2],[3,4]]}' | shasum -a 256
    const hex = sha256Hex(out);
    try std.testing.expectEqualStrings(
        "98da7f7f5f1a86edf3a7d006350ab3b488f9580eb0e5f81fd444ff548dc61708",
        &hex,
    );
}

test "golden vector 6: empty containers" {
    const a = std.testing.allocator;
    const parsed = try parseValue(a, "{\"obj\":{},\"arr\":[]}");
    defer parsed.deinit();
    const out = try stringify(a, parsed.value);
    defer a.free(out);
    // printf '%s' '{"arr":[],"obj":{}}' | shasum -a 256
    const hex = sha256Hex(out);
    try std.testing.expectEqualStrings(
        "7c557880ceed861401b04be6735c9708e326427e072562fd259da6f6a2612b96",
        &hex,
    );
}

test "digestString returns sha256:<hex> of canonical bytes" {
    const a = std.testing.allocator;
    const parsed = try parseValue(a, "{\"b\":2,\"a\":{\"d\":4,\"c\":3}}");
    defer parsed.deinit();
    const digest = try digestString(a, parsed.value);
    defer a.free(digest);
    // digest of canonical bytes {"a":{"c":3,"d":4},"b":2}
    try std.testing.expectEqualStrings(
        "sha256:c461c47a913352f1a21e3f2ea49e1fd34754c0dc12cb7366e4636d5e186c6c6e",
        digest,
    );
}

test "writeValue to a fixed buffer writer" {
    const a = std.testing.allocator;
    const parsed = try parseValue(a, "{\"b\":2,\"a\":1}");
    defer parsed.deinit();
    var buf: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeValue(&w, parsed.value);
    try std.testing.expectEqualStrings("{\"a\":1,\"b\":2}", w.buffered());
}

fn sha256Hex(bytes: []const u8) [std.crypto.hash.sha2.Sha256.digest_length * 2]u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(&digest, std.fmt.Case.lower);
}
