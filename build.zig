const std = @import("std");

/// oci.zig — pure-Zig OCI Distribution client.
///
/// Builds and registers all 11 public modules in the `oci` package
/// (consumers: `b.dependency("oci", .{}).module("<name>")`), plus a
/// combined `test` step that runs the std.testing tests of every module
/// file against the host target.
pub fn build(b: *std.Build) void {
    const ocispec = b.dependency("ocispec", .{});
    const ocispec_mod = ocispec.module("ocispec");

    const modules = [_]struct { name: []const u8, src: []const u8 }{
        .{ .name = "root", .src = "src/root.zig" },
        .{ .name = "client", .src = "src/client.zig" },
        .{ .name = "auth", .src = "src/auth.zig" },
        .{ .name = "reference", .src = "src/reference.zig" },
        .{ .name = "manifest", .src = "src/manifest.zig" },
        .{ .name = "blob", .src = "src/blob.zig" },
        .{ .name = "digest", .src = "src/digest.zig" },
        .{ .name = "canonical_json", .src = "src/canonical_json.zig" },
        .{ .name = "errors", .src = "src/errors.zig" },
        .{ .name = "secrets", .src = "src/secrets.zig" },
        .{ .name = "token_cache", .src = "src/token_cache.zig" },
    };

    for (modules) |m| {
        _ = b.addModule(m.name, .{ .root_source_file = b.path(m.src) });
    }

    const test_step = b.step("test", "Run unit tests");
    for (modules) |m| {
        // 0.16: addTest takes .root_module (no legacy .root_source_file).
        const test_mod = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(m.src),
                .target = b.graph.host,
                .optimize = .Debug,
            }),
        });
        // Import is lazy; harmless on modules that never reference it.
        test_mod.root_module.addImport("ocispec", ocispec_mod);
        test_step.dependOn(&test_mod.step);
    }
}
