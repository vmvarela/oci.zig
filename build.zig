const std = @import("std");

/// oci.zig — pure-Zig OCI Distribution client.
///
/// Builds and registers all 11 public modules in the `oci` package
/// (consumers: `b.dependency("oci", .{}).module("<name>")`), plus a
/// combined `test` step that runs the std.testing tests of every module
/// file against the host target.
pub fn build(b: *std.Build) void {
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
        // addTest's step only compiles; addRunArtifact actually executes the
        // binary so `zig build test` runs (not just compiles) the tests.
        const run = b.addRunArtifact(test_mod);
        test_step.dependOn(&run.step);
    }

    // Integration tests hit the network (a running zot registry) and are NOT
    // part of the default `test` step. Run with `zig build integration-test`
    // after pushing content via tests/setup.sh.
    //
    // The test imports the `root` module (which re-exports every submodule)
    // under the name "oci". Importing the submodules individually would
    // conflict: they use relative imports, so each is already part of the
    // root module's file set.
    const integration_test = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/integration.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    // std.c.getenv (used to read OCI_TEST_REGISTRY) needs libc.
    integration_test.root_module.link_libc = true;
    integration_test.root_module.addImport("oci", b.modules.get("root").?);
    // addTest's step only compiles; addRunArtifact actually executes the binary.
    const integration_run = b.addRunArtifact(integration_test);
    const integration_step = b.step("integration-test", "Run integration tests against a running zot registry");
    integration_step.dependOn(&integration_run.step);
}
