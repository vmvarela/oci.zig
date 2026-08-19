//! oci.zig — pure-Zig OCI Distribution client (reimplementation of
//! rust-oci-client v0.17.0) on Zig 0.16.0 std only.
//!
//! Public module surface. Consumers import submodules either via
//! `@import("root")` re-exports below or directly by module name.

pub const errors = @import("errors.zig");
pub const secrets = @import("secrets.zig");
pub const reference = @import("reference.zig");
pub const digest = @import("digest.zig");
pub const auth = @import("auth.zig");
pub const token_cache = @import("token_cache.zig");
pub const canonical_json = @import("canonical_json.zig");
pub const manifest = @import("manifest.zig");
pub const blob = @import("blob.zig");
pub const client = @import("client.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
