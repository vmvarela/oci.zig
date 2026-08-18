//! OCI Distribution client — Tier 1 read-path API (Client, resolvers,
//! pullManifest / pullBlob / pull* helpers).
//!
//! Phase C: implemented by the client lane. Placeholder only.

const std = @import("std");
const ocispec = @import("ocispec");

test {
    _ = std;
    _ = ocispec;
    @import("std").testing.refAllDecls(@This());
}
