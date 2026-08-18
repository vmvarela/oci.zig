//! Blob transport: SizedStream, BlobResponse, BlobStream over
//! std.http.Client with streaming and Range support.
//!
//! Phase B: implemented by the transport lane. Placeholder only.

const std = @import("std");
const ocispec = @import("ocispec");

test {
    _ = std;
    _ = ocispec;
    @import("std").testing.refAllDecls(@This());
}
