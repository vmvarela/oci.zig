//! TLS certificate types (mirror of rust-oci-client src/client.rs
//! Certificate / CertificateEncoding).

/// The encoding of a certificate.
pub const CertificateEncoding = enum {
    der,
    pem,
};

/// An X.509 certificate. `data` is caller-owned (no allocation, no deinit) —
/// matches how ClientConfig holds other slices (user_agent, etc.).
/// Build with `.{ .encoding = .pem, .data = bytes }` (or `.der`).
pub const Certificate = struct {
    encoding: CertificateEncoding,
    data: []const u8,
};
