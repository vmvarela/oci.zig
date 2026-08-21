//! TLS certificate types (mirror of rust-oci-client src/client.rs
//! Certificate / CertificateEncoding).

const std = @import("std");

/// The encoding of a certificate.
pub const CertificateEncoding = enum {
    der,
    pem,
};

/// An X.509 certificate. `data` is caller-owned (no allocation, no deinit) —
/// matches how ClientConfig holds other slices (user_agent, etc.).
pub const Certificate = struct {
    encoding: CertificateEncoding,
    data: []const u8,

    /// Builds a certificate from PEM bytes (caller-owned).
    pub fn fromPem(pem: []const u8) Certificate {
        return .{ .encoding = .pem, .data = pem };
    }

    /// Builds a certificate from DER bytes (caller-owned).
    pub fn fromDer(der: []const u8) Certificate {
        return .{ .encoding = .der, .data = der };
    }
};

test "fromPem sets pem encoding and preserves data" {
    const pem = "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n";
    const cert = Certificate.fromPem(pem);
    try std.testing.expectEqual(CertificateEncoding.pem, cert.encoding);
    try std.testing.expectEqualStrings(pem, cert.data);
}

test "fromDer sets der encoding and preserves data" {
    const der = [_]u8{ 0x30, 0x82, 0x01, 0x00 };
    const cert = Certificate.fromDer(&der);
    try std.testing.expectEqual(CertificateEncoding.der, cert.encoding);
    try std.testing.expectEqualSlices(u8, &der, cert.data);
}

test "CertificateEncoding has exactly der and pem" {
    try std.testing.expectEqual(@as(usize, 2), @typeInfo(CertificateEncoding).@"enum".fields.len);
}
