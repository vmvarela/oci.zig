//! Tier 1 read-path OCI Distribution client (mirror of rust-oci-client
//! v0.17.0 `client.rs`), built on Zig 0.16 std only.
//!
//! Transport is `std.http.Client` (struct literal `.{ .allocator, .io }`),
//! `std.Io` for I/O, `std.crypto.tls` for TLS. Public API is ocispec-free:
//! manifests are `manifest.OciManifest`, digests are strings, credentials are
//! `secrets.RegistryAuth`, references are `reference.Reference`.
//!
//! Error semantics (from `errors.OciError`): 404 -> `error.NotFound`,
//! 403 -> `error.Forbidden`, other non-2xx -> `error.UnexpectedStatus`,
//! 401 after the token flow -> `error.Unauthorized`.
//!
//! Ownership: every returned slice is allocated with the Client's allocator.
//! `OciManifest` values have no `deinit` (their strings are allocated by
//! `manifest.parse`); pass an arena allocator as the Client's allocator to
//! reclaim them at a scope boundary.

const std = @import("std");
const builtin = @import("builtin");
const errors = @import("errors.zig");
const secrets = @import("secrets.zig");
const reference = @import("reference.zig");
const digest = @import("digest.zig");
const auth_mod = @import("auth.zig");
const token_cache = @import("token_cache.zig");
const manifest = @import("manifest.zig");
const blob = @import("blob.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

/// Transport scheme selection.
pub const ClientProtocol = union(enum) {
    http,
    https,
    /// Comma-separated registry hosts that must use plain http (e.g.
    /// "localhost,127.0.0.1:5000"). Matched against the reference registry
    /// (host, or host:port).
    https_except: []const u8,
};

/// Client configuration. `accept_invalid_certificates` is accepted for API
/// parity but currently unused: `std.http.Client` has no per-request flag to
/// disable TLS verification (verification is all-or-nothing via the client's
/// `ca_bundle`). ponytail: TODO — wire it to a custom `ca_bundle` when needed.
pub const ClientConfig = struct {
    protocol: ClientProtocol = .https,
    user_agent: []const u8 = "oci.zig/0.1.0",
    accept_invalid_certificates: bool = false,
    /// Resolves an image index to a single platform manifest digest. Used by
    /// `pull` when the fetched document is an index. Defaults to
    /// `linuxAmd64Resolver`.
    platform_resolver: ?*const fn ([]const manifest.OciDescriptor) ?[]const u8 = null,

    /// Effective scheme for `registry` (https unless excepted).
    pub fn scheme(self: ClientConfig, registry: []const u8) []const u8 {
        return switch (self.protocol) {
            .http => "http",
            .https => "https",
            .https_except => |exceptions| blk: {
                var it = std.mem.splitScalar(u8, exceptions, ',');
                while (it.next()) |entry| {
                    const e = std.mem.trim(u8, entry, " \t");
                    if (e.len == 0) continue;
                    if (std.ascii.eqlIgnoreCase(e, registry)) break :blk "http";
                    if (std.mem.indexOfScalar(u8, registry, ':')) |colon| {
                        if (std.ascii.eqlIgnoreCase(e, registry[0..colon])) break :blk "http";
                    }
                }
                break :blk "https";
            },
        };
    }
};

/// Result of `pull`: the (possibly platform-resolved) manifest, the config
/// blob content when present, and the layer descriptors.
pub const ImageData = struct {
    manifest: manifest.OciManifest,
    config: ?[]const u8,
    layers: []manifest.OciDescriptor,
};

/// The OCI client. Holds configuration, the allocator, and the bearer token
/// cache. A fresh `std.http.Client` is created per operation from the `io`
/// passed to each method.
pub const Client = struct {
    config: ClientConfig,
    allocator: Allocator,
    token_cache: token_cache.TokenCache,

    pub fn init(allocator: Allocator, config: ClientConfig) Client {
        return .{
            .config = config,
            .allocator = allocator,
            .token_cache = token_cache.TokenCache.init(allocator),
        };
    }

    pub fn deinit(self: *Client) void {
        self.token_cache.deinit();
    }

    /// Resolves a bearer token for `image`/`op`, or null when the registry
    /// needs no authentication. Probes the image's manifest URL; on 401 it
    /// parses the `WWW-Authenticate` Bearer challenge, requests a token from
    /// the challenge realm (with the caller's credentials), caches it, and
    /// returns it. Returns null on a 200 probe.
    pub fn auth(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth, op: token_cache.RegistryOperation) !?[]const u8 {
        const probe = if (image.digest) |d|
            try std.fmt.allocPrint(self.allocator, "manifests/{s}", .{d})
        else if (image.tag) |t|
            try std.fmt.allocPrint(self.allocator, "manifests/{s}", .{t})
        else
            try self.allocator.dupe(u8, "");
        defer self.allocator.free(probe);
        const url = try buildUrl(self.allocator, self.config, image, probe, null);
        defer self.allocator.free(url);
        const uri = try std.Uri.parse(url);

        var http: std.http.Client = .{ .allocator = self.allocator, .io = io };
        defer http.deinit();
        var redirect_buf: [8192]u8 = undefined;

        var req = try http.request(.GET, uri, .{ .redirect_behavior = .unhandled });
        defer req.deinit();
        try req.sendBodiless();
        var resp = try req.receiveHead(&redirect_buf);
        const status = resp.head.status;

        var challenge_value: ?[]const u8 = null;
        if (status == .unauthorized) {
            var it = resp.head.iterateHeaders();
            while (it.next()) |h| {
                if (std.ascii.eqlIgnoreCase(h.name, "www-authenticate")) {
                    challenge_value = try self.allocator.dupe(u8, h.value);
                    break;
                }
            }
        }
        defer if (challenge_value) |v| self.allocator.free(v);

        switch (status) {
            .ok => return null,
            .unauthorized => {},
            else => return error.UnexpectedStatus,
        }

        const challenge = try auth_mod.parseBearerChallenge(challenge_value orelse return error.Unauthorized);
        defer challenge.deinit();

        // Token request: GET realm?service=..&scope=.. with the caller's creds.
        const token_url_str = try self.buildTokenUrlString(challenge);
        defer self.allocator.free(token_url_str);
        const token_uri = try std.Uri.parse(token_url_str);

        const auth_value = try secrets.basicAuthHeader(creds, self.allocator);
        defer if (auth_value) |v| self.allocator.free(v);

        var req2 = try http.request(.GET, token_uri, .{
            .redirect_behavior = .unhandled,
            .headers = .{ .authorization = if (auth_value) |v| .{ .override = v } else .default },
        });
        defer req2.deinit();
        try req2.sendBodiless();
        var resp2 = try req2.receiveHead(&redirect_buf);
        if (resp2.head.status != .ok) {
            return error.Unauthorized;
        }
        var transfer_buf: [8192]u8 = undefined;
        var out = std.ArrayList(u8).empty;
        defer out.deinit(self.allocator);
        const reader = resp2.reader(&transfer_buf);
        var chunk: [4096]u8 = undefined;
        while (true) {
            const n = try reader.readSliceShort(&chunk);
            if (n == 0) break;
            try out.appendSlice(self.allocator, chunk[0..n]);
        }

        const TokenResp = struct { token: ?[]const u8 = null, access_token: ?[]const u8 = null };
        const parsed = try std.json.parseFromSliceLeaky(TokenResp, self.allocator, out.items, .{ .ignore_unknown_fields = true });
        const token = parsed.token orelse parsed.access_token orelse return error.InvalidResponse;
        try self.token_cache.put(image.registry, image.repository, op, token, nowUnixSeconds(io));
        return try self.allocator.dupe(u8, token);
    }

    /// Lists the tags of `image`'s repository. `n` limits the result and
    /// `last` resumes after a tag (pagination). Two-level ownership: the
    /// returned slice and each tag string are separate allocations from the
    /// Client's allocator — free the slice, then each tag.
    pub fn listTags(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth, n: ?usize, last: ?[]const u8) ![]const []const u8 {
        var q = std.ArrayList(u8).empty;
        defer q.deinit(self.allocator);
        var first = true;
        if (n) |count| {
            const ns = try std.fmt.allocPrint(self.allocator, "n={d}", .{count});
            defer self.allocator.free(ns);
            try q.appendSlice(self.allocator, ns);
            first = false;
        }
        if (last) |l| {
            if (!first) try q.append(self.allocator, '&');
            try q.appendSlice(self.allocator, "last=");
            const enc = try percentEncode(self.allocator, l);
            defer self.allocator.free(enc);
            try q.appendSlice(self.allocator, enc);
        }
        const query: ?[]const u8 = if (q.items.len > 0) q.items else null;
        const url = try buildUrl(self.allocator, self.config, image, "tags/list", query);
        defer self.allocator.free(url);
        const uri = try std.Uri.parse(url);
        var result = try self.getBody(io, image, creds, .pull, uri, &.{});
        defer result.deinit(self.allocator);
        const TagList = struct { tags: []const []const u8 };
        const parsed = try std.json.parseFromSliceLeaky(TagList, self.allocator, result.body, .{ .allocate = .alloc_always, .ignore_unknown_fields = true });
        return parsed.tags;
    }

    /// Fetches the `Docker-Content-Digest` header of `image`'s manifest.
    /// Returns the digest string (allocated). Errors with `InvalidResponse`
    /// when the header is absent.
    pub fn fetchManifestDigest(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth) ![]const u8 {
        const ref_part = image.digest orelse image.tag orelse return error.InvalidReference;
        const path = try std.fmt.allocPrint(self.allocator, "manifests/{s}", .{ref_part});
        defer self.allocator.free(path);
        const url = try buildUrl(self.allocator, self.config, image, path, null);
        defer self.allocator.free(url);
        const uri = try std.Uri.parse(url);
        const accept = try acceptHeader(self.allocator, &manifest_accept_types);
        defer self.allocator.free(accept);
        var result = try self.getBody(io, image, creds, .pull, uri, &.{.{ .name = "Accept", .value = accept }});
        errdefer result.deinit(self.allocator);
        const d = result.digest_header orelse return error.InvalidResponse;
        result.digest_header = null;
        result.deinit(self.allocator);
        return d;
    }

    /// Pulls `image`'s manifest and its digest. The digest comes from the
    /// `Docker-Content-Digest` header, or is computed as sha256 of the body
    /// when the header is absent.
    pub fn pullManifest(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth) !PulledManifest {
        return self.pullManifestImpl(io, image, creds, &manifest_accept_types);
    }

    /// Pulls a single-platform manifest and its config blob. Errors when the
    /// fetched document is an index.
    pub fn pullManifestAndConfig(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth) !struct { manifest: manifest.OciImageManifest, config_digest: []const u8, config: []const u8 } {
        const pulled = try self.pullManifest(io, image, creds);
        defer self.allocator.free(pulled.digest);
        switch (pulled.manifest) {
            .index => return error.OciError,
            .manifest => |man| {
                const config_desc = man.config orelse return error.InvalidResponse;
                var aw = std.Io.Writer.Allocating.init(self.allocator);
                defer aw.deinit();
                try self.pullBlob(io, image, config_desc.digest, &aw.writer);
                const config = try self.allocator.dupe(u8, aw.written());
                return .{ .manifest = man, .config_digest = config_desc.digest, .config = config };
            },
        }
    }

    /// Streams a full blob to `writer`, verifying its sha256 digest on
    /// completion. `writer` is a `std.Io.Writer` (by value or pointer) or any
    /// type exposing `writeAll([]const u8) !void`. Auth via cached token; call
    /// `pullManifest`/`auth` first on private registries.
    pub fn pullBlob(self: *Client, io: Io, image: reference.Reference, digest_str: []const u8, writer: anytype) !void {
        var open = try self.openBlob(io, image, digest_str, null);
        errdefer {
            open.req.deinit();
            open.container.client.deinit();
            self.allocator.destroy(open.container);
        }
        var bs = blob.BlobStream.init(.{
            .reader = open.resp.reader(&open.container.transfer_buf),
            .size = open.resp.head.content_length orelse 0,
        }, try digest.parse(digest_str));
        var buf: [64 * 1024]u8 = undefined;
        while (true) {
            const n = try bs.read(&buf);
            if (n == 0) break;
            try writeAllTo(writer, buf[0..n]);
        }
        try bs.finish();
        open.req.deinit();
        open.container.client.deinit();
        self.allocator.destroy(open.container);
    }

    /// Opens a full blob for streaming. The consumer reads `stream` to EOF,
    /// calls `stream.finish()`, then `result.deinit()`. Auth via cached token;
    /// call `pullManifest`/`auth` first on private registries.
    pub fn pullBlobStream(self: *Client, io: Io, image: reference.Reference, digest_str: []const u8) !BlobStreamResult {
        var open = try self.openBlob(io, image, digest_str, null);
        var ok = false;
        defer if (!ok) {
            open.req.deinit();
            open.container.client.deinit();
            self.allocator.destroy(open.container);
        };
        const stream = blob.BlobStream.init(.{
            .reader = open.resp.reader(&open.container.transfer_buf),
            .size = open.resp.head.content_length orelse 0,
        }, try digest.parse(digest_str));
        ok = true;
        return .{ .stream = stream, .req = open.req, .container = open.container };
    }

    /// Opens a partial (Range) blob fetch. `offset` is the start byte and
    /// `length` the number of bytes (null = to end of blob). Expects a 206;
    /// the stream size is the full blob size from `Content-Range`. NO digest
    /// verification (upstream parity). The consumer reads `response` to EOF,
    /// then `result.deinit()`. Auth via cached token; call `pullManifest`/`auth`
    /// first on private registries.
    pub fn pullBlobStreamPartial(self: *Client, io: Io, image: reference.Reference, digest_str: []const u8, offset: u64, length: ?u64) !BlobResponseResult {
        if (length != null and length.? == 0) return error.InvalidRange;
        const range = if (length) |len|
            try std.fmt.allocPrint(self.allocator, "bytes={d}-{d}", .{ offset, offset + len - 1 })
        else
            try std.fmt.allocPrint(self.allocator, "bytes={d}-", .{offset});
        defer self.allocator.free(range);

        var open = try self.openBlob(io, image, digest_str, range);
        var ok = false;
        defer if (!ok) {
            open.req.deinit();
            open.container.client.deinit();
            self.allocator.destroy(open.container);
        };
        if (open.resp.head.status != .partial_content) return error.UnexpectedStatus;
        const total = contentRangeTotal(open.resp.head) orelse return error.InvalidResponse;
        const stream = blob.SizedStream{ .reader = open.resp.reader(&open.container.transfer_buf), .size = total };
        ok = true;
        return .{ .response = .{ .partial = stream }, .req = open.req, .container = open.container };
    }

    /// Convenience pull: fetches the manifest (resolving an index to the
    /// configured platform), the config blob when present, and the layer
    /// descriptors.
    pub fn pull(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth, accepted_media_types: []const []const u8) !ImageData {
        var m = try self.pullManifestImpl(io, image, creds, accepted_media_types);
        if (m.manifest.isIndex()) {
            const resolver = self.config.platform_resolver orelse linuxAmd64Resolver;
            const digest_str = resolver(m.manifest.index.manifests) orelse {
                self.allocator.free(m.digest);
                return error.NotFound;
            };
            self.allocator.free(m.digest);
            const sub = reference.Reference{ .registry = image.registry, .repository = image.repository, .digest = digest_str };
            m = try self.pullManifestImpl(io, sub, creds, accepted_media_types);
        }
        defer self.allocator.free(m.digest);

        var config: ?[]const u8 = null;
        var layers: []manifest.OciDescriptor = &.{};
        switch (m.manifest) {
            .manifest => |man| {
                if (man.config) |c| {
                    var aw = std.Io.Writer.Allocating.init(self.allocator);
                    defer aw.deinit();
                    try self.pullBlob(io, image, c.digest, &aw.writer);
                    config = try self.allocator.dupe(u8, aw.written());
                }
                layers = man.layers;
            },
            .index => unreachable,
        }
        return .{ .manifest = m.manifest, .config = config, .layers = layers };
    }

    /// Lists the referrers of `image`'s digest (OCI 1.1 referrers API),
    /// optionally filtered by `artifact_type`. On a 404 from the referrers
    /// endpoint, falls back to fetching the manifest by digest with
    /// `Accept: oci_index` (upstream parity). Returns the index descriptors.
    pub fn pullReferrers(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth, artifact_type: ?[]const u8) ![]manifest.OciDescriptor {
        const digest_str = image.digest orelse return error.InvalidReference;
        const path = try std.fmt.allocPrint(self.allocator, "referrers/{s}", .{digest_str});
        defer self.allocator.free(path);
        const query = if (artifact_type) |at|
            try std.fmt.allocPrint(self.allocator, "artifactType={s}", .{try percentEncode(self.allocator, at)})
        else
            null;
        defer if (query) |q| self.allocator.free(q);
        const url = try buildUrl(self.allocator, self.config, image, path, query);
        defer self.allocator.free(url);
        const uri = try std.Uri.parse(url);

        var result = self.getBody(io, image, creds, .pull, uri, &.{.{ .name = "Accept", .value = manifest.oci_index }}) catch |err| switch (err) {
            error.NotFound => {
                // Fallback: fetch the manifest by digest as an index.
                const path2 = try std.fmt.allocPrint(self.allocator, "manifests/{s}", .{digest_str});
                defer self.allocator.free(path2);
                const url2 = try buildUrl(self.allocator, self.config, image, path2, null);
                defer self.allocator.free(url2);
                const uri2 = try std.Uri.parse(url2);
                var r2 = try self.getBody(io, image, creds, .pull, uri2, &.{.{ .name = "Accept", .value = manifest.oci_index }});
                defer r2.deinit(self.allocator);
                return indexDescriptors(self.allocator, r2.body);
            },
            else => return err,
        };
        defer result.deinit(self.allocator);
        return indexDescriptors(self.allocator, result.body);
    }

    /// Returns the bearer token for `image`/`op` (from the cache when fresh,
    /// otherwise via the auth flow), or null when no auth is needed. Internal
    /// token-cache helper, exposed for callers that want to pre-authenticate.
    pub fn storeAuthIfNeeded(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth, op: token_cache.RegistryOperation) !?[]const u8 {
        const now = nowUnixSeconds(io);
        if (self.token_cache.get(image.registry, image.repository, op, now)) |t| {
            return try self.allocator.dupe(u8, t.token);
        }
        return self.auth(io, image, creds, op);
    }

    // ---- internal helpers ----

    fn pullManifestImpl(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth, accept_types: []const []const u8) !PulledManifest {
        const ref_part = image.digest orelse image.tag orelse return error.InvalidReference;
        const path = try std.fmt.allocPrint(self.allocator, "manifests/{s}", .{ref_part});
        defer self.allocator.free(path);
        const url = try buildUrl(self.allocator, self.config, image, path, null);
        defer self.allocator.free(url);
        const uri = try std.Uri.parse(url);
        const accept = try acceptHeader(self.allocator, accept_types);
        defer self.allocator.free(accept);
        var result = try self.getBody(io, image, creds, .pull, uri, &.{.{ .name = "Accept", .value = accept }});
        defer result.deinit(self.allocator);

        const digest_str = if (result.digest_header) |d|
            try self.allocator.dupe(u8, d)
        else
            try sha256DigestString(self.allocator, result.body);
        errdefer self.allocator.free(digest_str);
        const m = try manifest.OciManifest.parse(self.allocator, result.body);
        return .{ .manifest = m, .digest = digest_str };
    }

    /// Authorization header value for (image, op): the cached token if fresh,
    /// else derived directly from the caller's `auth` (no probe — a 401 on the
    /// actual request triggers the token flow). Caller frees the result.
    fn authorizationHeader(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth, op: token_cache.RegistryOperation) !?[]const u8 {
        const now = nowUnixSeconds(io);
        if (self.token_cache.get(image.registry, image.repository, op, now)) |t| {
            return try std.fmt.allocPrint(self.allocator, "Bearer {s}", .{t.token});
        }
        return secrets.basicAuthHeader(creds, self.allocator);
    }

    /// GET with auth (cache -> caller auth -> 401 token flow + one retry).
    /// Maps 404 -> NotFound, 403 -> Forbidden, other non-2xx -> UnexpectedStatus.
    /// Returns the body plus copied `Docker-Content-Digest` / `Content-Range`
    /// headers (owned by the caller via `GetResult.deinit`).
    fn getBody(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth, op: token_cache.RegistryOperation, uri: std.Uri, headers: []const std.http.Header) !GetResult {
        var http: std.http.Client = .{ .allocator = self.allocator, .io = io };
        defer http.deinit();
        var redirect_buf: [8192]u8 = undefined;

        var attempts: usize = 0;
        while (attempts < 2) : (attempts += 1) {
            const auth_value = try self.authorizationHeader(io, image, creds, op);
            defer if (auth_value) |v| self.allocator.free(v);

            var req = try http.request(.GET, uri, .{
                .redirect_behavior = .unhandled,
                .headers = .{ .authorization = if (auth_value) |v| .{ .override = v } else .default },
                .extra_headers = headers,
            });
            defer req.deinit();
            try req.sendBodiless();
            var resp = try req.receiveHead(&redirect_buf);
            const status = resp.head.status;

            if (status == .unauthorized and attempts == 0) {
                const token = try self.auth(io, image, creds, op);
                if (token) |t| self.allocator.free(t);
                continue;
            }

            switch (status) {
                .not_found => return error.NotFound,
                .forbidden => return error.Forbidden,
                else => {
                    if (status.class() != .success) return error.UnexpectedStatus;
                },
            }

            var result = GetResult{ .status = status };
            errdefer result.deinit(self.allocator);
            {
                var it = resp.head.iterateHeaders();
                while (it.next()) |h| {
                    if (std.ascii.eqlIgnoreCase(h.name, "docker-content-digest")) {
                        result.digest_header = try self.allocator.dupe(u8, h.value);
                    } else if (std.ascii.eqlIgnoreCase(h.name, "content-range")) {
                        result.content_range = try self.allocator.dupe(u8, h.value);
                    }
                }
            }
            var transfer_buf: [8192]u8 = undefined;
            var out = std.ArrayList(u8).empty;
            defer out.deinit(self.allocator);
            const reader = resp.reader(&transfer_buf);
            var chunk: [4096]u8 = undefined;
            while (true) {
                const n = try reader.readSliceShort(&chunk);
                if (n == 0) break;
                try out.appendSlice(self.allocator, chunk[0..n]);
            }
            result.body = try out.toOwnedSlice(self.allocator);
            return result;
        }
        return error.Unauthorized;
    }

    /// Opens a blob GET (full or Range) with auth retry, returning the
    /// received response. The `BlobHttp` container keeps the http.Client and
    /// transfer buffers alive; `req` points into it at a stable address.
    fn openBlob(self: *Client, io: Io, image: reference.Reference, digest_str: []const u8, range: ?[]const u8) !OpenBlob {
        const path = try std.fmt.allocPrint(self.allocator, "blobs/{s}", .{digest_str});
        defer self.allocator.free(path);
        const url = try buildUrl(self.allocator, self.config, image, path, null);
        defer self.allocator.free(url);
        const uri = try std.Uri.parse(url);

        const container = try self.allocator.create(BlobHttp);
        container.* = .{ .client = .{ .allocator = self.allocator, .io = io }, .req = undefined };
        errdefer {
            container.client.deinit();
            self.allocator.destroy(container);
        }

        var headers: [1]std.http.Header = undefined;
        var headers_len: usize = 0;
        if (range) |r| {
            headers[0] = .{ .name = "Range", .value = r };
            headers_len = 1;
        }

        var attempts: usize = 0;
        while (attempts < 2) : (attempts += 1) {
            const auth_value = try self.authorizationHeader(io, image, .anonymous, .pull);
            defer if (auth_value) |v| self.allocator.free(v);

            container.req = try container.client.request(.GET, uri, .{
                .redirect_behavior = .unhandled,
                .headers = .{ .authorization = if (auth_value) |v| .{ .override = v } else .default },
                .extra_headers = headers[0..headers_len],
            });
            errdefer container.req.deinit();
            try container.req.sendBodiless();
            const resp = try container.req.receiveHead(&container.redirect_buf);
            const status = resp.head.status;

            if (status == .unauthorized and attempts == 0) {
                container.req.deinit();
                const token = try self.auth(io, image, .anonymous, .pull);
                if (token) |t| self.allocator.free(t);
                continue;
            }

            switch (status) {
                .not_found => return error.NotFound,
                .forbidden => return error.Forbidden,
                else => {
                    if (status.class() != .success) return error.UnexpectedStatus;
                },
            }
            return .{ .container = container, .req = &container.req, .resp = resp };
        }
        return error.Unauthorized;
    }

    fn buildTokenUrlString(self: *Client, challenge: auth_mod.Challenge) ![]u8 {
        var buf = std.ArrayList(u8).empty;
        defer buf.deinit(self.allocator);
        try buf.appendSlice(self.allocator, challenge.realm);
        var first = std.mem.indexOfScalar(u8, challenge.realm, '?') == null;
        if (challenge.service) |s| {
            try buf.append(self.allocator, if (first) '?' else '&');
            first = false;
            try buf.appendSlice(self.allocator, "service=");
            const enc = try percentEncode(self.allocator, s);
            defer self.allocator.free(enc);
            try buf.appendSlice(self.allocator, enc);
        }
        if (challenge.scope) |s| {
            try buf.append(self.allocator, if (first) '?' else '&');
            try buf.appendSlice(self.allocator, "scope=");
            const enc = try percentEncode(self.allocator, s);
            defer self.allocator.free(enc);
            try buf.appendSlice(self.allocator, enc);
        }
        return buf.toOwnedSlice(self.allocator);
    }
};

/// A pulled manifest plus its digest (both allocated with the Client's
/// allocator).
pub const PulledManifest = struct {
    manifest: manifest.OciManifest,
    digest: []const u8,
};

/// Heap container keeping the http.Client and transfer buffers alive for the
/// lifetime of a returned blob Request (Request.deinit dereferences the
/// Client, and the body reader aliases the transfer buffer).
///
/// Note: `req.uri` slices point into the caller's url string, which is freed
/// when openBlob returns. This is inert — the request has already been sent
/// (sendHead ran) and redirects are `.unhandled`, so the uri is never read
/// again.
const BlobHttp = struct {
    client: std.http.Client,
    req: std.http.Client.Request,
    redirect_buf: [8192]u8 = undefined,
    transfer_buf: [64 * 1024]u8 = undefined,
};

/// A full-blob stream plus the owning Request and container. The consumer
/// reads `stream` to EOF, calls `stream.finish()`, then `deinit()` (which
/// releases the Request, the http.Client, and the container).
pub const BlobStreamResult = struct {
    stream: blob.BlobStream,
    req: *std.http.Client.Request,
    container: *BlobHttp,

    pub fn deinit(self: *BlobStreamResult) void {
        // Capture the allocator before client.deinit() (which sets client.*
        // to undefined).
        const allocator = self.container.client.allocator;
        self.req.deinit();
        self.container.client.deinit();
        allocator.destroy(self.container);
    }
};

/// A partial-blob response plus the owning Request and container. The
/// consumer reads `response` to EOF, then `deinit()`.
pub const BlobResponseResult = struct {
    response: blob.BlobResponse,
    req: *std.http.Client.Request,
    container: *BlobHttp,

    pub fn deinit(self: *BlobResponseResult) void {
        const allocator = self.container.client.allocator;
        self.req.deinit();
        self.container.client.deinit();
        allocator.destroy(self.container);
    }
};

const OpenBlob = struct {
    container: *BlobHttp,
    req: *std.http.Client.Request,
    resp: std.http.Client.Response,
};

/// Owned GET result; free with `deinit`.
const GetResult = struct {
    status: std.http.Status,
    body: []u8 = &.{},
    digest_header: ?[]u8 = null,
    content_range: ?[]u8 = null,

    fn deinit(self: *GetResult, allocator: Allocator) void {
        if (self.body.len > 0) allocator.free(self.body);
        if (self.digest_header) |d| allocator.free(d);
        if (self.content_range) |c| allocator.free(c);
    }
};

/// The five manifest/index/artifact media types accepted on manifest GETs.
const manifest_accept_types = [_][]const u8{
    manifest.oci_manifest,
    manifest.oci_index,
    manifest.docker_manifest_v2,
    manifest.docker_manifest_list,
    manifest.oci_artifact,
};

/// Joins media types into a single `Accept` header value.
fn acceptHeader(allocator: Allocator, types: []const []const u8) ![]u8 {
    return std.mem.join(allocator, ",", types);
}

/// Builds "<scheme>://<registry>/v2/<repository>/<path>[?<query>]".
/// `path` is the API path after "/v2/<repository>/" (e.g. "manifests/v1").
fn buildUrl(allocator: Allocator, config: ClientConfig, image: reference.Reference, path: []const u8, query: ?[]const u8) ![]u8 {
    const scheme = config.scheme(image.registry);
    if (query) |q| {
        return std.fmt.allocPrint(allocator, "{s}://{s}/v2/{s}/{s}?{s}", .{ scheme, image.registry, image.repository, path, q });
    }
    return std.fmt.allocPrint(allocator, "{s}://{s}/v2/{s}/{s}", .{ scheme, image.registry, image.repository, path });
}

/// Parses the `/total` of a `Content-Range: bytes <start>-<end>/<total>` header.
fn contentRangeTotal(head: std.http.Client.Response.Head) ?u64 {
    var it = head.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "content-range")) {
            const slash = std.mem.lastIndexOfScalar(u8, h.value, '/') orelse return null;
            return std.fmt.parseInt(u64, h.value[slash + 1 ..], 10) catch null;
        }
    }
    return null;
}

/// Parses a body as an OCI index and returns its descriptors.
fn indexDescriptors(allocator: Allocator, body: []const u8) ![]manifest.OciDescriptor {
    const m = try manifest.OciManifest.parse(allocator, body);
    switch (m) {
        .index => |idx| return idx.manifests,
        .manifest => return error.InvalidResponse,
    }
}

/// Percent-encodes `s` for use in a URI query value (RFC 3986 unreserved set
/// kept verbatim).
fn percentEncode(allocator: Allocator, s: []const u8) ![]u8 {
    const hex = "0123456789ABCDEF";
    var out = try allocator.alloc(u8, s.len * 3);
    var n: usize = 0;
    for (s) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
            out[n] = c;
            n += 1;
        } else {
            out[n] = '%';
            out[n + 1] = hex[c >> 4];
            out[n + 2] = hex[c & 0x0f];
            n += 3;
        }
    }
    return allocator.realloc(out, n);
}

/// "sha256:<hex>" of `bytes`.
fn sha256DigestString(allocator: Allocator, bytes: []const u8) ![]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &out, .{});
    const hex = std.fmt.bytesToHex(out, .lower);
    return std.fmt.allocPrint(allocator, "sha256:{s}", .{&hex});
}

/// Current Unix time in seconds via the Io clock.
fn nowUnixSeconds(io: Io) i64 {
    return std.Io.Timestamp.toSeconds(std.Io.Clock.real.now(io));
}

/// Writes `bytes` to a `std.Io.Writer` (by value or pointer) or any type with
/// `writeAll([]const u8) !void`.
fn writeAllTo(writer: anytype, bytes: []const u8) !void {
    switch (@TypeOf(writer)) {
        std.Io.Writer => {
            // ponytail: copying a Writer value is only safe when its state
            // lives inline (e.g. fixed-buffer); Allocating writers must be
            // passed by pointer.
            var w = writer;
            try std.Io.Writer.writeAll(&w, bytes);
        },
        *std.Io.Writer => try writer.writeAll(bytes),
        else => try writer.writeAll(bytes),
    }
}

// ---- platform resolvers ----

/// First descriptor matching linux/amd64.
pub fn linuxAmd64Resolver(descriptors: []const manifest.OciDescriptor) ?[]const u8 {
    return resolvePlatform(descriptors, "amd64", "linux");
}

/// First descriptor matching windows/amd64.
pub fn windowsAmd64Resolver(descriptors: []const manifest.OciDescriptor) ?[]const u8 {
    return resolvePlatform(descriptors, "amd64", "windows");
}

/// First descriptor matching the build host's os/arch.
pub fn currentPlatformResolver(descriptors: []const manifest.OciDescriptor) ?[]const u8 {
    const arch = switch (builtin.cpu.arch) {
        .x86_64 => "amd64",
        .aarch64 => "arm64",
        else => return null,
    };
    const os = switch (builtin.os.tag) {
        .linux => "linux",
        .macos => "darwin",
        .windows => "windows",
        else => return null,
    };
    return resolvePlatform(descriptors, arch, os);
}

fn resolvePlatform(descriptors: []const manifest.OciDescriptor, arch: []const u8, os: []const u8) ?[]const u8 {
    for (descriptors) |d| {
        if (d.platform) |p| {
            if (std.ascii.eqlIgnoreCase(p.architecture, arch) and std.ascii.eqlIgnoreCase(p.os, os)) {
                return d.digest;
            }
        }
    }
    return null;
}

// ---- tests ----

test "ClientConfig defaults" {
    const c = ClientConfig{};
    try std.testing.expectEqual(ClientProtocol.https, c.protocol);
    try std.testing.expectEqualStrings("oci.zig/0.1.0", c.user_agent);
    try std.testing.expectEqual(false, c.accept_invalid_certificates);
    try std.testing.expectEqual(@as(?*const fn ([]const manifest.OciDescriptor) ?[]const u8, null), c.platform_resolver);
}

test "scheme resolution" {
    const http_cfg = ClientConfig{ .protocol = .http };
    try std.testing.expectEqualStrings("http", http_cfg.scheme("registry.example.com"));

    const https_cfg = ClientConfig{ .protocol = .https };
    try std.testing.expectEqualStrings("https", https_cfg.scheme("registry.example.com"));

    const except_cfg = ClientConfig{ .protocol = .{ .https_except = "localhost,127.0.0.1:5000" } };
    try std.testing.expectEqualStrings("http", except_cfg.scheme("localhost"));
    try std.testing.expectEqualStrings("http", except_cfg.scheme("localhost:5000"));
    try std.testing.expectEqualStrings("http", except_cfg.scheme("127.0.0.1:5000"));
    try std.testing.expectEqualStrings("https", except_cfg.scheme("registry.example.com"));
}

test "buildUrl" {
    const a = std.testing.allocator;
    const cfg = ClientConfig{ .protocol = .https };
    const image = try reference.parse("registry.example.com/foo/bar:v1");

    const url = try buildUrl(a, cfg, image, "manifests/v1", null);
    defer a.free(url);
    try std.testing.expectEqualStrings("https://registry.example.com/v2/foo/bar/manifests/v1", url);

    const url2 = try buildUrl(a, cfg, image, "tags/list", "n=10");
    defer a.free(url2);
    try std.testing.expectEqualStrings("https://registry.example.com/v2/foo/bar/tags/list?n=10", url2);

    const http_cfg = ClientConfig{ .protocol = .http };
    const url3 = try buildUrl(a, http_cfg, image, "blobs/sha256:abc", null);
    defer a.free(url3);
    try std.testing.expectEqualStrings("http://registry.example.com/v2/foo/bar/blobs/sha256:abc", url3);
}

test "linux and windows resolvers pick first matching platform" {
    const descriptors = [_]manifest.OciDescriptor{
        .{ .media_type = manifest.oci_manifest, .digest = "sha256:arm", .size = 1, .platform = .{ .architecture = "arm64", .os = "linux" } },
        .{ .media_type = manifest.oci_manifest, .digest = "sha256:amd", .size = 1, .platform = .{ .architecture = "amd64", .os = "linux" } },
        .{ .media_type = manifest.oci_manifest, .digest = "sha256:win", .size = 1, .platform = .{ .architecture = "amd64", .os = "windows" } },
    };
    try std.testing.expectEqualStrings("sha256:amd", linuxAmd64Resolver(&descriptors).?);
    try std.testing.expectEqualStrings("sha256:win", windowsAmd64Resolver(&descriptors).?);
}

test "resolver returns null when no platform matches" {
    const descriptors = [_]manifest.OciDescriptor{
        .{ .media_type = manifest.oci_manifest, .digest = "sha256:x", .size = 1, .platform = .{ .architecture = "s390x", .os = "linux" } },
    };
    try std.testing.expectEqual(@as(?[]const u8, null), linuxAmd64Resolver(&descriptors));
}

test "currentPlatformResolver matches the build host" {
    const arch = switch (builtin.cpu.arch) {
        .x86_64 => "amd64",
        .aarch64 => "arm64",
        else => return, // skip on unsupported hosts
    };
    const os = switch (builtin.os.tag) {
        .linux => "linux",
        .macos => "darwin",
        .windows => "windows",
        else => return,
    };
    const descriptors = [_]manifest.OciDescriptor{
        .{ .media_type = manifest.oci_manifest, .digest = "sha256:host", .size = 1, .platform = .{ .architecture = arch, .os = os } },
        .{ .media_type = manifest.oci_manifest, .digest = "sha256:other", .size = 1, .platform = .{ .architecture = "s390x", .os = "linux" } },
    };
    try std.testing.expectEqualStrings("sha256:host", currentPlatformResolver(&descriptors).?);
}
