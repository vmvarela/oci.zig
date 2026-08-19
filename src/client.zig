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
const canonical_json = @import("canonical_json.zig");

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

pub const ClientConfig = struct {
    protocol: ClientProtocol = .https,
    user_agent: []const u8 = "oci.zig/0.1.0",
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
        const token = try self.tokenFromChallenge(io, challenge, creds, challenge.scope orelse "") orelse return null;
        try self.token_cache.put(image.registry, image.repository, op, token);
        return token;
    }

    /// Lists the tags of `image`'s repository. `n` limits the result and
    /// `last` resumes after a tag (pagination). Two-level ownership: the
    /// returned slice and each tag string are separate allocations from the
    /// Client's allocator — free the slice, then each tag.
    pub fn listTags(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth, n: ?usize, last: ?[]const u8) ![]const []const u8 {
        const query = try buildPaginationQuery(self.allocator, n, last);
        defer if (query) |q| self.allocator.free(q);
        const url = try buildUrl(self.allocator, self.config, image, "tags/list", query);
        defer self.allocator.free(url);
        const uri = try std.Uri.parse(url);
        var result = try self.getBody(io, image, creds, .pull, uri, &.{});
        defer result.deinit(self.allocator);
        const TagList = struct { tags: []const []const u8 };
        const parsed = try std.json.parseFromSliceLeaky(TagList, self.allocator, result.body, .{ .allocate = .alloc_always, .ignore_unknown_fields = true });
        return parsed.tags;
    }

    /// Lists the repositories of `image`'s registry (registry-scoped, no
    /// repository segment in the URL). `n` limits the result and `last`
    /// resumes after a repository (pagination: the caller passes the last
    /// returned repository back as `last` on the next call; the response
    /// carries no pagination fields). Two-level ownership: the returned slice
    /// and each repository string are separate allocations from the Client's
    /// allocator — free the slice, then each repo string.
    pub fn catalog(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth, n: ?usize, last: ?[]const u8) ![]const []const u8 {
        const url = try catalogUrl(self.allocator, self.config, image, n, last);
        defer self.allocator.free(url);
        const uri = try std.Uri.parse(url);
        var result = try self.getBody(io, image, creds, .pull, uri, &.{});
        defer result.deinit(self.allocator);
        const Catalog = struct { repositories: []const []const u8 };
        const parsed = try std.json.parseFromSliceLeaky(Catalog, self.allocator, result.body, .{ .allocate = .alloc_always, .ignore_unknown_fields = true });
        return parsed.repositories;
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

    /// Checks whether the blob `digest_str` exists in `image`'s repository
    /// (HEAD on the blob URL). Returns false when the blob is absent (404);
    /// any other failure is an error.
    pub fn blobExists(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth, digest_str: []const u8) !bool {
        const path = try std.fmt.allocPrint(self.allocator, "blobs/{s}", .{digest_str});
        defer self.allocator.free(path);
        const url = try buildUrl(self.allocator, self.config, image, path, null);
        defer self.allocator.free(url);
        const uri = try std.Uri.parse(url);
        return self.headRequest(io, image, creds, .pull, uri);
    }

    /// HEAD with auth (cache -> caller auth -> 401 token flow + one retry).
    /// Returns true on success, false on 404. `.forbidden` -> error.Forbidden,
    /// other non-success statuses -> error.UnexpectedStatus. No body is read.
    fn headRequest(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth, op: token_cache.RegistryOperation, uri: std.Uri) !bool {
        var http: std.http.Client = .{ .allocator = self.allocator, .io = io };
        defer http.deinit();
        var redirect_buf: [8192]u8 = undefined;

        var attempts: usize = 0;
        while (attempts < 2) : (attempts += 1) {
            const auth_value = try self.authorizationHeader(io, image, creds, op);
            defer if (auth_value) |v| self.allocator.free(v);

            var req = try http.request(.HEAD, uri, .{
                .redirect_behavior = .unhandled,
                .headers = .{ .authorization = if (auth_value) |v| .{ .override = v } else .default },
            });
            defer req.deinit();
            try req.sendBodiless();
            const resp = try req.receiveHead(&redirect_buf);
            const status = resp.head.status;

            if (status == .unauthorized and attempts == 0) {
                const token = try self.auth(io, image, creds, op);
                if (token) |t| self.allocator.free(t);
                continue;
            }

            switch (status) {
                .not_found => return false,
                .forbidden => return error.Forbidden,
                else => {
                    if (status.class() != .success) return error.UnexpectedStatus;
                    return true;
                },
            }
        }
        return error.Unauthorized;
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
    /// optionally filtered by `artifact_type` (exact match). Requests use the
    /// distribution media-type Accept header. On a 404 from the referrers
    /// endpoint, falls back to the tag schema: fetches `manifests/{tag}`
    /// where the tag is the digest with ':' replaced by '-'. A not-found
    /// fallback returns an EMPTY descriptor slice (no-referrers sentinel, not
    /// an error); a fallback resolving to a non-index document is an error
    /// (InvalidResponse). When `artifact_type` is set, the fallback
    /// descriptors are filtered client-side, order preserved. Ownership:
    /// descriptor strings are arena-allocated by `manifest.OciManifest.parse`;
    /// the returned slice references them.
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
        const accept = try acceptHeader(self.allocator, &distribution_accept_types);
        defer self.allocator.free(accept);

        var result = self.getBody(io, image, creds, .pull, uri, &.{.{ .name = "Accept", .value = accept }}) catch |err| switch (err) {
            error.NotFound => {
                // Tag-schema fallback: digest "sha256:abc" -> tag "sha256-abc".
                const tag = try std.mem.replaceOwned(u8, self.allocator, digest_str, ":", "-");
                defer self.allocator.free(tag);
                const path2 = try std.fmt.allocPrint(self.allocator, "manifests/{s}", .{tag});
                defer self.allocator.free(path2);
                const url2 = try buildUrl(self.allocator, self.config, image, path2, null);
                defer self.allocator.free(url2);
                const uri2 = try std.Uri.parse(url2);
                var r2 = self.getBody(io, image, creds, .pull, uri2, &.{.{ .name = "Accept", .value = accept }}) catch |e| switch (e) {
                    // No tag-schema manifest either: no referrers at all.
                    error.NotFound => return &[_]manifest.OciDescriptor{},
                    else => return e,
                };
                defer r2.deinit(self.allocator);
                const descs = try indexDescriptors(self.allocator, r2.body);
                if (artifact_type) |at| {
                    var filtered = std.ArrayList(manifest.OciDescriptor).empty;
                    defer filtered.deinit(self.allocator);
                    for (descs) |d| {
                        if (d.artifact_type) |dt| {
                            if (std.mem.eql(u8, dt, at)) try filtered.append(self.allocator, d);
                        }
                    }
                    return filtered.toOwnedSlice(self.allocator);
                }
                return descs;
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

    /// Pushes `data` as a complete blob in a single monolithic PUT
    /// (Oracle 1). Returns the allocated "sha256:<hex>" digest.
    pub fn pushBlob(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth, data: []const u8) ![]const u8 {
        const digest_str = try sha256DigestString(self.allocator, data);
        errdefer self.allocator.free(digest_str);
        // sendBodyComplete needs a mutable buffer.
        const body = try self.allocator.dupe(u8, data);
        defer self.allocator.free(body);

        const session_url = try buildUrl(self.allocator, self.config, image, "blobs/uploads/", null);
        defer self.allocator.free(session_url);
        const session_uri = try std.Uri.parse(session_url);
        const session = try self.writeExpect(io, image, creds, .POST, session_uri, &.{}, &.{}, .accepted);
        defer if (session.location) |l| self.allocator.free(l);
        const loc = session.location orelse return error.InvalidResponse;

        const loc_url = try locationToUrl(self.allocator, self.config, image.registry, loc);
        defer self.allocator.free(loc_url);
        const put_url = try appendDigestQuery(self.allocator, loc_url, digest_str);
        defer self.allocator.free(put_url);
        const put_uri = try std.Uri.parse(put_url);
        const octet = "application/octet-stream";
        const put = try self.writeExpect(io, image, creds, .PUT, put_uri, &.{
            .{ .name = "Content-Type", .value = octet },
        }, body, .created);
        defer if (put.location) |l| self.allocator.free(l);
        return digest_str;
    }

    /// Streams a blob from `reader` (any type exposing
    /// `readSliceShort([]u8) !usize`) in chunks, PATCHing each chunk
    /// (Oracle 1/7), then finalizing with the accumulated sha256 digest.
    /// `size` == 0 skips the chunk loop (empty blob). Returns the allocated
    /// "sha256:<hex>" digest.
    pub fn pushBlobStream(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth, reader: anytype, size: u64) ![]const u8 {
        const octet = "application/octet-stream";
        const buf = try self.allocator.alloc(u8, 4096 * 1024);
        defer self.allocator.free(buf);
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});

        const session_url = try buildUrl(self.allocator, self.config, image, "blobs/uploads/", null);
        defer self.allocator.free(session_url);
        const session_uri = try std.Uri.parse(session_url);
        const session = try self.writeExpect(io, image, creds, .POST, session_uri, &.{}, &.{}, .accepted);
        // Ownership of session.location moves into `loc` (single owner).
        var loc: ?[]u8 = session.location orelse return error.InvalidResponse;
        defer if (loc) |l| self.allocator.free(l);

        var start: u64 = 0;
        if (size > 0) {
            var r = reader; // methods need *Reader (mutable)
            while (true) {
                const n = try r.readSliceShort(buf);
                if (n == 0) break;
                hasher.update(buf[0..n]);
                const end = start + n - 1;

                const range = try contentRangeHeader(self.allocator, start, end);
                errdefer self.allocator.free(range);
                const loc_url = try locationToUrl(self.allocator, self.config, image.registry, loc.?);
                errdefer self.allocator.free(loc_url);
                const patch_uri = try std.Uri.parse(loc_url);
                const patch = try self.writeExpect(io, image, creds, .PATCH, patch_uri, &.{
                    .{ .name = "Content-Range", .value = range },
                    .{ .name = "Content-Type", .value = octet },
                }, buf[0..n], .accepted);
                self.allocator.free(range);
                self.allocator.free(loc_url);
                self.allocator.free(loc.?);
                loc = patch.location;
                if (loc == null) return error.InvalidResponse;
                start = end + 1;
            }
        }

        var out: [32]u8 = undefined;
        hasher.final(&out);
        const hex = std.fmt.bytesToHex(out, .lower);
        const digest_str = try std.fmt.allocPrint(self.allocator, "sha256:{s}", .{&hex});
        errdefer self.allocator.free(digest_str);

        const loc_url = try locationToUrl(self.allocator, self.config, image.registry, loc.?);
        defer self.allocator.free(loc_url);
        const fin_url = try appendDigestQuery(self.allocator, loc_url, digest_str);
        defer self.allocator.free(fin_url);
        const fin_uri = try std.Uri.parse(fin_url);
        const fin = try self.writeExpect(io, image, creds, .PUT, fin_uri, &.{}, &.{}, .created);
        defer if (fin.location) |l| self.allocator.free(l);
        return digest_str;
    }

    /// Cross-repo blob mount: POST with `?mount={digest_str}&from={source}`.
    /// Expects 201 (mounted). Any other status — including the 202 session
    /// fallback — is an error (Oracle 4: no fallback in the client).
    pub fn mountBlob(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth, source: reference.Reference, digest_str: []const u8) !void {
        _ = try digest.parse(digest_str);
        const query = try std.fmt.allocPrint(self.allocator, "mount={s}&from={s}", .{ digest_str, source.repository });
        defer self.allocator.free(query);
        const url = try buildUrl(self.allocator, self.config, image, "blobs/uploads/", query);
        defer self.allocator.free(url);
        const uri = try std.Uri.parse(url);
        const result = try self.writeExpect(io, image, creds, .POST, uri, &.{}, &.{}, .created);
        defer if (result.location) |l| self.allocator.free(l);
    }

    /// Puts `body` verbatim as `image`'s manifest under the given content
    /// type (Oracle m3). Reference: tag if set, else digest, else "latest".
    /// Returns the registry Location header (the canonical manifest URL), or
    /// the sha256 of `body` when the registry omits Location (Oracle m4).
    pub fn pushManifestRaw(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth, body: []const u8, content_type: []const u8) ![]const u8 {
        const ref_part = try manifestRef(self.allocator, image);
        defer self.allocator.free(ref_part);
        const path = try std.fmt.allocPrint(self.allocator, "manifests/{s}", .{ref_part});
        defer self.allocator.free(path);
        const url = try buildUrl(self.allocator, self.config, image, path, null);
        defer self.allocator.free(url);
        const uri = try std.Uri.parse(url);

        const body_copy = try self.allocator.dupe(u8, body); // sendBodyComplete needs mutable
        defer self.allocator.free(body_copy);
        const result = try self.writeExpect(io, image, creds, .PUT, uri, &.{
            .{ .name = "Content-Type", .value = content_type },
        }, body_copy, .created);
        if (result.location) |l| return l;
        return sha256DigestString(self.allocator, body);
    }

    /// Puts a manifest document, serialized canonically (RFC 8785, sorted
    /// keys); the returned digest is the sha256 of the canonical bytes sent.
    pub fn pushManifest(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth, m: *const manifest.OciManifest) ![]const u8 {
        const body = try manifestCanonicalBytes(self.allocator, m);
        defer self.allocator.free(body);
        const content_type = m.mediaType() orelse manifest.oci_manifest;
        return self.pushManifestRaw(io, image, creds, body, content_type);
    }

    /// Puts an image index, serialized canonically.
    pub fn pushManifestList(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth, index: *const manifest.OciImageIndex) ![]const u8 {
        const wrapped = manifest.OciManifest{ .index = index.* };
        return self.pushManifest(io, image, creds, &wrapped);
    }

    /// Pushes layers (each as a blob), then config, then the manifest
    /// (Oracle m5 ordering). When `manifest` is null, one is built from
    /// `config` + `layers` (config required in that case). Returns the
    /// manifest digest and the manifest URL that was PUT to.
    pub fn push(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth, manifest_opt: ?manifest.OciImageManifest, config: ?[]const u8, layers: []const []const u8) !struct { manifest_digest: []const u8, manifest_url: []const u8 } {
        const ref_part = try manifestRef(self.allocator, image);
        defer self.allocator.free(ref_part);
        const path = try std.fmt.allocPrint(self.allocator, "manifests/{s}", .{ref_part});
        defer self.allocator.free(path);
        const manifest_url = try buildUrl(self.allocator, self.config, image, path, null);
        errdefer self.allocator.free(manifest_url);

        if (manifest_opt) |m| {
            const wrapped = manifest.OciManifest{ .manifest = m };
            const digest_str = try self.pushManifest(io, image, creds, &wrapped);
            return .{ .manifest_digest = digest_str, .manifest_url = manifest_url };
        }
        if (config == null) return error.InvalidResponse;

        // Layers first, then config, then manifest. Single owner: one defer
        // (registered before the loop) frees only the filled entries [0..pushed]
        // and the backing array — on mid-loop error, post-loop error, and
        // success alike, exactly once each.
        const layer_digests = try self.allocator.alloc([]const u8, layers.len);
        var pushed: usize = 0;
        defer {
            for (layer_digests[0..pushed]) |d| self.allocator.free(d);
            self.allocator.free(layer_digests);
        }
        for (layers, 0..) |l, i| {
            layer_digests[i] = try self.pushBlob(io, image, creds, l);
            pushed += 1;
        }

        const config_digest = try self.pushBlob(io, image, creds, config.?);
        defer self.allocator.free(config_digest);

        const layer_descs = try self.allocator.alloc(manifest.OciDescriptor, layers.len);
        defer self.allocator.free(layer_descs);
        for (layers, 0..) |l, i| {
            layer_descs[i] = .{
                .media_type = manifest.oci_layer,
                .digest = layer_digests[i],
                .size = l.len,
            };
        }
        const built = manifest.OciImageManifest{
            .schema_version = 2,
            .media_type = manifest.oci_manifest,
            .config = .{
                .media_type = manifest.oci_config,
                .digest = config_digest,
                .size = config.?.len,
            },
            .layers = layer_descs,
        };
        const wrapped = manifest.OciManifest{ .manifest = built };
        const digest_str = try self.pushManifest(io, image, creds, &wrapped);
        return .{ .manifest_digest = digest_str, .manifest_url = manifest_url };
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

    /// Fetches a bearer token from the challenge's realm with `creds` and the
    /// given `scope` (per-request, not the challenge's scope). Returns the
    /// token (allocator-owned) or null when `creds` is anonymous. Caching of
    /// the returned token is the caller's job (the registry/repo of the cache
    /// key live at the call site).
    fn tokenFromChallenge(self: *Client, io: Io, challenge: auth_mod.Challenge, creds: secrets.RegistryAuth, scope: []const u8) !?[]const u8 {
        if (creds == .anonymous) return null;
        const token_url_str = try self.buildTokenUrlString(challenge, scope);
        defer self.allocator.free(token_url_str);
        const token_uri = try std.Uri.parse(token_url_str);

        const auth_value = try secrets.basicAuthHeader(creds, self.allocator);
        defer if (auth_value) |v| self.allocator.free(v);

        var http: std.http.Client = .{ .allocator = self.allocator, .io = io };
        defer http.deinit();
        var redirect_buf: [8192]u8 = undefined;
        var req = try http.request(.GET, token_uri, .{
            .redirect_behavior = .unhandled,
            .headers = .{ .authorization = if (auth_value) |v| .{ .override = v } else .default },
        });
        defer req.deinit();
        try req.sendBodiless();
        var resp = try req.receiveHead(&redirect_buf);
        if (resp.head.status != .ok) return error.Unauthorized;

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

        const TokenResp = struct { token: ?[]const u8 = null, access_token: ?[]const u8 = null };
        const parsed = try std.json.parseFromSliceLeaky(TokenResp, self.allocator, out.items, .{ .ignore_unknown_fields = true });
        const token = parsed.token orelse parsed.access_token orelse return error.InvalidResponse;
        return try self.allocator.dupe(u8, token);
    }

    /// Sends a write-path request with the 401 -> Bearer token retry
    /// (Oracle M1): first attempt uses `authorizationHeader` (cached token or
    /// caller creds); on 401, parses the Bearer challenge from the FAILED
    /// response, fetches a token with scope "repository:{repo}:pull,push",
    /// caches it under (registry, repo, .push), and retries once. Anonymous
    /// creds never retry. The container (http client + req) outlives the
    /// function; the caller keeps `resp` alive, then calls req.deinit() +
    /// client.deinit() + destroy (see WriteHttp).
    fn writeRequest(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth, method: std.http.Method, uri: std.Uri, extra_headers: []const std.http.Header, body: []u8) !WriteAttempt {
        const container = try self.allocator.create(WriteHttp);
        container.* = .{ .client = .{ .allocator = self.allocator, .io = io }, .req = undefined };
        errdefer {
            container.client.deinit();
            self.allocator.destroy(container);
        }

        var attempts: usize = 0;
        while (attempts < 2) : (attempts += 1) {
            const auth_value = try self.authorizationHeader(io, image, creds, .push);
            defer if (auth_value) |v| self.allocator.free(v);

            container.req = try container.client.request(method, uri, .{
                .redirect_behavior = .unhandled,
                .headers = .{ .authorization = if (auth_value) |v| .{ .override = v } else .default },
                .extra_headers = extra_headers,
            });
            errdefer container.req.deinit();
            try container.req.sendBodyComplete(body);
            var resp = try container.req.receiveHead(&container.redirect_buf);
            const status = resp.head.status;

            if (status == .unauthorized and attempts == 0 and creds != .anonymous) {
                // Extract the challenge BEFORE req.deinit() (head strings
                // borrow the connection buffer).
                var challenge_value: ?[]const u8 = null;
                var it = resp.head.iterateHeaders();
                while (it.next()) |h| {
                    if (std.ascii.eqlIgnoreCase(h.name, "www-authenticate")) {
                        challenge_value = try self.allocator.dupe(u8, h.value);
                        break;
                    }
                }
                // ALL fallible work happens before the explicit req.deinit();
                // any error here returns through the errdefer path, which
                // deinits the (still live) req exactly once.
                defer if (challenge_value) |v| self.allocator.free(v);
                const challenge = try auth_mod.parseBearerChallenge(challenge_value orelse return error.Unauthorized);
                defer challenge.deinit();
                const scope = try std.fmt.allocPrint(self.allocator, "repository:{s}:pull,push", .{image.repository});
                defer self.allocator.free(scope);
                const token = try self.tokenFromChallenge(io, challenge, creds, scope);
                if (token) |t| {
                    defer self.allocator.free(t);
                    try self.token_cache.put(image.registry, image.repository, .push, t);
                }
                // Last statement before continue: req is deinit'd exactly once.
                container.req.deinit();
                continue;
            }
            return .{ .container = container, .resp = resp };
        }
        return error.Unauthorized;
    }

    /// writeRequest + status gate: returns the (owned) Location on `want`,
    /// or drains the body and maps the error (401 -> Unauthorized, else
    /// mapErrorFromEnvelope). Always consumes the response body so the
    /// connection is reusable (Oracle m5).
    fn writeExpect(self: *Client, io: Io, image: reference.Reference, creds: secrets.RegistryAuth, method: std.http.Method, uri: std.Uri, headers: []const std.http.Header, body: []u8, want: std.http.Status) !WriteResult {
        var attempt = try self.writeRequest(io, image, creds, method, uri, headers, body);
        defer {
            attempt.container.req.deinit();
            attempt.container.client.deinit();
            self.allocator.destroy(attempt.container);
        }
        const status = attempt.resp.head.status;

        if (status != want) {
            const err_body = try readBody(self.allocator, &attempt.resp);
            defer self.allocator.free(err_body);
            if (status == .unauthorized) return error.Unauthorized;
            mapErrorFromEnvelope(self.allocator, err_body) catch |err| return err;
            unreachable;
        }

        // Location must be copied BEFORE resp.reader() invalidates head.
        var result = WriteResult{ .status = status };
        errdefer if (result.location) |l| self.allocator.free(l);
        var it = attempt.resp.head.iterateHeaders();
        while (it.next()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "location")) {
                result.location = try self.allocator.dupe(u8, h.value);
                break;
            }
        }
        const drained = try readBody(self.allocator, &attempt.resp);
        defer self.allocator.free(drained);
        return result;
    }

    fn buildTokenUrlString(self: *Client, challenge: auth_mod.Challenge, scope: []const u8) ![]u8 {
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
        if (scope.len > 0) {
            try buf.append(self.allocator, if (first) '?' else '&');
            try buf.appendSlice(self.allocator, "scope=");
            const enc = try percentEncode(self.allocator, scope);
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

/// Releases the Request, the http.Client, and the container. Captures the
/// allocator before client.deinit() (which sets client.* to undefined).
/// Shared by the BlobStreamResult/BlobResponseResult deinit methods.
fn destroyBlobContainer(req: *std.http.Client.Request, container: *BlobHttp) void {
    const allocator = container.client.allocator;
    req.deinit();
    container.client.deinit();
    allocator.destroy(container);
}

/// A full-blob stream plus the owning Request and container. The consumer
/// reads `stream` to EOF, calls `stream.finish()`, then `deinit()` (which
/// releases the Request, the http.Client, and the container).
pub const BlobStreamResult = struct {
    stream: blob.BlobStream,
    req: *std.http.Client.Request,
    container: *BlobHttp,

    pub fn deinit(self: *BlobStreamResult) void {
        destroyBlobContainer(self.req, self.container);
    }
};

/// A partial-blob response plus the owning Request and container. The
/// consumer reads `response` to EOF, then `deinit()`.
pub const BlobResponseResult = struct {
    response: blob.BlobResponse,
    req: *std.http.Client.Request,
    container: *BlobHttp,

    pub fn deinit(self: *BlobResponseResult) void {
        destroyBlobContainer(self.req, self.container);
    }
};

const OpenBlob = struct {
    container: *BlobHttp,
    req: *std.http.Client.Request,
    resp: std.http.Client.Response,
};

/// In-flight write request. The `WriteHttp` container keeps the http.Client,
/// the Request, and the redirect buffer alive; the caller consumes `resp`,
/// then releases the container (req.deinit -> client.deinit -> destroy).
const WriteAttempt = struct {
    container: *WriteHttp,
    resp: std.http.Client.Response,
};

/// Heap container for a write request: the http.Client must outlive its
/// Request (Client.deinit asserts no active requests), and the response head
/// borrows the redirect buffer.
const WriteHttp = struct {
    client: std.http.Client,
    req: std.http.Client.Request,
    redirect_buf: [8192]u8 = undefined,
};

/// Owned result of a write request: status plus the copied Location header
/// (null when absent). Free `location` with the Client's allocator.
const WriteResult = struct {
    status: std.http.Status,
    location: ?[]u8 = null,
};

/// Reads the full response body (draining the connection). Caller frees.
fn readBody(allocator: Allocator, resp: *std.http.Client.Response) ![]u8 {
    var transfer_buf: [8192]u8 = undefined;
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    const reader = resp.reader(&transfer_buf);
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = try reader.readSliceShort(&chunk);
        if (n == 0) break;
        try out.appendSlice(allocator, chunk[0..n]);
    }
    return out.toOwnedSlice(allocator);
}

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

/// The four distribution manifest media types accepted on referrers and
/// tag-schema fallback requests (upstream MIME_TYPES_DISTRIBUTION_MANIFEST).
const distribution_accept_types = [_][]const u8{
    manifest.docker_manifest_v2,
    manifest.docker_manifest_list,
    manifest.oci_manifest,
    manifest.oci_index,
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

/// Builds the "n=<n>[&last=<encoded>]" query fragment shared by listTags and
/// catalogUrl. Returns null when both `n` and `last` are absent; `last` is
/// percent-encoded. The result is an owned allocation (free with `allocator`).
fn buildPaginationQuery(allocator: Allocator, n: ?usize, last: ?[]const u8) !?[]const u8 {
    var q = std.ArrayList(u8).empty;
    defer q.deinit(allocator);
    var first = true;
    if (n) |count| {
        const ns = try std.fmt.allocPrint(allocator, "n={d}", .{count});
        defer allocator.free(ns);
        try q.appendSlice(allocator, ns);
        first = false;
    }
    if (last) |l| {
        if (!first) try q.append(allocator, '&');
        try q.appendSlice(allocator, "last=");
        const enc = try percentEncode(allocator, l);
        defer allocator.free(enc);
        try q.appendSlice(allocator, enc);
    }
    if (q.items.len == 0) return null;
    return try allocator.dupe(u8, q.items);
}

/// Builds "<scheme>://<registry>/v2/_catalog[?n=<n>[&last=<encoded>]]" —
/// registry-scoped, no repository segment. `n` and `last` are appended only
/// when present.
fn catalogUrl(allocator: Allocator, config: ClientConfig, image: reference.Reference, n: ?usize, last: ?[]const u8) ![]u8 {
    const scheme = config.scheme(image.registry);
    const query = try buildPaginationQuery(allocator, n, last);
    defer if (query) |q| allocator.free(q);
    if (query) |q| {
        return std.fmt.allocPrint(allocator, "{s}://{s}/v2/_catalog?{s}", .{ scheme, image.registry, q });
    }
    return std.fmt.allocPrint(allocator, "{s}://{s}/v2/_catalog", .{ scheme, image.registry });
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

/// Manifest reference for push: tag if set, else digest, else "latest".
fn manifestRef(allocator: Allocator, image: reference.Reference) ![]u8 {
    if (image.tag) |t| return allocator.dupe(u8, t);
    if (image.digest) |d| return allocator.dupe(u8, d);
    return allocator.dupe(u8, "latest");
}

/// Resolves a registry `Location` response header to an absolute URL.
/// Absolute locations are copied verbatim; relative ones (starting with "/")
/// are prefixed with "{scheme}://{registry}" (zot returns relative Locations).
fn locationToUrl(allocator: Allocator, config: ClientConfig, registry: []const u8, location: []const u8) ![]u8 {
    if (std.mem.startsWith(u8, location, "http://") or std.mem.startsWith(u8, location, "https://")) {
        return allocator.dupe(u8, location);
    }
    if (location.len > 0 and location[0] == '/') {
        const scheme = config.scheme(registry);
        return std.fmt.allocPrint(allocator, "{s}://{s}{s}", .{ scheme, registry, location });
    }
    return error.InvalidResponse;
}

/// Appends `?digest={digest}` (or `&digest={digest}` when the URL already
/// carries a query) to a blob upload session URL.
fn appendDigestQuery(allocator: Allocator, url: []const u8, digest_str: []const u8) ![]u8 {
    if (std.mem.indexOfScalar(u8, url, '?') != null) {
        return std.fmt.allocPrint(allocator, "{s}&digest={s}", .{ url, digest_str });
    }
    return std.fmt.allocPrint(allocator, "{s}?digest={s}", .{ url, digest_str });
}

/// "{start}-{end_inclusive}" — the OCI upload PATCH Content-Range form with
/// an INCLUSIVE end offset. Note: no "bytes " prefix (proven against zot:
/// the prefixed form is rejected with 416; the bare form matches the OCI
/// distribution spec's `Content-Range: <start>-<end>` for uploads).
fn contentRangeHeader(allocator: Allocator, start: u64, end_inclusive: u64) ![]u8 {
    return std.fmt.allocPrint(allocator, "{d}-{d}", .{ start, end_inclusive });
}

/// Maps a registry error envelope body to a client error: DIGEST_INVALID ->
/// error.InvalidDigest, MANIFEST_INVALID -> error.InvalidManifest, anything
/// else (including an unparseable body) -> error.UnexpectedStatus. Never
/// errors on malformed JSON.
fn mapErrorFromEnvelope(allocator: Allocator, body: []const u8) error{ InvalidDigest, InvalidManifest, UnexpectedStatus, OutOfMemory }!void {
    const parsed = std.json.parseFromSlice(errors.OciEnvelope, allocator, body, .{ .ignore_unknown_fields = true }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.UnexpectedStatus,
    };
    defer parsed.deinit();
    if (parsed.value.errors.len == 0) return error.UnexpectedStatus;
    switch (parsed.value.errors[0].code) {
        .digest_invalid => return error.InvalidDigest,
        .manifest_invalid => return error.InvalidManifest,
        else => return error.UnexpectedStatus,
    }
}

/// Serializes `m` through std.json (wire shape) then re-serializes the parsed
/// Value canonically (RFC 8785, sorted keys). The returned bytes are the exact
/// body that must be PUT to the registry.
fn manifestCanonicalBytes(allocator: Allocator, m: *const manifest.OciManifest) ![]u8 {
    const wire = try std.json.Stringify.valueAlloc(allocator, m.*, .{});
    defer allocator.free(wire);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, wire, .{});
    defer parsed.deinit();
    return canonical_json.stringify(allocator, parsed.value);
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

test "catalogUrl query params" {
    const a = std.testing.allocator;
    const cfg = ClientConfig{ .protocol = .https };
    const image = try reference.parse("registry.example.com/foo/bar:v1");

    const both = try catalogUrl(a, cfg, image, 10, "zot%repo");
    defer a.free(both);
    try std.testing.expectEqualStrings("https://registry.example.com/v2/_catalog?n=10&last=zot%25repo", both);

    const only_n = try catalogUrl(a, cfg, image, 5, null);
    defer a.free(only_n);
    try std.testing.expectEqualStrings("https://registry.example.com/v2/_catalog?n=5", only_n);

    const only_last = try catalogUrl(a, cfg, image, null, "abc");
    defer a.free(only_last);
    try std.testing.expectEqualStrings("https://registry.example.com/v2/_catalog?last=abc", only_last);

    const none = try catalogUrl(a, cfg, image, null, null);
    defer a.free(none);
    try std.testing.expectEqualStrings("https://registry.example.com/v2/_catalog", none);
}

test "catalogUrl is registry-scoped with no repository segment" {
    const a = std.testing.allocator;
    const image = try reference.parse("registry.example.com/team/proj/image:v1");
    // The reference's repository (team/proj/image) and tag must not appear.
    const url = try catalogUrl(a, ClientConfig{ .protocol = .https }, image, null, null);
    defer a.free(url);
    try std.testing.expectEqualStrings("https://registry.example.com/v2/_catalog", url);

    const url2 = try catalogUrl(a, ClientConfig{ .protocol = .http }, image, null, null);
    defer a.free(url2);
    try std.testing.expectEqualStrings("http://registry.example.com/v2/_catalog", url2);
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

test "resolver skips descriptors without platform" {
    const descriptors = [_]manifest.OciDescriptor{
        .{ .media_type = manifest.oci_manifest, .digest = "sha256:null-before", .size = 1 },
        .{ .media_type = manifest.oci_manifest, .digest = "sha256:match", .size = 1, .platform = .{ .architecture = "amd64", .os = "linux" } },
        .{ .media_type = manifest.oci_manifest, .digest = "sha256:null-after", .size = 1 },
    };
    try std.testing.expectEqualStrings("sha256:match", linuxAmd64Resolver(&descriptors).?);
}

test "resolver ignores variant and os.version" {
    const descriptors = [_]manifest.OciDescriptor{
        .{ .media_type = manifest.oci_manifest, .digest = "sha256:v8", .size = 1, .platform = .{ .architecture = "arm64", .os = "linux", .variant = "v8" } },
        .{ .media_type = manifest.oci_manifest, .digest = "sha256:osver", .size = 1, .platform = .{ .architecture = "windows", .os = "windows", .os_version = "10.0.17763.0" } },
        .{ .media_type = manifest.oci_manifest, .digest = "sha256:v7", .size = 1, .platform = .{ .architecture = "arm64", .os = "linux", .variant = "v7" } },
    };
    // Matching ignores variant/os.version: the first arm64/linux entry wins even
    // though a later entry shares os/arch with a different variant.
    try std.testing.expectEqualStrings("sha256:v8", resolvePlatform(&descriptors, "arm64", "linux").?);
    try std.testing.expectEqualStrings("sha256:osver", resolvePlatform(&descriptors, "windows", "windows").?);
}

test "resolver returns the first match in descriptor order" {
    const descriptors = [_]manifest.OciDescriptor{
        .{ .media_type = manifest.oci_manifest, .digest = "sha256:first", .size = 1, .platform = .{ .architecture = "amd64", .os = "linux" } },
        .{ .media_type = manifest.oci_manifest, .digest = "sha256:second", .size = 1, .platform = .{ .architecture = "amd64", .os = "linux" } },
    };
    try std.testing.expectEqualStrings("sha256:first", linuxAmd64Resolver(&descriptors).?);
}

test "buildTokenUrlString uses the passed scope" {
    const a = std.testing.allocator;
    var client = Client.init(a, .{ .protocol = .http });
    defer client.deinit();
    // Literal challenge: never deinit (would free comptime strings).
    const ch = auth_mod.Challenge{ .realm = "http://127.0.0.1:5000/auth", .service = "zot" };
    const url = try client.buildTokenUrlString(ch, "repository:testrepo:pull,push");
    defer a.free(url);
    // ':' '/' ',' are percent-encoded; the passed scope must be in the URL.
    try std.testing.expectEqualStrings(
        "http://127.0.0.1:5000/auth?service=zot&scope=repository%3Atestrepo%3Apull%2Cpush",
        url,
    );
}

test "tokenFromChallenge returns null for anonymous" {
    const a = std.testing.allocator;
    var io = std.Io.Threaded.init(a, .{});
    defer io.deinit();
    var client = Client.init(a, .{ .protocol = .http });
    defer client.deinit();
    const ch = auth_mod.Challenge{ .realm = "http://127.0.0.1:5000/auth" };
    // Anonymous short-circuits before any I/O.
    try std.testing.expectEqual(@as(?[]const u8, null), try client.tokenFromChallenge(io.io(), ch, .anonymous, "repository:x:pull"));
}

test "locationToUrl relative and absolute" {
    const a = std.testing.allocator;
    const cfg = ClientConfig{ .protocol = .http };

    const rel = try locationToUrl(a, cfg, "127.0.0.1:5000", "/v2/testrepo/blobs/uploads/abc");
    defer a.free(rel);
    try std.testing.expectEqualStrings("http://127.0.0.1:5000/v2/testrepo/blobs/uploads/abc", rel);

    const abs = try locationToUrl(a, cfg, "127.0.0.1:5000", "https://other.example/v2/x");
    defer a.free(abs);
    try std.testing.expectEqualStrings("https://other.example/v2/x", abs);

    try std.testing.expectError(error.InvalidResponse, locationToUrl(a, cfg, "127.0.0.1:5000", "relative-path"));
}

test "appendDigestQuery joins with ? or &" {
    const a = std.testing.allocator;

    const plain = try appendDigestQuery(a, "http://h/v2/r/blobs/uploads/u", "sha256:abc");
    defer a.free(plain);
    try std.testing.expectEqualStrings("http://h/v2/r/blobs/uploads/u?digest=sha256:abc", plain);

    const with_q = try appendDigestQuery(a, "http://h/v2/r/blobs/uploads/u?foo=1", "sha256:abc");
    defer a.free(with_q);
    try std.testing.expectEqualStrings("http://h/v2/r/blobs/uploads/u?foo=1&digest=sha256:abc", with_q);
}

test "contentRangeHeader inclusive end" {
    const a = std.testing.allocator;
    const r1 = try contentRangeHeader(a, 0, 4_194_303);
    defer a.free(r1);
    try std.testing.expectEqualStrings("0-4194303", r1);
    const r2 = try contentRangeHeader(a, 4_194_304, 8_388_607);
    defer a.free(r2);
    try std.testing.expectEqualStrings("4194304-8388607", r2);
}

test "mapErrorFromEnvelope maps codes and garbage" {
    const a = std.testing.allocator;
    try std.testing.expectError(
        error.InvalidManifest,
        mapErrorFromEnvelope(a, "{\"errors\":[{\"code\":\"MANIFEST_INVALID\"}]}"),
    );
    try std.testing.expectError(
        error.InvalidDigest,
        mapErrorFromEnvelope(a, "{\"errors\":[{\"code\":\"DIGEST_INVALID\"}]}"),
    );
    try std.testing.expectError(
        error.UnexpectedStatus,
        mapErrorFromEnvelope(a, "{\"errors\":[{\"code\":\"BLOB_UNKNOWN\"}]}"),
    );
    try std.testing.expectError(error.UnexpectedStatus, mapErrorFromEnvelope(a, "not json at all"));
    try std.testing.expectError(error.UnexpectedStatus, mapErrorFromEnvelope(a, "{\"errors\":[]}"));
}

test "manifestRef picks tag, then digest, then latest" {
    const a = std.testing.allocator;

    const with_tag = try reference.parse("registry.example.com/foo:my-tag");
    const r1 = try manifestRef(a, with_tag);
    defer a.free(r1);
    try std.testing.expectEqualStrings("my-tag", r1);

    const d = "sha256:3f57d9401f8d42f986df300f0c69192fc41da28ccc8d797829467780db3dd741";
    const with_digest = try reference.parse("registry.example.com/foo@" ++ d);
    const r2 = try manifestRef(a, with_digest);
    defer a.free(r2);
    try std.testing.expectEqualStrings(d, r2);

    const neither = try reference.parse("registry.example.com/foo");
    const r3 = try manifestRef(a, neither);
    defer a.free(r3);
    try std.testing.expectEqualStrings("latest", r3);
}

test "manifestCanonicalBytes digest matches the canonical body" {
    const a = std.testing.allocator;
    const m = manifest.OciManifest{ .manifest = .{ .layers = &.{} } };
    const body = try manifestCanonicalBytes(a, &m);
    defer a.free(body);

    // The body must hash (independently recomputed) to the digest the
    // registry will verify — asserts the canonical pipeline end to end.
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &out, .{});
    const hex = std.fmt.bytesToHex(out, .lower);
    const expected = try std.fmt.allocPrint(a, "sha256:{s}", .{&hex});
    defer a.free(expected);
    const recomputed = try sha256DigestString(a, body);
    defer a.free(recomputed);
    try std.testing.expectEqualStrings(expected, recomputed);

    // body must equal canonical_json.stringify of the same parsed Value.
    const parsed = try std.json.parseFromSlice(std.json.Value, a, body, .{});
    defer parsed.deinit();
    const canonical = try canonical_json.stringify(a, parsed.value);
    defer a.free(canonical);
    try std.testing.expectEqualStrings(canonical, body);
}
