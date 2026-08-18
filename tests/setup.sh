#!/usr/bin/env bash
# Pushes Tier 1 test content to a zot registry (default http://127.0.0.1:5000,
# override with $REGISTRY). Self-contained: generates the blobs and manifests,
# computes digests, and prints them. Used by CI and local integration tests.
#
# Push sequence (OCI distribution spec):
#   POST /v2/<repo>/blobs/uploads/  -> 202 + Location
#   PUT  <Location>?digest=<d>      -> 201
#   PUT  /v2/<repo>/manifests/<ref> -> 201 (OCI media types only; zot 415s docker-schema2)
set -euo pipefail

REGISTRY="${REGISTRY:-http://127.0.0.1:5000}"
REPO="testrepo"
DIR="$(cd "$(dirname "$0")" && pwd)"

OCI_MANIFEST="application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG="application/vnd.oci.image.config.v1+json"
OCI_LAYER="application/vnd.oci.image.layer.v1.tar+gzip"
SBOM="application/vnd.example.sbom.v1"

# --- blobs ---
CONFIG_FILE="$DIR/fixtures/config.json"
CONFIG_DIGEST="sha256:$(shasum -a 256 "$CONFIG_FILE" | awk '{print $1}')"
CONFIG_SIZE="$(wc -c < "$CONFIG_FILE" | tr -d " ")"

BLOB_FILE="$(mktemp)"
head -c 1048576 /dev/urandom > "$BLOB_FILE"
BLOB_DIGEST="sha256:$(shasum -a 256 "$BLOB_FILE" | awk '{print $1}')"
BLOB_SIZE="$(wc -c < "$BLOB_FILE" | tr -d " ")"

EMPTY_FILE="$(mktemp)"
printf '{}' > "$EMPTY_FILE"
EMPTY_DIGEST="sha256:$(shasum -a 256 "$EMPTY_FILE" | awk '{print $1}')"
EMPTY_SIZE="$(wc -c < "$EMPTY_FILE" | tr -d " ")"

trap 'rm -f "$BLOB_FILE" "$EMPTY_FILE" "$CANONICAL_FILE" "$V1_FILE" "$REFERRER_FILE"' EXIT

# --- push a blob: POST upload -> Location -> PUT ?digest= ---
push_blob() {
  local file="$1" digest="$2"
  local loc
  loc="$(curl -s -D - -o /dev/null -X POST "$REGISTRY/v2/$REPO/blobs/uploads/" \
    | grep -i '^location:' | tr -d '\r' | awk '{print $2}')"
  case "$loc" in
    http*) ;; # already absolute
    *) loc="$REGISTRY$loc" ;;
  esac
  case "$loc" in
    *\?*) sep='&' ;;
    *) sep='?' ;;
  esac
  curl -s -o /dev/null -X PUT "${loc}${sep}digest=$digest" --data-binary @"$file"
}

# --- push a manifest (OCI media type) ---
push_manifest() {
  local file="$1" ref="$2"
  curl -s -o /dev/null -X PUT "$REGISTRY/v2/$REPO/manifests/$ref" \
    -H "Content-Type: $OCI_MANIFEST" \
    --data-binary @"$file"
}

push_blob "$CONFIG_FILE" "$CONFIG_DIGEST"
push_blob "$BLOB_FILE" "$BLOB_DIGEST"
push_blob "$EMPTY_FILE" "$EMPTY_DIGEST"

# --- canonical manifest: sorted keys, no whitespace (matches canonical_json) ---
CANONICAL_JSON="{\"config\":{\"digest\":\"$CONFIG_DIGEST\",\"mediaType\":\"$OCI_CONFIG\",\"size\":$CONFIG_SIZE},\"layers\":[{\"digest\":\"$BLOB_DIGEST\",\"mediaType\":\"$OCI_LAYER\",\"size\":$BLOB_SIZE}],\"mediaType\":\"$OCI_MANIFEST\",\"schemaVersion\":2}"
CANONICAL_FILE="$(mktemp)"
printf '%s' "$CANONICAL_JSON" > "$CANONICAL_FILE"
CANONICAL_DIGEST="sha256:$(shasum -a 256 "$CANONICAL_FILE" | awk '{print $1}')"
CANONICAL_SIZE="$(wc -c < "$CANONICAL_FILE" | tr -d " ")"
push_manifest "$CANONICAL_FILE" "canonical"

# --- v1 manifest: same content, non-canonical key order ---
V1_JSON="{\"schemaVersion\":2,\"mediaType\":\"$OCI_MANIFEST\",\"config\":{\"mediaType\":\"$OCI_CONFIG\",\"size\":$CONFIG_SIZE,\"digest\":\"$CONFIG_DIGEST\"},\"layers\":[{\"mediaType\":\"$OCI_LAYER\",\"size\":$BLOB_SIZE,\"digest\":\"$BLOB_DIGEST\"}]}"
V1_FILE="$(mktemp)"
printf '%s' "$V1_JSON" > "$V1_FILE"
push_manifest "$V1_FILE" "v1"

# --- referrer manifest: artifactType + subject (canonical) + empty config ---
REFERRER_JSON="{\"artifactType\":\"$SBOM\",\"config\":{\"digest\":\"$EMPTY_DIGEST\",\"mediaType\":\"$OCI_CONFIG\",\"size\":$EMPTY_SIZE},\"layers\":[],\"mediaType\":\"$OCI_MANIFEST\",\"schemaVersion\":2,\"subject\":{\"digest\":\"$CANONICAL_DIGEST\",\"mediaType\":\"$OCI_MANIFEST\",\"size\":$CANONICAL_SIZE}}"
REFERRER_FILE="$(mktemp)"
printf '%s' "$REFERRER_JSON" > "$REFERRER_FILE"
REFERRER_DIGEST="sha256:$(shasum -a 256 "$REFERRER_FILE" | awk '{print $1}')"
push_manifest "$REFERRER_FILE" "$REFERRER_DIGEST"

echo "config:    $CONFIG_DIGEST ($CONFIG_SIZE B)"
echo "layer:     $BLOB_DIGEST ($BLOB_SIZE B)"
echo "empty:     $EMPTY_DIGEST ($EMPTY_SIZE B)"
echo "canonical: $CANONICAL_DIGEST ($CANONICAL_SIZE B)"
echo "referrer:  $REFERRER_DIGEST"
