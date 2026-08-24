#!/usr/bin/env bash
# Bump version in build.zig.zon, refresh fingerprint, commit, tag and push.
# Usage: scripts/release.sh [x.y.z]  (version defaults to the release-drafter draft)
set -euo pipefail

version="${1:-}"
if [ -z "$version" ]; then
    version=$(gh release list --draft --limit 1 --json name --jq '.[0].name | sub("^v"; "")')
    if [ -z "$version" ]; then
        echo "no release-drafter draft found, pass version explicitly: $0 <x.y.z>" >&2
        exit 1
    fi
    echo "using release-drafter version: $version"
fi

if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "usage: $0 [<x.y.z>]" >&2
    exit 1
fi

branch=$(git branch --show-current)
if [ "$branch" != "main" ]; then
    echo "run from main, current branch: $branch" >&2
    exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
    echo "working tree not clean, commit or stash first" >&2
    exit 1
fi

sed -i.bak "s/\.version = \"[^\"]*\"/.version = \"$version\"/" build.zig.zon
rm -f build.zig.zon.bak

zig build # rewrites the fingerprint in build.zig.zon

git add build.zig.zon
git commit -m "chore: bump version to $version"
git tag "v$version"
git push origin "$branch" "v$version"
