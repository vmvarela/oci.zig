# AGENTS.md

## Language rule

All documentation and comments in this repository MUST be written in English.

This applies to:
- source code comments (`//`, `///` doc comments)
- docs/ files, README, SPEC notes
- commit messages
- PR descriptions and review notes

Code identifiers follow Zig conventions (snake_case for functions/variables,
CamelCase for types). English spelling for any user-facing strings.

## PR titles

Pull request titles MUST use the [Conventional Commits](https://www.conventionalcommits.org/)
format: `<type>(<scope>): <description>` (e.g. `feat: add deleteManifest`,
`chore: use standard GitHub labels in release-drafter`). This keeps release
notes and the release-drafter autolabeler consistent with the commit history.

