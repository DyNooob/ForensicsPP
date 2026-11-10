# Project maintenance / 项目维护规则

[Documentation](README.md) · [Contributing](../CONTRIBUTING.md)

## Ownership and decisions

Forensics++ is maintained by DyNooob. Maintainers decide scope, review contributions, manage releases and coordinate security fixes through the repository. This document describes the current lightweight process; it does not invent a foundation, elected committee or formal support organization.

## Where work happens

- Reproducible defects and feature proposals: GitHub Issues.
- Code, fixtures, translations and documentation: pull requests.
- Vulnerabilities: the private address in [SECURITY.md](../SECURITY.md).
- Versioned changes: [CHANGELOG.md](../CHANGELOG.md) and [release notes](releases/README.md).

Do not use public discussions to exchange private evidence, credentials or unreviewed case exports.

## Acceptance criteria

Changes should serve a concrete browser-based workflow, state their limits and fit the shared execution/evidence/result architecture. A contribution may be deferred when it needs unsupported native APIs, unbounded resources, unclear redistribution rights or unmaintainable format coverage.

Review should focus on observable behavior, source provenance, compatibility, resource use, accessibility, offline behavior and verification. Claims in documentation must reflect tested implementation rather than aspirational feature names.

## Releases and compatibility

Stable versions use semantic versioning where practical. Format coverage can remain scoped even after 1.0. Backward-compatible additions do not remove the need to document changed defaults, storage migrations or evidence interpretation.

A release identifies a source commit/tag, explains user-visible changes and ships verified assets/checksums. Maintainers should not replace bytes under an existing published version without explicit correction notes. Prefer a patch release for changes to a published artifact.

## Conduct and support

Keep discussion respectful, concrete and reproducible. Disagree about implementation with evidence and alternatives; do not publish another person's private information. Maintainer availability determines review and release timing. No commercial support tier, fixed SLA or long-term maintenance promise is implied.
