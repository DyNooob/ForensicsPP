# Security policy

[Documentation](docs/README.md) · [Licensing](docs/LICENSING.md)

## Supported versions

Security work targets the latest stable release and the maintained `main` branch. Version 1.0.0 is the first stable release. Older pre-releases, downloaded ZIPs and browser-cached copies do not update themselves automatically; update to a verified current distribution when a fix is available.

No long-term-support branch or fixed patch-response time is promised.

## Report privately

Contact [toolab@digiforensics.cn](mailto:toolab@digiforensics.cn). Do not open a public issue containing an exploit, live credentials, private case data or real evidence.

Include the affected version/distribution and tool, browser/OS, a minimal synthetic reproduction, expected/observed behavior and potential impact. State whether the issue concerns parsing, archive traversal/expansion, code execution, persistent storage, cross-origin requests, package integrity or another boundary. Keep attachments minimal and review them for sensitive values.

Allow time for investigation before publishing exploit details. The maintainer can coordinate a fix and disclosure but does not promise a response schedule or bounty program.

## Application security model

Core examination runs in the browser without a Forensics++ analysis backend. The static host supplies executable code and therefore remains part of the trust boundary. Browser extensions, operating-system compromise, unsafe profiles and exported files are outside the application's isolation guarantees.

Parsers process untrusted bytes. Resource guards and workers reduce particular failure modes; they do not make the application a malware sandbox or guarantee that malformed input cannot affect a browser/library. Evidence identity, a content hash and a forensic interpretation are separate concepts.

## Website versus offline distribution

The website can use configured CDN resources and on-demand static lookup data. The complete offline ZIP contains runtime code/data and applies local-resource restrictions to its HTML entries. Those restrictions prevent external application resource requests in the covered flows, not all network traffic produced by the browser or operating system. External-service CyberChef operations are unavailable under the offline policy.

The offline launcher binds to loopback and uses Python standard-library HTTP serving. It is a local convenience server, not an Internet-facing production service.

## Storage and exports

Browser storage may retain settings, supported workspace state, analysis snapshots and localized data. Clearing it can remove recoverable work. Case/report exports can contain sensitive metadata even when raw evidence is not embedded. Preserve evidence separately and inspect exports before sharing them.

## Credentials and historical exposure

Credentials do not belong in source, documentation, examples, release notes or screenshots. Use environment-specific secret storage and placeholders in operational instructions. Removing an exposed value from a current file does not revoke it or remove it from repository history, caches or prior clones. Treat an exposed credential as compromised and rotate/revoke it through its owning service; history remediation is a separate coordinated action.

## Dependency and release integrity

Use the lockfile, verify relevant upstream provenance and ship required notices/corresponding sources. Release ZIPs include SHA-256 checksums and local data manifests. Checksums detect changed bytes; they do not establish who authored a release unless the checksum itself is obtained through a trusted channel. See [release engineering](docs/RELEASE.md) for publication checks.
