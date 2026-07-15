# Security Policy

## Supported Version

Security fixes are applied to the latest version on the `main` branch.

Forensics++ is currently a pre-1.0 project. Older snapshots and previously generated static builds may not receive fixes.

## Reporting a Vulnerability

Please contact the maintainer privately at [toolab@digiforensics.cn](mailto:toolab@digiforensics.cn). Do not open a public issue with exploit details, real evidence, credentials, or private email content. Keep the first message limited to the minimum synthetic reproduction needed to establish the issue.

Please include:

- The affected route or tool.
- Reproduction steps using synthetic data.
- Expected and observed behavior.
- Browser and operating system versions.
- Potential impact.

Do not attach real case files, credentials, private email, or other sensitive evidence.

## Security Model

Core Forensics++ tools are designed to process input in the browser without a Forensics++ backend. This does not make every browser environment trusted. Browser extensions, injected scripts, compromised dependencies, unsafe hosting, and exported files remain part of the threat model.

Network-dependent functionality must be optional, visible to the user, and disabled by default. Embedded third-party tools may have their own capabilities and security model.

## Responsible Disclosure

Please allow reasonable time to investigate and release a fix before public disclosure. Reports made in good faith are welcome.
