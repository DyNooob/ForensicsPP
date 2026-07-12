# Security Policy

## Supported Version

Security fixes are applied to the latest version on the `main` branch.

Forensics++ is currently a pre-1.0 project. Older snapshots and previously generated static builds may not receive fixes.

## Reporting a Vulnerability

Please use GitHub's private vulnerability reporting feature for the repository when it is available. If private reporting is unavailable, contact the maintainer through the contact information published on [loken.cn](https://www.loken.cn) and avoid including sensitive evidence or exploit details in the first message.

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
