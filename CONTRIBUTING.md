# Contributing to Forensics++

Thank you for helping improve Forensics++ / ForensicsPP.

The project favors practical, browser-local tools with clear inputs, explicit execution, readable results, and outputs that can be independently verified.

## Before You Start

- Search existing issues before opening a new one.
- Keep evidence processing local unless a network action is optional, clearly labeled, and disabled by default.
- Do not add claims that a single tool result proves authenticity, attribution, or legal conclusions.
- Prefer established project components and patterns over introducing another UI framework.

## Local Development

```bash
git clone https://github.com/DyNooob/ForensicsPP.git
cd ForensicsPP
npm ci
npm run dev
```

The development server prints the local URL. Vite normally starts on `http://localhost:5173/` and selects another port when needed.

## Required Checks

Run these before submitting a pull request:

```bash
npm run verify
```

This runs the automated test suite, copyright header check, TypeScript validation, production build and release artifact verification.

For layout changes, start the app on port `5174` and run the desktop audit:

```bash
npm run dev -- --port 5174
npm run audit:layout
```

The audit visits every tool route and exercises seeded and file-loaded states. When changing parser behavior, also include a small reproducible fixture and verify the expected values manually.

## Pull Requests

Keep each pull request focused. Describe:

1. What problem it solves.
2. What behavior changed.
3. How it was verified.
4. Whether it changes local storage, downloads, network behavior, or third-party dependencies.

Do not commit generated `dist/`, local screenshots, temporary evidence files, editor state, or dependency directories.

## Security Issues

Please report vulnerabilities privately by email to [toolab@digiforensics.cn](mailto:toolab@digiforensics.cn). Do not publish exploit details, real evidence, credentials, or private email content in a public issue. See [SECURITY.md](./SECURITY.md) for the information to include.

## License

By contributing, you agree that your contribution may be distributed under the project's [MIT License](./LICENSE).
