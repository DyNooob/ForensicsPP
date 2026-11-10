# Documentation / 文档中心

Documentation for Forensics++ **1.0.0**. Start with a task, then follow the corresponding guide. Current operational guidance is separated from historical release and audit records.

## Use the application / 使用

| Document | Purpose |
| --- | --- |
| [Getting started / 入门](GETTING_STARTED.md) | Select a distribution, load evidence, inspect results and export |
| [Offline operation / 离线使用](OFFLINE.md) | Download, verify, launch and rebuild without runtime downloads |
| [Tool reference / 工具手册](TOOLS.md) | All 35 visible workspaces, accepted inputs and limits |
| [Troubleshooting / 排错](TROUBLESHOOTING.md) | Startup, workers, caches, data packs, HEIC and large files |
| [Licensing / 许可与来源](LICENSING.md) | Source license, dependencies, lookup data and codec sources |

## Build and contribute / 开发

| Document | Purpose |
| --- | --- |
| [Architecture / 架构](ARCHITECTURE.md) | Module ownership, execution boundaries and data flow |
| [Analysis contracts / 分析契约](architecture/ANALYSIS_CONTRACTS.md) | Sources, runs, artifacts, findings and `.fppcase` |
| [Runtime lifecycle / 运行时](architecture/RUNTIME.md) | Lazy tools, worker cancellation, handoff and resource cleanup |
| [Workbench design / 工作台组织](WORKBENCH_CONSOLIDATION.md) | Shared evidence state and historical aliases |
| [Development / 开发指南](DEVELOPMENT.md) | Setup, coding conventions and adding a tool |
| [Validation / 测试验证](VALIDATION.md) | Test layers, fixtures, browser checks and coverage claims |
| [Contributing / 贡献指南](../CONTRIBUTING.md) | Issues, pull requests and review expectations |

## Maintain and release / 维护发布

- [Release engineering / 发布流程](RELEASE.md)
- [Hosting and CDN / 部署与 CDN](CDN.md)
- [Preview deployment / 预览部署](preview-deploy-runbook.md)
- [Governance / 项目维护规则](GOVERNANCE.md)
- [Security policy / 安全政策](../SECURITY.md)
- [Changelog / 变更记录](../CHANGELOG.md)
- [1.0 release notes](releases/v1.0.0.md) and [validation record](releases/v1.0.0-audit.md)

## Historical material / 历史资料

[Archive index](archive/README.md) identifies older audits, implementation plans and milestone reports. They describe their original snapshot and are not current instructions. Earlier [release notes](releases/README.md) are retained as release history; their test counts and limitations belong to that release.

When changing behavior, update the relevant guide and release notes together. Source locations are linked as repository-relative paths; commands assume the repository root unless a guide explicitly says to run inside an extracted package.
