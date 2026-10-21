# Architecture Decision Records

MADR-lite: one decision per file, `NNNN-slug.md`, sections Context / Decision / Alternatives considered / Consequences. A decision is changed by a new ADR that supersedes the old one; the old file keeps its status line updated.

| ADR | Title |
|---|---|
| [0001](0001-language-and-runtime.md) | Language and runtime model |
| [0002](0002-roles-and-modes.md) | Roles and modes |
| [0003](0003-configuration-and-zone-data.md) | Configuration and zone data |
| [0004](0004-split-horizon-by-zone-loading.md) | Split horizon by zone loading, no internal delegation |
| [0005](0005-naming-scheme.md) | Naming scheme |
| [0006](0006-dynamic-updates-for-acme.md) | Dynamic updates for ACME DNS-01 |
| [0007](0007-wire-protocol-scope.md) | Wire protocol scope |
| [0008](0008-upstream-forwarding-and-cache.md) | Upstream forwarding and cache (amended by 0012) |
| [0009](0009-public-ns-hosting.md) | Public nameserver hosting |
| [0010](0010-integration-contracts.md) | Integration contracts with kekkai, genkan, hanko, and the deployment repository |
| [0011](0011-testing-and-operations.md) | Testing and operations |
| [0012](0012-cache-ttl-bounds.md) | Cache TTL bounds (accepted 2026-10-21; amends 0008) |
