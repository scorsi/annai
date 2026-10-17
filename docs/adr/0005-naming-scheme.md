# ADR-0005: Naming scheme

- Status: accepted
- Date: 2026-10-14

## Context

Two domains at a registrar, written `example.org` (primary) and `example.net` in every annai document; the real names are deployment values. The primary domain is under `.dev`, which is on the HSTS preload list: browsers force HTTPS for every name under it, so every web-facing internal service needs a publicly valid certificate (hence DNS-01, ADR-0006). kekkai allocates an IPv4 and an IPv6 address per node.

## Decision

Under `example.org` (and identically under `example.net`):

| Name | Meaning | Served by |
|---|---|---|
| `<service>.uchi.example.org` | internal service, reachable only through kekkai | uchi zone |
| `<node>.kekkai.uchi.example.org` | kekkai node (A + AAAA from kekkai's allocation) | uchi zone |
| `annai.uchi.`, `genkan.uchi.` | internal infrastructure | uchi zone |
| `<service>.soto.example.org` | "private public": exposed to the Internet by genkan, for the author's own use | apex zone |
| `<edge>.soto.`, `genkan.soto.` | public edge infrastructure, hosts named by the deployment | apex zone |
| `<product>.example.org` | fully public product (e.g. `cv.example.org`), **CNAME → `<product>.soto.example.org`**; the `soto` name is canonical | apex zone |
| `example.org` (apex) | A/AAAA to the edge directly (a CNAME is not allowed at an apex) | apex zone |
| `ns1.example.org`, `ns2.example.org` | public nameservers, glue at the registrar; also serve `example.net` | apex zone |

Rules:

- Labels are lowercase `[a-z0-9-]`; Japanese names in romaji.
- Reverse zones (`in-addr.arpa` / `ip6.arpa`) for kekkai's IPv4 range and IPv6 prefix are generated from the same node data: `PTR → <node>.kekkai.uchi.example.org`.
- Search domains pushed to nodes (ADR-0010): `uchi.example.org`, `kekkai.uchi.example.org`, so `ssh <node>` works.
- `example.net` gets its own apex zone with the same structure; whether a given name has records there or CNAMEs to the primary domain is decided per record in Nix.

## Alternatives considered

- `<node>.kekkai.example.org` (kekkai as a sibling of uchi). Rejected: nodes are internal by definition; nesting under `uchi` keeps one internal zone.
- `<product>.soto.example.org` as the only public name. Rejected: product URLs should be short; the CNAME keeps `soto` as "what genkan exposes" and the short name as the brand.

## Consequences

- hanko issues a certificate covering both the canonical `soto` name and the product alias, and genkan serves both — contract in ADR-0010.
- One internal zone (`uchi.example.org`) is enough for v0; reverse zones are a v0 nice-to-have, not a blocker.
