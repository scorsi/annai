# ADR-0010: Integration contracts with kekkai, genkan, hanko, and the deployment repository

- Status: accepted
- Date: 2026-10-14

## Context

The homelab network stack is four products with one owner each: **annai** owns DNS (zones, resolution, resolver configuration of the hosts), **kekkai** owns the overlay and node-to-node transport, **genkan** is a reverse proxy that reads certificate files, **hanko** issues certificates. They share no code (ADR-0001). Each integration must be a small, explicit contract so the four projects can evolve independently.

## Decision

### kekkai ↔ annai

- Node names and addresses are **declared in Nix**, not pushed by kekkai-lighthouse. annai's uchi zone and reverse zones are generated from the same node list and address prefixes kekkai is configured from. There is no runtime channel between kekkai and annai, in either direction.
- **kekkai does nothing DNS-related**: no names, no resolver configuration (kekkai ADR 0010, 0027). The only exception is the tunnel DNS settings of the future iOS app, which point at annai because nothing else can set them there.
- **annai configures the resolvers.** annai's flake exports resolver client modules: for NixOS, systemd-resolved with the uchi instance(s) as per-link DNS of the overlay interface; for nix-darwin, the macOS resolver configuration. Both take the resolver address as a module option (a stable overlay address such as `annai.uchi.example.org` once the overlay exists) and push the search domains `uchi.example.org` and `kekkai.uchi.example.org` (ADR-0005).
- kekkai's per-peer firewall (kekkai ADR 0011) is default deny: the uchi host's peer entries must allow `udp/53` and `tcp/53` from every peer. This is a deployment value.
- Listener and resolver addresses are deployment values; which network carries them (a hypervisor bridge, the overlay) is not annai's concern.

### hanko → annai

- **DNS-01**: hanko sends RFC 2136 UPDATEs signed with its TSIG key to **every** `soto` instance (fan-out), adds/removes only `_acme-challenge.*` TXT, and verifies propagation by querying **each NS by address**, never through a resolver, before triggering CA validation (ADR-0006). The uchi instance is authoritative for `uchi.example.org` and answers `NXDOMAIN` for challenge names (ADR-0004), so a resolver-based check would never succeed. Key name and secret come from sops in the deployment repository.
- hanko speaks RFC 2136 only: no certificate exists before annai is the public NS (M4).
- hanko is the only RFC 2136 client, and this is the only runtime coupling between annai and another product.

### genkan ↔ annai

- Nothing at runtime. genkan's names (`*.soto.example.org`, product CNAMEs, `genkan.uchi.`) are declared in Nix; genkan never writes them and never runs an ACME challenge (genkan ADR 0004).
- genkan serves both the canonical `soto` name and the product alias for each product (ADR-0005) with the certificate hanko issues for both.

### deployment repository → annai

- annai exports a **NixOS module** (`services.annai`) from its own flake: options for mode, listeners, forwarding, update keys, and zones as Nix attribute sets; the module renders TOML (ADR-0003) and runs `annai check` at build time. The deployment repository composes zone contents from its host/node/service definitions and kekkai's address prefixes.
- annai exports the **resolver client modules** above (NixOS and nix-darwin). The nix-darwin module only configures the resolver: annai does not run on macOS.

## Alternatives considered

- **kekkai-lighthouse registering nodes in annai dynamically** (MagicDNS-style): rejected, nodes are already declarative; it would add a second dynamic channel and a second source of truth.
- **kekkai-node configuring the OS resolver**: rejected, kekkai's modules are agnostic of any DNS suffix (kekkai ADR 0022) and the addresses are static, so a Nix module owned by annai does the same with no runtime code.
- **genkan reading annai's zone files** to discover routes: rejected, inverted dependency; genkan's routes are declared in Nix too.
- **genkan or NixOS `security.acme` as the RFC 2136 client**: rejected, see ADR-0006; issuance is hanko's product.

## Consequences

- Adding a node or a service is one change in the deployment repository that updates kekkai, annai, genkan and hanko together.
- The only runtime coupling is hanko → soto instances over RFC 2136. Everything else is build-time.
