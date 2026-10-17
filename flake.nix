{
  description = "annai (案内, guidance) — DNS server for a Nix-managed homelab: package, NixOS module, dev shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";
    zig2nix = {
      url = "github:Cloudef/zig2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      zig2nix,
      ...
    }:
    let
      inherit (nixpkgs) lib;
      forAllSystems = lib.genAttrs [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      pkgsFor = system: nixpkgs.legacyPackages.${system};
      # ADR 0001: one tagged Zig release, the one the TOML dependency builds with (ADR 0003).
      envFor =
        system: zig2nix.outputs.zig-env.${system} { zig = zig2nix.outputs.packages.${system}.zig-0_16_0; };

      # Only what the Zig build reads: editing the docs or the Nix files doesn't rebuild the binary.
      src = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.unions [
          ./build.zig
          ./build.zig.zon
          ./build.zig.zon2json-lock
          ./src
        ];
      };
    in
    {
      packages = forAllSystems (system: {
        default = (envFor system).package {
          inherit src;
          # Static binary on Linux (ADR 0001); a no-op on macOS.
          zigPreferMusl = true;
          # `nix flake check` builds the package, so this runs `zig build test`.
          doCheck = true;
          zigCheckFlags = [ "test" ];
          meta = {
            description = "DNS server for a Nix-managed homelab";
            mainProgram = "annai";
          };
        };
      });

      nixosModules.default = import ./nix/module.nix self;

      # Module evaluation runs on every system: the options of nix/example.nix are evaluated in a
      # NixOS configuration, rendered by nix/render.nix with this system's packages, and checked by
      # `annai check`; a configuration that does not match its mode must fail that build.
      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          render =
            extra:
            let
              cfg =
                (lib.nixosSystem {
                  modules = [
                    self.nixosModules.default
                    ./nix/example.nix
                    extra
                    { nixpkgs.hostPlatform = lib.replaceStrings [ "darwin" ] [ "linux" ] system; }
                  ];
                }).config.services.annai;
            in
            import ./nix/render.nix {
              inherit pkgs cfg;
              package = self.packages.${system}.default;
            };
        in
        {
          default = self.packages.${system}.default;
          module = render { };
          module-mode-mismatch = pkgs.testers.testBuildFailure (render {
            services.annai.mode = lib.mkForce "soto";
            services.annai.forwarding.upstreams = [ "192.0.2.53" ];
          });
        }
      );

      devShells = forAllSystems (system: {
        default = (envFor system).mkShell { };
      });

      formatter = forAllSystems (system: (pkgsFor system).nixfmt-tree);
    };
}
