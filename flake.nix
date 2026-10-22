{
  description = "annai (案内, guidance) — DNS server for a Nix-managed homelab: package, NixOS module, dev shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";
    zig2nix = {
      url = "github:Cloudef/zig2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # Test only (ADR 0011): the log and metric validators the nixosTests run on annai's output.
    nisshi = {
      url = "git+ssh://git@forgejo.uchi.scorsi.dev:2222/scorsi/nisshi.git";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    masu = {
      url = "git+ssh://git@forgejo.uchi.scorsi.dev:2222/scorsi/masu.git";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      zig2nix,
      nisshi,
      masu,
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

      # No import-from-derivation: zig2nix would otherwise build zon2json, its target helper and
      # zon2nix at evaluation time, which a remote store (`--eval-store auto`) refuses to import.
      # So name, version, Zig target and dependencies are given here instead of computed by zig2nix.
      version = lib.head (
        builtins.match ".*\n    \\.version = \"([^\"]+)\".*" (builtins.readFile ./build.zig.zon)
      );
      # Static musl binary on Linux (ADR 0001).
      zigTargets = {
        aarch64-darwin = "aarch64-macos-none";
        aarch64-linux = "aarch64-linux-musl";
        x86_64-linux = "x86_64-linux-musl";
      };
      # Same derivation zon2nix generates from build.zig.zon2json-lock (Zig >= 0.16 layout: the
      # package tarballs under `$ZIG_GLOBAL_CACHE_DIR/p`), read with builtins.fromJSON instead.
      depsFor =
        system:
        let
          pkgs = pkgsFor system;
          zig = zig2nix.outputs.packages.${system}.zig-0_16_0;
          lock = lib.importJSON ./build.zig.zon2json-lock;
        in
        pkgs.linkFarm "annai-dependencies" (
          lib.mapAttrsToList (zhash: dep: {
            name = "${zhash}.tar.gz";
            path =
              pkgs.runCommand "${dep.name}.tar.gz"
                {
                  nativeBuildInputs = [ zig ];
                  outputHash = dep.hash;
                  outputHashMode = "flat";
                }
                ''
                  touch "$TMPDIR/build.zig" # workaround <https://codeberg.org/ziglang/zig/issues/31866>
                  hash="$(cd "$TMPDIR" && zig fetch --global-cache-dir "$TMPDIR" "${dep.url}")"
                  mv "$TMPDIR/p/$hash.tar.gz" "$out"
                '';
          }) lock
        );

      # Only what the Zig build reads: editing the docs or the Nix files doesn't rebuild the binary.
      src = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.unions [
          ./build.zig
          ./build.zig.zon
          ./src
        ];
      };
    in
    {
      packages = forAllSystems (system: {
        default = (envFor system).package {
          inherit src version;
          pname = "annai";
          zigTarget = zigTargets.${system};
          # A lock path that does not exist keeps zig2nix from running zon2nix; depsFor replaces it.
          zigBuildZonLock = "${src}/no-zon2nix";
          preBuild = ''
            ln -s ${depsFor system} "$ZIG_GLOBAL_CACHE_DIR"/p
          '';
          # `nix flake check` builds the package, so this runs `zig build test`.
          doCheck = true;
          zigCheckFlags = [ "test" ];
          meta = {
            description = "DNS server for a Nix-managed homelab";
            mainProgram = "annai";
          };
        };
      });

      nixosModules = {
        default = import ./nix/module.nix self;
        # Resolver clients (ADR 0010): point a host at the uchi instance with the search domains.
        resolver = import ./nix/resolver-nixos.nix;
      };
      darwinModules.resolver = import ./nix/resolver-darwin.nix;

      # Module evaluation runs on every system: the options of an example module are evaluated in
      # a NixOS configuration, rendered by nix/render.nix with this system's packages, and checked
      # by `annai check`; a configuration that does not match its mode must fail that build.
      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          render =
            example: extra:
            let
              cfg =
                (lib.nixosSystem {
                  modules = [
                    self.nixosModules.default
                    example
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
          module = render ./nix/example.nix { };
          module-soto = render ./nix/example-soto.nix { };
          module-metrics = render ./nix/example.nix { services.annai.metrics.listen = "[::1]:9153"; };
          # `annai check` refuses a metrics listener off loopback, as the module's assertion does,
          # and says so in a schema v1 line (ADR 0011): a refused start writes the same to the journal.
          module-metrics-public =
            pkgs.runCommand "module-metrics-public"
              {
                failed = pkgs.testers.testBuildFailure (
                  render ./nix/example.nix { services.annai.metrics.listen = "0.0.0.0:9153"; }
                );
              }
              ''
                grep -q '"event":"config-invalid"' $failed/testBuildFailure.log
                ${nisshi.lib.validateLogs.${system}} validate --logs < $failed/testBuildFailure.log
                touch $out
              '';
          module-metrics-assertion =
            let
              assertions =
                (lib.nixosSystem {
                  modules = [
                    self.nixosModules.default
                    ./nix/example.nix
                    {
                      services.annai.metrics.listen = "192.0.2.1:9153";
                      nixpkgs.hostPlatform = lib.replaceStrings [ "darwin" ] [ "linux" ] system;
                    }
                  ];
                }).config.assertions;
            in
            assert lib.any (a: !a.assertion) assertions;
            pkgs.writeText "module-metrics-assertion" "a non-loopback metrics listener fails the assertion";
          module-mode-mismatch = pkgs.testers.testBuildFailure (
            render ./nix/example.nix {
              services.annai.mode = lib.mkForce "soto";
              services.annai.forwarding.upstreams = [ "192.0.2.53" ];
            }
          );
        }
        # The integration tests of ADR 0011 (VMs: Linux only).
        // lib.optionalAttrs (lib.hasSuffix "-linux" system) (
          let
            # nisshi's and masu's validators (ADR 0011): every test checks annai's real output.
            validate = {
              logs = nisshi.lib.validateLogs.${system};
              metrics = masu.lib.validateMetrics.${system};
            };
          in
          {
            authoritative = import ./nix/test-authoritative.nix { inherit self pkgs validate; };
            forwarding = import ./nix/test-forwarding.nix { inherit self pkgs validate; };
            update = import ./nix/test-update.nix { inherit self pkgs validate; };
          }
        )
      );

      devShells = forAllSystems (system: {
        default = (envFor system).mkShell { };
      });

      # `nix run .#fuzz -- <codec|respond|update|update-state|tcp|forward> <seconds> [seed]` from the repository root
      # (ADR 0011): the seeded mutator of src/fuzz.zig in ReleaseSafe, so safety checks stay on.
      # Findings print as `fuzz: ...` lines; add each to src/corpus/fuzz.txt, which the tests replay.
      apps = forAllSystems (system: {
        fuzz = {
          type = "app";
          program = lib.getExe (
            (pkgsFor system).writeShellApplication {
              name = "annai-fuzz";
              runtimeInputs = [ zig2nix.outputs.packages.${system}.zig-0_16_0 ];
              text = ''
                if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
                  echo "usage: nix run .#fuzz -- <codec|respond|update|update-state|tcp|forward> <seconds> [seed]" >&2
                  exit 2
                fi
                exec zig build fuzz -Doptimize=ReleaseSafe -- "$@"
              '';
            }
          );
          meta.description = "Fuzz annai's codec, responder, UPDATE, TCP or forwarding path for a number of seconds";
        };
      });

      formatter = forAllSystems (system: (pkgsFor system).nixfmt-tree);
    };
}
