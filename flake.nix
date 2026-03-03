{
  description = "r7z - Pure-Rust 7z archive library";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      overlays = [(import rust-overlay)];
      pkgs = import nixpkgs {
        inherit system overlays;
      };

      rustToolchain = pkgs.rust-bin.stable.latest.default.override {
        extensions = ["rust-src" "rust-analyzer" "llvm-tools-preview"];
      };

      nativeBuildInputs = with pkgs;
        [
          rustToolchain
          cargo-flamegraph
          cargo-nextest
          gnuplot
          hyperfine
        ]
        ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
          perf
          valgrind
          mold
        ];

      cargoTargetEnvPrefix =
        pkgs.lib.toUpper (builtins.replaceStrings ["-"] ["_"]
          pkgs.stdenv.hostPlatform.rust.rustcTargetSpec);
    in {
      devShells.default = pkgs.mkShell {
        inherit nativeBuildInputs;

        shellHook = ''
          export RUST_SRC_PATH="${rustToolchain}/lib/rustlib/src/rust/library"
          export CARGO_TARGET_${cargoTargetEnvPrefix}_RUSTFLAGS="-C target-cpu=native${pkgs.lib.optionalString pkgs.stdenv.isLinux " -C link-arg=-fuse-ld=mold"}"
          echo "r7z dev shell  ($(rustc --version))"
        '';
      };
    });
}
