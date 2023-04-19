{
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    utils.url = "github:numtide/flake-utils";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "utils";
    };
  };

  outputs = { self, nixpkgs, utils, rust-overlay }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        rust = pkgs.rust-bin.nightly.latest.default.override {
          extensions = [ "rust-src" "rustfmt" "rust-analyzer" ];
          targets = [ "wasm32-wasi" "riscv64gc-unknown-none-elf" ];
        };

        riscv-toolchain = import nixpkgs {
          localSystem = "${system}";
          crossSystem = {
            config = "riscv64-unknown-linux-gnu";
          };
        };
        in {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [ zig rust tinyemu qemu riscv-toolchain.buildPackages.gcc riscv-toolchain.buildPackages.binutils ];
        };
      });
}
