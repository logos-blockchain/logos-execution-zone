{
  description = "Logos Execution Zone";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane.url = "github:ipetkov/crane";

    logos-blockchain-circuits = {
      url = "github:logos-blockchain/logos-blockchain-circuits";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      crane,
      logos-blockchain-circuits,
      ...
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-windows"
      ];

      forAll = nixpkgs.lib.genAttrs systems;

      mkPkgs =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
    in
    {
      packages = forAll (
        system:
        let
          pkgs = mkPkgs system;
          rustToolchain = pkgs.rust-bin.stable.latest.default;
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
          src = ./.;
          cargoLock = builtins.fromTOML (builtins.readFile ./Cargo.lock);

          # Parse Cargo.lock at eval time to find the locked risc0-circuit-recursion
          # version and its crates.io checksum — no hardcoding required.
          risc0CircuitRecursion = builtins.head (
            builtins.filter (p: p.name == "risc0-circuit-recursion") cargoLock.package
          );

          # Download the crate tarball from crates.io; the checksum from Cargo.lock
          # is the sha256 of the .crate file, so this is a verified fixed-output fetch.
          risc0CircuitRecursionCrate = pkgs.fetchurl {
            url = "https://crates.io/api/v1/crates/risc0-circuit-recursion/${risc0CircuitRecursion.version}/download";
            sha256 = risc0CircuitRecursion.checksum;
            name = "risc0-circuit-recursion-${risc0CircuitRecursion.version}.crate";
          };

          # Extract the zkr artifact hash from build.rs inside the crate (IFD).
          # This hash is both the S3 filename and the sha256 of the zip content.
          recursionZkrHash =
            let
              hashFile = pkgs.runCommand "extract-risc0-recursion-zkr-hash"
                { nativeBuildInputs = [ pkgs.gnutar ]; }
                ''
                  tmp=$(mktemp -d)
                  tar xf ${risc0CircuitRecursionCrate} -C "$tmp"
                  hash=$(grep -o '"[0-9a-f]\{64\}"' \
                    "$tmp/risc0-circuit-recursion-${risc0CircuitRecursion.version}/build.rs" \
                    | head -1 | tr -d '"')
                  printf '%s' "$hash" > $out
                '';
            in
            builtins.replaceStrings [ "\n" " " ] [ "" "" ] (builtins.readFile hashFile);

          # Pre-fetch the zkr zip so the sandboxed Rust build can't be blocked.
          recursionZkr = pkgs.fetchurl {
            url = "https://risc0-artifacts.s3.us-west-2.amazonaws.com/zkr/${recursionZkrHash}.zip";
            sha256 = recursionZkrHash;
          };

          commonArgs = {
            inherit src;
            buildInputs = [ pkgs.openssl ];
            nativeBuildInputs = [
              pkgs.pkg-config
              pkgs.clang
              pkgs.llvmPackages.libclang.lib
              pkgs.gnutar  # Required for crane's archive operations (macOS tar lacks --sort)
            ];
            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            # Point the risc0-circuit-recursion build script to the pre-fetched zip
            # so it doesn't try to download it inside the sandbox.
            RECURSION_SRC_PATH = "${recursionZkr}";
            # Provide a writable HOME so risc0-build-kernel can use its cache directory
            # (needed on macOS for Metal kernel compilation cache).
            # On macOS, append /usr/bin to PATH so xcrun (Metal compiler) can be found,
            # while keeping Nix tools (like gnutar) first in PATH.
            # This requires running with --option sandbox false for Metal GPU support.
            preBuild = ''
              export HOME=$(mktemp -d)
            '' + pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
              export PATH="$PATH:/usr/bin"
            '';
            LOGOS_BLOCKCHAIN_CIRCUITS = logos-blockchain-circuits.packages.${system}.default;
          };

          walletFfiPackage = craneLib.buildPackage (
            commonArgs
            // {
              pname = "logos-execution-zone-wallet-ffi";
              version = "0.1.0";
              cargoExtraArgs = "-p wallet-ffi";
              postInstall = ''
                mkdir -p $out/include
                cp wallet-ffi/wallet_ffi.h $out/include/
              ''
              + pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
                install_name_tool -id @rpath/libwallet_ffi.dylib $out/lib/libwallet_ffi.dylib
              '';
            }
          );

          indexerFfiPackage = craneLib.buildPackage (
            commonArgs
            // {
              pname = "logos-execution-zone-indexer-ffi";
              version = "0.1.0";
              cargoExtraArgs = "-p indexer_ffi";
              postInstall = ''
                mkdir -p $out/include
                cp indexer_ffi/indexer_ffi.h $out/include/
              ''
              + pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
                install_name_tool -id @rpath/libindexer_ffi.dylib $out/lib/libindexer_ffi.dylib
              '';
            }
          );
        in
        {
          wallet = walletFfiPackage;
          indexer = indexerFfiPackage;
          default = walletFfiPackage;
        }
      );
      devShells = forAll (
        system:
        let
          pkgs = mkPkgs system;
          walletFfiPackage = self.packages.${system}.wallet;
          walletFfiShell = pkgs.mkShell {
            inputsFrom = [ walletFfiPackage ];
          };
          indexerFfiPackage = self.packages.${system}.indexer;
          indexerFfiShell = pkgs.mkShell {
            inputsFrom = [ indexerFfiPackage ];
          };
        in
        {
          wallet = walletFfiShell;
          indexer = indexerFfiShell;
          default = walletFfiShell;
        }
      );
    };
}
