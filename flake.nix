{
  description = "Logos Execution Zone";

  inputs = {
    logos-liblogos.url = "github:logos-co/logos-liblogos";

    nixpkgs.follows = "logos-liblogos/nixpkgs";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane.url = "github:ipetkov/crane";

    # Must stay in sync with the lbc-* tags in logos-blockchain/Cargo.lock.
    logos-blockchain-circuits = {
      url = "github:logos-blockchain/logos-blockchain-circuits/2846ee7a4cfa24458bb8063412ab2e753b344d2f";
    };

    # Must stay in sync with the rust-rapidsnark rev in Cargo.lock.
    rust-rapidsnark = {
      url = "github:logos-blockchain/logos-blockchain-rust-rapidsnark/e91187f8ccb5bbfc7bb00dac88169112428da78f";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      crane,
      logos-blockchain-circuits,
      rust-rapidsnark,
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
          lbc_dir = logos-blockchain-circuits.packages.${system}.default;

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

          # risc0 compiles its Metal (GPU) prover kernels by invoking
          # `xcrun metal` / `xcrun metallib`. Under nix, the darwin stdenv sets
          # DEVELOPER_DIR/SDKROOT to its own SDK, which makes `xcrun` look for
          # the `metal` tool in the wrong place and fail with
          #   error: cannot execute tool 'metal' due to missing Metal Toolchain
          # even when a working Metal Toolchain is installed. This wrapper, put
          # first in PATH, clears those two vars for metal/metallib invocations
          # only — so they resolve the real system Xcode Metal Toolchain — while
          # every other xcrun call passes through with the nix environment
          # intact. (On recent macOS the Metal Toolchain is a per-user component;
          # `xcodebuild -downloadComponent MetalToolchain` must have been run.)
          metalStub = pkgs.writeShellScriptBin "xcrun" ''
            tool=
            for a in "$@"; do
              case "$a" in metal|metallib) tool=1 ;; esac
            done
            if [ -n "$tool" ]; then
              unset DEVELOPER_DIR SDKROOT
              export xcrun_nocache=1
            fi
            exec /usr/bin/xcrun "$@"
          '';

          commonArgs = {
            inherit src;
            buildInputs = [ pkgs.openssl ];
            nativeBuildInputs = [
              pkgs.pkg-config
              pkgs.clang
              pkgs.llvmPackages.libclang.lib
              pkgs.gnutar  # Required for crane's archive operations (macOS tar lacks --sort)
              pkgs.python3  # Required for correct builds now, as python is sandboxed in nix builds
            ];
            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            # Logos blockchain related env vars
            LBC_ROOT_DIR = logos-blockchain-circuits.packages.${system}.default;
            RAPIDSNARK_LIB_DIR = rust-rapidsnark.packages.${system}.rapidsnark;
            # Point the risc0-circuit-recursion build script to the pre-fetched zip
            # so it doesn't try to download it inside the sandbox.
            RECURSION_SRC_PATH = "${recursionZkr}";
            # Provide a writable HOME so risc0-build-kernel can use its cache directory
            # (needed on macOS for Metal kernel compilation cache).
            # On macOS, put the metalStub xcrun wrapper first so `xcrun metal` /
            # `metallib` resolve the system Metal Toolchain (see metalStub above),
            # and append /usr/bin for the real xcrun it execs.
            # This requires running with --option sandbox false for Metal GPU support.
            preBuild = ''
              export HOME=$(mktemp -d)
            '' + pkgs.lib.optionalString pkgs.stdenv.isDarwin ''
              export PATH="${metalStub}/bin:$PATH:/usr/bin"
            '';
          };

          walletFfiPackage = craneLib.buildPackage (
            commonArgs
            // {
              pname = "logos-execution-zone-wallet-ffi";
              version = "0.1.0";
              cargoExtraArgs = "-p wallet-ffi";
              postInstall = ''
                mkdir -p $out/include
                cp lez/wallet-ffi/wallet_ffi.h $out/include/
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
                cp lez/indexer/ffi/indexer_ffi.h $out/include/
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
