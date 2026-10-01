{
  description = "Logos Execution Zone";

  inputs = {
    logos-nix.url = "github:logos-co/logos-nix";

    nixpkgs.follows = "logos-nix/nixpkgs";

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
      logos-nix,
      rust-overlay,
      crane,
      logos-blockchain-circuits,
      rust-rapidsnark,
      ...
    }:
    let
      # Nix does not run on Windows, so a native "x86_64-windows" package set
      # cannot work: nixpkgs has no legacyPackages for it, and the attribute dies
      # in cc-wrapper ("called without required argument 'runtimeShell'"). It has
      # never built. Windows artifacts belong under a real build platform, named
      # `<name>-windows-x86_64` and produced by a cross build.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      forAll = nixpkgs.lib.genAttrs systems;

      mkPkgs =
        system:
        import nixpkgs {
          inherit system;
          overlays = logos-nix.lib.nativeOverlays ++ [ rust-overlay.overlays.default ];
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
            url = "https://static.crates.io/crates/risc0-circuit-recursion/${risc0CircuitRecursion.version}/download";
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
          # first in PATH, resolves metal/metallib from the Metal Toolchain
          # cryptex mount instead; with no cryptex it clears those two vars and
          # retries the old lookup. Every other xcrun call passes through with
          # the nix environment intact. (On recent macOS the Metal Toolchain is
          # a per-user component; `xcodebuild -downloadComponent MetalToolchain`
          # must have been run.)
          metalStub = pkgs.writeShellScriptBin "xcrun" ''
            orig=("$@")

            sdk=
            tool=
            args=()
            while [ $# -gt 0 ]; do
              case "$1" in
                --sdk) sdk=$2; shift 2 ;;
                metal|metallib)
                  if [ -z "$tool" ]; then tool=$1; else args+=("$1"); fi
                  shift
                  ;;
                *) args+=("$1"); shift ;;
              esac
            done

            # The mount is world-readable; only xcrun's lookup is per-user.
            if [ -n "$tool" ]; then
              for cand in /var/run/com.apple.security.cryptexd/mnt/*/Metal.xctoolchain/usr/bin/"$tool"; do
                [ -x "$cand" ] || continue
                if [ "$tool" = metal ] && [ -n "$sdk" ]; then
                  # Still under DEVELOPER_DIR, so nix's SDK; may fail, hence optional.
                  sysroot=$(/usr/bin/xcrun --sdk "$sdk" --show-sdk-path 2>/dev/null || true)
                  if [ -n "$sysroot" ]; then
                    exec "$cand" -isysroot "$sysroot" "''${args[@]}"
                  fi
                fi
                exec "$cand" "''${args[@]}"
              done

              # No cryptex: clear the nix SDK vars and retry the old lookup.
              unset DEVELOPER_DIR SDKROOT
              export xcrun_nocache=1
            fi

            exec /usr/bin/xcrun "''${orig[@]}"
          '';

          commonArgs = {
            inherit src;
            buildInputs = [ pkgs.openssl pkgs.pcsclite ];
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

          # ---- Windows (x86_64-pc-windows-gnu), cross-compiled ------------
          #
          # Nix does not run on Windows, so this is published under the
          # builder's own package set, the way zerokit and logos-delivery do it.
          # It appears only once both prebuilt inputs carry their Windows
          # artifacts; until then the attribute is absent rather than broken.
          mingw = pkgs.pkgsCross.mingwW64;

          # nvtx includes <Windows.h>; MinGW's header is lowercase and a cross
          # build runs on a case-sensitive filesystem.
          windowsHeaderShim = pkgs.runCommand "windows-h-shim" { } ''
            mkdir -p $out/include
            echo '#include <windows.h>' > $out/include/Windows.h
          '';

          circuitsWindows = logos-blockchain-circuits.packages.${system}.circuits-windows-x86_64-gnu;

          # rust-rapidsnark and the circuits each ship a static libgmp.a, and
          # linking both gives "multiple definition of __gmpn_*". Linux never
          # hits it because rust-rapidsnark links its shared library there.
          # Keep one: the circuits' copy, which their objects were built with.
          rapidsnarkWindows =
            let
              raw = rust-rapidsnark.packages.${system}.rapidsnark-windows-x86_64;
            in
            pkgs.runCommand "rapidsnark-windows-x86_64-nogmp" { } ''
              mkdir -p $out
              for f in ${raw}/*; do
                case "$(basename "$f")" in
                  libgmp.a) ;;
                  *) cp "$f" $out/ ;;
                esac
              done
              ln -s ${circuitsWindows}/lib/libgmp.a $out/libgmp.a
            '';

          # risc0-zkvm 3.0.5 compiles its r0vm "actor" prover unconditionally,
          # and that prover is a UnixStream socketpair. It is reachable only via
          # RISC0_PROVER=actor, and with the `prove` feature default_prover()
          # already returns the in-process LocalProver, so gating the module on
          # cfg(unix) costs Windows nothing. Patched in the vendor directory, so
          # the native builds and Cargo.lock are untouched.
          rustToolchainWindows = pkgs.rust-bin.stable.latest.default.override {
            targets = [ "x86_64-pc-windows-gnu" ];
          };
          craneLibWindows = (crane.mkLib pkgs).overrideToolchain rustToolchainWindows;
          vendorWindows =
            let
              plain = craneLibWindows.vendorCargoDeps { inherit src; };
            in
            pkgs.runCommand "lez-cargo-vendor-windows" { } ''
              cp -rL ${plain} $out
              chmod -R u+w $out
              # config.toml points every source at the ORIGINAL store path, so
              # without this cargo reads the unpatched crates and the patch below
              # is invisible.
              sed -i 's|${plain}|'"$out"'|g' $out/config.toml
              crate=$(find $out -maxdepth 3 -type d -name risc0-zkvm-3.0.5 | head -1)
              if [ -z "$crate" ]; then
                echo "risc0-zkvm-3.0.5 is not in the vendor dir; the layout changed" >&2
                exit 1
              fi
              patch -p1 -d "$crate" < ${./patches/risc0-zkvm-3.0.5-windows.patch}
              grep -q '#\[cfg(unix)\]' "$crate/src/host/client/prove/mod.rs" \
                || { echo "risc0 patch did not take" >&2; exit 1; }
              # The recorded per-file hashes no longer match; cargo accepts an
              # empty file map for a vendored source.
              ${pkgs.jq}/bin/jq '.files = {}' "$crate/.cargo-checksum.json" > "$crate/.cargo-checksum.json.new"
              mv "$crate/.cargo-checksum.json.new" "$crate/.cargo-checksum.json"
            '';

          walletFfiWindowsArgs = commonArgs // {
              cargoExtraArgs = "-p wallet-ffi";
              cargoVendorDir = vendorWindows;
              doCheck = false;

              CARGO_BUILD_TARGET = "x86_64-pc-windows-gnu";
              # rustc shells out to dlltool by bare name for this target, so the
              # toolchain has to be on PATH, not just named in the env below.
              nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ mingw.stdenv.cc ];

              CC_x86_64_pc_windows_gnu = "${mingw.stdenv.cc.targetPrefix}cc";
              CXX_x86_64_pc_windows_gnu = "${mingw.stdenv.cc.targetPrefix}c++";
              AR_x86_64_pc_windows_gnu = "${mingw.stdenv.cc.targetPrefix}ar";
              CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = "${mingw.stdenv.cc.targetPrefix}cc";

              # nixpkgs' mingw gcc pulls <mcfgthread/gthr.h> from the mcfgthreads
              # *dev* output; risc0's C++ kernels fail without it.
              CFLAGS_x86_64_pc_windows_gnu =
                "-I${windowsHeaderShim}/include "
                + "-I${mingw.windows.mcfgthreads.dev}/include "
                + "-I${mingw.windows.pthreads}/include";
              CXXFLAGS_x86_64_pc_windows_gnu =
                "-I${windowsHeaderShim}/include "
                + "-I${mingw.windows.mcfgthreads.dev}/include "
                + "-I${mingw.windows.pthreads}/include";

              # nixpkgs builds mingw-w64 against mcfgthread, so its libstdc++
              # pulls _MCF_mutex_*; rust's windows-gnu target links neither it
              # nor winpthread by default. libmman supplies the mmap/munmap the
              # circuit objects call.
              CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS =
                "-L native=${mingw.windows.mcfgthreads}/lib "
                + "-L native=${mingw.windows.pthreads}/lib "
                + "-l static=mcfgthread "
                + "-L native=${circuitsWindows}/lib "
                + "-l static=mman";

              RAPIDSNARK_LIB_DIR = rapidsnarkWindows;
              LBC_ROOT_DIR = circuitsWindows;
            };

          # crane builds `cargoArtifacts` itself when none is given, and that
          # build vendors again from the unpatched lock -- the risc0 gates would
          # silently not apply to the dependency stage.
          cargoArtifactsWindows = craneLibWindows.buildDepsOnly walletFfiWindowsArgs;

          walletFfiWindowsPackage = craneLibWindows.buildPackage (
            walletFfiWindowsArgs
            // {
              pname = "logos-execution-zone-wallet-ffi-windows";
              version = "0.1.0";
              cargoArtifacts = cargoArtifactsWindows;
              postInstall = ''
                mkdir -p $out/include
                cp lez/wallet-ffi/wallet_ffi.h $out/include/
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
        // nixpkgs.lib.optionalAttrs
          (
            system == "x86_64-linux"
            && rust-rapidsnark.packages.${system} ? rapidsnark-windows-x86_64
            && logos-blockchain-circuits.packages.${system} ? circuits-windows-x86_64-gnu
          )
          {
            wallet-windows-x86_64 = walletFfiWindowsPackage;
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
