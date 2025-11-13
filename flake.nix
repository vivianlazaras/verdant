{
  description = "Build Rust crate for Android (arm64-v8a)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
          config.android_sdk.accept_license = true;
        };
        pkgBuildInputs = with pkgs; [
          pkgs.glibc
          rust
          sdk
          ndk
          pkg-config
          cmake
          rust-cbindgen
        ];
        ndkVersion = "27.0.12077973";

        rust = pkgs.rustup;

        # Android SDK + NDK setup
        androidEnv = pkgs.androidenv.composeAndroidPackages {
          cmdLineToolsVersion = "12.0";
          platformToolsVersion = "34.0.5";
          buildToolsVersions = [ "34.0.0" ];
          platformVersions = [ "34" ];
          ndkVersion = ndkVersion;
          includeNDK = true;
        };

        ndk = androidEnv.ndk-bundle;
        sdk = androidEnv.androidsdk;

        androidTargets = [
          {
            name = "armv7";
            triple = "armv7-linux-androideabi";
            clangPrefix = "armv7a-linux-androideabi24";
            arch = "armeabi-v7a";
            bits = 32;
          }
          {
            name = "arm64";
            triple = "aarch64-linux-android";
            clangPrefix = "aarch64-linux-android24";
            arch = "arm64-v8a";
            bits = 64;
          }
          {
            name = "x86";
            triple = "i686-linux-android";
            clangPrefix = "i686-linux-android24";
            arch = "x86";
            bits = 32;
          }
          {
            name = "x86_64";
            triple = "x86_64-linux-android";
            clangPrefix = "x86_64-linux-android24";
            arch = "x86_64";
            bits = 64;
          }
        ];
        envSetup = ''
          export NDK_HOME=${ndk}
          export SDK_NDK=${ndk}/libexec/android-sdk/ndk/${ndkVersion}
          export PATH=$SDK_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
        '';
        configuredShellHook = builtins.concatStringsSep "\n" (map (t:
          ''
          triple_safe=${builtins.replaceStrings ["-"] ["_"] t.triple}
          export CC_$triple_safe="${t.clangPrefix}-clang"
          export CXX_$triple_safe="${t.clangPrefix}-clang++"

          export AR_$triple_safe="llvm-ar"
          if [ ${toString t.bits} -eq 64 ]; then
            export CFLAGS_$triple_safe="-DOPENSSL_64_BIT"
          else
            export CFLAGS_$triple_safe="-I${pkgs.pkgsCross.gnu32.glibc.dev}/include/ -DOPENSSL_32_BIT"
            
          fi
          rustup target add ${t.triple}
          echo " - $triple_safe (${t.arch}, ${toString t.bits}-bit) ready"
          ''
        ) androidTargets);
        buildTargets = builtins.concatStringsSep "\n" (map (t: ''
          cargo build --release --target ${t.triple}
        '' ) androidTargets);
        allTargetBuildPhase = builtins.concatStringsSep "\n" '' ${envSetup} ${configuredShellHook} ${buildTargets} '';
      
      in {
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "libverdant";
          version = "0.1.0";

          src = ./.;

          nativeBuildInputs = [
            rust
            ndk
          ];

          buildInputs = pkgBuildInputs;

          buildPhase = allTargetBuildPhase;

          installPhase = ''
            mkdir -p $out/lib
            cp -rf target/ $out/lib/
            cp -r ./src/include/ $out/include/ 
          '';
        };

        devShells.default = pkgs.mkShell {
          name = "verdant-devshell";
          buildInputs = pkgBuildInputs;
          
          shellHook = ''
            ${envSetup}
            
            ${configuredShellHook}

            echo "✅ Android NDK ready for Rust cross-compilation"
            echo "You can now run: cargo build --target aarch64-linux-android --release"
          '';
        };
  });
}
