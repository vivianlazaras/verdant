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

      in {
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "rust-android-crate";
          version = "0.1.0";

          src = ./.;

          nativeBuildInputs = [
            rust
            ndk
          ];

          buildPhase = ''
            export NDK_HOME=${ndk}
            export SDK_NDK=${ndk}/libexec/android-sdk/ndk/${ndkVersion}
            export PATH=$SDK_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
            
            # Setup environment for Android target
            export CC_aarch64_linux_android=aarch64-linux-android24-clang
            export CXX_aarch64_linux_android=aarch64-linux-android24-clang++
            export AR_aarch64_linux_android=llvm-ar

            rustup target add aarch64-linux-android

            # Build Rust crate as shared library (.so)
            cargo build --release --target aarch64-linux-android
          '';

          installPhase = ''
            mkdir -p $out/lib
            cp target/aarch64-linux-android/release/*.so $out/lib/
          '';
        };

        devShells.default = pkgs.mkShell {
          name = "rust-android-devshell";
          buildInputs = [
            rust
            sdk
            ndk
            pkgs.pkg-config
            pkgs.cmake
          ];

          shellHook = ''
            export NDK_HOME=${ndk}
            export SDK_NDK=${ndk}/libexec/android-sdk/ndk/${ndkVersion}
            export PATH=$SDK_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
            
            export CC_aarch64_linux_android=aarch64-linux-android24-clang
            export CXX_aarch64_linux_android=aarch64-linux-android24-clang++
            export AR_aarch64_linux_android=llvm-ar

            echo "✅ Android NDK ready for Rust cross-compilation"
            echo "You can now run: cargo build --target aarch64-linux-android --release"
          '';
        };
      });
}
