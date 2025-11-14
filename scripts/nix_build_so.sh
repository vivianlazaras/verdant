#!/usr/bin/env bash
set -e

if [[ -z "$1" ]]; then
    echo "Usage: $0 <android_project_path>"
    exit 1
fi

ANDROID_PROJECT_PATH="$1"

# Get the nix build output path
OUTPATH=$(nix build --print-out-paths | grep "/nix/store")
echo "Nix build output: $OUTPATH"

# Ensure jniLibs directory exists
JNI_LIBS_DIR="$ANDROID_PROJECT_PATH/app/src/main/jniLibs"
mkdir -p "$JNI_LIBS_DIR"

# Loop over target architectures
ARCHS=("armv7-linux-androideabi" "aarch64-linux-android" "i686-linux-android" "x86_64-linux-android")

for arch in "${ARCHS[@]}"; do
    # Map arch names to Android folder names
    case "$arch" in
        "armv7-linux-androideabi") FOLDER="armeabi-v7a" ;;
        "aarch64-linux-android") FOLDER="arm64-v8a" ;;
        "i686-linux-android") FOLDER="x86" ;;
        "x86_64-linux-android") FOLDER="x86_64" ;;
    esac

    TARGET_SO_DIR="$OUTPATH/lib/target/$arch/release"
    DEST_DIR="$JNI_LIBS_DIR/$FOLDER"
    mkdir -p "$DEST_DIR"

    echo "Copying $arch libraries to $DEST_DIR"
    sudo cp -v "$TARGET_SO_DIR"/*.so "$DEST_DIR"/ || echo "No .so files for $arch"
done

echo "✅ All libraries copied to jniLibs."
