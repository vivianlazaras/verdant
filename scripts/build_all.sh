declare -a targets=("x86_64-linux-android" "i686-linux-android" "armv7-linux-androideabi" "aarch64-linux-android")
for target in "${targets[@]}"; do
    echo "building for target: $target"
    cargo build --release --target $target --features jni
done