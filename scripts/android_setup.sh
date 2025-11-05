# Sets up some stuff for compiling to android

add_android_targets() {
    # Default Android architectures (Rust target triples)
    local targets=(
        aarch64-linux-android       # arm64-v8a
        armv7-linux-androideabi     # armeabi-v7a
        x86_64-linux-android        # x86_64
        i686-linux-android          # x86
    )

    # If arguments provided, use those instead
    if [ "$#" -gt 0 ]; then
        targets=("$@")
    fi

    echo "📦 Adding Rust targets for Android..."
    for target in "${targets[@]}"; do
        echo "➡️  Adding target: $target"
        rustup target add "$target"
    done

    echo "✅ All requested Android targets installed."
}

add_android_targets