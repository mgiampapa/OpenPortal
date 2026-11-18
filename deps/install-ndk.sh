#!/bin/bash
# Assemble the chunked NDK download into ~/Library/Android/sdk/ndk.
# Run this from your own Terminal (the chat sandbox cannot write >100MB files).
set -euo pipefail

cd "$(dirname "$0")"
OUT="$HOME/Library/Android/sdk/ndk"
mkdir -p "$OUT"

echo "==> assembling android-ndk-r28b-darwin.zip from $(ls ndk-parts | wc -l | tr -d ' ') parts"
cat ndk-parts/ndk.part* > android-ndk-r28b-darwin.zip

echo "==> verifying size"
ACTUAL=$(stat -f %z android-ndk-r28b-darwin.zip)
EXPECTED=949590256
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "size mismatch: $ACTUAL != $EXPECTED"; exit 1
fi

echo "==> unzipping into $OUT"
unzip -q -o android-ndk-r28b-darwin.zip -d "$OUT"
mv "$OUT/android-ndk-r28b" "$OUT/28.2.13676358"

echo "==> verifying toolchain"
CC="$OUT/28.2.13676358/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android29-clang"
"$CC" --version | head -1
ls "$OUT/28.2.13676358/simpleperf/bin/android/arm64/simpleperf" >/dev/null && echo "simpleperf OK"

echo "==> cleaning up"
rm -f android-ndk-r28b-darwin.zip
rm -rf ndk-parts
echo "NDK installed at $OUT/28.2.13676358"
