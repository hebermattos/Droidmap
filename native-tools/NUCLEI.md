# Bundling Nuclei for Android ARM64

The supplied executable is an Android AArch64 ELF using /system/bin/linker64.
It is 179238592 bytes and has SHA-256:
`0c2b5a0e9110ebeb63daead62fe7a41c5e91275ff7befbeb64fe3f4e0ffdae48`.

## Install in a local checkout

Extract nuclei-arm64.tar.gz and run:

```bash
tar -xzf nuclei-arm64.tar.gz
bash native-tools/install-nuclei-android.sh ./nuclei-arm64
./gradlew :app:assembleDebug
```

Expected destination: `app/src/main/jniLibs/arm64-v8a/libnuclei.so`.

## Notes

- The initial Nuclei integration expects `libnuclei.so` in Android's `nativeLibraryDir`.
- This is a Go executable with a native-library-compatible name, **not** a JNI shared library. Verify that Android's APK installer extracts it and that `ProcessBuilder` can launch it on Android 16.
- The project already sets `jniLibs.useLegacyPackaging true`. Confirm extracted executable permissions on a real device.
- Packaging without verifying Android runtime behavior is insufficient.
- The repository binary must be explicitly uploaded (preferably through Git LFS or a controlled release artifact). The script itself does not download executables.
- Do not change applicationId or signing keys; debug builds with `-PsideBySideInstall=true` intentionally use a different applicationId.
