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


## Preferred: commit the compressed archive

The Android workflow now detects `native-tools/nuclei-arm64.tar.gz`, verifies its
pinned SHA-256 (`2a432501808e60ab471f1ef3e4eef11904a19c69d5b31344b7f06fdd218369d5`),
extracts `nuclei-arm64`, verifies the binary checksum and installs it
under `jniLibs/arm64-v8a/libnuclei.so` during the CI build.

The supplied archive is about 70 MB, below GitHub's 100 MB Git file limit,
but exceeds the browser's 25 MB upload limit. Add it using Git CLI:

```bash
git checkout feature/nuclei-archive-in-repo
cp /path/to/nuclei-arm64.tar.gz native-tools/nuclei-arm64.tar.gz
git add native-tools/nuclei-arm64.tar.gz
git commit -m "Add pinned Android ARM64 Nuclei archive"
git push origin feature/nuclei-archive-in-repo
```

Do not commit the 171 MiB extracted executable (above GitHub's 100 MB limit).
If the archive is absent, CI retains the fallback to the existing GitHub release.
The archive is intentionally **not committed by the workflow-only change**.
