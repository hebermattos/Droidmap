#!/usr/bin/env bash
# Shared update identities. Certificate fingerprints are public; keys stay outside Git.
case "${NETMAP_APK_PROFILE:-current}" in
  current)
    update_package='com.netmap.android'
    update_parallel_install=false
    # Existing CI APK, run 39461734985 (2026-10-20), apksigner certificate digest.
    update_certificate='b76460326372e4f59a999d02908b014edfe8fe25edf3aa1a4339eb95a416dfb7'
    ;;
  legacy-dns)
    update_package='com.netmap.android.dns'
    update_parallel_install=true
    update_certificate='82a648c2bc78d4d22d159b77864b1b60f3540a0a85b2236cafd5d3f7a8021ef2'
    ;;
  *) echo 'Unknown NETMAP_APK_PROFILE; use current or legacy-dns.' >&2; return 1 ;;
esac

verify_update_keystore() {
  if [[ ! -f "${NETMAP_DEBUG_KEYSTORE:-}" ]]; then
    echo 'Restore the existing signing keystore and set NETMAP_DEBUG_KEYSTORE; no replacement key will be generated.' >&2
    return 1
  fi
  local actual
  actual="$(keytool -exportcert -keystore "$NETMAP_DEBUG_KEYSTORE" -storepass android -alias androiddebugkey | sha256sum | cut -d ' ' -f 1)" || return 1
  if [[ "$actual" != "$update_certificate" ]]; then
    echo "Signing certificate mismatch for $update_package; restore its original key." >&2
    return 1
  fi
}
