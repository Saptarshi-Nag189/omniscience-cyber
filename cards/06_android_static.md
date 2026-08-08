# Android Mobile Static Analysis (APK)

*Keywords: Android, APK, decompile, jadx, apktool, hardcoded secret, API key in app, insecure storage, SharedPreferences, SQLite cleartext, weak crypto, ECB, MD5, exported component, AndroidManifest, debuggable, cleartext traffic, cert pinning, mobsfscan, mobile static analysis.*

## APK static analysis workflow

Decompile then grep systematically — this is what `mobile_static.py` automates (jadx/apktool + detectors), cross-checked with `mobsfscan`. Steps: (1) `apktool d app.apk` for the manifest + smali + resources; `jadx -d out app.apk` for readable Java. (2) Read `AndroidManifest.xml` first: exported components, permissions, `android:debuggable`, `usesCleartextTraffic`, custom URL schemes, `networkSecurityConfig`. (3) grep decompiled source for secrets, crypto, storage sinks, and endpoints. (4) Flag any endpoint the app references that is OUT of scope — reporting/testing it violates the engagement rules. (5) Confirm exploitability dynamically (Frida/objection) and record device/OS + root status — required in mobile reports.

## Hardcoded secrets & endpoints in APKs

Search decompiled code and resources for embedded secrets: API keys, tokens, passwords, private keys, cloud credentials. Patterns: `AKIA[0-9A-Z]{16}` (AWS), `AIza[0-9A-Za-z\-_]{35}` (Google API), `-----BEGIN.*PRIVATE KEY-----`, `password=`, `secret`, `Bearer `, `api_key`. Check `res/values/strings.xml`, `assets/`, `BuildConfig`, and native libs. High-entropy strings (Shannon entropy > 4.0 over base64 charset) flag likely keys. Impact: a hardcoded backend key = server-side access for every app user; a signing/encryption key = forgery. This is the classic "insecure key management → critical data access" category the brief rewards.

## Insecure local storage (SharedPreferences / SQLite / files)

Mobile apps must not store credentials, tokens, or PII in cleartext on-device. Sinks to inspect: `SharedPreferences` (`getSharedPreferences`, `MODE_WORLD_READABLE` = critical), unencrypted `SQLite` DBs, files written to external storage (`getExternalStorageDir`, world-readable), `WebView` cache, logs (`Log.d` leaking tokens). On a rooted test device: `adb shell run-as <pkg> cat /data/data/<pkg>/shared_prefs/*.xml` reveals stored secrets. Finding a session token or /PII in plaintext SharedPreferences is a High finding. Remediation: Android Keystore for keys, EncryptedSharedPreferences/SQLCipher for data, never external storage for secrets, strip PII from logs.

## Weak crypto, manifest & platform flaws + CVSS

Weak crypto to flag: `DES`, `RC4`, `ECB` mode (`Cipher.getInstance("AES/ECB/...")`), `MD5`/`SHA1` for security, hardcoded IV/key, `new Random()` for tokens (not `SecureRandom`). Manifest flaws: `android:debuggable="true"` in release, `exported="true"` components with no permission (other apps invoke them), `usesCleartextTraffic="true"` (HTTP), missing cert pinning (MITM). Cleartext token in SharedPreferences: `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 6.2; hardcoded backend key granting server access: raise to `AV:N` and C:H/I:H → High/Critical. Remediation per class: strong AEAD crypto (AES-GCM) with Keystore-managed keys, `exported="false"` or permission-guard components, enforce HTTPS + pinning, disable debuggable in release.
