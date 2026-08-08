# iOS Mobile Testing (IPA static + dynamic)

*Keywords: iOS, iPhone app, IPA, Info.plist, NSAppTransportSecurity, ATS, NSUserDefaults, Keychain, plist secrets, Mach-O, class-dump, otool, objection, frida iOS, SSL pinning bypass, jailbreak, insecure iOS storage, mobile testing iOS.*

## iOS static analysis (IPA)

If an iOS app/IPA is in scope, static-analyze it. Steps: (1) Unzip the IPA (`unzip app.ipa`) → `Payload/App.app/`. (2) Inspect `Info.plist` for `NSAppTransportSecurity` exceptions (cleartext allowed), URL schemes, permissions, and `UIFileSharingEnabled` (exposes Documents). (3) `strings` and `otool -L`/`class-dump` the Mach-O binary for hardcoded secrets, API endpoints, and whether it links crypto/pinning libs. (4) Check for missing binary protections: PIE, stack canaries, ARC (`otool -hv`, `otool -Iv | grep stack_chk`). (5) grep the bundle and `.plist`/`.strings` resources for keys, tokens, backend URLs — flag any endpoint OUT of scope. Hardcoded secrets and cleartext-allowed ATS are the common static wins.

## iOS insecure storage & Keychain

iOS data-storage flaws: (1) Sensitive data in `NSUserDefaults` (plist, unencrypted) — credentials/tokens/PII stored there is a finding. (2) Plist/SQLite/Core Data files under the app sandbox holding cleartext secrets. (3) Keychain items with weak accessibility (`kSecAttrAccessibleAlways` vs `...WhenUnlockedThisDeviceOnly`) — accessible when locked or backed up. (4) Caches: `WKWebView`/`URLCache`, screenshot cache on backgrounding (app doesn't blur sensitive screens), pasteboard leaking data. On a jailbroken test device, browse `/var/mobile/Containers/Data/Application/<uuid>/` to confirm. Finding a token or PII in NSUserDefaults/plist is High.

## iOS dynamic analysis (jailbroken test device)

Dynamic iOS testing needs a jailbroken TEST device (record jailbreak status in every report). Tools: `objection` (`objection -g <app> explore`) and `frida` for runtime instrumentation — dump Keychain (`ios keychain dump`), inspect `NSUserDefaults`, bypass jailbreak detection and SSL pinning (`ios sslpinning disable`) to intercept the API in Burp/mitmproxy. Then run the SAME authz/IDOR differential tests against the mobile API as on web — a shared backend means one clean PoC from whichever client is easier. Confirm runtime auth/token handling, biometric/local-auth bypass, and deep-link/URL-scheme abuse.

## iOS CVSS and remediation

Token/PII in NSUserDefaults or weak-accessibility Keychain (local attacker or backup): `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = 6.2; hardcoded backend key granting server access → raise to `AV:N` C:H/I:H High/Critical; SSL-pinning absence enabling API MITM: Medium-High depending on what transits. Root causes: sensitive data in unencrypted stores, weak Keychain accessibility class, secrets in the binary, no ATS/pinning. Remediation: store secrets only in Keychain with `...WhenUnlockedThisDeviceOnly` + `.biometryCurrentSet`, never NSUserDefaults; enforce ATS (no cleartext exceptions); certificate pinning; blur sensitive screens on background; keep secrets server-side.
