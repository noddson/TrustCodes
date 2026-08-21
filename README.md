# TrustCodes

TrustCodes is a client-only HOTP/TOTP application. It has no backend, but it must be served over HTTP rather than opened through a `file://` URL.

## Run locally

From this directory:

```bash
npm start
```

Then open [http://localhost:4173](http://localhost:4173).

All application code still runs in the browser. The local server only delivers the static HTML, CSS, and JavaScript files. Use the same URL and port each time because browser storage is scoped to its origin.

## Simple mode

Once a channel is available, **Simple mode** replaces the normal workspace with one large active code or proof phrase, the person's name and photo, and a visual list of the other available channels. The mode preference is stored in local browser storage for that origin. Pressing the camera icon opens the operating system's image picker; saved-channel photos are resized locally and stored inside the encrypted vault entry.

`npm start` generates `version.json` before serving the app. Its displayed version is `YYYY.MM.<7-character Git commit>`, with `.d` appended when tracked files differ from `HEAD`. The footer links a valid generated version to that exact commit. CI or deployment builds can use `GITHUB_SHA` or `COMMIT_SHA`; `version.json` is a generated artifact and is not committed.

## Important security and liability limitations

TrustCodes compares possession of configured cryptographic material. It does not establish a person's identity, authority, honesty, intent, or physical presence, and it cannot guarantee that a person, conversation, device, channel, or request is legitimate, private, uncompromised, or secure. Codes and proofs can be shared, relayed, coerced, stolen, guessed, or generated on a compromised device.

**Client-only proof-state limitation:** TrustCodes has no server, shared ledger, or authoritative record of which one-way proofs have already been accepted. Replay resistance depends on each verifier retaining its newest local hash-chain anchor. A phrase rejected by the current verifier can be accepted again by a stale, duplicated, restored, cleared, or rolled-back verifier state. Multiple verifier devices and backups can also diverge. Treat “consumed” as a change to one local verifier state—not a guarantee that a proof is globally or permanently unreplayable—and independently confirm sensitive requests through a previously trusted channel.

To the fullest extent permitted by law, this app is provided “as is” and “as available,” without warranties or guarantees, and the developer is not liable for loss or harm arising from its use, misuse or reliance on its results. It is important to independently confirm the person and every sensitive, unusual, urgent, or high-value request using a previously trusted contact method before sharing information, sending money, granting access, or acting. You assume all risk of use.

This notice describes intended product limitations; it is not legal advice and does not replace advice from a qualified lawyer about enforceability, consumer-protection rules, privacy obligations, or the terms needed for a particular deployment or jurisdiction.

## Pay what you want

TrustCodes is available without payment. Anyone who wants to support continued development can make an optional [pay-what-you-want contribution](https://paypal.me/noddson).

## QR setup exchange

- New channels use an authenticated `TC2-` setup package. TrustCodes generates a random eight-word one-time setup passphrase, derives an AES-256-GCM key with PBKDF2-HMAC-SHA256, a random 128-bit salt, and 600,000 iterations, and encrypts the complete setup payload. The passphrase is never included in the setup code or QR.
- Send the encrypted setup code and its one-time passphrase through separate methods. After authenticated decryption, both devices display the same 48-bit SHA-256 setup fingerprint in a visually distinct format such as `9F2A-C71D-84B6`; the importer must explicitly confirm that every character matches before the channel is accepted.
- The setup passphrase and fingerprint are cleared when the creator leaves the sharing screen. The importer clears the passphrase immediately after successful decryption. They are never persisted in the vault. A copied setup package can still be decrypted later by anyone who obtains its passphrase, so “one-time” describes the intended exchange rather than guaranteed erasure of copies.
- **Show QR** renders only the encrypted setup package locally. The QR is hidden until requested and cleared from its canvas when hidden or when setup finishes.
- On import, **Enable camera scanner** requests camera permission only after the button is pressed. It prefers the browser's native QR detector and falls back to the locally vendored `jsQR` decoder.
- Camera frames are processed only in page memory, are never uploaded or saved, and capture stops after a successful scan, cancellation, tab change, page hiding, or navigation.
- Camera access requires HTTPS or `localhost`. Pasting the setup code remains available if permission is denied or no camera is present.
- Legacy `TC1-` setup codes remain importable for compatibility, but they are not authenticated by a one-time setup passphrase and the app labels them as legacy imports.

The QR encoder and fallback decoder are vendored for offline use. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Encrypted local vault

Saved channels are stored in IndexedDB as an AES-256-GCM ciphertext. New vaults use a random 256-bit data-encryption key. New and changed recovery passphrases must contain 12–64 characters, including uppercase and lowercase letters, a number, and a symbol. Existing vaults created under the earlier policy remain unlockable. The recovery passphrase is processed locally with PBKDF2-HMAC-SHA256, a random 128-bit salt, and 600,000 iterations; that derived key wraps the random vault key. Neither the passphrase nor any unwrapped key is persisted. A saved channel's locally resized contact photo is part of the encrypted ciphertext.

On compatible secure browsers, vault creation can also register a local passkey and use the WebAuthn PRF extension after system user verification. The 32-byte PRF result is passed through HKDF and wraps the same random vault key, allowing Face ID, fingerprint, or device-passcode unlock while the recovery passphrase remains available. TrustCodes stores only the credential ID, random PRF input, KDF salt, and wrapped vault key—not biometric data, a device passcode, or the PRF secret. Actual PRF support is established only when the browser and passkey provider successfully create the device-unlock credential.

The gear beside the vault control opens vault options. An unlocked vault passphrase can be changed there, and device unlock can be enabled or removed. The current passphrase is verified before saved entries are re-encrypted with a fresh vault key and salt. Keeping device unlock enabled also requires system user verification so the new vault key can be wrapped again. A failed verification, passkey operation, or encryption attempt leaves the previous vault record intact.

The same gear offers **Purge vault**, protected by two warning and confirmation stages. Purging permanently deletes the encrypted vault record in the current browser context, including all saved channels, photos, counters, and proof state. Unsaved in-memory channels are not deleted. A TrustCodes passkey may remain listed in the operating system's credential manager because websites cannot delete it directly, but it is useless after its corresponding encrypted vault record is purged.

Without an unlocked vault and an explicitly selected save option, channels, cryptographic material, counters, proof state, and contact photos remain only in the current page's memory and disappear on reload or close. They are not written to plaintext browser storage. The only simple-mode value stored outside the vault is the non-sensitive on/off preference in LocalStorage.

This protects secrets **at rest** while the vault is locked or the browser is closed. It does not protect an unlocked session: the page's JavaScript must be able to use the key and decrypted channel material, so a compromised page, browser extension, browser profile, or device could expose it. JavaScript also cannot guarantee immediate zeroization after locking because garbage collection is controlled by the runtime.

WebAuthn PRF binds the device-unlock wrapping secret to a passkey and requires the browser's system user-verification ceremony. It does not turn the static site into a native keychain: after a successful unlock, the page's JavaScript runtime still receives a usable in-memory vault key.

Keep any setup backup and its one-time passphrase safe and separate. Browser data can be cleared, and there is no recovery service for either the setup passphrase or vault passphrase.

## Google Drive encrypted backup

The vault gear contains manual **Back up now** and **Restore** controls using Google Drive's hidden `appDataFolder`. TrustCodes requests only the `https://www.googleapis.com/auth/drive.appdata` scope. The uploaded JSON envelope contains the already-encrypted vault record, an explicit `lastBackedUpAt` timestamp, and cryptographic metadata; it does not contain the recovery passphrase, an unwrapped vault key, plaintext channel contents, context values, or plaintext contact photos.

To enable the controls for a deployment:

1. In Google Cloud, enable the Google Drive API and configure the OAuth consent screen.
2. Create an OAuth 2.0 **Web application** client.
3. Add `https://noddson.github.io` as an authorized JavaScript origin for GitHub Pages. Add `http://localhost:4173` for local development.
4. Put the public client ID in `google-drive-config.js`. Do not add a client secret; browser applications cannot keep one confidential.

Access tokens are held only in page memory and are revoked when **Disconnect** is pressed. Backups are never automatic. A backup updates the one known TrustCodes app-data file; duplicates stop the operation rather than allowing an ambiguous overwrite. Restore downloads and strictly validates the encrypted record before showing a destructive confirmation, then replaces—never merges—the local browser vault and requires the restored vault's recovery passphrase or compatible device credential to unlock it.

## Trust models

- Mutual HOTP/TOTP stores the same secret on both devices, so either device can generate the same code.
- One-way proof gives the prover a private hash-chain seed and the verifier only the current anchor. An accepting verifier advances its own local anchor so that same state rejects the phrase afterward; this is not global replay prevention and can be undone by state rollback or replacement. New channels require 5 to 10 words: 5 (OK, 55 bits), 6 (Good, 66 bits), 7 (Great, 77 bits), 8 (Excellent, 88 bits), 9 (Fantastic, 99 bits), or 10 (Legendary, 110 bits). Four-word proofs and setup imports are rejected as too weak.
- The generated one-time setup passphrase authenticates and encrypts the initial setup package. It is separate from both the vault recovery passphrase and the optional per-use context. It confirms possession of the independently transferred setup passphrase, not a person's legal identity, and it cannot prevent real-time relay or compromise of both transfer methods.
- Context is an optional shared secret fixed by the creator. PBKDF2-HMAC-SHA256 (600,000 rounds) combines it with a different random salt for each device and wraps that device's secret, seed, or anchor. The creator's input is then discarded. Setup codes and vault entries contain only the salt and wrapped material, never the context value.
- Both people re-enter the context only while using the TrustCode. If both omit a configured context—or enter the same wrong value—the independently salted material produces unrelated codes or proofs. If the creator leaves context blank, the channel preserves normal context-free HOTP/TOTP or hash-chain behavior.
- A context is closer to an additional secret than a public cryptographic salt. Use a strong, memorable value if relying on it: someone with setup material and an observed valid code may be able to test context guesses offline.
- Human-facing letters-and-numbers codes use Crockford Base32 (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`). Internal shared secrets continue to use RFC 4648 Base32. When normalizing entered codes, `O` is accepted as `0`, while `I` and `L` are accepted as `1`.

Mutual-code strength labels compare the raw displayed guess space: Very weak (&lt;17 bits), Weak (17–21), Basic (22–32), Fair (33–43), Okay (44–54), Good (55–65), Great (66–76), Excellent (77–87), and Fantastic (88+). One-way proofs use the more conservative tiers listed above. These labels do not measure the entropy of the underlying shared secret or determine whether a request is safe.

The green details card beneath each strength selector gives the qualitative rating, exact number of possible values, and an illustrative average and exhaustive search time at 20 billion trials per second. This is a fixed high-end-GPU-class scenario, not a prediction. For one-way proofs, offline search is relevant if the verifier anchor is exposed. For mutual codes, enumerating the displayed code space does not recover the shared secret because an observed code does not provide an offline correctness test.

## Browser security policy

- The application and privacy-policy pages enforce a restrictive Content Security Policy before loading any resources and send no referrer information on outbound navigation.
- `_headers` defines the complete response-header policy for header-capable static hosts or reverse proxies, including clickjacking protection, MIME-sniffing protection, browser-feature restrictions, cross-origin opener/resource policies, and HSTS.
- GitHub Pages supplies HTTPS/HSTS but does not apply repository `_headers` files. On the current GitHub Pages deployment, the CSP and referrer policy are enforced through HTML metadata; the remaining response-only controls require a header-capable host or proxy in front of the site.

## Deployment dependency controls

- `package-lock.json` fixes npm dependency archives by exact version, registry URL, and integrity hash. CI installs that lockfile with lifecycle scripts disabled, audits high-severity vulnerabilities, and does not install dependencies in the deployment job.
- Every third-party GitHub Action is pinned to a full commit SHA. Checkout does not persist workflow credentials, the runner and Node release are fixed, and a regression test rejects mutable Action references or weakened install settings.
- Dependabot checks npm and GitHub Actions dependencies weekly. Updates still require the normal validation job before deployment.

## Test

```bash
npm run check
```
