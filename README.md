# Trust Codes

Trust Codes is a client-only HOTP/TOTP application. It has no backend, but it must be served over HTTP rather than opened through a `file://` URL.

## Run locally

From this directory:

```bash
npm start
```

Then open [http://localhost:4173](http://localhost:4173).

All application code still runs in the browser. The local server only delivers the static HTML, CSS, and JavaScript files. Use the same URL and port each time because browser storage is scoped to its origin.

## Simple mode

Once a channel is available, **Simple mode** replaces the normal workspace with one large active code or proof phrase, the person's name and photo, and a visual list of the other available channels. The mode preference is stored in local browser storage for that origin. Press the camera icon on the active photo to take or choose a picture; saved-channel photos are resized locally and stored inside the encrypted vault entry.

`npm start` generates `version.json` before serving the app. Its displayed version is `YYYY.MM.<7-character Git commit>`, with `.d` appended when tracked files differ from `HEAD`. The footer links a valid generated version to that exact commit. CI or deployment builds can use `GITHUB_SHA` or `COMMIT_SHA`; `version.json` is a generated artifact and is not committed.

## Important security and liability limitations

Trust Codes compares possession of configured cryptographic material. It does not establish a person's identity, authority, honesty, intent, or physical presence, and it cannot guarantee that a person, conversation, device, channel, or request is legitimate, private, uncompromised, or secure. Codes and proofs can be shared, relayed, coerced, stolen, guessed, or generated on a compromised device.

To the fullest extent permitted by law, this app is provided “as is” and “as available,” without warranties or guarantees, and the developer is not liable for loss or harm arising from its use, misuse or reliance on its results. It is important to independently confirm the person and every sensitive, unusual, urgent, or high-value request using a previously trusted contact method before sharing information, sending money, granting access, or acting. You assume all risk of use.

This notice describes intended product limitations; it is not legal advice and does not replace advice from a qualified lawyer about enforceability, consumer-protection rules, privacy obligations, or the terms needed for a particular deployment or jurisdiction.

## Pay what you want

Trust Codes is available without payment. Anyone who wants to support continued development can make an optional [pay-what-you-want contribution](https://paypal.me/noddson).

## QR setup exchange

- After creating a channel, **Show QR** renders the same setup code locally. The QR is hidden until requested and cleared from its canvas when hidden or when setup finishes.
- On import, **Enable camera scanner** requests camera permission only after the button is pressed. It prefers the browser's native QR detector and falls back to the locally vendored `jsQR` decoder.
- Camera frames are processed only in page memory, are never uploaded or saved, and capture stops after a successful scan, cancellation, tab change, page hiding, or navigation.
- Camera access requires HTTPS or `localhost`. Pasting the setup code remains available if permission is denied or no camera is present.
- A setup QR is as sensitive as its text setup code. It contains wrapped channel material and its salt, but never the context.

The QR encoder and fallback decoder are vendored for offline use. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Encrypted local vault

Saved channels are stored in IndexedDB as an AES-256-GCM ciphertext. A key is derived locally from the vault passphrase with PBKDF2-HMAC-SHA256, a random 128-bit salt, and 600,000 iterations. Neither the passphrase nor the derived key is persisted.

This protects secrets **at rest** while the vault is locked or the browser is closed. It does not protect an unlocked session: the page's JavaScript must be able to use the key and decrypted channel material, so a compromised page, browser extension, browser profile, or device could expose it. JavaScript also cannot guarantee immediate zeroization after locking because garbage collection is controlled by the runtime.

For isolation backed by the operating system's Keychain/Credential Manager, this static web app would need to become a signed native application or native wrapper. WebAuthn can protect an unlock operation, but a purely web client still has to expose usable secrets to its JavaScript runtime after unlock.

Keep the one-time setup code somewhere safe. Browser data can be cleared, and there is no recovery service for the vault passphrase.

## Trust models

- Mutual HOTP/TOTP stores the same secret on both devices, so either device can generate the same code.
- One-way proof gives the prover a private hash-chain seed and the verifier only the current anchor. Each accepted phrase is consumed once. Phrase strength is configurable from four words (Okay, 44 bits) through eight words (Fantastic, 88 bits), with six words (Great, 66 bits) as the default.
- Context is an optional shared secret fixed by the creator. PBKDF2-HMAC-SHA256 (600,000 rounds) combines it with a different random salt for each device and wraps that device's secret, seed, or anchor. The creator's input is then discarded. Setup codes and vault entries contain only the salt and wrapped material, never the context value.
- Both people re-enter the context only while using the TrustCode. If both omit a configured context—or enter the same wrong value—the independently salted material produces unrelated codes or proofs. If the creator leaves context blank, the channel preserves normal context-free HOTP/TOTP or hash-chain behavior.
- A context is closer to an additional secret than a public cryptographic salt. Use a strong, memorable value if relying on it: someone with setup material and an observed valid code may be able to test context guesses offline.
- Human-facing letters-and-numbers codes use Crockford Base32 (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`). Internal shared secrets continue to use RFC 4648 Base32. When normalizing entered codes, `O` is accepted as `0`, while `I` and `L` are accepted as `1`.

Strength labels consistently compare the raw displayed guess space: Very weak (&lt;17 bits), Weak (17–21), Basic (22–32), Fair (33–43), Okay (44–54), Good (55–65), Great (66–76), Excellent (77–87), and Fantastic (88+). These labels do not measure the entropy of the underlying shared secret or determine whether a request is safe.

The green details card beneath each strength selector gives the qualitative rating, exact number of possible values, and an illustrative average and exhaustive search time at 20 billion trials per second. This is a fixed high-end-GPU-class scenario, not a prediction. For one-way proofs, offline search is relevant if the verifier anchor is exposed. For mutual codes, enumerating the displayed code space does not recover the shared secret because an observed code does not provide an offline correctness test.

## Test

```bash
npm run check
```
