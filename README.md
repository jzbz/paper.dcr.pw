# Decred Paper Wallet — `index.html`

A **single, self-contained HTML file** that generates real, spendable Decred (DCR)
mainnet paper wallets **entirely offline**. Open it in any modern browser — no server,
no network, no dependencies. Save it to disk and run it air-gapped.

> ⚠️ For real funds: save this page, disconnect from the network, generate, **print**
> (don't screenshot), and store the paper offline. Send a small test deposit and confirm
> it arrives before funding in full.

---

## Supported seed formats

The **Seed format** selector produces five kinds of wallet. All derive the first
external address at BIP44 path **`m/44'/42'/0'/0/0`** (Decred coin type 42, secp256k1),
and all yield a mainnet `Ds…` address + `Pm…` WIF private key.

| Format | Words | Encoding | Imports into |
|--------|-------|----------|--------------|
| **Decred native** *(default)* | **33** | dcrwallet PGP word-list seed | Decrediton / dcrwallet (CLI) |
| **Cake · DCRDEX · Bison** | **15** | custom: entropy + **birthday** + checksum | Cake Wallet, DCRDEX, Bison Wallet |
| **BIP39** | 12 | BIP39 (128-bit) | hardware / third-party wallets |
| **BIP39** | 24 | BIP39 (256-bit) | hardware / third-party wallets |
| **Hex seed** | — | raw 32-byte seed (hex) | dcrwallet hex import |

### How each format derives keys
- **Native (33-word):** 32 random bytes are the BIP32 seed *directly* (HMAC-SHA512
  `"Bitcoin seed"` → master key). The 33 words encode those 32 bytes plus a 1-byte
  checksum via the interleaved 512-word **PGP word list**; checksum byte =
  `sha256(sha256(seed))[0]`. **No passphrase** — the words *are* the seed.
- **15-word (Cake / DCRDEX / Bison):** a custom format (`decred.org/dcrdex/client/mnemonic`,
  also used by `decred/libwallet`). 165 bits = **18-byte entropy + 2-byte birthday**
  (days since the Unix epoch, big-endian) + a 5-bit checksum (top 5 bits of
  `sha256(entropy‖birthday)`), encoded with the standard BIP-0039 English word list,
  11 bits/word, MSB-first. The BIP32 seed is **`blake256(entropy ‖ uint32_BE(42))`** —
  this `blake256` tweak (coin type 42) is exactly what makes Cake, DCRDEX and Bison
  produce the *same* wallet. The birthday speeds up SPV restore and does **not** affect
  the keys. **No passphrase** (disallowed by the format).
- **BIP39 (12/24):** standard BIP39 — entropy → English mnemonic → `PBKDF2-HMAC-SHA512`
  (`"mnemonic"`+passphrase, 2048 rounds) → 64-byte BIP32 seed. Optional passphrase
  (25th word) supported.
- **Hex seed:** 32 random bytes used as the BIP32 seed directly (identical derivation
  to the 33-word native format — the 33 words are just a checksummed encoding of these
  bytes). Importable via dcrwallet's hex seed entry.

This matches `decred/dcrwallet` (`walletseed`, `pgpwordlist`), `decred/dcrd`
(`hdkeychain`), and `decred.org/dcrdex/client/mnemonic` + `decred/libwallet`
(`dcr/loader.go`, `STFifteenWords`).

---

## Verify or import a seed

An offline tool to **bring your own seed**. Paste a 33-word Decred phrase, a 15-word
Cake/DCRDEX/Bison phrase (its encoded birthday is shown), a 12/24-word BIP39 phrase, or a
raw hex seed. The format is auto-detected; it validates word membership, position parity,
and the checksum, and reports precise errors (unknown word, swapped/missing word, checksum
failure). A 15-word phrase is always interpreted as the Cake/DCRDEX/Bison format. It then
shows the re-derived address (use it to confirm a freshly written-down phrase before
funding) and a **“Use as paper wallet”** button that loads the seed into the main card so
you can print it. Words are re-rendered in canonical form (PGP casing / lowercase BIP39).

---

## Cryptographic architecture

Pure-JS, dependency-free. Web Crypto provides SHA-256/512, HMAC, and PBKDF2; everything
Decred-specific is implemented from scratch:

- **BLAKE-256 (r14)** — Decred hashes pubkeys with `blake256r14`, not SHA-256; also used
  for the 15-word seed tweak.
- **RIPEMD-160** — `hash160 = ripemd160(blake256(pubkey))`.
- **secp256k1** — BigInt affine math → compressed pubkeys.
- **base58check** — Decred checksum = `blake256(blake256(payload))[:4]`.
  Address = `base58check([0x07,0x3f] ++ hash160)` (`Ds…`); WIF =
  `base58check([0x22,0xde] ++ 0x00 ++ priv)` (`Pm…`).
- **BIP32/39/44**, the Decred PGP seed encoding, and the DCRDEX/Bison 15-word encoding.
- **QR codes** — Project Nayuki's public-domain generator → crisp SVG.

### Verification — checked against canonical published vectors
- `test/verify.js` (**36/36**): PGP encode/decode vs `dcrwallet/walletseed` vectors; full
  derivation (`master + CKD + hash160 + base58check + version bytes`) vs `dcrd/hdkeychain`
  `dprv`/`dpub` extended-key vectors (exact); secp256k1 generator; BIP39 Trezor vector.
- `test/verify15.js` (**10/10**): the 15-word encoder is byte-identical to a literal port of
  the `dcrdex client/mnemonic` Go bit-packing (1000 random cases) and decodes the **real**
  vector from `decred/libwallet` `dcr/dcr_test.go` (`"peace option follow … silly"` →
  birthday `1740614400`, exact round-trip); plus the `STFifteenWords` blake256-tweak
  derivation.

Reference vectors:
- Native seed `000102…1f` → `DsUobw8mjYbXT9BrrwkNt5NaUveJyqiBDtc` /
  `PmQemEJb6WZy33Lk2SccamHvXPovET3LxgFX7Q7pRiE6rg1cKo6M8`.
- 15-word `"peace option follow minute useful proud orphan zero truck response satisfy
  shell need chef silly"` → `DsXUwBFUZsGw6r1JXcAs2EFh6Ug51VDeWez` (birthday 2025-02-27).

---

## UI

Dark aurora-glass surface. Public material is green ("safe to share"); secret material —
private key, its QR, the seed grid / hex — is coral and **blurred until "Reveal secrets"**.
**Print** emits a black-on-white fold-&-cut sheet (public half, dashed cut line, private
half). Auto-generates on load using `crypto.getRandomValues`; every Generate is fresh.
Fonts (Space Grotesk, JetBrains Mono) are **embedded as base64 woff2** so the file is
pixel-faithful with zero network access.

---

## Build

`index.html` is the **deliverable** and runs standalone — but it is *generated*, not
hand-edited. The build inlines the vendored engines, the PGP word list, the fonts, and
the favicon into `src/template.html` to produce the single offline file. Editing the
generated 169 KB bundle (with ~70 KB of base64 fonts and minified libs inlined) directly
would be error-prone and would obscure the security-critical code; keeping the crypto as
separate, individually-reviewable, vector-tested files is the whole point. **Edit `src/`,
then rebuild.**

```
node build.js          # src/template.html + engines + PGP list + fonts  ->  index.html
node test/verify.js    # crypto regression vs canonical dcrd/dcrwallet vectors (36/36)
node test/verify15.js  # 15-word DCRDEX/Bison format vs canonical vectors (10/10)
```

```
index.html               the deliverable — open offline (generated by build.js)
README.md                this file
build.js                 deterministic bundler (run from anywhere)
src/
  template.html          markup + CSS + app controller, with inline-blob placeholders
  decred-crypto.js       vendored engine: BLAKE-256, RIPEMD-160, secp256k1, base58check,
                         BIP32/39/44, Decred PGP seed + DCRDEX/Bison 15-word + hex
  qrcode.js              vendored QR generator (Project Nayuki, public domain)
  bip39-wordlist.js      the 2048-word BIP-0039 English list
  pgp-words.json         the 512-word Decred PGP list (byte-exact from dcrwallet)
  fonts/*.woff2          Space Grotesk + JetBrains Mono (latin subset, base64'd at build)
test/
  verify.js              engine vectors (PGP, BIP32 dprv/dpub, secp256k1, BIP39 Trezor)
  verify15.js            15-word vectors (literal Go port + libwallet real vector)
```

---

## Security model & caveats
- Keys are generated **locally** with the platform CSPRNG and never transmitted.
- Anyone holding the **WIF or the seed phrase/hex** controls the funds.
- The 15-word format bakes in a creation-date "birthday" (day precision) for faster SPV
  restore; it reveals roughly when the wallet was made but never affects the keys.
- **Content-Security-Policy** (`default-src 'none'`) is embedded in the page — the
  browser is instructed to refuse *all* network fetches, so even injected code could not
  exfiltrate keys.
- **Startup self-test**: before enabling Generate, the page re-derives the canonical
  test vectors (native 33-word, 15-word Bison, BIP39+passphrase, QR). A truncated or
  corrupted copy of `index.html` fails loudly and disables itself instead of producing
  wrong keys. A passing run shows *self-test ✓* in the badge when offline.
- The header badge warns when the browser is **online**; generate real wallets
  air-gapped.
- If a **BIP39 passphrase** is set, the screen and the printed sheet both carry a
  warning that the seed alone will not restore the wallet — store the passphrase
  separately (it is never printed).
- Print rather than screenshot; store the paper offline, safe from fire and theft.
- **Verify before funding:** use the verify panel (or import into a Decred wallet) and
  send a small test deposit first.
