/* dcr-engine.mjs — window.DCR backed by the dcr-ts library.
 *
 * Drop-in replacement for the hand-rolled decred-crypto.js engine. Every
 * consensus-critical byte format now comes from dcr-ts, which is verified
 * byte-for-byte against dcrd (github.com/jzbz/dcr-ts). Elliptic-curve math and
 * the standard KDFs come from the audited @noble / @scure packages that dcr-ts
 * builds on, instead of being hand-implemented here.
 *
 * The public surface (window.DCR.*) kept the old engine's names, minus three
 * no-ops removed later (see the BIP39 section). Two behavioural changes from
 * the old engine, both bug fixes: WIF uses dcrd's single-BLAKE-256 checksum (the old engine used a
 * double-BLAKE-256 checksum, producing WIFs that dcrwallet/Decrediton reject),
 * and hardened derivation follows dcrd's hdkeychain rather than strict BIP32
 * (ExtendedKey.derive() is the Decred variant; deriveBip32Std is the strict
 * form).
 *
 * esbuild bundles this (+ dcr-ts + noble/scure) into a single IIFE that
 * build.js inlines into the offline index.html.
 */
import {
  blake256,
  base58Encode,
  checkEncode,
  publicKeyFromPrivate,
  addressFromPubKey,
  encodeWif,
  SignatureType,
  ExtendedKey,
  mainnet,
  entropyToMnemonic as dcrEntropyToMnemonic,
  mnemonicToSeed as dcrMnemonicToSeed,
  validateMnemonic as dcrValidateMnemonic,
} from "dcr-ts";
import { ripemd160 } from "@noble/hashes/legacy.js";

// @noble/hashes 2.x keeps its license banner in its TypeScript sources only, not
// in the JavaScript esbuild bundles, so it is restated here for the inlined copy
// (bundle.mjs keeps legal comments). noble-curves and scure-bip39 still carry
// their own.
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */

// ---------- byte helpers ----------
// Strict: an odd length or a non-hex character throws rather than being padded
// or read as a zero byte, so two different malformed strings cannot collapse
// into one valid-looking seed.
function hexToBytes(h) {
  if (typeof h !== "string" || h.length % 2 || !/^[0-9a-fA-F]*$/.test(h))
    throw new Error("hexToBytes: expected an even-length hex string");
  const a = new Uint8Array(h.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
  return a;
}
function bytesToHex(b) {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}

// ---------- base58 / base58check (double-BLAKE-256 checksum: addresses, dprv) ----------
const base58encode = (bytes) => base58Encode(bytes);
const base58checkDcr = (payload) => checkEncode(payload);

// ---------- keys ----------
const pubFromPriv = (priv32) => publicKeyFromPrivate(priv32); // 33-byte compressed

// ---------- BIP32 (returns the old {key, chain} node shape) ----------
// Indices go to dcr-ts as given: it refuses a non-integer or anything outside
// 0..2^32-1, where `i >>> 0` used to wrap 2^32 to child 0.
async function derivePath(seed, indices) {
  let k = ExtendedKey.fromSeed(seed, mainnet);
  for (const i of indices) k = k.derive(i);
  return { key: k.privateKeyBytes(), chain: k.chainCode.slice() };
}

// ---------- BIP39 (dcr-ts bundles the English wordlist via @scure/bip39) ----------
//
// There is deliberately no setWordlist/hasWordlist here. They used to exist as
// no-ops for compatibility with the hand-rolled engine this replaced — one
// stored an array nothing read, the other returned a constant `true` — which
// made a readiness gate that could not fail and an injection point that could
// not inject. @scure/bip39 carries the canonical English list and derivation
// consults that one, so the list the app ships (src/bip39-wordlist.js) is only
// used for the printed 15-word Bison phrase. test/verify.js pins the two
// together word for word; nothing else can.
async function entropyToMnemonic(entropy) {
  return dcrEntropyToMnemonic(entropy);
}
async function mnemonicToSeed(mnemonic, passphrase = "") {
  return dcrMnemonicToSeed(mnemonic, passphrase);
}
// The old engine's leniency: trim, lowercase, collapse whitespace. validate and
// walletFromMnemonic both apply it, so a phrase that validates derives the
// wallet its canonical form names, not a different one from its raw spelling.
const canonicalMnemonic = (m) => String(m).trim().toLowerCase().split(/\s+/).join(" ");
async function validateMnemonic(mnemonic) {
  return dcrValidateMnemonic(canonicalMnemonic(mnemonic));
}

// ---------- Decred address / WIF ----------
const addressFromPub = (pubCompressed) => addressFromPubKey(pubCompressed, mainnet);
// WIF checksum is single-BLAKE-256 (dcrd's chainhash.HashB), via dcr-ts encodeWif.
const wifFromPriv = (priv32) => encodeWif(priv32, mainnet, SignatureType.Ecdsa);

// ---------- high-level wallet generation ----------
function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}
async function walletFromMnemonic(mnemonic, passphrase = "", index = 0) {
  mnemonic = canonicalMnemonic(mnemonic);
  const seed = await mnemonicToSeed(mnemonic, passphrase);
  const H = 0x80000000;
  const node = await derivePath(seed, [44 + H, 42 + H, 0 + H, 0, index]);
  const priv = node.key;
  const pub = pubFromPriv(priv);
  return {
    mnemonic,
    privHex: bytesToHex(priv),
    wif: wifFromPriv(priv),
    pubHex: bytesToHex(pub),
    address: addressFromPub(pub),
    path: "m/44'/42'/0'/0/" + index,
  };
}
async function generateWallet(strength = 256, passphrase = "") {
  if (![128, 160, 192, 224, 256].includes(strength))
    throw new Error("generateWallet: strength must be 128, 160, 192, 224 or 256 bits");
  const entropy = randomBytes(strength / 8);
  const mnemonic = await entropyToMnemonic(entropy);
  return walletFromMnemonic(mnemonic, passphrase, 0);
}

const DCR = {
  // primitives (exposed for testing)
  hexToBytes, bytesToHex, blake256, ripemd160, base58encode, base58checkDcr,
  pubFromPriv, derivePath,
  // bip39
  entropyToMnemonic, mnemonicToSeed, validateMnemonic,
  // decred
  addressFromPub, wifFromPriv,
  // high level
  walletFromMnemonic, generateWallet, randomBytes,
};

const g =
  typeof window !== "undefined" ? window : typeof globalThis !== "undefined" ? globalThis : this;
g.DCR = DCR;
