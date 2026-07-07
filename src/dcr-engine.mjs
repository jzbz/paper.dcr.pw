/* dcr-engine.mjs — window.DCR backed by the dcr-ts library.
 *
 * Drop-in replacement for the hand-rolled decred-crypto.js engine. Every
 * consensus-critical byte format now comes from dcr-ts, which is verified
 * byte-for-byte against dcrd (github.com/jzbz/dcr-ts). Elliptic-curve math and
 * the standard KDFs come from the audited @noble / @scure packages that dcr-ts
 * builds on, instead of being hand-implemented here.
 *
 * The public surface (window.DCR.*) is identical to the old engine, so
 * index.html and test/*.js are unchanged. The one behavioural change is a bug
 * fix: WIF now uses dcrd's single-BLAKE-256 checksum (the old engine used a
 * double-BLAKE-256 checksum, producing WIFs that dcrwallet/Decrediton reject).
 *
 * esbuild bundles this (+ dcr-ts + noble/scure) into a single IIFE that
 * build.js inlines into the offline index.html.
 */
import {
  blake256,
  hash256,
  base58Encode,
  checkEncode,
  publicKeyFromPrivate,
  isValidPrivateKey,
  addressFromPubKey,
  encodeWif,
  SignatureType,
  ExtendedKey,
  mainnet,
  entropyToMnemonic as dcrEntropyToMnemonic,
  mnemonicToSeed as dcrMnemonicToSeed,
  validateMnemonic as dcrValidateMnemonic,
} from "dcr-ts";
import { ripemd160 } from "@noble/hashes/ripemd160";

// ---------- byte helpers (identical to the old engine) ----------
function hexToBytes(h) {
  if (h.length % 2) h = "0" + h;
  const a = new Uint8Array(h.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
  return a;
}
function bytesToHex(b) {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}

// ---------- hashing ----------
const blake256d = (data) => hash256(data); // double BLAKE-256

// ---------- base58 / base58check (double-BLAKE-256 checksum: addresses, dprv) ----------
const base58encode = (bytes) => base58Encode(bytes);
const base58checkDcr = (payload) => checkEncode(payload);

// ---------- keys ----------
const pubFromPriv = (priv32) => publicKeyFromPrivate(priv32); // 33-byte compressed

// ---------- BIP32 (returns the old {key, chain} node shape) ----------
async function masterFromSeed(seed) {
  const k = ExtendedKey.fromSeed(seed, mainnet);
  return { key: k.privateKeyBytes(), chain: k.chainCode.slice() };
}
async function derivePath(seed, indices) {
  let k = ExtendedKey.fromSeed(seed, mainnet);
  for (const i of indices) k = k.derive(i >>> 0);
  return { key: k.privateKeyBytes(), chain: k.chainCode.slice() };
}

// ---------- BIP39 (dcr-ts bundles the English wordlist via @scure/bip39) ----------
let WORDLIST = null; // kept only so setWordlist/hasWordlist stay no-op compatible
function setWordlist(arr) {
  WORDLIST = arr;
}
function hasWordlist() {
  return true; // @scure/bip39 always has the canonical English wordlist
}
async function entropyToMnemonic(entropy) {
  return dcrEntropyToMnemonic(entropy);
}
async function mnemonicToSeed(mnemonic, passphrase = "") {
  return dcrMnemonicToSeed(mnemonic, passphrase);
}
async function validateMnemonic(mnemonic) {
  // Preserve the old engine's leniency: trim, lowercase, collapse whitespace.
  const norm = String(mnemonic).trim().toLowerCase().split(/\s+/).join(" ");
  return dcrValidateMnemonic(norm);
}

// ---------- Decred address / WIF ----------
const hash160 = (pub) => ripemd160(blake256(pub));
const addressFromPub = (pubCompressed) => addressFromPubKey(pubCompressed, mainnet);
// WIF checksum is single-BLAKE-256 (dcrd's chainhash.HashB), via dcr-ts encodeWif.
const wifFromPriv = (priv32) => encodeWif(priv32, mainnet, SignatureType.Ecdsa);

// ---------- high-level wallet generation ----------
function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}
function privFromRandom() {
  let k;
  do {
    k = randomBytes(32);
  } while (!isValidPrivateKey(k));
  return k;
}
async function walletFromMnemonic(mnemonic, passphrase = "", index = 0) {
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
  const entropy = randomBytes(strength / 8);
  const mnemonic = await entropyToMnemonic(entropy);
  return walletFromMnemonic(mnemonic, passphrase, 0);
}

const DCR = {
  // primitives (exposed for testing)
  hexToBytes, bytesToHex, blake256, blake256d, ripemd160, base58encode, base58checkDcr,
  pubFromPriv, masterFromSeed, derivePath,
  // bip39
  setWordlist, hasWordlist, entropyToMnemonic, mnemonicToSeed, validateMnemonic,
  // decred
  addressFromPub, wifFromPriv,
  // high level
  privFromRandom, walletFromMnemonic, generateWallet, randomBytes,
};

const g =
  typeof window !== "undefined" ? window : typeof globalThis !== "undefined" ? globalThis : this;
g.DCR = DCR;
