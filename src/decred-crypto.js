/* decred-crypto.js — self-contained, offline Decred key engine.
 * No external dependencies. Uses Web Crypto (SHA-256/512, HMAC, PBKDF2) +
 * pure-JS BLAKE-256(r14), RIPEMD-160, base58check, secp256k1, BIP39/32/44.
 * Exposes window.DCR.
 *
 * Decred specifics:
 *   - hash160 = ripemd160(blake256(pubkey))         (blake256r14, NOT sha256)
 *   - base58check checksum = blake256(blake256(x))[:4]
 *   - mainnet P2PKH netID = [0x07,0x3f]  -> "Ds…"
 *   - mainnet WIF prefix  = [0x22,0xde], ecType secp256k1 = 0x00 -> "Pm…"
 *   - BIP44 path m/44'/42'/0'/0/0  (coin type 42)
 */
(function () {
  'use strict';

  // ---------- byte helpers ----------
  const enc = new TextEncoder();
  function hexToBytes(h) {
    if (h.length % 2) h = '0' + h;
    const a = new Uint8Array(h.length / 2);
    for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
    return a;
  }
  function bytesToHex(b) {
    let s = '';
    for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
    return s;
  }
  function concat(...arrs) {
    let n = 0;
    for (const a of arrs) n += a.length;
    const out = new Uint8Array(n);
    let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  }
  function bytesToBig(b) {
    let x = 0n;
    for (let i = 0; i < b.length; i++) x = (x << 8n) | BigInt(b[i]);
    return x;
  }
  function bigToBytes(x, len) {
    const out = new Uint8Array(len);
    for (let i = len - 1; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
    return out;
  }

  // ---------- BLAKE-256 (r14) ----------
  const BLAKE_IV = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ]);
  const BLAKE_C = new Uint32Array([
    0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
    0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
    0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
    0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917
  ]);
  const BLAKE_SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
  ];
  function rotr32(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }

  function blakeCompress(h, m, t0, t1) {
    const v = new Uint32Array(16);
    for (let i = 0; i < 8; i++) v[i] = h[i];
    for (let i = 0; i < 8; i++) v[i + 8] = BLAKE_C[i];
    v[12] = (v[12] ^ t0) >>> 0;
    v[13] = (v[13] ^ t0) >>> 0;
    v[14] = (v[14] ^ t1) >>> 0;
    v[15] = (v[15] ^ t1) >>> 0;

    for (let r = 0; r < 14; r++) {
      const s = BLAKE_SIGMA[r % 10];
      function G(a, b, c, d, i) {
        const sx = s[2 * i], sy = s[2 * i + 1];
        v[a] = (v[a] + v[b] + ((m[sx] ^ BLAKE_C[sy]) >>> 0)) >>> 0;
        v[d] = rotr32((v[d] ^ v[a]) >>> 0, 16);
        v[c] = (v[c] + v[d]) >>> 0;
        v[b] = rotr32((v[b] ^ v[c]) >>> 0, 12);
        v[a] = (v[a] + v[b] + ((m[sy] ^ BLAKE_C[sx]) >>> 0)) >>> 0;
        v[d] = rotr32((v[d] ^ v[a]) >>> 0, 8);
        v[c] = (v[c] + v[d]) >>> 0;
        v[b] = rotr32((v[b] ^ v[c]) >>> 0, 7);
      }
      G(0, 4, 8, 12, 0); G(1, 5, 9, 13, 1); G(2, 6, 10, 14, 2); G(3, 7, 11, 15, 3);
      G(0, 5, 10, 15, 4); G(1, 6, 11, 12, 5); G(2, 7, 8, 13, 6); G(3, 4, 9, 14, 7);
    }
    for (let i = 0; i < 8; i++) h[i] = (h[i] ^ v[i] ^ v[i + 8]) >>> 0;
  }

  function blake256(data) {
    const M = data.length;
    const L = M * 8; // bit length
    const rem = M % 64;
    const padLen = rem < 56 ? (56 - rem) : (120 - rem);
    const total = M + padLen + 8;
    const buf = new Uint8Array(total);
    buf.set(data, 0);
    buf[M] = 0x80;
    buf[total - 9] |= 0x01; // BLAKE-256 trailing 1 bit
    const dv = new DataView(buf.buffer);
    dv.setUint32(total - 8, Math.floor(L / 0x100000000) >>> 0, false);
    dv.setUint32(total - 4, L >>> 0, false);

    const h = new Uint32Array(BLAKE_IV);
    const nBlocks = total / 64;
    for (let b = 0; b < nBlocks; b++) {
      const msgBytesThisBlock = Math.max(0, Math.min(M, (b + 1) * 64) - b * 64);
      let t0 = 0, t1 = 0;
      if (msgBytesThisBlock > 0) {
        const bitsThrough = Math.min(M, (b + 1) * 64) * 8;
        t0 = bitsThrough >>> 0;
        t1 = Math.floor(bitsThrough / 0x100000000) >>> 0;
      }
      const m = new Uint32Array(16);
      for (let i = 0; i < 16; i++) m[i] = dv.getUint32(b * 64 + i * 4, false);
      blakeCompress(h, m, t0, t1);
    }
    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) odv.setUint32(i * 4, h[i], false);
    return out;
  }
  function blake256d(data) { return blake256(blake256(data)); }

  // ---------- RIPEMD-160 ----------
  function ripemd160(data) {
    const rol = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
    const f = (j, x, y, z) =>
      j < 16 ? (x ^ y ^ z) :
      j < 32 ? ((x & y) | (~x & z)) :
      j < 48 ? ((x | ~y) ^ z) :
      j < 64 ? ((x & z) | (y & ~z)) :
               (x ^ (y | ~z));
    const K = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
    const KK = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];
    const r = [
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
      7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
      3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
      1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
      4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13];
    const rr = [
      5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
      6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
      15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
      8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
      12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11];
    const s = [
      11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
      7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
      11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
      11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
      9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6];
    const ss = [
      8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
      9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
      9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
      15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
      8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11];

    const len = data.length;
    const padded = new Uint8Array((((len + 8) >> 6) + 1) << 6);
    padded.set(data);
    padded[len] = 0x80;
    const bl = len * 8;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 8, bl >>> 0, true);
    dv.setUint32(padded.length - 4, Math.floor(bl / 0x100000000) >>> 0, true);

    let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
    const X = new Uint32Array(16);
    for (let off = 0; off < padded.length; off += 64) {
      for (let i = 0; i < 16; i++) X[i] = dv.getUint32(off + i * 4, true);
      let al = h0, bl2 = h1, cl = h2, dl = h3, el = h4;
      let ar = h0, br = h1, cr = h2, dr = h3, er = h4;
      for (let j = 0; j < 80; j++) {
        const rnd = (j / 16) | 0;
        let t = (al + f(j, bl2, cl, dl) + X[r[j]] + K[rnd]) >>> 0;
        t = (rol(t, s[j]) + el) >>> 0;
        al = el; el = dl; dl = rol(cl, 10); cl = bl2; bl2 = t;
        const rndR = 4 - rnd;
        let tr = (ar + f(79 - j, br, cr, dr) + X[rr[j]] + KK[rnd]) >>> 0;
        tr = (rol(tr, ss[j]) + er) >>> 0;
        ar = er; er = dr; dr = rol(cr, 10); cr = br; br = tr;
      }
      const t = (h1 + cl + dr) >>> 0;
      h1 = (h2 + dl + er) >>> 0;
      h2 = (h3 + el + ar) >>> 0;
      h3 = (h4 + al + br) >>> 0;
      h4 = (h0 + bl2 + cr) >>> 0;
      h0 = t;
    }
    const out = new Uint8Array(20);
    const odv = new DataView(out.buffer);
    odv.setUint32(0, h0, true); odv.setUint32(4, h1, true); odv.setUint32(8, h2, true);
    odv.setUint32(12, h3, true); odv.setUint32(16, h4, true);
    return out;
  }

  // ---------- base58 ----------
  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  function base58encode(bytes) {
    let x = bytesToBig(bytes);
    let out = '';
    while (x > 0n) { const r = x % 58n; x = x / 58n; out = B58[Number(r)] + out; }
    for (let i = 0; i < bytes.length && bytes[i] === 0; i++) out = '1' + out;
    return out;
  }
  function base58checkDcr(payload) {
    const cks = blake256d(payload).slice(0, 4);
    return base58encode(concat(payload, cks));
  }

  // ---------- secp256k1 ----------
  const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
  const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
  function mod(a, m) { a %= m; if (a < 0n) a += m; return a; }
  function inv(a, m) {
    let [or, r] = [mod(a, m), m], [os, s] = [1n, 0n];
    while (r !== 0n) { const q = or / r; [or, r] = [r, or - q * r]; [os, s] = [s, os - q * s]; }
    return mod(os, m);
  }
  function ptDouble(Pt) {
    if (!Pt) return null;
    const lam = mod(3n * Pt.x * Pt.x * inv(2n * Pt.y, P), P);
    const x3 = mod(lam * lam - 2n * Pt.x, P);
    const y3 = mod(lam * (Pt.x - x3) - Pt.y, P);
    return { x: x3, y: y3 };
  }
  function ptAdd(A, B) {
    if (!A) return B;
    if (!B) return A;
    if (A.x === B.x) { if (mod(A.y + B.y, P) === 0n) return null; return ptDouble(A); }
    const lam = mod((B.y - A.y) * inv(mod(B.x - A.x, P), P), P);
    const x3 = mod(lam * lam - A.x - B.x, P);
    const y3 = mod(lam * (A.x - x3) - A.y, P);
    return { x: x3, y: y3 };
  }
  function ptMul(k) {
    let R = null, A = { x: Gx, y: Gy };
    while (k > 0n) { if (k & 1n) R = ptAdd(R, A); A = ptDouble(A); k >>= 1n; }
    return R;
  }
  function pubFromPriv(priv32) {
    const k = mod(bytesToBig(priv32), N);
    const Q = ptMul(k);
    const prefix = (Q.y & 1n) ? 0x03 : 0x02;
    return concat(new Uint8Array([prefix]), bigToBytes(Q.x, 32));
  }

  // ---------- Web Crypto wrappers ----------
  async function sha256(b) { return new Uint8Array(await crypto.subtle.digest('SHA-256', b)); }
  async function hmacSha512(key, data) {
    const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-512' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', k, data));
  }
  async function pbkdf2Sha512(pw, salt, iterations, dkLenBytes) {
    const k = await crypto.subtle.importKey('raw', pw, 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-512' }, k, dkLenBytes * 8);
    return new Uint8Array(bits);
  }

  // ---------- BIP32 ----------
  async function masterFromSeed(seed) {
    const I = await hmacSha512(enc.encode('Bitcoin seed'), seed);
    return { key: I.slice(0, 32), chain: I.slice(32, 64) };
  }
  async function ckdPriv(node, index) {
    const idx = new Uint8Array(4);
    new DataView(idx.buffer).setUint32(0, index >>> 0, false);
    let data;
    if (index >= 0x80000000) data = concat(new Uint8Array([0]), node.key, idx);
    else data = concat(pubFromPriv(node.key), idx);
    const I = await hmacSha512(node.chain, data);
    const ki = mod(bytesToBig(I.slice(0, 32)) + bytesToBig(node.key), N);
    return { key: bigToBytes(ki, 32), chain: I.slice(32, 64) };
  }
  async function derivePath(seed, indices) {
    let node = await masterFromSeed(seed);
    for (const i of indices) node = await ckdPriv(node, i);
    return node;
  }

  // ---------- BIP39 ----------
  // WORDLIST is filled from the official BIP39 english list (see setWordlist).
  let WORDLIST = null;
  function setWordlist(arr) { WORDLIST = arr; }
  function hasWordlist() { return Array.isArray(WORDLIST) && WORDLIST.length === 2048; }

  async function entropyToMnemonic(entropy) {
    if (!hasWordlist()) throw new Error('wordlist not loaded');
    const ENT = entropy.length * 8;
    const CS = ENT / 32;
    const hash = await sha256(entropy);
    // bit string
    let bits = '';
    for (const byte of entropy) bits += byte.toString(2).padStart(8, '0');
    let csBits = '';
    for (const byte of hash) csBits += byte.toString(2).padStart(8, '0');
    bits += csBits.slice(0, CS);
    const words = [];
    for (let i = 0; i < bits.length; i += 11) {
      words.push(WORDLIST[parseInt(bits.slice(i, i + 11), 2)]);
    }
    return words.join(' ');
  }
  async function mnemonicToSeed(mnemonic, passphrase = '') {
    const norm = mnemonic.normalize('NFKD');
    const salt = ('mnemonic' + passphrase).normalize('NFKD');
    return pbkdf2Sha512(enc.encode(norm), enc.encode(salt), 2048, 64);
  }
  async function validateMnemonic(mnemonic) {
    if (!hasWordlist()) return false;
    const words = mnemonic.trim().toLowerCase().split(/\s+/);
    if (![12, 15, 18, 21, 24].includes(words.length)) return false;
    let bits = '';
    for (const w of words) {
      const idx = WORDLIST.indexOf(w);
      if (idx < 0) return false;
      bits += idx.toString(2).padStart(11, '0');
    }
    const ENT = (bits.length * 32) / 33;
    const CS = bits.length - ENT;
    const entBits = bits.slice(0, ENT), csBits = bits.slice(ENT);
    const entropy = new Uint8Array(ENT / 8);
    for (let i = 0; i < entropy.length; i++) entropy[i] = parseInt(entBits.slice(i * 8, i * 8 + 8), 2);
    const hash = await sha256(entropy);
    let expect = '';
    for (const b of hash) expect += b.toString(2).padStart(8, '0');
    return expect.slice(0, CS) === csBits;
  }

  // ---------- Decred address / WIF ----------
  const DCR_P2PKH = new Uint8Array([0x07, 0x3f]);   // mainnet "Ds…"
  const DCR_WIF = new Uint8Array([0x22, 0xde]);     // mainnet "Pm…"
  function hash160(pub) { return ripemd160(blake256(pub)); }
  function addressFromPub(pubCompressed) {
    return base58checkDcr(concat(DCR_P2PKH, hash160(pubCompressed)));
  }
  function wifFromPriv(priv32) {
    // [prefix(2)][ecType=0x00][priv(32)] then blake256d checksum
    return base58checkDcr(concat(DCR_WIF, new Uint8Array([0x00]), priv32));
  }

  // ---------- High-level wallet generation ----------
  function randomBytes(n) {
    const b = new Uint8Array(n);
    crypto.getRandomValues(b);
    return b;
  }
  // Single keypair from raw entropy (private key directly). Always valid range.
  function privFromRandom() {
    let k;
    do { k = bytesToBig(randomBytes(32)); } while (k === 0n || k >= N);
    return bigToBytes(k, 32);
  }
  // Full HD wallet: mnemonic -> seed -> m/44'/42'/0'/0/index
  async function walletFromMnemonic(mnemonic, passphrase = '', index = 0) {
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
      path: "m/44'/42'/0'/0/" + index
    };
  }
  // Generate a fresh wallet from `strength` bits (128=12 words, 256=24 words).
  async function generateWallet(strength = 256, passphrase = '') {
    const entropy = randomBytes(strength / 8);
    const mnemonic = await entropyToMnemonic(entropy);
    return walletFromMnemonic(mnemonic, passphrase, 0);
  }

  window.DCR = {
    // primitives (exposed for testing)
    hexToBytes, bytesToHex, blake256, blake256d, ripemd160, base58encode, base58checkDcr,
    pubFromPriv, masterFromSeed, derivePath,
    // bip39
    setWordlist, hasWordlist, entropyToMnemonic, mnemonicToSeed, validateMnemonic,
    // decred
    addressFromPub, wifFromPriv,
    // high level
    privFromRandom, walletFromMnemonic, generateWallet, randomBytes
  };
})();
