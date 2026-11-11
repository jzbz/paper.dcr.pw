'use strict';
// Verification harness: proves the Decred crypto (engine + the app's native PGP
// path, as shipped in src/template.html) against official dcrd/dcrwallet test
// vectors and against independent implementations. Run with: node test/verify.js
const nodecrypto = require('crypto');

// The engine, the word lists, the QR generator and the app's seed extension,
// loaded the way the page loads them.
const { DCR, QR, PGP_WORDLIST: PGP } = require('./load-app');
const pgpIndex = {}; PGP.forEach((w, i) => pgpIndex[w.toLowerCase()] = i);

const hex = (b) => Buffer.from(b).toString('hex');
const fromHex = (h) => new Uint8Array(Buffer.from(h, 'hex'));
let pass = 0, fail = 0;
function check(name, got, want) {
  const ok = got === want;
  if (ok) { pass++; console.log('  ✓', name); }
  else { fail++; console.log('  ✗', name, '\n      got : ' + got + '\n      want: ' + want); }
}
// The message an async call rejects with, or 'resolved' if it did not reject.
async function rejection(f) {
  try { await f(); return 'resolved'; } catch (e) { return e.userMessage || e.message; }
}

// ---------- sha256 double checksum (native seed) ----------
function checksumByte(data) {
  const h1 = nodecrypto.createHash('sha256').update(Buffer.from(data)).digest();
  const h2 = nodecrypto.createHash('sha256').update(h1).digest();
  return h2[0];
}
function pgpEncode(seed) {
  const words = [];
  for (let i = 0; i < seed.length; i++) {
    let bb = seed[i] * 2; if (i % 2 !== 0) bb++;
    words.push(PGP[bb]);
  }
  let bb = checksumByte(seed) * 2; if (seed.length % 2 !== 0) bb++;
  words.push(PGP[bb]);
  return words.join(' ');
}
function pgpDecode(mnemonic) {
  const words = mnemonic.trim().split(/\s+/);
  const out = [];
  for (let idx = 0; idx < words.length; idx++) {
    const i = pgpIndex[words[idx].toLowerCase()];
    if (i === undefined) throw new Error('not in list: ' + words[idx]);
    if (i % 2 !== idx % 2) throw new Error('bad position: ' + words[idx]);
    out.push(i >> 1);
  }
  const data = out.slice(0, -1);
  if (checksumByte(data) !== out[out.length - 1]) throw new Error('checksum mismatch');
  return new Uint8Array(data);
}

// ---------- independent BIP32 (Node HMAC) with fingerprint tracking ----------
function hmac512(key, data) {
  return new Uint8Array(nodecrypto.createHmac('sha512', Buffer.from(key)).update(Buffer.from(data)).digest());
}
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
function bytesToBig(b){let x=0n;for(const v of b)x=(x<<8n)|BigInt(v);return x;}
function bigToBytes(x,len){const o=new Uint8Array(len);for(let i=len-1;i>=0;i--){o[i]=Number(x&0xffn);x>>=8n;}return o;}
function hash160(pub){return DCR.ripemd160(DCR.blake256(pub));}
function master(seed){
  const I = hmac512(new TextEncoder().encode('Bitcoin seed'), seed);
  return {key:I.slice(0,32), chain:I.slice(32), depth:0, parentFP:new Uint8Array(4), childNum:0};
}
function ckd(node, index){
  const idx = new Uint8Array(4); new DataView(idx.buffer).setUint32(0, index>>>0, false);
  let data;
  if (index >= 0x80000000) data = concatU8(new Uint8Array([0]), node.key, idx);
  else data = concatU8(DCR.pubFromPriv(node.key), idx);
  const I = hmac512(node.chain, data);
  const ki = ((bytesToBig(I.slice(0,32)) + bytesToBig(node.key)) % N);
  const parentFP = hash160(DCR.pubFromPriv(node.key)).slice(0,4);
  return {key:bigToBytes(ki,32), chain:I.slice(32), depth:node.depth+1, parentFP, childNum:index};
}
function concatU8(...a){let n=0;for(const x of a)n+=x.length;const o=new Uint8Array(n);let k=0;for(const x of a){o.set(x,k);k+=x.length;}return o;}
function derive(seed, path){let n=master(seed);for(const i of path)n=ckd(n,i);return n;}

// extended key serialization (Decred mainnet)
const VER_PRIV = fromHex('02fda4e8'), VER_PUB = fromHex('02fda926');
function serialize(node, priv){
  const ver = priv ? VER_PRIV : VER_PUB;
  const depth = new Uint8Array([node.depth & 0xff]);
  const childNum = new Uint8Array(4); new DataView(childNum.buffer).setUint32(0, node.childNum>>>0, false);
  const keyData = priv ? concatU8(new Uint8Array([0]), node.key) : DCR.pubFromPriv(node.key);
  const payload = concatU8(ver, depth, node.parentFP, childNum, node.chain, keyData);
  return DCR.base58checkDcr(payload);
}

(async () => {
  console.log('\n== PGP word list / native seed encode (dcrwallet seed_test vectors) ==');
  const sv = [
    ['e58294f2e9a227486e8b061b31cc528fd7fa3f19', 'topmost Istanbul Pluto vagabond treadmill Pacific brackish dictator goldfish Medusa afflict bravado chatter revolver Dupont midsummer stopwatch whimsical cowbell bottomless fracture'],
    ['d1d464c004f00fb5c9a4c8d8e433e7fb7ff56256', 'stairway souvenir flytrap recipe adrift upcoming artist positive spearhead Pandora spaniel stupendous tonic concurrent transit Wichita lockup visitor flagpole escapade merit'],
    ['e34cd132128c1929ec96865ced5c4d0bf40a5d021fcef58d27dbfee371d210', 'tissue disbelief stairway component atlas megaton bedlamp certify tumor monument necklace fascinate tunnel fascinate dreadful armistice upshot Apollo exceed aftermath billiard sardonic vapor microscope brackish suspicious woodlark torpedo hamlet sensation assume recipe'],
  ];
  // Each vector through the independent oracle (pgpEncode/pgpDecode above) and
  // through the shipped encoder and decoder from src/template.html.
  for (let i = 0; i < sv.length; i++) {
    check('oracle encode vec ' + i, pgpEncode(fromHex(sv[i][0])), sv[i][1]);
    check('shipped encode vec ' + i, await DCR.encodeSeedMnemonic(fromHex(sv[i][0])), sv[i][1]);
  }
  // 31 zero bytes -> aardvark... insurgent
  const zeros = new Uint8Array(31);
  const zerosWant = 'aardvark adroitness '.repeat(15) + 'aardvark insurgent';
  check('oracle encode 31 zero bytes', pgpEncode(zeros), zerosWant);
  check('shipped encode 31 zero bytes', await DCR.encodeSeedMnemonic(zeros), zerosWant);
  // decode round-trip
  for (let i = 0; i < sv.length; i++) {
    check('oracle decode vec ' + i, hex(pgpDecode(sv[i][1])), sv[i][0]);
    check('shipped decode vec ' + i, hex(await DCR.decodeSeedMnemonic(sv[i][1].split(' '))), sv[i][0]);
  }

  console.log('\n== secp256k1 generator (pubFromPriv(1) == G) ==');
  check('G', hex(DCR.pubFromPriv(bigToBytes(1n, 32))),
    '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');

  console.log('\n== BIP32 extended keys vs dcrd hdkeychain test vectors (mainnet) ==');
  const hk = 0x80000000;
  const v1 = '000102030405060708090a0b0c0d0e0f';
  const v2 = 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542';
  const vecs = [
    [v1, [], 'dpubZ9169KDAEUnyoBhjjmT2VaEodr6pUTDoqCEAeqgbfr2JfkB88BbK77jbTYbcYXb2FVz7DKBdW4P618yd51MwF8DjKVopSbS7Lkgi6bowX5w', 'dprv3hCznBesA6jBtmoyVFPfyMSZ1qYZ3WdjdebquvkEfmRfxC9VFEFi2YDaJqHnx7uGe75eGSa3Mn3oHK11hBW7KZUrPxwbCPBmuCi1nwm182s'],
    [v1, [hk], 'dpubZCGVaKZBiMo7pMgLaZm1qmchjWenTeVcUdFQkTNsFGFEA6xs4EW8PKiqYqP7HBAitt9Hw16VQkQ1tjsZQSHNWFc6bEK6bLqrbco24FzBTY4', 'dprv3kUQDBztdyjKuwnaL3hfKYpT7W6X2huYH5d61YSWFBebSYwEBHAXJkCpQ7rvMAxPzKqxVCGLvBqWvGxXjAyMJsV1XwKkfnQCM9KctC8k8bk'],
    [v1, [hk, 1], 'dpubZEDyZgdnFBMHxqNhfCUwBfAg1UmXHiTmB5jKtzbAZhF8PTzy2PwAicNdkg1CmW6TARxQeUbgC7nAQenJts4YoG3KMiqcjsjgeMvwLc43w6C', 'dprv3nRtCZ5VAoHW4RUwQgRafSNRPUDFrmsgyY71A5eoZceVfuyL9SbZe2rcbwDW2UwpkEniE4urffgbypegscNchPajWzy9QS4cRxF8QYXsZtq'],
    [v1, [hk, 1, hk+2], 'dpubZGLz7gsJAWzUksvtw3opxx5eeLq5fRaUMDABA3bdUVfnGUk5fiS5Cc3kZGTjWtYr3jrEavQQnAF6jv2WCpZtFX4uFgifXqev6ED1TM9rTCB', 'dprv3pYtkZK168vgrU38gXkUSjHQ2LGpEUzQ9fXrR8fGUR59YviSnm6U82XjQYhpJEUPnVcC9bguJBQU5xVM4VFcDHu9BgScGPA6mQMH4bn5Cth'],
    [v1, [hk, 1, hk+2, 2, 1000000000], 'dpubZL6d9amjfRy1zeoZM2zHDU7uoMvwPqtxHRQAiJjeEtQQWjP3retQV1qKJyzUd6ZJNgbJGXjtc5pdoBcTTYTLoxQzvV9JJCzCjB2eCWpRf8T', 'dprv3tJXnTDSb3uE6Euo6WvvhFKfBMNfxuJt5smqyPoHEoomoBMQyhYoQSKJAHWtWxmuqdUVb8q9J2NaTkF6rYm6XDrSotkJ55bM21fffa7VV97'],
    [v2, [], 'dpubZ9169KDAEUnynoD4qvXJwmxZt3FFA5UdWn1twnRReE9AxjCKJLNFY1uBoegbFmwzA4Du7yqnu8tLivhrCCH6P3DgBS1HH5vmf8MpNXvvYT9', 'dprv3hCznBesA6jBtPKJbQTxRZAKG2gyj8tZKEPaCsV4e9YYFBAgRP2eTSPAeu4r8dTMt9q51j2Vdt5zNqj7jbtovvocrP1qLj6WUTLF9xYQt4y'],
    [v2, [0, hk+2147483647, 1, hk+2147483646, 2], 'dpubZJoBFoQJ35zvEBgsfhJBssnAp8TY5gvruzQFLmyxcqRb7enVtGfSkLo2CkAZJMpa6T2fx6fUtvTgXtUvSVgAZ56bEwGxQsToeZfFV8VadE1', 'dprv3s15tfqzxhw8Kmo7RBEqMeyvC7uGekLniSmvbs3bckpxQ6ks1KKqfmH144Jgh3PLxkyZRcS367kp7DrtUmnG16NpnsoNhxSXRgKbJJ7MUQR'],
  ];
  for (const [seedHex, path, wantPub, wantPriv] of vecs) {
    const n = derive(fromHex(seedHex), path);
    const label = 'm/' + (path.length ? path.map(p => p>=hk ? (p-hk)+"'" : ''+p).join('/') : '');
    check('priv ' + label, serialize(n, true), wantPriv);
    check('pub  ' + label, serialize(n, false), wantPub);
  }

  console.log('\n== Native end-to-end: generate 32-byte seed -> mnemonic -> address -> WIF round-trip ==');
  // derive address from a native 32-byte seed at m/44'/42'/0'/0/0
  async function nativeWallet(seed32) {
    const n = derive(seed32, [44+hk, 42+hk, 0+hk, 0, 0]);
    const pub = DCR.pubFromPriv(n.key);
    return { addr: DCR.addressFromPub(pub), wif: DCR.wifFromPriv(n.key), priv: hex(n.key) };
  }
  const seed32 = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const mn = pgpEncode(seed32);
  console.log('  mnemonic(33w):', mn.split(' ').length, 'words');
  check('mnemonic decodes back to seed', hex(pgpDecode(mn)), hex(seed32));
  check('shipped mnemonic is the oracle mnemonic', await DCR.encodeSeedMnemonic(seed32), mn);
  // The reference vector (README, and the page's self-test), through the shipped
  // derivation (dcrd's hdkeychain variant) and through the strict-BIP32 oracle.
  // The two agree for this seed; they differ for about 1 seed in 128.
  const wantAddr = 'DsUobw8mjYbXT9BrrwkNt5NaUveJyqiBDtc';
  const wantWif = 'PmQemEJb6WZy33Lk2SccamHvXPovET3LxgFX7Q7pRiE6rg1e4GBPh';
  const shipped = await DCR.walletFromSeedBytes(seed32, 0);
  check('shipped address', shipped.address, wantAddr);
  check('shipped wif', shipped.wif, wantWif);
  const w = await nativeWallet(seed32);
  check('oracle address', w.addr, wantAddr);
  check('oracle wif', w.wif, wantWif);

  console.log('\n== restoreFromInput, the verify panel\'s parser ==');
  const r33 = await DCR.restoreFromInput(mn);
  check('33-word native -> address', r33.kind + ' ' + r33.address, 'native ' + wantAddr);
  const r21 = await DCR.restoreFromInput(sv[0][1]);
  check('21-word native keeps its own length', r21.label + ' / ' + r21.words.length, 'Decred native · 21 words / 21');
  const rhex = await DCR.restoreFromInput('0x' + hex(seed32).toUpperCase());
  check('hex seed -> address', rhex.kind + ' ' + rhex.address, 'hex ' + wantAddr);
  const typo = mn.split(' '); typo[9] = 'banana';
  check('33 words, one not in the PGP list: the word is named',
    await rejection(() => DCR.restoreFromInput(typo.join(' '))), '“banana” is not in the Decred word list.');
  const swapped = mn.split(' '); [swapped[3], swapped[4]] = [swapped[4], swapped[3]];
  check('33 words, two swapped: the position is named',
    (await rejection(() => DCR.restoreFromInput(swapped.join(' ')))).slice(0, 8), 'Word #4 ');
  check('more than 65 words is refused before decoding',
    (await rejection(() => DCR.restoreFromInput('aardvark adroitness '.repeat(33) + 'aardvark'))).slice(0, 14), 'Too many words');
  check('unrecognized phrase: the message does not offer 15-word BIP39',
    await rejection(() => DCR.restoreFromInput('one two three four five six seven eight nine ten eleven twelve')),
    'Not a recognized Decred (33-word) or BIP39 (12/18/21/24-word) seed phrase. Check for typos or missing words.');
  const r15 = await DCR.restoreFromInput('peace option follow minute useful proud orphan zero truck response satisfy shell need chef silly');
  check('15 words -> Cake/DCRDEX/Bison', r15.kind + ' ' + r15.address + ' ' + r15.birthday, 'bison15 DsXUwBFUZsGw6r1JXcAs2EFh6Ug51VDeWez 1740614400');

  console.log('\n== BIP39 (existing engine) sanity: 12/15/24 word generation ==');
  for (const [strength, words] of [[128,12],[160,15],[256,24]]) {
    const wal = await DCR.generateWallet(strength, '');
    const n = wal.mnemonic.split(' ').length;
    check(`BIP39 ${words}w count`, ''+n, ''+words);
    check(`BIP39 ${words}w valid`, ''+(await DCR.validateMnemonic(wal.mnemonic)), 'true');
    check(`BIP39 ${words}w addr Ds`, wal.address.slice(0,2), 'Ds');
  }

  console.log('\n== BIP39 Trezor seed vector (mnemonic->seed PBKDF2) ==');
  const trezorMn = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const seed = await DCR.mnemonicToSeed(trezorMn, 'TREZOR');
  check('trezor seed', hex(seed), 'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04');
  const trezorAddr = 'Dsn1KktBp4eWd7JSPt1HYkLdPbgtEvqZLsj'; // the page's self-test value
  check('trezor address', (await DCR.walletFromMnemonic(trezorMn, 'TREZOR', 0)).address, trezorAddr);
  // A spelling validateMnemonic accepts derives the wallet of its canonical form.
  const sloppy = '  ' + trezorMn.toUpperCase().split(' ').join('  \n ') + ' ';
  check('sloppy spelling validates', '' + (await DCR.validateMnemonic(sloppy)), 'true');
  check('sloppy spelling derives the canonical wallet', (await DCR.walletFromMnemonic(sloppy, 'TREZOR', 0)).address, trezorAddr);
  const rb = await DCR.restoreFromInput(sloppy, 'TREZOR');
  check('restoreFromInput BIP39 + passphrase', rb.label + ' ' + rb.address, 'BIP39 · 12 words + passphrase ' + trezorAddr);

  console.log('\n== engine helpers refuse malformed arguments instead of coercing them ==');
  check('hexToBytes non-hex', (await rejection(() => DCR.hexToBytes('gg'))).slice(0, 10), 'hexToBytes');
  check('hexToBytes odd length', (await rejection(() => DCR.hexToBytes('abc'))).slice(0, 10), 'hexToBytes');
  check('derivePath index 2^32', '' + ((await rejection(() => DCR.derivePath(seed32, [2 ** 32]))) !== 'resolved'), 'true');
  check('generateWallet(128.9)', (await rejection(() => DCR.generateWallet(128.9))).slice(0, 14), 'generateWallet');

  console.log('\n== QR generator known answer (also pinned by the page\'s self-test) ==');
  // Module matrix for the reference address, rows of 0/1 joined by newlines.
  // Checked against libqrencode (same data and ECC codewords; it picks another
  // mask) and decoded back to the address by zbar.
  const qr = QR.encode(wantAddr, 'MEDIUM');
  const rows = qr.modules.map((r) => r.map((b) => (b ? '1' : '0')).join('')).join('\n');
  check('QR matrix sha256', nodecrypto.createHash('sha256').update(rows).digest('hex'),
    'e6a2add1c67300f36797268d52481635cf6638777d387ee90afdea74c31e5179');

  // ---------- the app's BIP39 list IS the list derivation uses ----------
  // src/bip39-wordlist.js is the sole source of words for the printed 15-word
  // Bison phrase, while BIP39 seeds are derived by dcr-ts through @scure's own
  // copy. Nothing in the code ties the two together, so a single edited or
  // reordered entry would print a phrase that does not restore the wallet
  // beside it — silently, since every other check would still pass.
  //
  // The first 11 bits of the entropy select the first word, so walking i over
  // 0..2047 and reading word 0 back names every entry in @scure's list exactly
  // once, and compares it against the shipped one.
  console.log('\n== the shipped BIP39 wordlist matches the one dcr-ts derives with ==');
  const shippedList = global.window.BIP39_WORDLIST;
  check('shipped list is 2048 words', '' + shippedList.length, '2048');
  let mismatches = [];
  for (let i = 0; i < 2048; i++) {
    const e = new Uint8Array(16);
    e[0] = i >> 3;
    e[1] = (i & 7) << 5;
    const first = (await DCR.entropyToMnemonic(e)).split(' ')[0];
    if (first !== shippedList[i]) mismatches.push(`${i}: derived "${first}" vs shipped "${shippedList[i]}"`);
  }
  check('all 2048 indices agree', mismatches.length ? mismatches.slice(0, 3).join('; ') : 'none', 'none');

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail ? 1 : 0);
})();
