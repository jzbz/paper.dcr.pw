'use strict';
// Verifies the shipped DCRDEX/Bison/Cake 15-word "seed + birthday" codec (the
// app's encode15Word / decode15Word / walletFrom15Entropy, loaded from
// src/template.html) against:
//  (a) a literal port of dcrdex client/mnemonic/seed.go bit-packing,
//  (b) the real vector from decred/libwallet dcr/dcr_test.go (TestDecryptSeed "ok 15"),
//  (c) the STFifteenWords derivation from libwallet dcr/loader.go.
const nc = require('crypto');

const { DCR, BIP39_WORDLIST: WL } = require('./load-app');
const WLIDX = {}; WL.forEach((w,i)=>WLIDX[w]=i);

const hex = b => Buffer.from(b).toString('hex');
const fromHex = h => new Uint8Array(Buffer.from(h,'hex'));
let pass=0, fail=0;
function check(n,g,w){ const ok=g===w; if(ok){pass++;console.log('  ✓',n);} else {fail++;console.log('  ✗',n,'\n     got :',g,'\n     want:',w);} }

const ENT=18, TB=2, WORDS=15, SPD=86400;
function sha256(b){ return new Uint8Array(nc.createHash('sha256').update(Buffer.from(b)).digest()); }

// ---------- (a) LITERAL port of dcrdex Go generateMnemonic / DecodeMnemonic ----------
function goGenerate(entropy, unixSecs){
  const days = Math.floor(unixSecs / SPD) & 0xffff;
  const timeB = [ (days>>8)&0xff, days&0xff ];
  const buf = new Uint8Array(ENT+TB+1);
  buf.set(entropy,0); buf[ENT]=timeB[0]; buf[ENT+1]=timeB[1];
  const h = sha256(buf.slice(0,ENT+TB));
  buf[ENT+TB] = h[0] & 248;
  let cursor=0; const words=[];
  for(let i=0;i<WORDS;i++){
    const idxB=[0,0];
    let byteIdx=cursor>>3, remain=8-(cursor%8);
    if(remain<3){
      const clearN=8-remain; const masked=((buf[byteIdx]<<clearN)&0xff)>>clearN;
      idxB[0]=(masked<<(3-remain))&0xff; cursor+=remain; byteIdx++;
      const n=3-remain; idxB[0]|=buf[byteIdx]>>(8-n); cursor+=n;
    } else { idxB[0]=((buf[byteIdx]<<(8-remain))&0xff)>>5; cursor+=3; }
    byteIdx=cursor>>3; remain=8-(cursor%8);
    idxB[1]=(buf[byteIdx]<<(8-remain))&0xff; cursor+=remain;
    if(remain<8){ const n=8-remain; byteIdx++; idxB[1]|=buf[byteIdx]>>(8-n); cursor+=n; }
    const idx=(idxB[0]<<8)|idxB[1];
    words.push(WL[idx]);
  }
  return words.join(' ');
}
function goDecode(mnemonic){
  const words = mnemonic.trim().split(/\s+/);
  if(words.length!==15) throw new Error('expected 15 words, got '+words.length);
  const buf=new Uint8Array(ENT+TB+1); let cursor=0;
  for(const word of words){
    const v=WLIDX[word]; if(v===undefined) throw new Error('word not known: '+word);
    const b0=(v>>8)&0xff, b1=v&0xff;
    let byteIdx=cursor>>3, avail=8-(cursor%8);
    if(avail<3){ buf[byteIdx]|=b0>>(3-avail); cursor+=avail; byteIdx++; const n=3-avail; buf[byteIdx]=(b0<<(8-n))&0xff; cursor+=n; }
    else { buf[byteIdx]|=(b0<<(avail-3))&0xff; cursor+=3; }
    byteIdx=cursor>>3; avail=8-(cursor%8);
    buf[byteIdx]|=b1>>(8-avail); cursor+=avail;
    if(avail<8){ byteIdx++; const n=8-avail; buf[byteIdx]|=(b1<<(8-n))&0xff; cursor+=n; }
  }
  const acquired=buf[ENT+TB]>>3;
  const h=sha256(buf.slice(0,ENT+TB));
  if(acquired !== (h[0]>>3)) throw new Error('checksum mismatch');
  const entropy=buf.slice(0,ENT);
  const days=(buf[ENT]<<8)|buf[ENT+1];
  return { entropy, unixSecs: days*SPD };
}

// ---------- (c) derivation: STFifteenWords (libwallet loader.go) ----------
function tweakedSeedFor(entropy){
  const b = new Uint8Array(entropy.length+4);
  b.set(entropy,0);
  // binary.BigEndian.PutUint32(b[len:], 42)
  b[entropy.length]=0; b[entropy.length+1]=0; b[entropy.length+2]=0; b[entropy.length+3]=42;
  return DCR.blake256(b);
}
async function wallet15(entropy){
  const ts = tweakedSeedFor(entropy);
  const H=0x80000000;
  const node = await DCR.derivePath(ts, [44+H,42+H,0+H,0,0]);
  const pub = DCR.pubFromPriv(node.key);
  return { tweakedSeed: hex(ts), address: DCR.addressFromPub(pub), wif: DCR.wifFromPriv(node.key) };
}

(async()=>{
  console.log('\n== (a): shipped encode15Word === literal Go packing (1000 random) ==');
  let allEq=true;
  for(let t=0;t<1000;t++){
    const e=new Uint8Array(ENT); for(let i=0;i<ENT;i++) e[i]=(Math.random()*256)|0;
    const secs=((Math.random()*65535)|0)*SPD;
    const mn=await DCR.encode15Word(e,secs);
    if(goGenerate(e,secs)!==mn){ allEq=false; console.log('ENCODE MISMATCH', hex(e), secs); break; }
    const d=await DCR.decode15Word(mn.split(' ')), g=goDecode(mn);
    if(hex(d.entropy)!==hex(g.entropy) || d.unixSecs!==g.unixSecs){ allEq=false; console.log('DECODE MISMATCH', hex(e), secs); break; }
  }
  check('shipped codec agrees with the Go port (1000 random)', ''+allEq, 'true');

  console.log('\n== (b) REAL vector: libwallet dcr_test.go TestDecryptSeed "ok 15" ==');
  const wantMn = 'peace option follow minute useful proud orphan zero truck response satisfy shell need chef silly';
  const wantBday = 1740614400;
  const dec = await DCR.decode15Word(wantMn.split(' '));
  check('decoded birthday == 1740614400', ''+dec.unixSecs, ''+wantBday);
  check('decoded day index', ''+(dec.unixSecs/SPD), '20146');
  check('re-encode round-trips to same words', await DCR.encode15Word(dec.entropy, dec.unixSecs), wantMn);
  check('go-decode agrees on entropy', hex(goDecode(wantMn).entropy), hex(dec.entropy));
  console.log('  decoded entropy (18B):', hex(dec.entropy));

  console.log('\n== (c) STFifteenWords derivation of the real vector ==');
  // The reference address (README, and the page's self-test), through the
  // shipped walletFrom15Entropy and through the test's own tweak + derivePath.
  const want15 = 'DsXUwBFUZsGw6r1JXcAs2EFh6Ug51VDeWez';
  const w = await wallet15(dec.entropy);
  const ws = await DCR.walletFrom15Entropy(dec.entropy);
  console.log('  tweakedSeed:', w.tweakedSeed);
  check('shipped address', ws.address, want15);
  check('oracle address', w.address, want15);
  check('shipped and oracle WIF agree', ws.wif, w.wif);

  console.log('\n== round-trip on fresh random 18-byte entropy ==');
  const e2=DCR.randomBytes(18); const secs2=Math.floor(Date.now()/1000);
  const mn2=await DCR.encode15Word(e2,secs2);
  check('fresh 15-word count', ''+mn2.split(' ').length, '15');
  check('fresh round-trip entropy', hex((await DCR.decode15Word(mn2.split(' '))).entropy), hex(e2));

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail?1:0);
})();
