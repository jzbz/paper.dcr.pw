'use strict';
// Assembles the standalone, offline single-file index.html by inlining the
// vendored engines, the PGP word list, the fonts, and the favicon into
// src/template.html. Deterministic — run from anywhere: `node build.js`.
const fs = require('fs');
const path = require('path');
const root = __dirname;
const src = (p) => path.join(root, 'src', p);

let html = fs.readFileSync(src('template.html'), 'utf8');

const engine  = fs.readFileSync(src('decred-crypto.js'), 'utf8');
const bip39   = fs.readFileSync(src('bip39-wordlist.js'), 'utf8');
const qr      = fs.readFileSync(src('qrcode.js'), 'utf8');
const pgp     = fs.readFileSync(src('pgp-words.json'), 'utf8').trim(); // JS array literal
const grotesk = fs.readFileSync(src('fonts/space-grotesk.woff2')).toString('base64');
const mono    = fs.readFileSync(src('fonts/jetbrains-mono.woff2')).toString('base64');

// Favicon: the Decred (dcr.svg) logo, rounded, base64-encoded (no URL-escaping needed).
const faviconSvg =
  "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'>" +
  "<defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1'>" +
  "<stop offset='0' stop-color='#2ED6A1'/><stop offset='1' stop-color='#36C5E0'/></linearGradient></defs>" +
  "<rect width='64' height='64' rx='12' fill='url(#g)'/>" +
  "<path d='M43.21 40.24 51 48h-7.65L30.5 35.2h8a6.4 6.4 0 1 0 0-12.8h-2.6L29.43 16h8.72A12.82 12.82 0 0 1 51 28.8c0 5.2-2.3 9.26-7.79 11.44' fill='#fff'/>" +
  "<path d='M20.79 23.76 13 16h7.66l12.85 12.8h-7.95a6.4 6.4 0 1 0 0 12.8h2.59l6.42 6.4h-8.72A12.82 12.82 0 0 1 13 35.2c0-5.2 2.3-9.26 7.79-11.44' fill='#fff'/></svg>";
const faviconB64 = Buffer.from(faviconSvg, 'utf8').toString('base64');

function inject(marker, content){
  if (html.indexOf(marker) < 0) throw new Error('marker not found: ' + marker);
  html = html.split(marker).join(content);
}

// guard: none of the injected JS may contain a closing script tag
for (const [name, s] of [['engine', engine], ['bip39', bip39], ['qr', qr], ['pgp', pgp]]){
  if (/<\/script/i.test(s)) throw new Error('injected ' + name + ' contains </script');
}

inject('/*__ENGINE__*/', engine);
inject('/*__BIP39__*/', bip39);
inject('/*__PGPWORDS__*/', pgp);
inject('/*__QR__*/', qr);
inject('__FONT_GROTESK_B64__', grotesk);
inject('__FONT_MONO_B64__', mono);
inject('__FAVICON_B64__', faviconB64);

const left = html.match(/__[A-Z0-9_]+__|\/\*__[A-Z0-9_]+__\*\//g);
if (left) throw new Error('unreplaced placeholders: ' + left.join(', '));

fs.writeFileSync(path.join(root, 'index.html'), html);
console.log('wrote index.html (' + (Buffer.byteLength(html) / 1024).toFixed(0) + ' KB)');
