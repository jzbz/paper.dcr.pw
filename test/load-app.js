'use strict';
// Loads what index.html loads, in the page's order: the dcr-ts engine bundle,
// the BIP39 list, the PGP list, the QR generator, and the app's seed-extension
// script taken verbatim from src/template.html. The suites therefore call the
// shipped encoders, decoders and restoreFromInput, not copies of them; their own
// independent implementations stay on as the oracles those are checked against.
const fs = require('fs');
const path = require('path');
const src = (p) => path.join(__dirname, '..', 'src', p);

global.window = global.window || {};
const run = (code) => (0, eval)(code); // indirect eval: global scope, as a <script> runs

run(fs.readFileSync(src('engine.bundle.js'), 'utf8'));
run(fs.readFileSync(src('bip39-wordlist.js'), 'utf8'));
run('window.PGP_WORDLIST = ' + fs.readFileSync(src('pgp-words.json'), 'utf8').trim() + ';');
run(fs.readFileSync(src('qrcode.js'), 'utf8'));

const template = fs.readFileSync(src('template.html'), 'utf8');
const m = template.match(/<!-- native Decred \(PGP word list\) seed extensions to window\.DCR -->\s*<script>([\s\S]*?)<\/script>/);
if (!m) throw new Error('load-app: seed-extension script not found in src/template.html');
run(m[1]);

module.exports = {
  DCR: global.window.DCR,
  QR: global.window.QR,
  BIP39_WORDLIST: global.window.BIP39_WORDLIST,
  PGP_WORDLIST: global.window.PGP_WORDLIST,
};
