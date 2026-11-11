'use strict';
// index.html is the file users run, and it is generated: this checks that the
// committed copy is byte for byte what the current sources build (after the
// pretest bundle step has regenerated src/engine.bundle.js). It fails when src/
// or a dependency changed and `npm run build` was not run, or when index.html
// was edited by hand.
const fs = require('fs');
const { assemble, output } = require('../build.js');

const built = assemble();
const committed = fs.readFileSync(output, 'utf8');
if (built === committed) {
  console.log('\n== index.html is what the sources build ==\n  ✓ identical (' + Buffer.byteLength(built) + ' bytes)');
  process.exit(0);
}
let i = 0;
while (i < built.length && built[i] === committed[i]) i++;
const line = built.slice(0, i).split('\n').length;
console.log('\n== index.html is what the sources build ==\n  ✗ index.html differs from a fresh build from line ' + line +
  ' (built ' + Buffer.byteLength(built) + ' bytes, committed ' + Buffer.byteLength(committed) + '). Run `npm run build`.');
process.exit(1);
