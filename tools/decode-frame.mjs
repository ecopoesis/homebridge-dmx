// Decode a captured 576-byte DMX frame with the recovered AES-256 key, and
// pin down the first-block IV construction.
//
// AES-256-CBC: blocks 1..33 decrypt from the key alone. Block 0 needs the IV:
//   P0 = D(key, C0) XOR IV
// We compute D(key,C0), then try nonce-derived IV constructions and pick the
// one whose resulting P0 looks like DMX (consistent with blocks 1..33).
//
// Usage:
//   node tools/decode-frame.mjs <frame.bin> [key-hex]
//   (key defaults to the value recovered by Path C)

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';

const DEFAULT_KEY =
  '531e1b9f097be5de5785f5bf86473da34839fabb76676e95c0e4b808b42f8ac0';

const [, , framePath, keyArg] = process.argv;
if (!framePath) {
  console.error('usage: node tools/decode-frame.mjs <frame.bin> [key-hex]');
  process.exit(1);
}
const key = Buffer.from((keyArg || DEFAULT_KEY).replace(/\s/g, ''), 'hex');
if (key.length !== 32) { console.error('key must be 32 bytes'); process.exit(1); }

const frame = fs.readFileSync(framePath);
if (frame.length !== 576) { console.error(`need 576 bytes, got ${frame.length}`); process.exit(1); }

const header = frame.subarray(0, 0x20);
const body   = frame.subarray(0x20, 0x240);          // 544 B
const nonce  = Buffer.from(header.subarray(0x18, 0x20));

console.log('header :', header.toString('hex').match(/../g).join(' '));
console.log('  magic =', header.subarray(0, 8).toString());
console.log('  seq   =', header[0x17], ' nonce =', nonce.toString('hex'));
console.log('  key   =', key.toString('hex'));
console.log();

// CBC-decrypt the whole body with IV=0:
//   out[0:16]   = D(key,C0)            = IV XOR P0
//   out[16:544] = real plaintext P1..P33
const d = crypto.createDecipheriv('aes-256-cbc', key, Buffer.alloc(16));
d.setAutoPadding(false);
const out = Buffer.concat([d.update(body), d.final()]);
const Dt0 = out.subarray(0, 16);                     // D(key,C0)
const known = out.subarray(16);                      // 528 bytes, real DMX

let zeros = 0;
for (const b of known) if (b === 0) zeros++;
console.log(`plaintext blocks 1..33 (528 B real DMX, ${(zeros / known.length * 100).toFixed(1)}% zero):`);
for (let o = 0; o < known.length; o += 32) {
  const row = known.subarray(o, o + 32);
  if (row.every(b => b === 0)) continue;             // skip all-zero rows
  console.log(`  P[+0x${(o + 16).toString(16).padStart(3, '0')}] ${row.toString('hex').match(/../g).join(' ')}`);
}
console.log('  (all-zero rows omitted)');
console.log();

// --- recover the IV: P0 = D(key,C0) XOR IV --------------------------------
console.log(`D(key,C0) = ${Dt0.toString('hex')}   (= IV XOR P0)`);
console.log();

const z8 = Buffer.alloc(8);
const fieldA = Buffer.from(header.subarray(0x0a, 0x12));   // varying 8-byte field
const blocks16 = [
  ['nonce|0',        Buffer.concat([nonce, z8])],
  ['0|nonce',        Buffer.concat([z8, nonce])],
  ['nonce|nonce',    Buffer.concat([nonce, nonce])],
  ['fieldA|nonce',   Buffer.concat([fieldA, nonce])],
  ['nonce|fieldA',   Buffer.concat([nonce, fieldA])],
  ['hdr[0:16]',      Buffer.from(header.subarray(0, 16))],
  ['hdr[16:32]',     Buffer.from(header.subarray(16, 32))],
  ['nonce|nonceR',   Buffer.concat([nonce, Buffer.from(nonce).reverse()])],
  ['zero',           Buffer.alloc(16)],
];

function ecbEncrypt(block) {
  const c = crypto.createCipheriv('aes-256-ecb', key, null);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(block), c.final()]);
}

// Assuming P0 = 0 (DMX ch 1-16 off), the IV equals D(key,C0). Test which
// construction reproduces it — directly, or as AES-256(key, block).
console.log(`assuming P0 = 0  ->  IV should equal D(key,C0) = ${Dt0.toString('hex')}`);
console.log();
console.log('testing IV constructions:');
let hit = null;
for (const [name, blk] of blocks16) {
  if (blk.equals(Dt0)) {
    console.log(`  ✅ IV = ${name}   (direct)`);
    hit = `${name} (direct)`;
  }
  const enc = ecbEncrypt(blk);
  if (enc.equals(Dt0)) {
    console.log(`  ✅ IV = AES-256-ECB(key, ${name})`);
    hit = `AES-256-ECB(key, ${name})`;
  }
}
if (!hit) {
  console.log('  (no match — P0 may be non-zero, or IV uses other inputs)');
  console.log();
  console.log('Definitive next step: in HWM, set every channel to 0 (blackout),');
  console.log('capture a frame, re-run this. Then P0 = 0 for sure and');
  console.log('IV = D(key,C0) exactly — and these guesses will resolve it.');
} else {
  console.log();
  console.log(`✅ IV CONSTRUCTION: ${hit}`);
}
