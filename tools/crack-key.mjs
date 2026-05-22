// Path A, final step — brute-force the AES key out of a saved cipher-object
// dump by testing every window against a captured 576-byte DMX frame.
//
// The lldb scan (lldb_pathA_scan.py) saved the cipher object to
// /tmp/stick-pathA-obj-*.bin. The raw key is somewhere in there, but the
// exact offset / length / mode / byte order are uncertain. So: slide a
// window over the whole dump, try it as an AES key in every common mode,
// and score the decrypted DMX payload (DMX = mostly-zero bytes).
//
// Modes and what the IV does:
//   ecb           - no IV; every block independent
//   cbc/cfb/cfb8  - IV only affects the first block(s); blocks 1..33 (528
//                   bytes) decrypt from the key alone -> scored IV-free
//   ofb/ctr       - keystream depends on key AND the nonce/counter, every
//                   block -> we try several nonce-derived 16-byte IVs
//
// Usage:
//   node tools/crack-key.mjs <frame.bin> [objdump.bin ...]
//   (objdumps default to /tmp/stick-pathA-obj-*.bin)

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';

let [, , framePath, ...objPaths] = process.argv;
if (!framePath) {
  console.error('usage: node tools/crack-key.mjs <frame.bin> [objdump.bin ...]');
  process.exit(1);
}
if (objPaths.length === 0) {
  objPaths = fs.readdirSync('/tmp')
    .filter(f => /^stick-pathA-obj-.*\.bin$/.test(f))
    .map(f => '/tmp/' + f);
  if (objPaths.length === 0) {
    console.error('no /tmp/stick-pathA-obj-*.bin found — pass dumps explicitly');
    process.exit(1);
  }
}

const frame = fs.readFileSync(framePath);
if (frame.length !== 576) {
  console.error(`frame must be 576 bytes, got ${frame.length}`);
  process.exit(1);
}
const header = frame.subarray(0, 0x20);
const body   = frame.subarray(0x20, 0x240);        // 544 bytes, 34 AES blocks
const nonce  = Buffer.from(header.subarray(0x18, 0x20));   // 8 bytes

// candidate 16-byte IV / initial-counter blocks built from the clear header
const z8 = Buffer.alloc(8);
const ivCandidates = [
  ['nonce|0',   Buffer.concat([nonce, z8])],
  ['0|nonce',   Buffer.concat([z8, nonce])],
  ['nonce|nonce', Buffer.concat([nonce, nonce])],
  ['nonce|0..1', Buffer.concat([nonce, Buffer.from('0000000000000001', 'hex')])],
  ['hdr[0:16]', Buffer.from(header.subarray(0, 16))],
  ['hdr[16:32]', Buffer.from(header.subarray(16, 32))],
  ['zero',      Buffer.alloc(16)],
];
const ZERO_IV = Buffer.alloc(16);

// score a region of the plaintext: fraction of zero bytes
function zeroRatio(out, from) {
  let zeros = 0;
  for (let i = from; i < out.length; i++) if (out[i] === 0) zeros++;
  return zeros / (out.length - from);
}

function wordswap(buf) {
  const o = Buffer.from(buf);
  for (let i = 0; i + 4 <= o.length; i += 4) {
    const a = o[i], b = o[i + 1], c = o[i + 2], d = o[i + 3];
    o[i] = d; o[i + 1] = c; o[i + 2] = b; o[i + 3] = a;
  }
  return o;
}

function tryDecrypt(algo, key, iv) {
  const d = iv === null
    ? crypto.createDecipheriv(algo, key, null)
    : crypto.createDecipheriv(algo, key, iv);
  d.setAutoPadding(false);
  return Buffer.concat([d.update(body), d.final()]);
}

const results = [];
let tried = 0;

for (const objPath of objPaths) {
  const buf = fs.readFileSync(objPath);
  const objName = objPath.split('/').pop();
  for (const keylen of [16, 24, 32]) {
    const bits = keylen * 8;
    for (let off = 0; off + keylen <= buf.length; off++) {
      const window = buf.subarray(off, off + keylen);
      for (const [formName, keyBuf] of [['asis', window], ['wswap', wordswap(window)]]) {
        const note = (extra) => ({ obj: objName, off, keylen, form: formName,
          key: Buffer.from(keyBuf).toString('hex'), ...extra });

        // --- ECB: no IV, score everything --------------------------------
        try { tried++;
          const out = tryDecrypt(`aes-${bits}-ecb`, keyBuf, null);
          const z = zeroRatio(out, 0);
          if (z > 0.55) results.push(note({ mode: 'ecb', iv: '-', z,
            sample: out.subarray(0, 32).toString('hex') }));
        } catch { /* skip */ }

        // --- CBC / CFB / CFB8: IV-free score of blocks 1.. --------------
        for (const mode of ['cbc', 'cfb', 'cfb8']) {
          try { tried++;
            const out = tryDecrypt(`aes-${bits}-${mode}`, keyBuf, ZERO_IV);
            const z = zeroRatio(out, 16);
            if (z > 0.55) results.push(note({ mode, iv: 'n/a(blk1+)', z,
              sample: out.subarray(16, 48).toString('hex') }));
          } catch { /* skip */ }
        }

        // --- OFB / CTR: keystream depends on the nonce ------------------
        for (const mode of ['ofb', 'ctr']) {
          for (const [ivName, iv] of ivCandidates) {
            try { tried++;
              const out = tryDecrypt(`aes-${bits}-${mode}`, keyBuf, iv);
              const z = zeroRatio(out, 0);
              if (z > 0.55) results.push(note({ mode, iv: ivName, z,
                sample: out.subarray(0, 32).toString('hex') }));
            } catch { /* skip */ }
          }
        }
      }
    }
  }
}

console.log(`tried ${tried} (key,mode,iv,order) combinations`);
console.log(`frame: seq=${frame[0x17]} nonce=${nonce.toString('hex')}`);
console.log();

results.sort((a, b) => b.z - a.z);
if (results.length === 0) {
  console.log('❌ nothing decrypted to DMX-shaped plaintext under any of:');
  console.log('   ecb / cbc / cfb / cfb8 / ofb / ctr  (aes-128/192/256, both byte orders).');
  console.log('   The key is not a byte-contiguous window of the cipher object,');
  console.log('   OR it is derived (KDF) from the object bytes before use,');
  console.log('   OR the block cipher is non-standard. Next: capture a 2nd frame');
  console.log('   for a keystream diff, or Path C (patch the encrypt fn to log $rdi).');
  process.exit(3);
}

console.log(`top ${Math.min(15, results.length)} candidates (zero-ratio):`);
for (const r of results.slice(0, 15)) {
  const pct = (r.z * 100).toFixed(1);
  const flag = r.z > 0.80 ? '  <<< KEY FOUND' : '';
  console.log(`  ${pct}%  aes-${r.keylen * 8}-${r.mode} iv=${r.iv} ${r.form}` +
              `  ${r.obj}+0x${r.off.toString(16)}${flag}`);
  console.log(`        key=${r.key}`);
  console.log(`        plaintext=${r.sample}`);
}

const best = results[0];
console.log();
if (best.z > 0.80) {
  console.log('✅ KEY RECOVERED');
  console.log(`   algorithm : aes-${best.keylen * 8}-${best.mode}` +
              `  iv=${best.iv}  (byte order: ${best.form})`);
  console.log(`   key       : ${best.key}`);
  console.log(`   location  : ${best.obj} +0x${best.off.toString(16)}`);
  process.exit(0);
} else {
  console.log('⚠️  best candidate is below the 80% confidence bar — inspect above.');
  process.exit(2);
}
