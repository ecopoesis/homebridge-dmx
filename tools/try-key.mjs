// Verify a recovered AES key against a captured 576-byte DMX frame.
//
// Generalises try-hardcoded-key.mjs: takes the key (and optionally IV / mode)
// on the command line, so it works with keys extracted by the Path A lldb
// scan (tools/lldb-pathA-scan.py).
//
// Usage:
//   node tools/try-key.mjs <frame.bin> <key-hex> [iv-hex] [cbc|cfb]
//
// Key insight: with the CORRECT key, AES-CBC and AES-CFB both decrypt blocks
// 1..33 correctly regardless of the IV (only block 0 depends on the IV). So
// a high zero-ratio here confirms the key even if the IV is unknown/wrong.
//
// Examples:
//   node tools/try-key.mjs /tmp/frame.bin $(xxd -p -c256 /tmp/stick-pathA-key-0.bin)
//   node tools/try-key.mjs /tmp/frame.bin 527a5b46...  0011..  cfb

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';

const [, , framePath, keyHex, ivHex, modeArg] = process.argv;
if (!framePath || !keyHex) {
  console.error('usage: node tools/try-key.mjs <frame.bin> <key-hex> [iv-hex] [cbc|cfb]');
  process.exit(1);
}

const frame = fs.readFileSync(framePath);
if (frame.length !== 576) {
  console.error(`expected exactly 576 bytes, got ${frame.length}`);
  process.exit(1);
}

const key = Buffer.from(keyHex.replace(/\s/g, ''), 'hex');
if (key.length !== 16) {
  console.error(`key must be 16 bytes (32 hex chars), got ${key.length}`);
  process.exit(1);
}

const header = frame.subarray(0, 0x20);
const body   = frame.subarray(0x20, 0x240);   // 544 bytes = 34 AES blocks

// candidate IVs to try (block 0 only depends on this; blocks 1..33 don't)
const ivs = [];
if (ivHex) {
  ivs.push(['cli', Buffer.from(ivHex.replace(/\s/g, ''), 'hex')]);
} else {
  ivs.push(['zero',      Buffer.alloc(16)]);
  ivs.push(['nonce|0',   Buffer.concat([header.subarray(0x18, 0x20), Buffer.alloc(8)])]);
  ivs.push(['hdr16..32', Buffer.from(header.subarray(0x10, 0x20))]);
}

const modes = modeArg ? [modeArg.toLowerCase()] : ['cbc', 'cfb'];

console.log('clear header (32B):', header.toString('hex').match(/../g).join(' '));
console.log(`  session_magic = ${header.subarray(0, 8).toString()}`);
console.log(`  channels      = ${header.readUInt16LE(0x14)}`);
console.log(`  seq           = ${header[0x17]}`);
console.log(`  nonce         = ${header.subarray(0x18, 0x20).toString('hex')}`);
console.log(`  key           = ${key.toString('hex')}`);
console.log();

function analyse(out) {
  let zeros = 0, max = 0, nonzero = [];
  for (let i = 0; i < out.length; i++) {
    if (out[i] === 0) zeros++;
    else { if (out[i] > max) max = out[i]; if (nonzero.length < 24) nonzero.push(`${i}:${out[i]}`); }
  }
  return { zeroRatio: zeros / out.length, max, nonzero };
}

let best = null;
for (const algo of modes) {
  const cipherName = algo === 'cbc' ? 'aes-128-cbc' : 'aes-128-cfb';
  for (const [ivLabel, iv] of ivs) {
    if (iv.length !== 16) { console.log(`  skip ${algo}/${ivLabel}: bad iv len`); continue; }
    try {
      const d = crypto.createDecipheriv(cipherName, key, iv);
      d.setAutoPadding(false);
      const out = Buffer.concat([d.update(body), d.final()]);
      const a = analyse(out);
      const pct = (a.zeroRatio * 100).toFixed(1);
      const verdict = a.zeroRatio > 0.80 ? '  <<< LOOKS LIKE VALID DMX' : '';
      console.log(`${algo.toUpperCase()} iv=${ivLabel.padEnd(10)} zero=${pct}%  max=${a.max}${verdict}`);
      console.log(`   first 32B: ${out.subarray(0, 32).toString('hex')}`);
      if (a.nonzero.length) console.log(`   nonzero[idx:val]: ${a.nonzero.join(' ')}`);
      if (!best || a.zeroRatio > best.zeroRatio) best = { algo, ivLabel, ...a };
    } catch (e) {
      console.log(`${algo.toUpperCase()} iv=${ivLabel}: error ${e.message}`);
    }
  }
}

console.log();
if (best && best.zeroRatio > 0.80) {
  console.log(`✅ KEY VERIFIED — best: ${best.algo.toUpperCase()} iv=${best.ivLabel} ` +
              `zero=${(best.zeroRatio * 100).toFixed(1)}%`);
  console.log('   (block 0 may differ until the real IV is known — that is expected)');
  process.exit(0);
} else {
  console.log('❌ key did not produce DMX-shaped plaintext.');
  console.log('   Either the key is wrong, or the cipher/mode differs from AES-128.');
  process.exit(3);
}
