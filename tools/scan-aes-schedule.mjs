// Path A fallback — heap-wide AES-128 key-schedule search.
//
// Runs OFFLINE against the memory dump produced by lldb-pathA-scan.py when
// invoked with STICK_HEAP_DUMP=1. Use this only if the fast vptr-localised
// scan finds no key (e.g. the cipher object stores round keys outside the
// 0x800-byte window, or at an unexpected offset).
//
// A valid AES-128 forward key schedule is 176 bytes whose word expansion is
// self-consistent — random memory matches with vanishing probability, so any
// hit is almost certainly a real round-key array. We recover the 16-byte
// master key (w[0..3]) from it.
//
// Usage:
//   node tools/scan-aes-schedule.mjs /tmp/stick-heap
//
// Also exports scheduleKey() / SBOX / RCON for tools/test-aes-detector.mjs.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const SBOX = Buffer.from(
  '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0' +
  'b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275' +
  '09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf' +
  'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2' +
  'cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb' +
  'e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08' +
  'ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e' +
  'e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16',
  'hex');
export const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

// Full AES-128 schedule validation of buf[o .. o+176).
// Returns a 16-byte Buffer (the master key) on success, else null.
export function scheduleKey(buf, o) {
  if (o + 176 > buf.length) return null;

  // cheap filter: verify word 4 first (one 4-byte compare, kills ~2^-32)
  // temp = SubWord(RotWord(w3)) ^ Rcon1 ; w4 == w0 ^ temp
  const t0 = SBOX[buf[o + 13]] ^ RCON[0];
  const t1 = SBOX[buf[o + 14]];
  const t2 = SBOX[buf[o + 15]];
  const t3 = SBOX[buf[o + 12]];
  if ((buf[o]     ^ t0) !== buf[o + 16]) return null;
  if ((buf[o + 1] ^ t1) !== buf[o + 17]) return null;
  if ((buf[o + 2] ^ t2) !== buf[o + 18]) return null;
  if ((buf[o + 3] ^ t3) !== buf[o + 19]) return null;

  // full check: all 44 words
  const w = new Array(44);
  for (let i = 0; i < 44; i++) w[i] = buf.subarray(o + 4 * i, o + 4 * i + 4);
  for (let i = 4; i < 44; i++) {
    let a, b, c, d;
    const p = w[i - 1];
    if (i % 4 === 0) {
      a = SBOX[p[1]] ^ RCON[i / 4 - 1];
      b = SBOX[p[2]];
      c = SBOX[p[3]];
      d = SBOX[p[0]];
    } else {
      a = p[0]; b = p[1]; c = p[2]; d = p[3];
    }
    const q = w[i - 4];
    if ((q[0] ^ a) !== w[i][0]) return null;
    if ((q[1] ^ b) !== w[i][1]) return null;
    if ((q[2] ^ c) !== w[i][2]) return null;
    if ((q[3] ^ d) !== w[i][3]) return null;
  }
  return Buffer.from(buf.subarray(o, o + 16));
}

function main() {
  const dir = process.argv[2] || '/tmp/stick-heap';
  const manifestPath = path.join(dir, 'manifest.txt');
  if (!fs.existsSync(manifestPath)) {
    console.error(`no manifest at ${manifestPath}`);
    console.error('run the lldb scan with STICK_HEAP_DUMP=1 first');
    process.exit(1);
  }

  const manifest = fs.readFileSync(manifestPath, 'utf8').trim().split('\n');
  const found = new Map();   // keyhex -> [addr,...]
  let totalBytes = 0;
  const t0 = Date.now();

  for (const line of manifest) {
    const [baseHex, , fname] = line.trim().split(/\s+/);
    if (!fname) continue;
    const base = BigInt(baseHex);
    const buf = fs.readFileSync(path.join(dir, fname));
    totalBytes += buf.length;
    const limit = buf.length - 176;
    // round keys are word-aligned in practice; step 4 keeps it fast
    for (let o = 0; o <= limit; o += 4) {
      const key = scheduleKey(buf, o);
      if (key) {
        const hex = key.toString('hex');
        const addr = '0x' + (base + BigInt(o)).toString(16);
        if (!found.has(hex)) found.set(hex, []);
        found.get(hex).push(addr);
      }
    }
  }

  const secs = ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`scanned ${(totalBytes / 1048576).toFixed(1)} MiB in ${secs}s`);
  console.log();

  if (found.size === 0) {
    console.log('no AES-128 key schedule found in the dump.');
    console.log('the impl likely expands the schedule on the fly — fall back to');
    console.log('reading the raw 16-byte key at cipher_obj+0x48 (see scan log).');
    process.exit(3);
  }

  console.log(`found ${found.size} distinct AES-128 key(s):`);
  let n = 0;
  for (const [hex, addrs] of found) {
    const spaced = hex.match(/../g).join(' ');
    console.log(`  [${n}] ${spaced}`);
    console.log(`      at ${addrs.slice(0, 6).join(', ')}` +
                `${addrs.length > 6 ? ` (+${addrs.length - 6} more)` : ''}`);
    fs.writeFileSync(`/tmp/stick-heapscan-key-${n}.bin`, Buffer.from(hex, 'hex'));
    n++;
  }
  console.log();
  console.log('verify each against a captured frame:');
  console.log('  node tools/try-key.mjs <frame.bin> <key-hex>');
}

// run main() only when executed directly, not when imported by the test
const isMain = process.argv[1] &&
  fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1]);
if (isMain) main();
