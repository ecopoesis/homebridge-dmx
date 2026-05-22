// Recover the AES-256-CBC first-block IV construction from a pcap of frames.
//
// With the key known, for every frame:  D(key,C0) = IV XOR P0.
// If the DMX state is constant across the capture, P0 is the same in every
// frame, so for the CORRECT IV construction H(header):
//     D(key,C0) XOR H(header)  ==  P0  ==  the same constant in every frame.
// We test each candidate H and look for one that yields a frame-invariant
// residual. That residual is P0 (block-0 plaintext); H is the IV rule.
//
// Usage:
//   node tools/find-iv.mjs <capture.pcap> [key-hex]

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';

const DEFAULT_KEY =
  '531e1b9f097be5de5785f5bf86473da34839fabb76676e95c0e4b808b42f8ac0';

const [, , pcapPath, keyArg] = process.argv;
if (!pcapPath) { console.error('usage: node tools/find-iv.mjs <capture.pcap> [key-hex]'); process.exit(1); }
const key = Buffer.from((keyArg || DEFAULT_KEY).replace(/\s/g, ''), 'hex');
if (key.length !== 32) { console.error('key must be 32 bytes'); process.exit(1); }

// --- parse pcap, collect every 576-byte UDP payload to the Stick ----------
const STICK_IP = process.env.STICK_IP || '192.168.96.2';
const STICK_PORT = Number(process.env.STICK_PORT || 2431);
const buf = fs.readFileSync(pcapPath);
const magic = buf.readUInt32LE(0);
const le = magic === 0xa1b2c3d4;
if (!le && magic !== 0xd4c3b2a1) { console.error('bad pcap magic'); process.exit(2); }
const linkType = le ? buf.readUInt32LE(20) : buf.readUInt32BE(20);
const ethSkip = linkType === 1 ? 14 : linkType === 0 ? 4 : 14;

const frames = [];
let off = 24;
while (off + 16 <= buf.length) {
  const capLen = le ? buf.readUInt32LE(off + 8) : buf.readUInt32BE(off + 8);
  off += 16;
  if (off + capLen > buf.length) break;
  const pkt = buf.subarray(off, off + capLen);
  off += capLen;
  if (pkt.length < ethSkip + 28) continue;
  const ip = pkt.subarray(ethSkip);
  if (ip[9] !== 17) continue;                            // not UDP
  const dstIp = `${ip[16]}.${ip[17]}.${ip[18]}.${ip[19]}`;
  const udp = ip.subarray((ip[0] & 0x0f) * 4);
  if (udp.length < 8) continue;
  const dstPort = udp.readUInt16BE(2);
  const payload = udp.subarray(8, udp.readUInt16BE(4));
  if (dstIp === STICK_IP && dstPort === STICK_PORT && payload.length === 576)
    frames.push(Buffer.from(payload));
}
console.log(`parsed ${frames.length} encrypted 576-byte frames from ${pcapPath}`);
if (frames.length < 2) { console.error('need at least 2 frames'); process.exit(3); }

// --- D(key,C0) for each frame --------------------------------------------
function decBlock0(frame) {
  const d = crypto.createDecipheriv('aes-256-cbc', key, Buffer.alloc(16));
  d.setAutoPadding(false);
  return d.update(frame.subarray(0x20, 0x30));            // D(key,C0), IV=0
}
function ecb(block) {
  const c = crypto.createCipheriv('aes-256-ecb', key, null);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(block), c.final()]);
}
function xor(a, b) {
  const o = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) o[i] = a[i] ^ b[i];
  return o;
}

const recs = frames.map(f => ({
  hdr: f.subarray(0, 0x20),
  nonce: Buffer.from(f.subarray(0x18, 0x20)),
  fieldA: Buffer.from(f.subarray(0x0a, 0x12)),
  dt0: decBlock0(f),
}));

// also reuse the per-session key material A||B from the Path C device dump,
// if present — the IV might be keyed on that instead.
let AB = null;
try {
  const dev = fs.readFileSync(
    fs.readdirSync('/tmp').filter(f => /^stick-pathC-blob-device_/.test(f))
      .map(f => '/tmp/' + f)[0]);
  // cipher_obj = device + 0x1618 ; A||B at cipher_obj + 0x28
  AB = Buffer.from(dev.subarray(0x1618 + 0x28, 0x1618 + 0x28 + 32));
  console.log(`loaded A||B from device dump: ${AB.toString('hex')}`);
} catch { /* optional */ }

const z8 = Buffer.alloc(8);
function blocks(r) {
  const b = [
    ['nonce|0',      Buffer.concat([r.nonce, z8])],
    ['0|nonce',      Buffer.concat([z8, r.nonce])],
    ['nonce|nonce',  Buffer.concat([r.nonce, r.nonce])],
    ['fieldA|nonce', Buffer.concat([r.fieldA, r.nonce])],
    ['nonce|fieldA', Buffer.concat([r.nonce, r.fieldA])],
    ['hdr[0:16]',    Buffer.from(r.hdr.subarray(0, 16))],
    ['hdr[16:32]',   Buffer.from(r.hdr.subarray(16, 32))],
    ['hdr[10:26]',   Buffer.from(r.hdr.subarray(0x0a, 0x1a))],
    ['nonce|nonceR', Buffer.concat([r.nonce, Buffer.from(r.nonce).reverse()])],
  ];
  return b;
}

// --- test each construction for a frame-invariant residual ---------------
function evaluate(label, hOf) {
  const tally = new Map();
  for (const r of recs) {
    const resid = xor(r.dt0, hOf(r)).toString('hex');
    tally.set(resid, (tally.get(resid) || 0) + 1);
  }
  let best = null;
  for (const [resid, n] of tally)
    if (!best || n > best.n) best = { resid, n };
  return { label, frac: best.n / recs.length, resid: best.resid, distinct: tally.size };
}

const names = blocks(recs[0]).map(([n]) => n);
const results = [];
for (let i = 0; i < names.length; i++) {
  const name = names[i];
  results.push(evaluate(`IV = ${name}`, r => blocks(r)[i][1]));
  results.push(evaluate(`IV = AES(key, ${name})`, r => ecb(blocks(r)[i][1])));
  if (AB) {
    const abEcb = (blk) => {
      const c = crypto.createCipheriv('aes-256-ecb', AB, null);
      c.setAutoPadding(false);
      return Buffer.concat([c.update(blk), c.final()]);
    };
    results.push(evaluate(`IV = AES(A||B, ${name})`, r => abEcb(blocks(r)[i][1])));
  }
}

results.sort((a, b) => b.frac - a.frac);
console.log();
console.log('IV construction — fraction of frames sharing one residual (=P0):');
for (const r of results.slice(0, 12))
  console.log(`  ${(r.frac * 100).toFixed(1).padStart(5)}%  ${r.label.padEnd(26)}` +
              `  ${r.frac > 0.8 ? 'P0=' + r.resid : `(${r.distinct} distinct)`}`);

console.log();
const win = results[0];
if (win.frac > 0.8) {
  console.log(`✅ IV CONSTRUCTION: ${win.label}`);
  console.log(`   block-0 plaintext P0 = ${win.resid}`);
} else {
  console.log('⚠️  no construction gives a frame-invariant residual.');
  console.log('   Either the DMX state changed during capture, or the IV uses');
  console.log('   inputs not tested here. The residual counts above hint which.');
}
