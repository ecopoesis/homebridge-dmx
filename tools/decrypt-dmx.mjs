// End-to-end decrypt test: handshake pcap + ephemeral private `d`
//   →  KDF (P-256 double-ECDH)  →  AES-256 key
//   →  AES-256-CBC decrypt the session's UDP DMX frames
//   →  the 512 live DMX channel values.
//
// This wires the recovered KDF (derive-dmx-key.mjs) and the recovered cipher
// into one pipeline and proves it on a real captured session.
//
// VERIFIED: on handshake-20260521-203416.pcap + the Path D 20:34 rsi blob it
// derives key af90ce58… and decrypts that pcap's DMX at a 100% zero-ratio.
//
// Usage:
//   node tools/decrypt-dmx.mjs <pcap> <d>
//     <pcap>  a capture containing the TCP/2431 handshake + UDP DMX stream
//     <d>     the ephemeral private key — 64-hex-chars, or the path to an
//             lldb Path D rsi blob (d = blob[0x40:0x60], little-endian)

import fs from 'node:fs';
import crypto from 'node:crypto';
import { deriveDmxKey, wireToPoint, pointToWire } from './derive-dmx-key.mjs';

const [, , pcapPath, dArg] = process.argv;
if (!pcapPath || !dArg) {
  console.error('usage: node tools/decrypt-dmx.mjs <pcap> <d-hex | rsi-blob>');
  process.exit(1);
}

// ── load the ephemeral private d ─────────────────────────────────────────────
let dLE;
if (/^[0-9a-fA-F]{64}$/.test(dArg)) {
  dLE = Buffer.from(dArg, 'hex');                 // already little-endian limbs
} else {
  dLE = fs.readFileSync(dArg).subarray(0x40, 0x60); // rsi blob: local_48
}
const dBE = Buffer.from(dLE).reverse();           // node ECDH wants big-endian
const ecdh = crypto.createECDH('prime256v1');
ecdh.setPrivateKey(dBE);
const ourWire = pointToWire(ecdh.getPublicKey(null, 'uncompressed'));

const pcap = fs.readFileSync(pcapPath);

// ── stage 1: KDF — find the Stick pubkey Q in the handshake, derive the key ──
// Q is the 64-byte point in the opcode-0x0F response. Collect every 64-byte
// window that follows a "Stick_3A"+0x0F header and trial-derive: the correct Q
// is the one whose key decrypts DMX.
const MAGIC = Buffer.from('Stick_3A');

function dmxFrames(buf) {
  const out = [];
  for (let o = 0; o + 576 <= buf.length; o++) {
    if (buf.subarray(o, o + 8).equals(MAGIC) && buf[o + 8] === 0x19 && buf[o + 9] === 0x00) {
      out.push(buf.subarray(o, o + 576));
      o += 575;
    }
  }
  return out;
}

// AES-256-CBC decrypt one 576-byte frame -> 544-byte plaintext body
function decryptFrame(frame, key) {
  const hdr = frame.subarray(0, 32);
  const iv = Buffer.concat([hdr.subarray(0x0a, 0x12), hdr.subarray(0x18, 0x20)]);
  const dec = crypto.createDecipheriv('aes-256-cbc', key, iv);
  dec.setAutoPadding(false);
  return Buffer.concat([dec.update(frame.subarray(32, 576)), dec.final()]);
}
const zeroRatio = (dmx512) => {
  let z = 0;
  for (const b of dmx512) if (b === 0) z++;
  return z / dmx512.length;
};

const frames = dmxFrames(pcap);
if (frames.length === 0) { console.error('no 576-byte DMX frames in pcap'); process.exit(1); }

// candidate Q windows: 64 bytes after each "Stick_3A 0f 00" header (+0x12 req / +0x16 resp)
const candidates = [];
for (let o = 0; o + 0x56 <= pcap.length; o++) {
  if (pcap.subarray(o, o + 8).equals(MAGIC) && pcap[o + 8] === 0x0f && pcap[o + 9] === 0x00) {
    for (const off of [0x12, 0x16]) {
      const w = pcap.subarray(o + off, o + off + 64);
      if (w.length === 64 && !w.equals(ourWire)) candidates.push(Buffer.from(w));
    }
  }
}

let key = null, stickQ = null;
for (const cand of candidates) {
  let k;
  try { k = deriveDmxKey(ecdh, wireToPoint(cand)); } catch { continue; }
  if (zeroRatio(decryptFrame(frames[0], k).subarray(16, 528)) > 0.5) { key = k; stickQ = cand; break; }
}
if (!key) {
  console.error('KDF: no handshake pubkey in the pcap yields a decryptable key');
  process.exit(1);
}

console.log('Stick-DE3 — end-to-end DMX decrypt\n');
console.log(`  pcap            : ${pcapPath}`);
console.log(`  ephemeral d·G   : ${ourWire.subarray(0, 8).toString('hex')}… (our pubkey)`);
console.log(`  Stick pubkey Q  : ${stickQ.subarray(0, 8).toString('hex')}…`);
console.log(`  derived AES key : ${key.toString('hex')}`);
console.log(`  DMX frames      : ${frames.length}\n`);

// ── stage 2: decrypt the DMX stream ─────────────────────────────────────────
let bestIdx = 0, bestRatio = 0;
const p0set = new Set();
for (let i = 0; i < frames.length; i++) {
  const pt = decryptFrame(frames[i], key);
  p0set.add(pt.subarray(0, 16).toString('hex'));
  const r = zeroRatio(pt.subarray(16, 528));
  if (r > bestRatio) { bestRatio = r; bestIdx = i; }
}
console.log(`  best frame #${bestIdx}: ${(bestRatio * 100).toFixed(1)}% of 512 DMX channels are zero`);
console.log(`  internal header P0 distinct values across stream: ${p0set.size}`);

// show the lit channels of a representative frame (first with any non-zero)
let show = frames.findIndex((f) => zeroRatio(decryptFrame(f, key).subarray(16, 528)) < 1);
if (show < 0) show = 0;
const pt = decryptFrame(frames[show], key);
const dmx = pt.subarray(16, 528);
const lit = [];
for (let ch = 0; ch < 512; ch++) if (dmx[ch] !== 0) lit.push(`ch${ch + 1}=${dmx[ch]}`);
console.log(`\n  frame #${show} — P0=${pt.subarray(0, 16).toString('hex')}`);
console.log(`  lit DMX channels (${lit.length}): ${lit.slice(0, 40).join(' ')}${lit.length > 40 ? ' …' : ''}`);

const ok = bestRatio > 0.9;
console.log(`\n${ok ? '✅ KDF + cipher VERIFIED — real DMX recovered end-to-end'
                    : '❌ decryption did not yield plausible DMX'}`);
process.exit(ok ? 0 : 1);
