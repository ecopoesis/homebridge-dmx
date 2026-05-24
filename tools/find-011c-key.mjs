// Brute-force search for the AES-256 key that decrypts the 0x011c reply.
//
// We have constraints on the plaintext:
//   - 240 bytes = 15 AES-CBC blocks decrypts to 236-byte useful body + 4 padding
//   - Padding is either PKCS#7 (`04 04 04 04`) or zero-fill (`00 00 00 00`)
//   - Per HWM (FUN_1001676a0), plaintext has a self-consistency check:
//     plaintext[0..4] == ~plaintext[0x64..0x68] (bitwise-complement)
//
// Strategy: walk every 32-byte aligned offset of the HardwareManager binary
// and try that 32 bytes as an AES-256 key against a captured (IV, ciphertext).
// Pre-filter by padding tail; secondary-filter by the complement check.
//
//   node tools/find-011c-key.mjs <pcap> <hwm-binary>

import fs from 'node:fs';
import crypto from 'node:crypto';

const [, , pcapPath, hwmPath] = process.argv;
if (!pcapPath || !hwmPath) {
  console.error('usage: node tools/find-011c-key.mjs <pcap> <hwm-binary>');
  process.exit(1);
}

// --- extract one 0x011c reply ---------------------------------------------
function extractFirstReply(pcap) {
  const buf = fs.readFileSync(pcap);
  const le = buf.readUInt32LE(0) === 0xa1b2c3d4;
  function ipFromEth(p) {
    if (p.length < 14) return null;
    let o = 12, e = p.readUInt16BE(o);
    for (let i = 0; i < 2 && e === 0x8100; i++) { o += 4; if (o+2>p.length) return null; e = p.readUInt16BE(o); }
    return e === 0x0800 ? p.subarray(o + 2) : null;
  }
  const streams = new Map();
  let off = 24;
  while (off + 16 <= buf.length) {
    const capLen = le ? buf.readUInt32LE(off + 8) : buf.readUInt32BE(off + 8);
    off += 16; if (off + capLen > buf.length) break;
    const pkt = buf.subarray(off, off + capLen); off += capLen;
    const ip = ipFromEth(pkt); if (!ip || ip.length < 20 || ((ip[0]>>4)&0xf)!==4) continue;
    const ihl = (ip[0]&0x0f)*4; if (ip[9]!==6) continue;
    const tcp = ip.subarray(ihl);
    if (tcp.readUInt16BE(0) !== 2431) continue;
    const seq = tcp.readUInt32BE(4);
    const dataOff = (tcp[12]>>4)*4;
    const payload = tcp.subarray(dataOff);
    if (!payload.length) continue;
    const key = `${ip[12]}.${ip[13]}.${ip[14]}.${ip[15]}:${tcp.readUInt16BE(0)}->${ip[16]}.${ip[17]}.${ip[18]}.${ip[19]}:${tcp.readUInt16BE(2)}`;
    if (!streams.has(key)) streams.set(key, []);
    streams.get(key).push({ seq, payload });
  }
  for (const segs of streams.values()) {
    segs.sort((a,b)=>(a.seq-b.seq+0x100000000)%0x100000000);
    const seen = new Set(); const out = [];
    const base = segs[0].seq;
    for (const s of segs) {
      const k = `${s.seq}:${s.payload.length}`; if (seen.has(k)) continue; seen.add(k);
      const o = (s.seq-base+0x100000000)%0x100000000;
      while (out.length < o + s.payload.length) out.push(0);
      for (let i = 0; i < s.payload.length; i++) out[o+i] = s.payload[i];
    }
    const r = Buffer.from(out);
    for (let i = 0; i + 24 <= r.length; i++) {
      if (r.subarray(i,i+8).toString() !== 'Stick_3A') continue;
      if (r.readUInt16LE(i+8) !== 0x011c) continue;
      const len = r.readUInt32LE(i+0x14);
      if (len !== 284) continue;
      const msg = r.subarray(i, i + 284);
      return { iv: Buffer.from(msg.subarray(0x1a, 0x2a)), ct: Buffer.from(msg.subarray(0x2c, 0x2c + 240)) };
    }
  }
  return null;
}

const reply = extractFirstReply(pcapPath);
if (!reply) { console.error('no 0x011c reply in', pcapPath); process.exit(2); }
console.log(`reply: IV=${reply.iv.toString('hex')}`);
console.log(`ct[0:32]=${reply.ct.subarray(0,32).toString('hex')}`);

// --- candidate key generator ----------------------------------------------
const bin = fs.readFileSync(hwmPath);
console.log(`binary: ${hwmPath}  ${bin.length} bytes`);

// Try every 32-byte aligned offset.  Also try byte-aligned (stride 1) for the
// last-pass.  Reject keys that are obviously not credible (all zero, all FF).
function isBoring(k) {
  let z = 0, ff = 0, distinct = new Set();
  for (const b of k) { if (b===0) z++; if (b===0xff) ff++; distinct.add(b); }
  if (z > 20 || ff > 20) return true;
  if (distinct.size < 6) return true;
  return false;
}

// Decrypt one block trial: returns Buffer or null on AES error
function dec(keyBuf, iv, ct) {
  try {
    const d = crypto.createDecipheriv('aes-256-cbc', keyBuf, iv);
    d.setAutoPadding(false);
    return Buffer.concat([d.update(ct), d.final()]);
  } catch { return null; }
}

// Validation:
//  1. last 4 bytes of plaintext must be 04 04 04 04  OR  00 00 00 00
//  2. plaintext[0..4]  XOR  plaintext[0x64..0x68]  ==  0xff,0xff,0xff,0xff
function isValid(pt) {
  if (!pt) return null;
  const t0 = pt[236], t1 = pt[237], t2 = pt[238], t3 = pt[239];
  const isPkcs7 = t0===4 && t1===4 && t2===4 && t3===4;
  const isZero  = t0===0 && t1===0 && t2===0 && t3===0;
  if (!isPkcs7 && !isZero) return null;
  // self-consistency check
  let comp = true;
  for (let i = 0; i < 4; i++) {
    if (((pt[i] ^ pt[0x64+i]) & 0xff) !== 0xff) { comp = false; break; }
  }
  return { padKind: isPkcs7 ? 'pkcs7' : 'zero', comp };
}

console.log('\n=== pass 1: 32-byte aligned candidates ===');
let tested = 0, hits = 0;
for (let i = 0; i + 32 <= bin.length; i += 8) {       // 8-byte alignment is reasonable
  const k = bin.subarray(i, i + 32);
  if (isBoring(k)) continue;
  const pt = dec(k, reply.iv, reply.ct);
  tested++;
  const v = isValid(pt);
  if (v) {
    hits++;
    console.log(`  HIT @ 0x${i.toString(16)}  pad=${v.padKind}  comp=${v.comp}`);
    console.log(`     key = ${k.toString('hex')}`);
    console.log(`     pt[0..32]   = ${pt.subarray(0,32).toString('hex')}`);
    console.log(`     pt[0x60..]  = ${pt.subarray(0x60,0x80).toString('hex')}`);
    if (v.comp) console.log(`     *** complement check PASSED -- almost certainly the key ***`);
  }
  if (tested % 500000 === 0) {
    console.log(`  ... tested ${tested}, hits=${hits}`);
  }
}
console.log(`done: tested=${tested}  hits=${hits}`);
