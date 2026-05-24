// Decrypt a captured 0x011c reply.
//
// Per FUN_1001bbca0 (Ghidra): the 240-byte ciphertext at reply[+0x2c] is
// AES-256-CBC encrypted; IV is reply[+0x1a:+0x2a]; expected plaintext
// length is 0x00ec (236 bytes -- last 4 of the 240B decrypt are slack/pad).
//
// We don't yet know the key. Try the two known candidates:
//   1. The static SEC1 P-256 point X-coord (32 bytes)
//   2. The XOR-deobfuscated 33-byte secret, first 32 bytes
//
//   node tools/decrypt-011c.mjs <pcap>

import fs from 'node:fs';
import crypto from 'node:crypto';

function ipFromEth(pkt) {
  if (pkt.length < 14) return null;
  let off = 12, eth = pkt.readUInt16BE(off);
  for (let i = 0; i < 2 && eth === 0x8100; i++) { off += 4; if (off + 2 > pkt.length) return null; eth = pkt.readUInt16BE(off); }
  return eth === 0x0800 ? pkt.subarray(off + 2) : null;
}
function reassemble(segs) {
  if (!segs.length) return Buffer.alloc(0);
  segs.sort((a, b) => (a.seq - b.seq + 0x100000000) % 0x100000000);
  const seen = new Set(); const out = [];
  const base = segs[0].seq;
  for (const s of segs) {
    const k = `${s.seq}:${s.payload.length}`; if (seen.has(k)) continue; seen.add(k);
    const off = (s.seq - base + 0x100000000) % 0x100000000;
    while (out.length < off + s.payload.length) out.push(0);
    for (let i = 0; i < s.payload.length; i++) out[off + i] = s.payload[i];
  }
  return Buffer.from(out);
}
function extractReplies(pcapPath) {
  const buf = fs.readFileSync(pcapPath);
  const le = buf.readUInt32LE(0) === 0xa1b2c3d4;
  const streams = new Map();
  let off = 24;
  while (off + 16 <= buf.length) {
    const capLen = le ? buf.readUInt32LE(off + 8) : buf.readUInt32BE(off + 8);
    off += 16; if (off + capLen > buf.length) break;
    const pkt = buf.subarray(off, off + capLen); off += capLen;
    const ip = ipFromEth(pkt); if (!ip || ip.length < 20 || ((ip[0] >> 4) & 0xf) !== 4) continue;
    const ihl = (ip[0] & 0x0f) * 4; if (ip[9] !== 6) continue;
    const tcp = ip.subarray(ihl);
    const sp = tcp.readUInt16BE(0); if (sp !== 2431) continue;
    const seq = tcp.readUInt32BE(4); const dataOff = (tcp[12] >> 4) * 4;
    const payload = tcp.subarray(dataOff); if (!payload.length) continue;
    const src = `${ip[12]}.${ip[13]}.${ip[14]}.${ip[15]}:${sp}`;
    const dst = `${ip[16]}.${ip[17]}.${ip[18]}.${ip[19]}:${tcp.readUInt16BE(2)}`;
    const k = [src, dst].sort().join('<->');
    if (!streams.has(k)) streams.set(k, []);
    streams.get(k).push({ seq, payload });
  }
  const replies = [];
  for (const [k, segs] of streams) {
    const r = reassemble(segs);
    for (let i = 0; i + 24 <= r.length; i++) {
      const m = r.subarray(i, i + 8).toString();
      if (m !== 'Stick_3A' && m !== 'LSAG_ALL') continue;
      if (r.readUInt16LE(i + 8) !== 0x011c) continue;
      const len = r.readUInt32LE(i + 0x14);
      if (len < 0x18 || len > 0x400 || i + len > r.length) continue;
      const msg = r.subarray(i, i + len);
      if (msg.length !== 284) continue;
      replies.push({ pcap: pcapPath, stream: k, msg });
    }
  }
  return replies;
}

// Candidate AES-256 keys.
const KEYS = [
  ['static SEC1 X (P-256 point)', '28081290396d063e5114526ed978b926558f6ba1c96ad2facf76fffb3ffea0fe'],
  ['XOR-deobfuscated (first 32)', '527a5b46c56f3a5e670b4f0e338727d94737ec0fc4af0dba93a51d93965191d0'],
  // also reversed-endian variants just in case
  ['static SEC1 X reversed',     '28081290396d063e5114526ed978b926558f6ba1c96ad2facf76fffb3ffea0fe'.match(/../g).reverse().join('')],
  ['XOR-deobf reversed',         '527a5b46c56f3a5e670b4f0e338727d94737ec0fc4af0dba93a51d93965191d0'.match(/../g).reverse().join('')],
];

function tryDecrypt(label, keyHex, iv, ct) {
  try {
    const key = Buffer.from(keyHex, 'hex');
    if (key.length !== 32) return null;
    const d = crypto.createDecipheriv('aes-256-cbc', key, iv);
    d.setAutoPadding(false);
    const pt = Buffer.concat([d.update(ct), d.final()]);
    // score: how printable / structured?
    let printable = 0, zero = 0;
    for (const b of pt) {
      if (b === 0) zero++;
      else if (b >= 0x20 && b < 0x7f) printable++;
    }
    return { label, keyHex, pt, printable, zero, total: pt.length };
  } catch (e) {
    return { label, keyHex, err: e.message };
  }
}

const pcaps = process.argv.slice(2);
if (!pcaps.length) { console.error('usage: node tools/decrypt-011c.mjs <pcap> [<pcap>...]'); process.exit(1); }

for (const p of pcaps) {
  const reps = extractReplies(p);
  console.log(`\n=== ${p}: ${reps.length} 0x011c replies ===`);
  for (const r of reps) {
    const tok = r.msg.readUInt32LE(0x0a);
    const iv = r.msg.subarray(0x1a, 0x2a);
    const ct = r.msg.subarray(0x2c, 0x2c + 240);
    console.log(`\n  token=${tok}  IV=${iv.toString('hex')}`);
    for (const [label, keyHex] of KEYS) {
      const res = tryDecrypt(label, keyHex, iv, ct);
      if (!res) continue;
      if (res.err) { console.log(`    ${label.padEnd(28)} ERR ${res.err}`); continue; }
      console.log(`    ${label.padEnd(28)} printable=${res.printable.toString().padStart(3)}/${res.total}  zero=${res.zero.toString().padStart(3)}  first16=${res.pt.subarray(0,16).toString('hex')}`);
      if (res.printable > 40 || res.zero > 20) {
        console.log(`      preview: ${res.pt.subarray(0, 64).toString('hex')}`);
        console.log(`      ascii  : ${res.pt.subarray(0, 96).toString('binary').replace(/[^\x20-\x7e]/g, '.')}`);
      }
    }
  }
}
