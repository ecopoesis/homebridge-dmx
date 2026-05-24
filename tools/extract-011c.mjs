// Extract every TCP/2431 message with opcode 0x011c from a pcap.
//
// Both directions: client->Stick (request body, if any) and Stick->client
// (the 263-byte session-unique reply blob we don't decode). Strips 802.1Q
// tags so it works on the UniFi-mirror pcaps as well as laptop captures.
//
//   node tools/extract-011c.mjs <file.pcap>

import fs from 'node:fs';

const [, , pcapPath] = process.argv;
if (!pcapPath) { console.error('usage: node tools/extract-011c.mjs <file.pcap>'); process.exit(1); }

const buf = fs.readFileSync(pcapPath);
const magic = buf.readUInt32LE(0);
const le = magic === 0xa1b2c3d4;
if (!le && magic !== 0xd4c3b2a1) { console.error('bad pcap'); process.exit(2); }

// IP-level walker that handles 802.1Q-tagged frames too.
function ipFromEth(pkt) {
  if (pkt.length < 14) return null;
  let off = 12;
  let eth = pkt.readUInt16BE(off);
  // walk up to 2 VLAN tags
  for (let i = 0; i < 2 && eth === 0x8100; i++) {
    off += 4;
    if (off + 2 > pkt.length) return null;
    eth = pkt.readUInt16BE(off);
  }
  if (eth !== 0x0800) return null;
  return pkt.subarray(off + 2);
}

// Reassemble per-connection TCP streams so an 0x011c reply that spans
// segments still surfaces as one message.
const streams = new Map();   // key -> { c2s: {seq0,buf}, s2c: {seq0,buf} }

let off = 24;
while (off + 16 <= buf.length) {
  const capLen = le ? buf.readUInt32LE(off + 8) : buf.readUInt32BE(off + 8);
  const tsSec = le ? buf.readUInt32LE(off) : buf.readUInt32BE(off);
  const tsUsec = le ? buf.readUInt32LE(off + 4) : buf.readUInt32BE(off + 4);
  off += 16;
  if (off + capLen > buf.length) break;
  const pkt = buf.subarray(off, off + capLen);
  off += capLen;
  const ip = ipFromEth(pkt);
  if (!ip || ip.length < 20) continue;
  if (((ip[0] >> 4) & 0xf) !== 4) continue;
  const ihl = (ip[0] & 0x0f) * 4;
  if (ip[9] !== 6) continue;       // TCP only
  const tcp = ip.subarray(ihl);
  const sp = tcp.readUInt16BE(0), dp = tcp.readUInt16BE(2);
  if (sp !== 2431 && dp !== 2431) continue;
  const seq = tcp.readUInt32BE(4);
  const dataOff = (tcp[12] >> 4) * 4;
  const payload = tcp.subarray(dataOff);
  if (payload.length === 0) continue;
  const src = `${ip[12]}.${ip[13]}.${ip[14]}.${ip[15]}:${sp}`;
  const dst = `${ip[16]}.${ip[17]}.${ip[18]}.${ip[19]}:${dp}`;
  const cs = [src, dst].sort().join(' <-> ');
  if (!streams.has(cs)) streams.set(cs, { c2s: [], s2c: [], t0: tsSec + tsUsec / 1e6 });
  const dir = sp === 2431 ? 's2c' : 'c2s';
  streams.get(cs)[dir].push({ seq, payload, t: tsSec + tsUsec / 1e6 });
}

function reassemble(segments) {
  if (!segments.length) return Buffer.alloc(0);
  segments.sort((a, b) => (a.seq - b.seq + 0x100000000) % 0x100000000);
  // De-dup retransmits (same seq, same length).
  const seen = new Set();
  const parts = [];
  let base = segments[0].seq;
  let cursor = base;
  for (const s of segments) {
    const k = `${s.seq}:${s.payload.length}`;
    if (seen.has(k)) continue;
    seen.add(k);
    const off = (s.seq - base + 0x100000000) % 0x100000000;
    while (parts.length < off + s.payload.length) parts.push(0);
    for (let i = 0; i < s.payload.length; i++) parts[off + i] = s.payload[i];
  }
  return Buffer.from(parts);
}

// Walk a reassembled stream looking for messages by the 8-byte magic
// (Stick_3A or LSAG_ALL) followed by 2-byte LE opcode == 0x011c.
function scan(direction, key, segs) {
  const buf = reassemble(segs);
  for (let i = 0; i + 10 <= buf.length; i++) {
    const m = buf.subarray(i, i + 8).toString();
    if (m !== 'Stick_3A' && m !== 'LSAG_ALL') continue;
    const op = buf.readUInt16LE(i + 8);
    if (op !== 0x011c) continue;
    // We don't know the length-prefix scheme universally, but we can
    // print everything from this magic to the next magic (or end).
    let j = i + 10;
    while (j + 8 <= buf.length) {
      const mm = buf.subarray(j, j + 8).toString();
      if (mm === 'Stick_3A' || mm === 'LSAG_ALL') break;
      j++;
    }
    const msg = buf.subarray(i, j);
    console.log(`\n--- ${key}  ${direction}  opcode=0x011c  len=${msg.length}B ---`);
    console.log(`magic=${m}  token=${buf.readUInt32LE(i + 10)}  bytes:`);
    for (let k = 0; k < msg.length; k += 32) {
      const row = msg.subarray(k, Math.min(k + 32, msg.length));
      console.log(`  ${k.toString().padStart(4)} : ${row.toString('hex')}`);
    }
  }
}

console.log(`pcap ${pcapPath}: ${streams.size} TCP/2431 stream(s)`);
for (const [k, s] of streams) {
  scan('S->C', k, s.s2c);
  scan('C->S', k, s.c2s);
}
