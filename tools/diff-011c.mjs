// Byte-by-byte diff of every 0x011c S->C reply across one or more pcaps.
// Identifies which byte positions are constant across sessions vs which
// vary -- so we know exactly which bytes inside that 258-byte payload
// HWM might be reading as session-state vs structure.
//
//   node tools/diff-011c.mjs <pcap> [<pcap>...]

import fs from 'node:fs';

function ipFromEth(pkt) {
  if (pkt.length < 14) return null;
  let off = 12;
  let eth = pkt.readUInt16BE(off);
  for (let i = 0; i < 2 && eth === 0x8100; i++) {
    off += 4; if (off + 2 > pkt.length) return null;
    eth = pkt.readUInt16BE(off);
  }
  if (eth !== 0x0800) return null;
  return pkt.subarray(off + 2);
}

function reassemble(segs) {
  if (!segs.length) return Buffer.alloc(0);
  segs.sort((a, b) => (a.seq - b.seq + 0x100000000) % 0x100000000);
  const seen = new Set();
  let base = segs[0].seq;
  const out = [];
  for (const s of segs) {
    const k = `${s.seq}:${s.payload.length}`;
    if (seen.has(k)) continue;
    seen.add(k);
    const off = (s.seq - base + 0x100000000) % 0x100000000;
    while (out.length < off + s.payload.length) out.push(0);
    for (let i = 0; i < s.payload.length; i++) out[off + i] = s.payload[i];
  }
  return Buffer.from(out);
}

function extractReplies(pcapPath) {
  const buf = fs.readFileSync(pcapPath);
  const magic = buf.readUInt32LE(0);
  const le = magic === 0xa1b2c3d4;
  if (!le && magic !== 0xd4c3b2a1) return [];
  const streams = new Map();
  let off = 24;
  while (off + 16 <= buf.length) {
    const capLen = le ? buf.readUInt32LE(off + 8) : buf.readUInt32BE(off + 8);
    off += 16;
    if (off + capLen > buf.length) break;
    const pkt = buf.subarray(off, off + capLen); off += capLen;
    const ip = ipFromEth(pkt);
    if (!ip || ip.length < 20 || ((ip[0] >> 4) & 0xf) !== 4) continue;
    const ihl = (ip[0] & 0x0f) * 4;
    if (ip[9] !== 6) continue;
    const tcp = ip.subarray(ihl);
    const sp = tcp.readUInt16BE(0), dp = tcp.readUInt16BE(2);
    if (sp !== 2431) continue;                         // S->C only
    const seq = tcp.readUInt32BE(4);
    const dataOff = (tcp[12] >> 4) * 4;
    const payload = tcp.subarray(dataOff);
    if (!payload.length) continue;
    const src = `${ip[12]}.${ip[13]}.${ip[14]}.${ip[15]}:${sp}`;
    const dst = `${ip[16]}.${ip[17]}.${ip[18]}.${ip[19]}:${dp}`;
    const k = [src, dst].sort().join('<->');
    if (!streams.has(k)) streams.set(k, []);
    streams.get(k).push({ seq, payload });
  }
  const replies = [];
  for (const [k, segs] of streams) {
    const reassembled = reassemble(segs);
    for (let i = 0; i + 10 <= reassembled.length; i++) {
      const m = reassembled.subarray(i, i + 8).toString();
      if (m !== 'Stick_3A' && m !== 'LSAG_ALL') continue;
      if (reassembled.readUInt16LE(i + 8) !== 0x011c) continue;
      // length-prefix at +0x14
      if (i + 0x18 > reassembled.length) continue;
      const len = reassembled.readUInt32LE(i + 0x14);
      if (len < 0x18 || len > 0x400 || i + len > reassembled.length) continue;
      replies.push({ pcap: pcapPath, stream: k, msg: reassembled.subarray(i, i + len) });
    }
  }
  return replies;
}

const all = [];
for (const pcap of process.argv.slice(2)) {
  const reps = extractReplies(pcap);
  console.log(`${pcap}: ${reps.length} 0x011c replies`);
  all.push(...reps);
}
if (all.length < 2) { console.error('need >= 2 replies to diff'); process.exit(1); }

const L = Math.min(...all.map((r) => r.msg.length));
console.log(`\nshortest = ${L}B; diffing ${all.length} replies position-by-position\n`);

// Constant vs variable map.
const ranges = [];   // [{start,end,kind: 'const'|'var', vals?}]
let cur = null;
for (let i = 0; i < L; i++) {
  const vals = new Set(all.map((r) => r.msg[i]));
  const kind = vals.size === 1 ? 'const' : 'var';
  if (!cur || cur.kind !== kind) {
    if (cur) ranges.push(cur);
    cur = { start: i, end: i, kind, vals };
  } else {
    cur.end = i;
    if (kind === 'const') cur.vals = vals;
  }
}
if (cur) ranges.push(cur);

console.log('=== regions ===');
for (const r of ranges) {
  if (r.kind === 'const') {
    const v = all[0].msg.subarray(r.start, r.end + 1).toString('hex');
    console.log(`  +0x${r.start.toString(16).padStart(3,'0')}..+0x${r.end.toString(16).padStart(3,'0')}  (${r.end-r.start+1}B)  CONST = ${v}`);
  } else {
    console.log(`  +0x${r.start.toString(16).padStart(3,'0')}..+0x${r.end.toString(16).padStart(3,'0')}  (${r.end-r.start+1}B)  variable`);
  }
}

// Side-by-side first 64 bytes of payload (after the 0x1c header).
console.log('\n=== first 64B of payload (offset 0x1c..0x5c) per session ===');
for (const r of all) {
  const tag = r.pcap.split('/').pop() + ' tok=' + r.msg.readUInt32LE(0x0a);
  console.log(`  ${tag.padEnd(34)} ${r.msg.subarray(0x1c, 0x5c).toString('hex')}`);
}
