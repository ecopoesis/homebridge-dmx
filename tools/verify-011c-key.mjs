// Verify the recovered AES-256 key by decrypting every 0x011c reply across
// multiple pcaps + locate the key's address in the HardwareManager binary.
//
//   node tools/verify-011c-key.mjs

import fs from 'node:fs';
import crypto from 'node:crypto';

const KEY = Buffer.from('ea079afbbdd859719322e3f6e3c670223da627f9b6146e4ba6eb0f4a18739205', 'hex');
const HWM = '/Applications/ESA2/HardwareManager/HardwareManager.app/Contents/MacOS/HardwareManager';
const PCAPS = ['/tmp/hwm-A.pcap', '/tmp/hwm-B.pcap', '/tmp/sd-xhl.pcap'];

function ipFromEth(p){if(p.length<14)return null;let o=12,e=p.readUInt16BE(o);for(let i=0;i<2&&e===0x8100;i++){o+=4;if(o+2>p.length)return null;e=p.readUInt16BE(o);}return e===0x0800?p.subarray(o+2):null;}

function extractReplies(pcap) {
  const buf = fs.readFileSync(pcap);
  const le = buf.readUInt32LE(0) === 0xa1b2c3d4;
  const streams = new Map();
  let off = 24;
  while (off + 16 <= buf.length) {
    const capLen = le ? buf.readUInt32LE(off+8) : buf.readUInt32BE(off+8);
    off += 16; if (off + capLen > buf.length) break;
    const pkt = buf.subarray(off, off+capLen); off += capLen;
    const ip = ipFromEth(pkt); if (!ip || ip.length<20 || ((ip[0]>>4)&0xf)!==4) continue;
    const ihl = (ip[0]&0xf)*4; if (ip[9]!==6) continue;
    const tcp = ip.subarray(ihl);
    if (tcp.readUInt16BE(0) !== 2431) continue;
    const seq = tcp.readUInt32BE(4); const dataOff = (tcp[12]>>4)*4;
    const payload = tcp.subarray(dataOff); if (!payload.length) continue;
    const k = `${ip[12]}.${ip[13]}.${ip[14]}.${ip[15]}<->${ip[16]}.${ip[17]}.${ip[18]}.${ip[19]}`;
    if (!streams.has(k)) streams.set(k, []);
    streams.get(k).push({ seq, payload });
  }
  const out = [];
  for (const [k, segs] of streams) {
    segs.sort((a,b)=>(a.seq-b.seq+0x100000000)%0x100000000);
    const seen = new Set(); const arr = [];
    const base = segs[0].seq;
    for (const s of segs) {
      const kk = `${s.seq}:${s.payload.length}`; if (seen.has(kk)) continue; seen.add(kk);
      const o = (s.seq - base + 0x100000000) % 0x100000000;
      while (arr.length < o + s.payload.length) arr.push(0);
      for (let i = 0; i < s.payload.length; i++) arr[o+i] = s.payload[i];
    }
    const r = Buffer.from(arr);
    for (let i = 0; i + 24 <= r.length; i++) {
      if (r.subarray(i,i+8).toString() !== 'Stick_3A') continue;
      if (r.readUInt16LE(i+8) !== 0x011c) continue;
      if (r.readUInt32LE(i+0x14) !== 284) continue;
      const msg = r.subarray(i, i+284);
      out.push({ pcap, stream: k, token: msg.readUInt32LE(0x0a),
                 iv: msg.subarray(0x1a, 0x2a),
                 ct: msg.subarray(0x2c, 0x2c+240) });
    }
  }
  return out;
}

function dec(iv, ct) {
  const d = crypto.createDecipheriv('aes-256-cbc', KEY, iv);
  d.setAutoPadding(false);
  return Buffer.concat([d.update(ct), d.final()]);
}

console.log('=== verify key against captured replies ===\n');
let constMap = null;
const allPlaintexts = [];
for (const p of PCAPS) {
  for (const r of extractReplies(p)) {
    const pt = dec(r.iv, r.ct);
    allPlaintexts.push(pt);
    console.log(`${p}  stream ${r.stream}  token=${r.token}`);
    console.log(`  pt[  0:32 ] = ${pt.subarray(0,32).toString('hex')}`);
    console.log(`  pt[ 32:64 ] = ${pt.subarray(32,64).toString('hex')}`);
    console.log(`  pt[ 64:96 ] = ${pt.subarray(64,96).toString('hex')}`);
    console.log(`  pt[ 96:128] = ${pt.subarray(96,128).toString('hex')}`);
    console.log(`  pt[128:160] = ${pt.subarray(128,160).toString('hex')}`);
    console.log(`  pt[160:192] = ${pt.subarray(160,192).toString('hex')}`);
    console.log(`  pt[192:224] = ${pt.subarray(192,224).toString('hex')}`);
    console.log(`  pt[224:240] = ${pt.subarray(224,240).toString('hex')}`);
    console.log(`  ascii      : ${pt.toString('binary').replace(/[^\x20-\x7e]/g,'.').slice(0,160)}`);
    // self-consistency check
    let comp = 0;
    for (let i = 0; i < 4; i++) if (((pt[i] ^ pt[0x64+i]) & 0xff) === 0xff) comp++;
    console.log(`  complement-check pt[0..4] vs ~pt[0x64..0x68] : ${comp}/4 bytes`);
    console.log();
  }
}

// Constant-byte map across all plaintexts
if (allPlaintexts.length >= 2) {
  console.log('=== byte-by-byte CONST/VAR map across all decrypted replies ===');
  const ranges = []; let cur = null;
  for (let i = 0; i < 240; i++) {
    const vals = new Set(allPlaintexts.map(p => p[i]));
    const kind = vals.size === 1 ? 'const' : 'var';
    if (!cur || cur.kind !== kind) { if (cur) ranges.push(cur); cur = { start: i, end: i, kind }; }
    else cur.end = i;
  }
  if (cur) ranges.push(cur);
  for (const r of ranges) {
    const slice = allPlaintexts[0].subarray(r.start, r.end+1).toString('hex');
    console.log(`  +0x${r.start.toString(16).padStart(3,'0')}..+0x${r.end.toString(16).padStart(3,'0')}  (${(r.end-r.start+1).toString().padStart(3)}B)  ${r.kind}${r.kind==='const'?'  = '+slice:''}`);
  }
}

// Find the key in the binary
console.log('\n=== locate key in HardwareManager binary ===');
const bin = fs.readFileSync(HWM);
let off = 0, hits = [];
while (true) {
  const idx = bin.indexOf(KEY, off);
  if (idx === -1) break;
  hits.push(idx);
  off = idx + 1;
}
for (const h of hits) {
  const vmaddr = h + 0x100000000;       // assume the standard Mach-O 64-bit base
  console.log(`  file 0x${h.toString(16)}  (vmaddr ≈ 0x${vmaddr.toString(16)})`);
}
if (!hits.length) console.log('  NOT found in binary -- might be assembled at runtime');
