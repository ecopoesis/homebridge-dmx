// TCP stream reassembler for the Stick-DE3 TCP/2431 control channel.
//
// Pulls ALL payload bytes from both directions, in order, and prints them
// as labelled message frames. The Stick's protocol has a clean "magic +
// opcode" header on each application message, so we can chunk by parsing
// the magic alone.
//
// Output: one block per application message:
//   [time] DIR len=N  magic+opcode header  + full hex dump

import fs from 'node:fs';

const [, , pcapPath] = process.argv;
if (!pcapPath) { console.error('usage: node dump-tcp-stream.mjs <file.pcap>'); process.exit(1); }

const STICK_IP   = process.env.STICK_IP   || '192.168.96.2';
const STICK_PORT = Number(process.env.STICK_PORT || 2431);

const buf = fs.readFileSync(pcapPath);
const magic = buf.readUInt32LE(0);
const le = magic === 0xa1b2c3d4 ? true : magic === 0xd4c3b2a1 ? false : null;
if (le === null) { console.error('not a pcap'); process.exit(2); }
const linkType = le ? buf.readUInt32LE(20) : buf.readUInt32BE(20);
const ethSkip = linkType === 1 ? 14 : 4;

// Gather all TCP payload chunks in order with direction + timestamp.
const chunks = [];
let off = 24;
while (off + 16 <= buf.length) {
  const tsSec  = le ? buf.readUInt32LE(off)     : buf.readUInt32BE(off);
  const tsUsec = le ? buf.readUInt32LE(off + 4) : buf.readUInt32BE(off + 4);
  const capLen = le ? buf.readUInt32LE(off + 8) : buf.readUInt32BE(off + 8);
  off += 16;
  if (off + capLen > buf.length) break;
  const pkt = buf.subarray(off, off + capLen);
  off += capLen;
  if (pkt.length < ethSkip + 20) continue;
  const ip = pkt.subarray(ethSkip);
  if (((ip[0] >> 4) & 0xf) !== 4) continue;
  const ihl = (ip[0] & 0x0f) * 4;
  const proto = ip[9];
  if (proto !== 6) continue;
  const srcIp = `${ip[12]}.${ip[13]}.${ip[14]}.${ip[15]}`;
  const dstIp = `${ip[16]}.${ip[17]}.${ip[18]}.${ip[19]}`;
  const tcp = ip.subarray(ihl);
  if (tcp.length < 20) continue;
  const sp = tcp.readUInt16BE(0), dp = tcp.readUInt16BE(2);
  const dataOff = (tcp[12] >> 4) * 4;
  const payload = tcp.subarray(dataOff);
  if (payload.length === 0) continue;
  if (!((srcIp === STICK_IP && sp === STICK_PORT) || (dstIp === STICK_IP && dp === STICK_PORT))) continue;
  const dir = (srcIp === STICK_IP) ? 'S→C' : 'C→S';
  chunks.push({ ts: `${tsSec}.${String(tsUsec).padStart(6,'0')}`, dir, payload });
}

// Re-chunk by application message: each message starts with 8-byte magic
// "LSAG_ALL" or "Stick_3A". Concatenate contiguous same-direction chunks,
// then split by magic occurrences.
function chunkByMagic(data) {
  const out = [];
  let i = 0;
  while (i < data.length) {
    // Find next magic at i (must be at start of message)
    const m1 = data.indexOf(Buffer.from('LSAG_ALL'), i);
    const m2 = data.indexOf(Buffer.from('Stick_3A'), i);
    const next = (m1 === -1) ? m2 : (m2 === -1) ? m1 : Math.min(m1, m2);
    if (next === -1) { out.push(data.subarray(i)); break; }
    if (next > i) out.push(data.subarray(i, next));
    // Find end = next magic after `next`
    const a = data.indexOf(Buffer.from('LSAG_ALL'), next + 8);
    const b = data.indexOf(Buffer.from('Stick_3A'), next + 8);
    const end = (a === -1) ? b : (b === -1) ? a : Math.min(a, b);
    if (end === -1) { out.push(data.subarray(next)); break; }
    out.push(data.subarray(next, end));
    i = end;
  }
  return out;
}

// Run the dir state machine
let stream = { 'C→S': Buffer.alloc(0), 'S→C': Buffer.alloc(0) };
let msgCount = 0;
for (const c of chunks) {
  stream[c.dir] = Buffer.concat([stream[c.dir], c.payload]);
  // Try to consume complete messages from this direction
  const msgs = chunkByMagic(stream[c.dir]);
  if (msgs.length > 1) {
    for (let i = 0; i < msgs.length - 1; i++) {
      msgCount++;
      const m = msgs[i];
      const magic = m.length >= 8 ? m.subarray(0, 8).toString('latin1') : '???';
      const opcode = m.length >= 10 ? m.readUInt16LE(8).toString(16).padStart(4,'0') : '?';
      console.log(`[${c.ts}] msg#${msgCount} ${c.dir} ${m.length}B  magic="${magic}" opcode=0x${opcode}`);
      // Full hex dump in rows of 16
      for (let off = 0; off < m.length; off += 16) {
        const row = m.subarray(off, off + 16);
        const hex = Array.from(row).map(b => b.toString(16).padStart(2, '0')).join(' ');
        const ascii = Array.from(row).map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('');
        console.log(`    ${off.toString(16).padStart(4,'0')}: ${hex.padEnd(48)}  |${ascii}|`);
      }
      console.log();
    }
    stream[c.dir] = msgs[msgs.length - 1];
  }
}
// Flush any leftover partial messages
for (const dir of ['C→S', 'S→C']) {
  if (stream[dir].length) {
    msgCount++;
    const m = stream[dir];
    const magic = m.length >= 8 ? m.subarray(0, 8).toString('latin1') : '???';
    const opcode = m.length >= 10 ? m.readUInt16LE(8).toString(16).padStart(4,'0') : '?';
    console.log(`[flush] msg#${msgCount} ${dir} ${m.length}B  magic="${magic}" opcode=0x${opcode}`);
    for (let off = 0; off < m.length; off += 16) {
      const row = m.subarray(off, off + 16);
      const hex = Array.from(row).map(b => b.toString(16).padStart(2, '0')).join(' ');
      const ascii = Array.from(row).map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('');
      console.log(`    ${off.toString(16).padStart(4,'0')}: ${hex.padEnd(48)}  |${ascii}|`);
    }
    console.log();
  }
}
console.log(`# total messages: ${msgCount}`);
