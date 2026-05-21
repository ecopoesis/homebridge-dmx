// Quick summary of every packet in a pcap, with TCP/UDP demux and payload preview.

import fs from 'node:fs';

const [, , pcapPath] = process.argv;
if (!pcapPath) { console.error('usage: node dump-pcap-summary.mjs <file.pcap>'); process.exit(1); }

const buf = fs.readFileSync(pcapPath);
const magic = buf.readUInt32LE(0);
const le = magic === 0xa1b2c3d4 ? true : magic === 0xd4c3b2a1 ? false : null;
if (le === null) { console.error('not a pcap'); process.exit(2); }
const linkType = le ? buf.readUInt32LE(20) : buf.readUInt32BE(20);
const ethSkip = linkType === 1 ? 14 : 4;

let off = 24, idx = 0;
while (off + 16 <= buf.length) {
  const tsSec  = le ? buf.readUInt32LE(off)     : buf.readUInt32BE(off);
  const tsUsec = le ? buf.readUInt32LE(off + 4) : buf.readUInt32BE(off + 4);
  const capLen = le ? buf.readUInt32LE(off + 8) : buf.readUInt32BE(off + 8);
  off += 16;
  if (off + capLen > buf.length) break;
  const pkt = buf.subarray(off, off + capLen);
  off += capLen;
  idx++;

  if (pkt.length < ethSkip + 20) continue;
  const ip = pkt.subarray(ethSkip);
  if (((ip[0] >> 4) & 0xf) !== 4) continue;
  const ihl = (ip[0] & 0x0f) * 4;
  const proto = ip[9];
  const srcIp = `${ip[12]}.${ip[13]}.${ip[14]}.${ip[15]}`;
  const dstIp = `${ip[16]}.${ip[17]}.${ip[18]}.${ip[19]}`;
  const l4 = ip.subarray(ihl);
  const ts = `${tsSec}.${String(tsUsec).padStart(6,'0')}`;
  if (proto === 6) {           // TCP
    const sp = l4.readUInt16BE(0), dp = l4.readUInt16BE(2);
    const flags = l4[13];
    const fStr = [
      flags&0x02?'S':'', flags&0x10?'A':'', flags&0x08?'P':'',
      flags&0x01?'F':'', flags&0x04?'R':''
    ].join('');
    const dataOff = (l4[12] >> 4) * 4;
    const payload = l4.subarray(dataOff);
    console.log(`#${idx} ${ts} TCP ${srcIp}:${sp} -> ${dstIp}:${dp} [${fStr}] payload=${payload.length}B${payload.length?'  '+payload.subarray(0,40).toString('hex'):''}`);
  } else if (proto === 17) {   // UDP
    const sp = l4.readUInt16BE(0), dp = l4.readUInt16BE(2);
    const ulen = l4.readUInt16BE(4) - 8;
    const payload = l4.subarray(8, 8+ulen);
    const preview = payload.length > 32 ? payload.subarray(0,32).toString('hex')+'...' : payload.toString('hex');
    console.log(`#${idx} ${ts} UDP ${srcIp}:${sp} -> ${dstIp}:${dp} payload=${ulen}B  ${preview}`);
  } else {
    console.log(`#${idx} ${ts} proto=${proto} ${srcIp}->${dstIp}`);
  }
}
