#!/usr/bin/env node
// send_dmx — set DMX channels on a Nicolaudie Stick-DE3, transactionally.
//
//   node tools/send_dmx.mjs <ip> <universe,channel=value> [more…]
//   e.g.  node tools/send_dmx.mjs 192.168.96.2 0,22=8 0,1=255 0,6=128
//
// It connects to the Stick (TCP/2431), runs the handshake, derives the
// per-session AES key via the recovered KDF, sends the encrypted 576-byte
// DMX frame over UDP, then disconnects cleanly — relying on the Stick's
// "latch on clean disconnect" behaviour to hold the values.
//
// ── what is solid vs. hopeful ───────────────────────────────────────────────
//  SOLID  (verified): the KDF, the AES-256-CBC frame cipher, the 576-byte
//         frame layout, the fixed internal header P0. A frame built here is
//         byte-compatible with what Hardware Manager emits.
//  HOPEFUL (untested against hardware): the TCP handshake sequence is modelled
//         on a captured Hardware Manager session. The Stick may want more (or
//         fewer) messages, or may reject a partial handshake. Iterate from the
//         on-wire behaviour. The clean-disconnect latch is per the project
//         notes but only HWM has been observed doing it.
//
// channel is 1..512; value is 0..255; universe selects the DMX port field.

import net from 'node:net';
import dgram from 'node:dgram';
import crypto from 'node:crypto';
import { makeEphemeral, deriveDmxKey, pointToWire, wireToPoint } from './derive-dmx-key.mjs';

const TCP_PORT = 2431;
const UDP_DST_PORT = 2431;
const UDP_SRC_PORT = 2430;
const MAGIC = Buffer.from('Stick_3A');
const LSAG = Buffer.from('LSAG_ALL');
// the 16-byte internal plaintext header — a fixed constant (RE-confirmed)
const P0 = Buffer.from('5b4e99da9685ad976c432b0a7ff9ffcc', 'hex');
// HMAC-SHA256 key for the 0x48 TCP-auth handshake — an internal Hardware
// Manager constant ("#h.6xcKsGD{y}-z"), extracted at runtime via
// tools/hmac-key.sh and verified against a captured HWM handshake.
const AUTH_KEY = Buffer.from('23682e3678634b7347447b797d2d7a', 'hex');
// the Stick's static 0x0F pubkey (constant across every observed session);
// used as a fallback if the live 0x0F reply can't be parsed.
const Q_FALLBACK = Buffer.from(
  '87ef58c2660c272b54a74bbc94cb8518108e370b7eed78456bd8d120c6b9ac0a' +
  'd791e4ce698aea761679f4b92a3ecf2acd12bf9bc308ce0ba8cb9663' + '0871105e', 'hex');

// ── args ────────────────────────────────────────────────────────────────────
const [, , ip, ...assigns] = process.argv;
if (!ip || assigns.length === 0) {
  console.error('usage: node tools/send_dmx.mjs <ip> <universe,channel=value> […]');
  process.exit(1);
}
// universe -> Uint8Array(512) of channel values
const universes = new Map();
for (const a of assigns) {
  const m = /^(\d+),(\d+)=(\d+)$/.exec(a.trim());
  if (!m) { console.error(`bad assignment: "${a}" (want universe,channel=value)`); process.exit(1); }
  const [u, ch, val] = [+m[1], +m[2], +m[3]];
  if (ch < 1 || ch > 512) { console.error(`channel ${ch} out of range 1..512`); process.exit(1); }
  if (val < 0 || val > 255) { console.error(`value ${val} out of range 0..255`); process.exit(1); }
  if (!universes.has(u)) universes.set(u, new Uint8Array(512));
  universes.get(u)[ch - 1] = val;
}

// ── tiny helpers ────────────────────────────────────────────────────────────
let tokenN = 0x80;
const token = () => { const b = Buffer.alloc(8); b.writeUInt32LE(tokenN++, 0); return b; };
const msg = (magic, opcode, ...parts) => {
  const op = Buffer.alloc(2); op.writeUInt16LE(opcode, 0);
  return Buffer.concat([magic, op, ...parts]);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// All received TCP bytes accumulate here for the life of the connection, so a
// reply already sitting in the buffer is never missed.
let rxBuf = Buffer.alloc(0);
const attachReader = (sock) => sock.on('data', (d) => { rxBuf = Buffer.concat([rxBuf, d]); });

/** find a Stick_3A/LSAG message with `opcode` and at least `minLen` bytes. */
function findMsg(opcode, minLen) {
  for (let o = 0; o + 10 <= rxBuf.length; o++) {
    if ((rxBuf.subarray(o, o + 8).equals(MAGIC) || rxBuf.subarray(o, o + 8).equals(LSAG)) &&
        rxBuf.readUInt16LE(o + 8) === opcode && rxBuf.length >= o + minLen) {
      return rxBuf.subarray(o, o + minLen);
    }
  }
  return null;
}
/** poll rxBuf until `predicate` returns non-null, or timeout. */
function waitFor(predicate, timeoutMs) {
  return new Promise((resolve) => {
    const deadline = Date.now() + timeoutMs;
    const tick = () => {
      const r = predicate();
      if (r != null) return resolve(r);
      if (Date.now() > deadline) return resolve(null);
      setTimeout(tick, 20);
    };
    tick();
  });
}

// ── the DMX frame builder (verified format) ─────────────────────────────────
let seqCtr = 0;
function buildFrame(key, channels512, port) {
  // fieldA (+0x0a) is the SAME session message counter as the TCP tokens —
  // the UDP DMX frames continue the sequence. A counter that jumps backwards
  // (a separate low-valued counter) makes the Stick drop every frame.
  const fieldA = token();
  const nonce = crypto.randomBytes(8);
  const iv = Buffer.concat([fieldA, nonce]);                       // 16-byte CBC IV
  const plain = Buffer.concat([P0, Buffer.from(channels512), Buffer.alloc(16)]); // 544
  const c = crypto.createCipheriv('aes-256-cbc', key, iv);
  c.setAutoPadding(false);
  const body = Buffer.concat([c.update(plain), c.final()]);        // 544
  const hdr = Buffer.alloc(32);
  MAGIC.copy(hdr, 0);
  hdr.writeUInt16LE(0x0019, 8);
  fieldA.copy(hdr, 0x0a);
  hdr.writeUInt16LE(port, 0x12);
  hdr.writeUInt16LE(512, 0x14);
  hdr[0x16] = 100;
  hdr[0x17] = seqCtr++ & 0xff;
  nonce.copy(hdr, 0x18);
  return Buffer.concat([hdr, body]);                              // 576
}

// ── main ────────────────────────────────────────────────────────────────────
const log = (...a) => console.log('  ', ...a);

async function handshake(sock) {
  attachReader(sock);

  // 1. 0x47 — LSAG_ALL hello; the Stick replies with its 32-byte handshake key
  sock.write(msg(LSAG, 0x47, token()));
  const r47 = await waitFor(() => findMsg(0x47, 54), 3000);
  let stickKey = Buffer.alloc(32);
  if (r47 != null) {
    stickKey = Buffer.from(r47.subarray(0x16, 0x36));   // Stick handshake key
    log('0x47 ok — got Stick handshake key');
  } else log('0x47 — no reply (continuing)');

  // 2. 0x48 — authenticated handshake. The message is
  //      magic(8) ‖ 0x48 ‖ token(8) ‖ softwareName(32) ‖ stickKey(32)
  //    followed by HMAC-SHA256(AUTH_KEY, that 82-byte head). The Stick
  //    verifies the HMAC; a bad one => reply status 100 (PermissionDenied)
  //    and the session is never promoted to a live control session.
  const software = Buffer.alloc(32); software.write('software');
  const head48 = msg(LSAG, 0x48, token(), software, stickKey);   // 82 bytes
  const mac48 = crypto.createHmac('sha256', AUTH_KEY).update(head48).digest();
  sock.write(Buffer.concat([head48, mac48]));                    // 114 bytes
  const r48 = await waitFor(() => findMsg(0x48, 22), 2000);
  if (r48) {
    const st = r48.readUInt32LE(0x12);
    log(`0x48 auth status: ${st}` + (st === 0 ? ' (ok)' : ' (REJECTED)'));
  } else log('0x48 — no reply');

  // 3. observed pre-DMX chatter — sent ONE AT A TIME. HWM never batches these;
  //    a single coalesced TCP segment leaves the Stick without sending its
  //    0xc9 status, i.e. it never registers the session as a live client.
  for (const m of [
    msg(MAGIC, 0x46, Buffer.alloc(4)),
    msg(MAGIC, 0x09, Buffer.from('14000000', 'hex')),
    msg(MAGIC, 0x09, Buffer.from('14000000', 'hex')),
    msg(MAGIC, 0x00, Buffer.from('14000000', 'hex')),
    msg(MAGIC, 0x011c, token(), Buffer.from('01001600', 'hex')),
    msg(MAGIC, 0x05, Buffer.from('0200', 'hex')),
  ]) {
    sock.write(m);
    await sleep(140);   // separate segment + let the Stick reply
  }
  if (findMsg(0x00c9, 18)) log('0xc9 status received — Stick registered the session');

  // 4. 0x10 — crypto-state query. HWM sees state 3 on a fresh device; state 4
  //    means a DMX key from a previous session is still latched.
  rxBuf = Buffer.alloc(0);
  sock.write(msg(MAGIC, 0x10, token()));
  const r10 = await waitFor(() => findMsg(0x10, 22), 2000);
  if (r10) log(`0x10 crypto state: ${r10.readUInt32LE(0x12)}`);
  rxBuf = Buffer.alloc(0);

  // 5. 0x0F — the DMX key exchange: send our P-256 ephemeral pubkey
  const ecdh = makeEphemeral();
  const ourP256 = pointToWire(ecdh.getPublicKey(null, 'uncompressed'));  // 64-byte wire form
  sock.write(msg(MAGIC, 0x0f, token(), ourP256));
  const r0f = await waitFor(() => findMsg(0x0f, 86), 3000);
  let Qwire = Q_FALLBACK;
  if (r0f != null) {
    Qwire = r0f.subarray(0x16, 0x56);   // Stick DMX pubkey, 64-byte wire form
    log('0x0F ok — got Stick DMX pubkey');
  } else log('0x0F — no reply, using known static Stick key');

  // 6. derive the DMX session key (KDF: P-256 double-ECDH)
  const key = deriveDmxKey(ecdh, wireToPoint(Qwire));
  log('DMX key derived:', key.toString('hex'));

  // 6b. device sync. After 0x0F, HWM does 0x10, three 0x71 parameter reads,
  //     then ~252 0x70 reads (it pulls the showfile/SD image). The Stick
  //     appears to gate live DMX on a client that has performed this sync,
  //     so replicate it: 0x71 params + a sequential 0x70 sector download.
  sock.write(msg(MAGIC, 0x10, token())); await sleep(120);
  for (const p of ['0200000000', '0100000000', '0000000000']) {
    sock.write(msg(MAGIC, 0x71, token(), Buffer.from(p, 'hex')));
    await sleep(80);
  }
  log('0x70 device download (256 sectors) …');
  for (let sec = 0; sec < 256; sec++) {
    const body = Buffer.alloc(5);
    body.writeUInt32LE(sec, 0);
    body[4] = 1;
    sock.write(msg(MAGIC, 0x70, token(), body));
    await sleep(12);
    if ((sec & 0x1f) === 0x1f) rxBuf = Buffer.alloc(0);   // keep rxBuf bounded
  }
  await sleep(200);
  rxBuf = Buffer.alloc(0);

  // 7. enter live mode. In the captured HWM session the DMX stream begins
  //    only after this 0x75/0x74/0x2e/0x10/0x11 sequence; the long 0x70
  //    showfile download HWM does in between is editor-only and is skipped.
  sock.write(msg(MAGIC, 0x75, token())); await sleep(140);
  sock.write(msg(MAGIC, 0x74, token())); await sleep(140);
  sock.write(msg(MAGIC, 0x2e, Buffer.alloc(32))); await sleep(140);  // 0x2e: 32B payload, no token
  sock.write(msg(MAGIC, 0x10, token())); await sleep(140);
  sock.write(msg(MAGIC, 0x11, token()));                 // "go live"
  const r11 = await waitFor(() => findMsg(0x11, 22), 3000);
  log(r11 ? 'live mode enabled (0x11 ok)' : '0x11 — no reply (streaming anyway)');
  return key;
}

async function main() {
  console.log(`send_dmx → ${ip}`);
  const sock = net.createConnection({ host: ip, port: TCP_PORT });
  sock.on('error', (e) => { console.error('TCP error:', e.message); process.exit(1); });
  sock.setTimeout(5000);
  await new Promise((res, rej) => {
    sock.once('connect', res);
    sock.once('error', rej);
    sock.once('timeout', () => rej(new Error(`no response from ${ip}:${TCP_PORT} (timeout)`)));
  });
  sock.setTimeout(0);
  log('TCP connected');

  const key = await handshake(sock);

  // UDP DMX sender
  const udp = dgram.createSocket('udp4');
  await new Promise((res, rej) => { udp.once('error', rej); udp.bind(UDP_SRC_PORT, res); });

  for (const [u, chans] of universes) {
    const lit = [...chans.entries()].filter(([, v]) => v).map(([i, v]) => `ch${i + 1}=${v}`);
    log(`universe ${u}: ${lit.join(' ') || '(all 0)'}`);
  }
  // stream the frame(s) at ~28 Hz while keeping the live session alive with a
  // TCP 0x1a heartbeat every ~1s (HWM does this the whole time it streams —
  // without it the Stick stops honouring the UDP stream). 0x10 once first.
  sock.write(msg(MAGIC, 0x10, token()));
  const STREAM_MS = Number(process.env.STREAM_MS || 6000);
  const deadline = Date.now() + STREAM_MS;
  let nFrames = 0, beats = 0, lastBeat = Date.now();
  while (Date.now() < deadline) {
    for (const [u, chans] of universes) {
      const frame = buildFrame(key, chans, u);
      await new Promise((res) => udp.send(frame, UDP_DST_PORT, ip, () => res()));
      nFrames++;
    }
    if (Date.now() - lastBeat >= 1000) {
      rxBuf = Buffer.alloc(0);
      sock.write(msg(MAGIC, 0x1a, token(), Buffer.alloc(4)));   // streaming heartbeat
      const hb = await waitFor(() => findMsg(0x1a, 44), 800);
      // the 0x1a reply carries the Stick's DMX frame counter at +0x24 — if it
      // climbs while we stream, the Stick is receiving our UDP frames.
      if (hb) log(`heartbeat ${beats}: Stick DMX frame counter = ${hb.readUInt32LE(0x24)}`);
      else log(`heartbeat ${beats}: no reply`);
      lastBeat = Date.now();
      beats++;
    }
    await sleep(35);
  }
  log(`streamed ${nFrames} frames + ${beats} heartbeats over ${STREAM_MS}ms`);

  udp.close();
  // clean TCP disconnect → the Stick latches the last DMX values
  await new Promise((res) => sock.end(res));
  log('disconnected cleanly — Stick should hold the values');
}

main().catch((e) => { console.error('failed:', e.message); process.exit(1); });
