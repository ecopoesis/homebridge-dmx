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
let fieldCtr = 1, seqCtr = 0;
function buildFrame(key, channels512, port) {
  const fieldA = Buffer.alloc(8); fieldA.writeUInt16LE((fieldCtr += 3) & 0xffff, 0);
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

  // 1. 0x47 — LSAG_ALL key-exchange request
  sock.write(msg(LSAG, 0x47, token()));
  const r47 = await waitFor(() => findMsg(0x47, 54), 3000);
  let stickX25519 = crypto.randomBytes(32);
  if (r47 != null) {
    stickX25519 = r47.subarray(0x16, 0x36);   // Stick handshake key, 32 bytes
    log('0x47 ok — got Stick handshake key');
  } else log('0x47 — no reply (continuing)');

  // 2. 0x48 — software name ‖ stick pub (echoed) ‖ our pub
  const software = Buffer.alloc(32); software.write('software');
  const ourX25519 = crypto.randomBytes(32);   // X25519 secret is unused downstream
  sock.write(msg(LSAG, 0x48, token(), software, stickX25519, ourX25519));
  await sleep(120);

  // 3. observed pre-DMX chatter (replayed; payloads as captured)
  sock.write(msg(MAGIC, 0x46, Buffer.alloc(4)));
  sock.write(msg(MAGIC, 0x09, Buffer.from('14000000', 'hex')));
  sock.write(msg(MAGIC, 0x09, Buffer.from('14000000', 'hex')));
  sock.write(msg(MAGIC, 0x00, Buffer.from('14000000', 'hex')));
  sock.write(msg(MAGIC, 0x011c, token(), Buffer.from('01001600', 'hex')));
  sock.write(msg(MAGIC, 0x05, Buffer.from('0200', 'hex')));
  await sleep(200);

  // 4. 0x10 — crypto-state query
  sock.write(msg(MAGIC, 0x10, token()));
  await sleep(150);

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
    // send the frame several times — UDP is lossy, the Stick wants a stream
    for (let i = 0; i < 12; i++) {
      const frame = buildFrame(key, chans, u);
      await new Promise((res) => udp.send(frame, UDP_DST_PORT, ip, () => res()));
      await sleep(35);   // ~28 Hz, matching HWM's tame stream
    }
  }
  log('frames sent');

  udp.close();
  // clean TCP disconnect → the Stick latches the last DMX values
  await new Promise((res) => sock.end(res));
  log('disconnected cleanly — Stick should hold the values');
}

main().catch((e) => { console.error('failed:', e.message); process.exit(1); });
