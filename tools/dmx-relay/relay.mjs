// Stick-DE3 pacing relay
//
// Sits between Nicolaudie Hardware Manager / ESA Pro 2 and the Stick-DE3.
// Point the Nicolaudie software at THIS host's IP instead of 192.168.96.2.
//
// Why this exists:
//  - UDP/2430 carries the live DMX stream. A gigabit PC blasts this far
//    faster than DMX can ever leave the wire (~44 Hz hard ceiling). The
//    Stick's network task starves its DMX engine -> lights freeze / stay on.
//    Fix: last-frame-wins coalescing, forward at a sane fixed rate.
//  - TCP/2431 is the control/session channel. The Stick has effectively one
//    session slot; when Hardware Manager restarts, the old half-open socket
//    is never freed and you can't reconnect until a power-cycle.
//    Fix: enforce a single session and hard-RST the previous one the instant
//    a new client connects.
//
// Zero dependencies (node dgram + net), ESM, matches the repo toolchain.

import dgram from 'node:dgram';
import net from 'node:net';

const STICK_IP   = process.env.STICK_IP   || '192.168.96.2';
const UDP_PORT   = Number(process.env.UDP_PORT   || 2430); // local listen port
const TCP_PORT   = Number(process.env.TCP_PORT   || 2431); // local listen port
// Upstream Stick ports default to the listen ports (same number, different
// host) — that's the real-world case. Overridable for testing on loopback.
const STICK_UDP_PORT = Number(process.env.STICK_UDP_PORT || UDP_PORT);
const STICK_TCP_PORT = Number(process.env.STICK_TCP_PORT || TCP_PORT);
const BIND       = process.env.BIND       || '0.0.0.0';
const RATE_HZ    = Number(process.env.RATE_HZ    || 40);   // DMX wire ceiling is ~44 Hz
const STALE_MS   = Number(process.env.STALE_MS   || 2000); // stop streaming this long after last input
// Number of leading bytes of each UDP datagram to use as a coalescing bucket
// key. 0 = single bucket (one universe, our case: 18 fixtures x 5ch = 90ch).
// Bump this only if Nicolaudie streams multiple universes as separate packets.
const COALESCE_KEY_BYTES = Number(process.env.COALESCE_KEY_BYTES || 0);

const tickMs = Math.max(1, Math.round(1000 / RATE_HZ));

function log(...a) {
  console.log(new Date().toISOString(), ...a);
}

// ---------------------------------------------------------------------------
// UDP pacer: latest-packet-wins, forwarded at RATE_HZ
// ---------------------------------------------------------------------------

const buckets = new Map();        // key -> { buf, dirty }
let lastClient = null;            // { address, port } of the Nicolaudie box
let lastInputAt = 0;
let udpIn = 0, udpOut = 0, udpDropped = 0;

const udpSock = dgram.createSocket('udp4');

function bucketKey(buf) {
  if (COALESCE_KEY_BYTES <= 0) return '_';
  return buf.subarray(0, COALESCE_KEY_BYTES).toString('hex');
}

udpSock.on('message', (buf, rinfo) => {
  // Traffic coming back from the Stick (replies/beacons) -> pass to client.
  // Match IP *and* the Stick's service port: DMX-over-IP nodes answer from
  // their listening port, and this disambiguates from the Nicolaudie client
  // (which sources from an ephemeral port, and in prod a different IP too).
  if (rinfo.address === STICK_IP && rinfo.port === STICK_UDP_PORT) {
    if (lastClient) udpSock.send(buf, lastClient.port, lastClient.address);
    return;
  }
  // Inbound from Nicolaudie: remember client, coalesce, count drops.
  lastClient = { address: rinfo.address, port: rinfo.port };
  lastInputAt = Date.now();
  const k = bucketKey(buf);
  const prev = buckets.get(k);
  if (prev && prev.dirty) udpDropped++; // an un-sent frame is being overwritten
  buckets.set(k, { buf, dirty: true });
  udpIn++;
});

udpSock.on('error', (err) => log('UDP socket error:', err.message));

setInterval(() => {
  if (Date.now() - lastInputAt > STALE_MS) return; // Nicolaudie idle/quit
  for (const entry of buckets.values()) {
    if (!entry.dirty) continue;
    udpSock.send(entry.buf, STICK_UDP_PORT, STICK_IP);
    entry.dirty = false;
    udpOut++;
  }
}, tickMs);

udpSock.bind(UDP_PORT, BIND, () => {
  log(`UDP pacer  ${BIND}:${UDP_PORT}  ->  ${STICK_IP}:${STICK_UDP_PORT}  @ ${RATE_HZ} Hz`);
});

// ---------------------------------------------------------------------------
// TCP proxy: single session, hard-RST the old one on a new connect
// ---------------------------------------------------------------------------

let session = null; // { client, upstream }
let connSeq = 0;
let activeClients = 0;
const DEBUG = process.env.DEBUG !== '0'; // byte-level handshake tracing

function hardKill(sock) {
  if (!sock || sock.destroyed) return;
  // RST rather than graceful FIN so the Stick drops its session slot now.
  if (typeof sock.resetAndDestroy === 'function') sock.resetAndDestroy();
  else sock.destroy();
}

function teardown(reason) {
  if (!session) return;
  const s = session;
  session = null;
  log(`TCP session torn down (${reason})`);
  hardKill(s.client);
  hardKill(s.upstream);
}

const tcpServer = net.createServer((client) => {
  const id = ++connSeq;
  const t0 = Date.now();
  activeClients++;
  log(`[#${id}] TCP client connected ${client.remoteAddress}:${client.remotePort}  (activeClients=${activeClients})`);
  if (activeClients > 1) {
    log(`[#${id}] *** OVERLAP: ${activeClients} client connections at once — Connect likely opens multiple sockets; single-session RST may be breaking the handshake`);
  }

  // One session at a time. A reconnecting Hardware Manager must not be
  // blocked by the previous wedged socket.
  if (session) {
    const age = ((Date.now() - session.t0) / 1000).toFixed(1);
    log(`[#${id}] superseding session #${session.id} (age ${age}s, handshake ${session.gotStickHello ? 'completed' : 'NEVER completed'})`);
    teardown(`superseded by client #${id}`);
  }

  const upstream = net.connect({ host: STICK_IP, port: STICK_TCP_PORT });
  upstream.setNoDelay(true);
  client.setNoDelay(true);

  const thisSession = { client, upstream, id, t0, gotStickHello: false };
  session = thisSession;

  const connectTimer = setTimeout(() => {
    if (session === thisSession && upstream.connecting) {
      log(`[#${id}] TCP upstream connect timeout to ${STICK_IP}:${STICK_TCP_PORT}`);
      teardown('upstream connect timeout');
    }
  }, 5000);

  upstream.on('connect', () => {
    clearTimeout(connectTimer);
    log(`[#${id}] TCP upstream established -> ${STICK_IP}:${STICK_TCP_PORT}`);
    if (DEBUG) {
      let cHead = false, uHead = false;
      client.on('data', (d) => {
        if (!cHead) { cHead = true;
          log(`[#${id}] C->S first ${d.length}B: ${d.subarray(0, 32).toString('hex')} | ${JSON.stringify(d.subarray(0, 16).toString('latin1'))}`); }
      });
      upstream.on('data', (d) => {
        if (!uHead) { uHead = true;
          thisSession.gotStickHello = true;
          log(`[#${id}] S->C first ${d.length}B: ${d.subarray(0, 32).toString('hex')} | ${JSON.stringify(d.subarray(0, 16).toString('latin1'))}  <-- STICK RESPONDED`); }
      });
    }
    client.pipe(upstream);
    upstream.pipe(client);
  });

  const onEnd = (who) => () => {
    if (session === thisSession) {
      const age = ((Date.now() - t0) / 1000).toFixed(1);
      teardown(`#${id} ${who} closed after ${age}s, stick ${thisSession.gotStickHello ? 'had responded' : 'NEVER responded'}`);
    }
  };
  const onErr = (who) => (err) => {
    if (session === thisSession) teardown(`#${id} ${who} error: ${err.message}`);
    else hardKill(who === 'client' ? client : upstream);
  };

  client.on('close', () => { activeClients--; });
  client.on('close', onEnd('client'));
  client.on('error', onErr('client'));
  upstream.on('close', onEnd('upstream'));
  upstream.on('error', onErr('upstream'));
});

tcpServer.on('error', (err) => log('TCP server error:', err.message));
tcpServer.listen(TCP_PORT, BIND, () => {
  log(`TCP proxy  ${BIND}:${TCP_PORT}  ->  ${STICK_IP}:${STICK_TCP_PORT}  (single session, RST on supersede)`);
});

// ---------------------------------------------------------------------------
// Heartbeat / stats
// ---------------------------------------------------------------------------

setInterval(() => {
  log(`stats  udp in=${udpIn} out=${udpOut} dropped=${udpDropped}  tcp=${session ? 'connected' : 'idle'}`);
  udpIn = udpOut = udpDropped = 0;
}, 10000);

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    log(`${sig} received, shutting down`);
    teardown('relay shutdown');
    process.exit(0);
  });
}
