// Stick-DE3 "Quick Trigger" tester — documented, UNencrypted, UNauthenticated
// control path (STICK Remote Protocol spec, section 1).
//
// Sends a 24-byte Quick Trigger packet via UDP to the Stick on port 2430.
// Per the spec, UDP/2430 Quick Triggering "has no authentication layer" — so
// this works regardless of firmware 2.x TCP auth / "Security for Cloud Access".
//
// Packet layout (exact, from the spec; example in the spec sums to 24 bytes):
//   [0..7]  ID[8]      "Stick_3A"
//   [8..9]  OpCode[2]  109  -> 0x6D 0x00  (LE)
//   [10..11]SceneNr[2] LE   (Scene Number = Page*50 + SceneInPage)
//   [12]    ZoneSyncId 1
//   [13]    Command    1    (see CMD below)
//   [14..15]Dimmer[2]  LE
//   [16..17]Speed[2]   LE
//   [18]    Unused     1
//   [19]    Unused     1
//   [20..23]Color[4]   R G B 00
//
// Usage:
//   node tools/quick-trigger.mjs blackout-on
//   node tools/quick-trigger.mjs blackout-off
//   node tools/quick-trigger.mjs scene-on  <sceneNr>
//   node tools/quick-trigger.mjs scene-off <sceneNr>
//   node tools/quick-trigger.mjs dimmer <sceneNr> <0-255>
//   node tools/quick-trigger.mjs color  <sceneNr> <r> <g> <b>
//   node tools/quick-trigger.mjs raw    <sceneNr> <cmd> [dimmer] [r] [g] [b]
// Env: STICK_IP (default 192.168.96.2), STICK_PORT (default 2430)

import dgram from 'node:dgram';

const STICK_IP   = process.env.STICK_IP   || '192.168.96.2';
const STICK_PORT = Number(process.env.STICK_PORT || 2430);

const CMD = {
  'scene-off': 0, 'scene-on': 1, 'pause-off': 2, 'pause-on': 3,
  'reset': 4, 'dimmer-set': 5, 'speed-set': 6, 'color-set': 7,
  'blackout-off': 8, 'blackout-on': 9,
};

function buildPacket({ scene = 0, zoneSync = 0, command = 0, dimmer = 0, speed = 0, r = 0, g = 0, b = 0 }) {
  const p = Buffer.alloc(24);
  p.write('Stick_3A', 0, 'latin1'); // [0..7]
  p.writeUInt16LE(109, 8);          // [8..9]  OpCode
  p.writeUInt16LE(scene & 0xffff, 10); // [10..11] SceneNr
  p.writeUInt8(zoneSync & 0xff, 12);   // [12]
  p.writeUInt8(command & 0xff, 13);    // [13] Command
  p.writeUInt16LE(dimmer & 0xffff, 14);// [14..15] Dimmer
  p.writeUInt16LE(speed & 0xffff, 16); // [16..17] Speed
  // [18],[19] unused = 0
  p.writeUInt8(r & 0xff, 20);
  p.writeUInt8(g & 0xff, 21);
  p.writeUInt8(b & 0xff, 22);
  // [23] = 0
  return p;
}

const [sub, ...rest] = process.argv.slice(2);
if (!sub) {
  console.error('usage: node tools/quick-trigger.mjs <blackout-on|blackout-off|scene-on|scene-off|dimmer|color|raw> [args]');
  process.exit(1);
}

let opts;
switch (sub) {
  case 'blackout-on':  opts = { command: CMD['blackout-on'] }; break;
  case 'blackout-off': opts = { command: CMD['blackout-off'] }; break;
  case 'scene-on':     opts = { command: CMD['scene-on'],  scene: +rest[0] }; break;
  case 'scene-off':    opts = { command: CMD['scene-off'], scene: +rest[0] }; break;
  case 'dimmer':       opts = { command: CMD['dimmer-set'], scene: +rest[0], dimmer: +rest[1] }; break;
  case 'color':        opts = { command: CMD['color-set'],  scene: +rest[0], r: +rest[1], g: +rest[2], b: +rest[3] }; break;
  case 'raw':          opts = { scene: +rest[0], command: +rest[1], dimmer: +(rest[2]||0), r: +(rest[3]||0), g: +(rest[4]||0), b: +(rest[5]||0) }; break;
  default:
    console.error(`unknown subcommand: ${sub}`);
    process.exit(1);
}

const pkt = buildPacket(opts);
const sock = dgram.createSocket('udp4');
const ts = new Date().toISOString();
sock.send(pkt, STICK_PORT, STICK_IP, (err) => {
  if (err) { console.error(`${ts}  send error:`, err.message); process.exit(1); }
  console.log(`${ts}  -> ${STICK_IP}:${STICK_PORT}  ${sub} ${rest.join(' ')}`);
  console.log(`  ${pkt.length}B: ${pkt.toString('hex').replace(/(..)/g, '$1 ').trim()}`);
  sock.close();
});
