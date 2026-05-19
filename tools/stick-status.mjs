// Stick-DE3 status reader — objectively check if the device is in REMOTE/LIVE
// mode vs standalone. Per the STICK Remote Protocol spec, once connected to
// TCP/2431 the Stick sends a status packet every 5s. Key fields:
//   offset 47 = Remote Clients Count
//   offset 48 = Live Mode Is Activated  (1 = live/remote, 0 = standalone)
// (Documented status layout starts: ID[8], OpCode, Ver, SceneNr[2],
//  SceneName[12], ZoneNr, ZoneName[12], Dimmer[2], R,G,B, Speed[2],
//  3x icon flags, RemoteClients, LiveMode, Screen, Led, ZoneCount,
//  SceneState, ImgDisplayed, ImgFullscreen.)
//
// NOTE: on fw2.x/3.x TCP requires auth. If "Security for Cloud Access" is
// still enabled this may only get the LSAG/auth-challenge reply, not a clean
// status packet — which itself is the finding (device never enters remote
// mode for us). Raw hex is always dumped so we can see exactly what comes.
//
// Usage: node tools/stick-status.mjs            (watches for ~30s)
//        STICK_IP=192.168.96.2 node tools/stick-status.mjs

import net from 'node:net';

const STICK_IP   = process.env.STICK_IP   || '192.168.96.2';
const STICK_PORT = Number(process.env.STICK_TCP_PORT || 2431);
const WATCH_MS   = Number(process.env.WATCH_MS || 30000);
const GREET = Buffer.from('4c5341475f414c4c000015000000', 'hex'); // observed LSAG_ALL client greeting

const ts = () => new Date().toISOString();
const sock = net.connect({ host: STICK_IP, port: STICK_PORT });
sock.setNoDelay(true);

sock.on('connect', () => {
  console.log(`${ts()}  connected ${STICK_IP}:${STICK_PORT} — sending LSAG_ALL greeting`);
  sock.write(GREET);
});

sock.on('data', (b) => {
  const isStatus = b.length >= 49 && b.subarray(0, 8).toString('latin1') === 'Stick_3A';
  console.log(`\n${ts()}  <-- ${b.length}B`);
  console.log('  hex: ' + b.subarray(0, Math.min(b.length, 64)).toString('hex').replace(/(..)/g, '$1 ').trim());
  if (isStatus) {
    const sceneName = b.subarray(12, 24).toString('latin1').replace(/\0.*$/, '');
    const zoneName  = b.subarray(25, 37).toString('latin1').replace(/\0.*$/, '');
    const remoteClients = b.length > 47 ? b[47] : '?';
    const liveMode      = b.length > 48 ? b[48] : '?';
    console.log(`  ID=Stick_3A OpCode=${b[8]} Ver=${b[9]}`);
    console.log(`  sceneName=${JSON.stringify(sceneName)} zoneName=${JSON.stringify(zoneName)}`);
    console.log(`  >>> RemoteClientsCount[off47]=${remoteClients}  LiveModeIsActivated[off48]=${liveMode} <<<`);
    if (liveMode === 0) console.log('  ** Live mode NOT active — device is in STANDALONE (this is the suspected root cause) **');
    if (liveMode === 1) console.log('  ** Live mode ACTIVE — device is in REMOTE mode **');
  } else {
    console.log('  (not a documented status packet — likely the LSAG/auth-challenge reply; fw3 TCP auth not satisfied)');
  }
});

sock.on('error', (e) => console.log(`${ts()}  error: ${e.message}`));
sock.on('close', () => console.log(`${ts()}  closed`));

setTimeout(() => { console.log(`\n${ts()}  done (${WATCH_MS}ms)`); sock.destroy(); process.exit(0); }, WATCH_MS);
