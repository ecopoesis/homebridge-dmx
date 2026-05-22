import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { StickConnection, parseStatus, discoverEasyRemote, sendUdp, buildQuickTriggerPacket, SCENE_CMD } from '../stick/protocol.js'

interface Config {
  host: string
  tcpPort: number
  udpPort: number
  easyRemotePort: number
}

function loadConfig(): Config {
  const configPath = resolve(process.cwd(), 'stick-de3.json')
  return JSON.parse(readFileSync(configPath, 'utf-8'))
}

function hexDump(buf: Buffer, label?: string): void {
  if (label) console.log(`\n--- ${label} (${buf.length} bytes) ---`)
  const hex = Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join(' ')
  const ascii = Array.from(buf).map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('')
  for (let i = 0; i < buf.length; i += 16) {
    const hexSlice = hex.substring(i * 3, (i + 16) * 3).trim()
    const asciiSlice = ascii.substring(i, i + 16)
    console.log(`  ${i.toString(16).padStart(4, '0')}  ${hexSlice.padEnd(48)}  ${asciiSlice}`)
  }
}

async function probeTcp(config: Config): Promise<void> {
  console.log(`\n=== TCP PROBE: ${config.host}:${config.tcpPort} ===`)

  const conn = new StickConnection(config.host, config.tcpPort)
  let messageCount = 0
  const maxMessages = 3

  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      console.log('\n  TCP: Timed out after 20s')
      conn.close()
      resolve()
    }, 20_000)

    conn.on('raw', (data: Buffer) => {
      hexDump(data, `TCP message #${messageCount + 1}`)
      const status = parseStatus(data)
      if (status) {
        console.log('\n  Parsed status:')
        console.log(`    Opcode:         0x${status.opcode.toString(16).padStart(2, '0')} (${status.opcode})`)
        console.log(`    Version:        ${status.version}`)
        console.log(`    Scene:          #${status.sceneNr} "${status.sceneName}" (state: ${status.sceneState})`)
        console.log(`    Zone:           #${status.zoneNumber} "${status.zoneName}" (count: ${status.zoneCount})`)
        console.log(`    Dimmer:         ${status.dimmerValue}`)
        console.log(`    Color:          R=${status.colorR} G=${status.colorG} B=${status.colorB}`)
        console.log(`    Speed:          ${status.speedValue}`)
        console.log(`    Live Mode:      ${status.liveModeActive}`)
        console.log(`    Remote Clients: ${status.remoteClients}`)
        console.log(`    Screen:         ${status.currentScreen}`)
        console.log(`    LED Status:     ${status.ledStatus}`)
        console.log(`    Icons visible:  speed=${status.speedIconVisible} color=${status.colorIconVisible} dimmer=${status.dimmerIconVisible}`)
      }

      messageCount++
      if (messageCount >= maxMessages) {
        console.log(`\n  TCP: Received ${maxMessages} status messages, closing`)
        clearTimeout(timeout)
        conn.close()
        resolve()
      }
    })

    conn.on('error', (err: Error) => {
      console.log(`  TCP ERROR: ${err.message}`)
      clearTimeout(timeout)
      resolve()
    })

    conn.on('close', () => {
      console.log('  TCP: Connection closed')
    })

    console.log('  Connecting...')
    conn.connect().then(() => {
      console.log('  Connected! Waiting for status messages (Stick sends every ~5s)...')
    }).catch((err) => {
      console.log(`  TCP CONNECT FAILED: ${err.message}`)
      clearTimeout(timeout)
      resolve()
    })
  })
}

async function probeEasyRemote(config: Config): Promise<void> {
  console.log(`\n=== EASY REMOTE PROBE: ${config.host}:${config.easyRemotePort} ===`)
  console.log('  Sending discovery (action=ready)...')

  const objects = await discoverEasyRemote(config.host, config.easyRemotePort, 5000)

  if (objects.length === 0) {
    console.log('  No Easy Remote objects found (timeout or no layout configured)')
  } else {
    console.log(`  Found ${objects.length} objects:`)
    for (const obj of objects) {
      console.log(`    [${obj.type}] id=${obj.id} page=${obj.page} name="${obj.name}"`)
    }
  }
}

async function probeHandshake(config: Config): Promise<void> {
  console.log(`\n=== HANDSHAKE PROBE: Trying opcode 0x1A (HardwareManager keepalive) ===`)

  const conn = new StickConnection(config.host, config.tcpPort)
  let messageCount = 0

  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      console.log('\n  Handshake probe timed out after 20s')
      conn.close()
      resolve()
    }, 20_000)

    conn.on('raw', (data: Buffer) => {
      hexDump(data, `Response #${messageCount + 1}`)

      if (data.length >= 9) {
        const magic = data.subarray(0, 8).toString('ascii')
        const opcode = data.readUInt8(8)
        console.log(`  Magic: ${magic}, Opcode: 0x${opcode.toString(16)} (${opcode})`)
        if (data.length >= 10) {
          const opcode2 = data.readUInt8(9)
          console.log(`  Opcode word (LE): 0x${(opcode | (opcode2 << 8)).toString(16)}`)
        }
      }

      const status = parseStatus(data)
      if (status) {
        console.log('  → Parsed as status message:')
        console.log(`    Scene: #${status.sceneNr} "${status.sceneName}"`)
        console.log(`    Zone: #${status.zoneNumber} "${status.zoneName}"`)
        console.log(`    Live Mode: ${status.liveModeActive}`)
        console.log(`    Remote Clients: ${status.remoteClients}`)
      }

      messageCount++
      if (messageCount >= 5) {
        clearTimeout(timeout)
        conn.close()
        resolve()
      }
    })

    conn.on('error', (err: Error) => {
      console.log(`  ERROR: ${err.message}`)
      clearTimeout(timeout)
      resolve()
    })

    conn.connect().then(() => {
      console.log('  Connected. Sending opcode 0x1A handshake...')

      // Replicate the packet format we saw HardwareManager use:
      // Stick_3A + 1a00 + 0000 + 0000000000000000
      const handshake = Buffer.alloc(20)
      Buffer.from('Stick_3A').copy(handshake, 0)
      handshake.writeUInt8(0x1a, 8)
      handshake.writeUInt8(0x00, 9)
      handshake.writeUInt16LE(0x0000, 10)
      // rest is zeros

      conn.send(handshake)
      console.log('  Handshake sent. Waiting for responses...')

      // Also try sending a Quick Trigger after handshake to see if it works now
      setTimeout(() => {
        console.log('\n  Sending Quick Trigger scene 0 ON via TCP...')
        const qt = buildQuickTriggerPacket(0, SCENE_CMD.ON)
        conn.send(qt)
      }, 2000)
    }).catch((err) => {
      console.log(`  CONNECT FAILED: ${err.message}`)
      clearTimeout(timeout)
      resolve()
    })
  })
}

async function probeQuickTriggerUdp(config: Config): Promise<void> {
  console.log(`\n=== UDP QUICK TRIGGER TEST ===`)
  console.log('  Sending scene 1 ON via UDP (watch the Stick screen!)...')

  const packetOn = buildQuickTriggerPacket(0, SCENE_CMD.ON)
  hexDump(packetOn, 'Scene 0 ON')
  await sendUdp(config.host, config.udpPort, packetOn)
  console.log('  Sent. Check if the Stick display changed.')

  await new Promise(r => setTimeout(r, 3000))

  console.log('  Sending scene 0 OFF...')
  const packetOff = buildQuickTriggerPacket(0, SCENE_CMD.OFF)
  await sendUdp(config.host, config.udpPort, packetOff)
  console.log('  Sent OFF. Check if Stick display reverted.')
}

async function probeUdpResponse(config: Config): Promise<void> {
  console.log(`\n=== UDP PROBE: ${config.host}:${config.udpPort} ===`)
  console.log('  Sending a Quick Trigger scene-off packet via UDP...')

  // Scene 0, command OFF (harmless - turns off scene 0 which likely doesn't exist)
  const packet = buildQuickTriggerPacket(0, SCENE_CMD.OFF)
  hexDump(packet, 'UDP Quick Trigger packet (scene 0 off)')

  try {
    await sendUdp(config.host, config.udpPort, packet)
    console.log('  UDP: Packet sent successfully (no response expected for UDP)')
  } catch (err: any) {
    console.log(`  UDP ERROR: ${err.message}`)
  }
}

async function main() {
  console.log('Stick-DE3 Protocol Probe')
  console.log('========================')

  const config = loadConfig()
  console.log(`Config: host=${config.host} tcp=${config.tcpPort} udp=${config.udpPort} easyRemote=${config.easyRemotePort}`)

  // Run probes sequentially so output is readable
  await probeHandshake(config)
  await probeQuickTriggerUdp(config)
  await probeEasyRemote(config)

  console.log('\n=== PROBE COMPLETE ===')
}

main().catch(console.error)
