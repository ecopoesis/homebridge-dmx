import * as net from 'node:net'
import * as dgram from 'node:dgram'
import { EventEmitter } from 'node:events'

const MAGIC = Buffer.from('Stick_3A')

const OPCODE_QUICK_TRIGGER = 0x6d
const OPCODE_BUTTON_SIM = 0x65
const OPCODE_STATUS = 0x23

export const SCENE_CMD = {
  OFF: 0,
  ON: 1,
  PAUSE_OFF: 2,
  PAUSE_ON: 3,
  RESET: 4,
  DIMMER_SET: 5,
  SPEED_SET: 6,
  COLOR_SET: 7,
  BLACKOUT_OFF: 8,
  BLACKOUT_ON: 9,
} as const

export interface StickStatus {
  opcode: number
  version: number
  sceneNr: number
  sceneName: string
  zoneNumber: number
  zoneName: string
  dimmerValue: number
  colorR: number
  colorG: number
  colorB: number
  speedValue: number
  speedIconVisible: boolean
  colorIconVisible: boolean
  dimmerIconVisible: boolean
  remoteClients: number
  liveModeActive: boolean
  currentScreen: number
  ledStatus: number
  zoneCount: number
  sceneState: number
  isImageDisplayed: boolean
  isImageFullscreen: boolean
}

export interface EasyRemoteObject {
  id: number
  page: number
  name: string
  type: string
}

export function buildQuickTrigger(sceneNr: number, command: number, opts?: {
  dimmer?: number
  speed?: number
  colorR?: number
  colorG?: number
  colorB?: number
}): Buffer {
  const buf = Buffer.alloc(22)
  MAGIC.copy(buf, 0)
  buf.writeUInt16LE(OPCODE_QUICK_TRIGGER, 8)
  buf.writeUInt16LE(sceneNr, 10)
  buf.writeUInt8(0, 12) // zone sync
  buf.writeUInt8(command, 13)
  buf.writeUInt16LE(opts?.dimmer ?? 0, 14)
  buf.writeUInt16LE(opts?.speed ?? 0, 16)
  buf.writeUInt8(0, 18) // alignment
  buf.writeUInt8(0, 19) // alignment
  buf.writeUInt8(opts?.colorR ?? 0, 20)
  buf.writeUInt8(opts?.colorG ?? 0, 21)
  buf.writeUInt8(opts?.colorB ?? 0, 22 - 1) // last usable in 22-byte buf...
  // Actually the packet needs to be bigger for color
  return buf
}

export function buildQuickTriggerPacket(sceneNr: number, command: number, opts?: {
  dimmer?: number
  speed?: number
  colorR?: number
  colorG?: number
  colorB?: number
}): Buffer {
  // Total: 8 (magic) + 2 (opcode) + 2 (scene) + 1 (zone sync) + 1 (cmd) + 2 (dimmer) + 2 (speed) + 1 (align) + 1 (align) + 4 (color) = 24
  const buf = Buffer.alloc(24)
  MAGIC.copy(buf, 0)
  buf.writeUInt16LE(OPCODE_QUICK_TRIGGER, 8)
  buf.writeUInt16LE(sceneNr, 10)
  buf.writeUInt8(0, 12)
  buf.writeUInt8(command, 13)
  buf.writeUInt16LE(opts?.dimmer ?? 0, 14)
  buf.writeUInt16LE(opts?.speed ?? 0, 16)
  buf.writeUInt8(0, 18)
  buf.writeUInt8(0, 19)
  buf.writeUInt8(opts?.colorR ?? 0, 20)
  buf.writeUInt8(opts?.colorG ?? 0, 21)
  buf.writeUInt8(opts?.colorB ?? 0, 22)
  buf.writeUInt8(0, 23)
  return buf
}

export function buildButtonSim(buttonId: number, event: number, value: number = 0): Buffer {
  const buf = Buffer.alloc(12)
  MAGIC.copy(buf, 0)
  buf.writeUInt8(OPCODE_BUTTON_SIM, 8)
  buf.writeUInt8(buttonId, 9)
  buf.writeUInt8(event, 10)
  buf.writeUInt8(value, 11)
  return buf
}

export function parseStatus(data: Buffer): StickStatus | null {
  if (data.length < 8) return null
  const magic = data.subarray(0, 8).toString('ascii')
  if (magic !== 'Stick_3A') return null

  const opcode = data.readUInt8(8)

  if (data.length < 55) {
    return {
      opcode,
      version: 0, sceneNr: 0, sceneName: '', zoneNumber: 0, zoneName: '',
      dimmerValue: 0, colorR: 0, colorG: 0, colorB: 0, speedValue: 0,
      speedIconVisible: false, colorIconVisible: false, dimmerIconVisible: false,
      remoteClients: 0, liveModeActive: false, currentScreen: 0, ledStatus: 0,
      zoneCount: 0, sceneState: 0, isImageDisplayed: false, isImageFullscreen: false,
    }
  }

  return {
    opcode,
    version: data.readUInt8(9),
    sceneNr: data.readUInt16LE(10),
    sceneName: data.subarray(12, 24).toString('ascii').replace(/\0/g, '').trim(),
    zoneNumber: data.readUInt8(24),
    zoneName: data.subarray(25, 37).toString('ascii').replace(/\0/g, '').trim(),
    dimmerValue: data.readUInt16LE(37),
    colorR: data.readUInt8(39),
    colorG: data.readUInt8(40),
    colorB: data.readUInt8(41),
    speedValue: data.readUInt16LE(42),
    speedIconVisible: data.readUInt8(44) !== 0,
    colorIconVisible: data.readUInt8(45) !== 0,
    dimmerIconVisible: data.readUInt8(46) !== 0,
    remoteClients: data.readUInt8(47),
    liveModeActive: data.readUInt8(48) !== 0,
    currentScreen: data.readUInt8(49),
    ledStatus: data.readUInt8(50),
    zoneCount: data.readUInt8(51),
    sceneState: data.readUInt8(52),
    isImageDisplayed: data.readUInt8(53) !== 0,
    isImageFullscreen: data.readUInt8(54) !== 0,
  }
}

export class StickConnection extends EventEmitter {
  private socket: net.Socket | null = null
  private host: string
  private port: number

  constructor(host: string, port: number = 2431) {
    super()
    this.host = host
    this.port = port
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket = new net.Socket()
      this.socket.setTimeout(15_000)

      this.socket.on('data', (data) => {
        this.emit('raw', data)
        const status = parseStatus(data)
        if (status) {
          this.emit('status', status)
        }
      })

      this.socket.on('error', (err) => this.emit('error', err))
      this.socket.on('close', () => this.emit('close'))
      this.socket.on('timeout', () => {
        this.emit('error', new Error('Connection timeout'))
        this.socket?.destroy()
      })

      this.socket.connect(this.port, this.host, () => {
        resolve()
      })
    })
  }

  send(data: Buffer): boolean {
    if (!this.socket || this.socket.destroyed) return false
    return this.socket.write(data)
  }

  sendRaw(data: Buffer): boolean {
    return this.send(data)
  }

  close() {
    this.socket?.destroy()
    this.socket = null
  }
}

export function sendUdp(host: string, port: number, data: Buffer): Promise<void> {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4')
    sock.send(data, port, host, (err) => {
      sock.close()
      if (err) reject(err)
      else resolve()
    })
  })
}

export function discoverEasyRemote(host: string, port: number = 4003, timeoutMs: number = 3000): Promise<EasyRemoteObject[]> {
  return new Promise((resolve) => {
    const objects: EasyRemoteObject[] = []
    const sock = dgram.createSocket('udp4')

    const timer = setTimeout(() => {
      sock.close()
      resolve(objects)
    }, timeoutMs)

    sock.on('message', (msg) => {
      const text = msg.toString()
      const params = new URLSearchParams(text.replace(/\r?\n$/, ''))
      const action = params.get('action')

      if (action === 'set_layer') {
        objects.push({
          id: parseInt(params.get('id') ?? '0'),
          page: parseInt(params.get('page') ?? '0'),
          name: params.get('name') ?? '',
          type: params.get('type') ?? '',
        })
      }

      if (action === 'done') {
        clearTimeout(timer)
        sock.close()
        resolve(objects)
      }
    })

    sock.on('error', () => {
      clearTimeout(timer)
      sock.close()
      resolve(objects)
    })

    const msg = Buffer.from('action=ready&width=0&height=0\r\n')
    sock.send(msg, port, host)
  })
}
