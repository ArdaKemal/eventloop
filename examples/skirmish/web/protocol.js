// Skirmish wire format (examples/skirmish/PROTOCOL.md). All integers are little-endian.

export const PROTOCOL_NAME = 'skirmish/1';
export const MAX_INPUTS = 4;
export const NAME_MAX = 16;
export const CHAT_MAX = 200;
export const KILLCAM_KIND = 1;
export const SCOREBOARD_REQUEST = 1;

export const DGRAM = { INPUT: 1, PING: 2, PONG: 2, SNAPSHOT: 3 };
export const CTRL = { HELLO: 1, WELCOME: 1, JOIN: 2, LEAVE: 3, KILL: 4, CHAT: 5, NOTICE: 6 };
export const BUTTON = { FWD: 1, BACK: 2, LEFT: 4, RIGHT: 8, FIRE: 16, ROCKET: 32 };
export const PLAYER_FLAG = { ALIVE: 1, FIRED: 2 };
export const SELF_FLAG_ALIVE = 1;
export const EFFECT = { TRACER: 1, EXPLOSION: 2 };
export const WEAPON = { RIFLE: 1, ROCKET: 2 };
export const WEAPON_NAME = { 1: 'rifle', 2: 'rocket' };
export const CLOSE = { SERVER_FULL: 1, TOO_SLOW: 2, PROTOCOL: 3, SHUTDOWN: 4, INVALID_NAME: 5 };
export const CLOSE_TEXT = {
  0: 'closed',
  1: 'server full',
  2: 'too slow',
  3: 'protocol error',
  4: 'server shutting down',
  5: 'invalid name',
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// Bounds-checked little-endian reader over a Uint8Array.
class Reader {
  constructor(bytes) {
    this.b = bytes;
    this.dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.o = 0;
  }
  need(n) {
    if (this.o + n > this.b.length) throw new RangeError('truncated message');
  }
  u8() { this.need(1); const v = this.dv.getUint8(this.o); this.o += 1; return v; }
  u16() { this.need(2); const v = this.dv.getUint16(this.o, true); this.o += 2; return v; }
  u32() { this.need(4); const v = this.dv.getUint32(this.o, true); this.o += 4; return v; }
  f64() { this.need(8); const v = this.dv.getFloat64(this.o, true); this.o += 8; return v; }
  q8() { return this.u16() / 256; }
  bytes(n) { this.need(n); const v = this.b.slice(this.o, this.o + n); this.o += n; return v; }
  str(n) { this.need(n); const v = decoder.decode(this.b.subarray(this.o, this.o + n)); this.o += n; return v; }
}

// Chunk queue that hands out exact byte counts, however the stream splits them.
export class ByteQueue {
  constructor() {
    this.chunks = [];
    this.head = 0;
    this.size = 0;
  }
  push(chunk) {
    if (chunk.length === 0) return;
    this.chunks.push(chunk);
    this.size += chunk.length;
  }
  // Returns exactly n bytes, or null (consuming nothing) when fewer are queued.
  take(n) {
    if (this.size < n) return null;
    const out = new Uint8Array(n);
    let o = 0;
    while (o < n) {
      const c = this.chunks[0];
      const k = Math.min(c.length - this.head, n - o);
      out.set(c.subarray(this.head, this.head + k), o);
      o += k;
      this.head += k;
      if (this.head === c.length) { this.chunks.shift(); this.head = 0; }
    }
    this.size -= n;
    return out;
  }
}

// Splits a stream of u16-length-prefixed messages into payloads (type byte first).
export class Deframer {
  constructor() {
    this.queue = new ByteQueue();
    this.want = -1;
  }
  push(chunk) {
    this.queue.push(chunk);
    const out = [];
    for (;;) {
      if (this.want < 0) {
        const h = this.queue.take(2);
        if (!h) break;
        this.want = h[0] | (h[1] << 8);
        if (this.want === 0) throw new RangeError('empty control message');
      }
      const body = this.queue.take(this.want);
      if (!body) break;
      this.want = -1;
      out.push(body);
    }
    return out;
  }
}

function frame(payload) {
  const out = new Uint8Array(2 + payload.length);
  new DataView(out.buffer).setUint16(0, payload.length, true);
  out.set(payload, 2);
  return out;
}

// ---- client -> server ----

export function encodeHello(name) {
  const bytes = encoder.encode(name);
  if (bytes.length < 1 || bytes.length > NAME_MAX) throw new RangeError(`name must be 1-${NAME_MAX} bytes`);
  const payload = new Uint8Array(2 + bytes.length);
  payload[0] = CTRL.HELLO;
  payload[1] = bytes.length;
  payload.set(bytes, 2);
  return frame(payload);
}

// entries: newest first, consecutive seqs; entry = {seq, buttons, yaw16, viewTick}.
export function encodeInput(entries) {
  const count = Math.min(entries.length, MAX_INPUTS);
  const out = new Uint8Array(6 + 7 * count);
  const dv = new DataView(out.buffer);
  dv.setUint8(0, DGRAM.INPUT);
  dv.setUint32(1, entries[0].seq, true);
  dv.setUint8(5, count);
  for (let i = 0; i < count; i++) {
    const e = entries[i], o = 6 + 7 * i;
    dv.setUint8(o, e.buttons);
    dv.setUint16(o + 1, e.yaw16, true);
    dv.setUint32(o + 3, e.viewTick >>> 0, true);
  }
  return out;
}

export function encodePing(timeMs) {
  const out = new Uint8Array(9);
  out[0] = DGRAM.PING;
  new DataView(out.buffer).setFloat64(1, timeMs, true);
  return out;
}

// Raw UTF-8 for a chat uni stream, trimmed and cut to CHAT_MAX bytes on a character boundary.
export function encodeChat(text) {
  let s = text.trim();
  let bytes = encoder.encode(s);
  while (bytes.length > CHAT_MAX) {
    s = s.slice(0, -1);
    bytes = encoder.encode(s);
  }
  return bytes;
}

export function encodeScoreboardRequest() {
  return Uint8Array.of(SCOREBOARD_REQUEST);
}

// ---- server -> client datagrams ----

function readWorld(r) {
  const players = [];
  for (let n = r.u8(); n > 0; n--) {
    const id = r.u8(), x = r.q8(), y = r.q8(), yaw16 = r.u16(), hp = r.u8(), flags = r.u8();
    players.push({
      id, x, y, yaw16, hp,
      alive: (flags & PLAYER_FLAG.ALIVE) !== 0,
      fired: (flags & PLAYER_FLAG.FIRED) !== 0,
    });
  }
  const projectiles = [];
  for (let n = r.u8(); n > 0; n--) {
    const id = r.u16(), x = r.q8(), y = r.q8(), owner = r.u8();
    projectiles.push({ id, x, y, owner });
  }
  const effects = [];
  for (let n = r.u8(); n > 0; n--) {
    const kind = r.u8(), owner = r.u8();
    const x1 = r.q8(), y1 = r.q8(), x2 = r.q8(), y2 = r.q8();
    effects.push({ kind, owner, x1, y1, x2, y2 });
  }
  return { players, projectiles, effects };
}

function readSnapshot(r) {
  const tick = r.u32(), ackSeq = r.u32();
  const selfX = r.f64(), selfY = r.f64();
  const selfHp = r.u8(), selfFlags = r.u8();
  const respawnMs = r.u16(), rocketCooldownMs = r.u16();
  return {
    tick, ackSeq, selfX, selfY, selfHp,
    selfAlive: (selfFlags & SELF_FLAG_ALIVE) !== 0,
    respawnMs, rocketCooldownMs,
    ...readWorld(r),
  };
}

// Returns {kind: 'snapshot', ...} or {kind: 'pong', timeMs}. Throws on malformed input.
export function decodeDatagram(bytes) {
  const r = new Reader(bytes);
  const type = r.u8();
  if (type === DGRAM.SNAPSHOT) return { kind: 'snapshot', ...readSnapshot(r) };
  if (type === DGRAM.PONG && bytes.length === 9) return { kind: 'pong', timeMs: r.f64() };
  throw new Error(`unexpected datagram type ${type}`);
}

// ---- server -> client control stream (payload = type byte + body) ----

function readPlayers(r) {
  const out = [];
  for (let n = r.u8(); n > 0; n--) {
    const id = r.u8();
    const name = r.str(r.u8());
    const kills = r.u16(), deaths = r.u16();
    out.push({ id, name, kills, deaths });
  }
  return out;
}

export function decodeControl(bytes) {
  const r = new Reader(bytes);
  const type = r.u8();
  switch (type) {
    case CTRL.WELCOME: {
      const yourId = r.u8(), tickRate = r.u16(), snapshotRate = r.u16();
      const w = r.u8(), h = r.u8();
      const cells = r.bytes(w * h);
      const players = readPlayers(r);
      return { event: 'welcome', yourId, tickRate, snapshotRate, map: { w, h, cells }, players };
    }
    case CTRL.JOIN: {
      const id = r.u8();
      const name = r.str(r.u8());
      return { event: 'join', id, name };
    }
    case CTRL.LEAVE:
      return { event: 'leave', id: r.u8() };
    case CTRL.KILL: {
      const killer = r.u8(), victim = r.u8(), weapon = r.u8();
      return { event: 'kill', killer, victim, weapon };
    }
    case CTRL.CHAT: {
      const id = r.u8();
      const text = r.str(r.u8());
      return { event: 'chat', id, text };
    }
    case CTRL.NOTICE:
      return { event: 'notice', text: r.str(r.u8()) };
    default:
      throw new Error(`unknown control message ${type}`);
  }
}

// Scoreboard response body (no framing; the stream FIN ends it).
export function decodeScoreboard(bytes) {
  return readPlayers(new Reader(bytes));
}

// ---- killcam server uni stream ----

export function decodeKillcamHeader(bytes) {
  const r = new Reader(bytes);
  const kind = r.u8();
  if (kind !== KILLCAM_KIND) throw new Error(`unknown uni stream kind ${kind}`);
  const killerId = r.u8(), victimId = r.u8(), frameCount = r.u16();
  return { killerId, victimId, frameCount };
}

// bytes = u32 tick + world frame body (the u16 length prefix is already removed).
export function decodeKillcamFrame(bytes) {
  const r = new Reader(bytes);
  const tick = r.u32();
  return { tick, ...readWorld(r) };
}
