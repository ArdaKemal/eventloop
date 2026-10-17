// Client-side prediction, reconciliation and snapshot interpolation.
// Shared by the game (game.js) and the bots (bots.js).

import { MAX_INPUTS } from './protocol.js';
import { stepMove, TICK_RATE } from './sim.js';

export const RENDER_DELAY_TICKS = 6; // 100 ms at 60 Hz
export const SNAPSHOT_HISTORY = 32;
export const INPUT_HISTORY = 240;    // bounded unacked inputs

// Own predicted position. predict() is called once per 1/60 s step; onSnapshot()
// drops acked inputs, resets to the authoritative position and replays the rest.
export class ClientState {
  constructor(map) {
    this.map = map;
    this.seq = 0;
    this.pending = [];   // {seq, buttons, yaw16, viewTick, x, y} oldest first
    this.x = 0;
    this.y = 0;
    this.alive = true;
    this.ackSeq = 0;
    this.errorLast = 0; // prediction error (map units) at the last reconcile
    this.errorAvg = 0;  // exponentially weighted average of the same
  }

  predict(buttons, yaw16, viewTick) {
    this.seq += 1;
    const p = stepMove(this.map, this.x, this.y, buttons, yaw16, this.alive);
    this.x = p.x;
    this.y = p.y;
    this.pending.push({ seq: this.seq, buttons, yaw16, viewTick, x: this.x, y: this.y });
    if (this.pending.length > INPUT_HISTORY) this.pending.shift();
    return this.seq;
  }

  // Up to MAX_INPUTS newest pending inputs, newest first (for encodeInput).
  recent() {
    return this.pending.slice(-MAX_INPUTS).reverse();
  }

  // Returns the prediction error measured at this snapshot, or null when no
  // pending input matches ack_seq.
  onSnapshot(snap) {
    let error = null;
    const acked = this.pending.find((e) => e.seq === snap.ackSeq);
    if (acked) {
      error = Math.hypot(acked.x - snap.selfX, acked.y - snap.selfY);
      this.errorLast = error;
      this.errorAvg = this.errorAvg * 0.95 + error * 0.05;
    }
    this.pending = this.pending.filter((e) => e.seq > snap.ackSeq);
    this.ackSeq = Math.max(this.ackSeq, snap.ackSeq);
    this.alive = snap.selfAlive;
    let x = snap.selfX, y = snap.selfY;
    for (const e of this.pending) {
      const p = stepMove(this.map, x, y, e.buttons, e.yaw16, this.alive);
      x = p.x;
      y = p.y;
      e.x = x;
      e.y = y;
    }
    this.x = x;
    this.y = y;
    return error;
  }
}

const wrap16 = (v) => ((v % 65536) + 65536) % 65536;
const lerp = (a, b, t) => a + (b - a) * t;
function lerpYaw16(a, b, t) {
  const d = wrap16(b - a + 32768) - 32768;
  return wrap16(a + d * t);
}

function blend(aList, bList, mix) {
  const byId = new Map(aList.map((e) => [e.id, e]));
  return bList.map((q) => {
    const p = byId.get(q.id);
    return p ? mix(p, q) : q;
  });
}

// Recent snapshots (each carries .at = local arrival time in ms).
export class SnapshotBuffer {
  constructor(capacity = SNAPSHOT_HISTORY) {
    this.items = [];
    this.capacity = capacity;
  }

  push(snap, now) {
    snap.at = now;
    this.items.push(snap);
    if (this.items.length > this.capacity) this.items.shift();
  }

  get newest() {
    return this.items.length ? this.items[this.items.length - 1] : null;
  }

  // Server tick being rendered: RENDER_DELAY_TICKS behind the estimated current tick,
  // clamped to the buffered range.
  renderTick(now, tickRate = TICK_RATE) {
    const n = this.newest;
    if (!n) return 0;
    const est = n.tick + (now - n.at) * tickRate / 1000;
    const oldest = this.items[0].tick;
    return Math.min(n.tick, Math.max(oldest, est - RENDER_DELAY_TICKS));
  }

  // Interpolated {players, projectiles} at a (possibly fractional) tick, or null.
  sample(tick) {
    const items = this.items;
    if (!items.length) return null;
    let j = 0;
    while (j < items.length && items[j].tick <= tick) j++;
    if (j === 0) return { players: items[0].players, projectiles: items[0].projectiles };
    if (j === items.length) {
      const last = items[j - 1];
      return { players: last.players, projectiles: last.projectiles };
    }
    const a = items[j - 1], b = items[j];
    const t = (tick - a.tick) / (b.tick - a.tick);
    return {
      players: blend(a.players, b.players, (p, q) => ({
        id: q.id,
        x: lerp(p.x, q.x, t),
        y: lerp(p.y, q.y, t),
        yaw16: lerpYaw16(p.yaw16, q.yaw16, t),
        hp: q.hp,
        alive: q.alive,
        fired: q.fired,
      })),
      projectiles: blend(a.projectiles, b.projectiles, (p, q) => ({
        id: q.id,
        x: lerp(p.x, q.x, t),
        y: lerp(p.y, q.y, t),
        owner: q.owner,
      })),
    };
  }
}

// Effects from frames (snapshots or killcam frames) created within the last
// `window` ticks before `tick`. Each gets .age in seconds.
export function collectEffects(frames, tick, window = 36) {
  const out = [];
  for (const f of frames) {
    if (f.tick > tick || tick - f.tick >= window) continue;
    const age = (tick - f.tick) / TICK_RATE;
    for (const e of f.effects) out.push({ ...e, age });
  }
  return out;
}
