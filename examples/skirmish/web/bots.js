// Bot clients: one SkirmishConnection per bot, driven by a shared 60 Hz accumulator.

import { SkirmishConnection } from './net.js';
import { ClientState, RENDER_DELAY_TICKS } from './client_state.js';
import { BUTTON, CLOSE_TEXT } from './protocol.js';
import { TICK_RATE, cellAt, hasLineOfSight, radToYaw16, wrapAngle } from './sim.js';

const STEP_MS = 1000 / TICK_RATE;
const TURN_FIGHT = 0.12;
const TURN_WALK = 0.08;
const RECONNECT_MS = 2000;
const CHAT_LINES = [
  'gg', 'nice shot', 'anyone got a rocket?', 'this map is tight',
  'strafing is for the weak', 'lag?', 'brb', 'reloading my patience',
  'eventloop goes brrr', 'wall hugger here',
];
const NEIGHBOURS = [[1, 0], [-1, 0], [0, 1], [0, -1]];
const N = Math.min(64, Math.max(1, parseInt(new URLSearchParams(location.search).get('n') || '8', 10) || 8));
const $ = (id) => document.getElementById(id);
const rand = (a, b) => a + Math.random() * (b - a);
const clamp = (v, m) => Math.max(-m, Math.min(m, v));

let stopped = false;

// Floor cells reachable from start (4-connected), as [cx, cy] pairs.
function reachableCells(map, start) {
  const seen = new Set([start[1] * map.w + start[0]]);
  const queue = [start];
  const out = [];
  for (let i = 0; i < queue.length; i++) {
    const [cx, cy] = queue[i];
    if (cellAt(map, cx, cy) === 0) out.push([cx, cy]);
    for (const [dx, dy] of NEIGHBOURS) {
      const nx = cx + dx, ny = cy + dy;
      const key = ny * map.w + nx;
      if (seen.has(key) || cellAt(map, nx, ny) !== 0) continue;
      seen.add(key);
      queue.push([nx, ny]);
    }
  }
  return out;
}

class Bot {
  constructor(index) {
    this.name = `bot-${index}`;
    this.conn = null;
    this.state = null;
    this.snap = null;
    this.status = 'waiting';
    this.closeText = '';
    this.kcRecv = 0;
    this.kcAborted = 0;
    this.lastStats = null;
    this.yaw = rand(0, 2 * Math.PI);
    this.reachable = null;
    this.target = null;
    this.jitter = 0;
    this.jitterAt = 0;
    this.strafe = 0;
    this.strafeAt = 0;
    this.stuckAt = 0;
    this.stuckPos = null;
    this.chatAt = 0;
    this.scoreAt = 0;
    this.scoreBusy = false;
    this.reconnectTimer = null;
    this.reconnectAt = 0;
  }

  connect() {
    if (stopped) return;
    clearTimeout(this.reconnectTimer);
    const conn = new SkirmishConnection(this.name);
    this.conn = conn;
    this.status = 'connecting';
    this.closeText = '';
    this.state = null;
    this.snap = null;
    this.reachable = null;
    this.target = null;
    conn.on('welcome', (w) => {
      if (conn !== this.conn) return;
      this.state = new ClientState(w.map);
      this.status = 'joined';
      this.chatAt = performance.now() + rand(8000, 15000);
      this.scoreAt = performance.now() + rand(3000, 6000);
    });
    conn.on('snapshot', (s) => {
      if (conn !== this.conn || !this.state) return;
      this.state.onSnapshot(s);
      this.snap = s;
      this.status = s.selfAlive ? 'playing' : 'dead';
    });
    conn.on('killcamStart', () => {
      if (conn !== this.conn) return;
      this.kcRecv++;
      if (Math.random() < 0.5) {
        setTimeout(() => conn.abortKillcam(), rand(300, 1500));
      }
    });
    conn.on('killcamEnd', (e) => {
      if (conn === this.conn && e.reason === 'aborted') this.kcAborted++;
    });
    conn.on('closed', (info) => {
      if (conn !== this.conn) return;
      this.lastStats = conn.getStats();
      this.conn = null;
      this.state = null;
      this.snap = null;
      this.closeText = `${info.closeCode ?? '-'} ${CLOSE_TEXT[info.closeCode] ?? ''} ${info.reason || ''}`.trim();
      if (stopped) {
        this.status = 'stopped';
        return;
      }
      this.status = 'waiting';
      this.reconnectAt = performance.now() + RECONNECT_MS;
      this.reconnectTimer = setTimeout(() => this.connect(), RECONNECT_MS);
    });
    conn.connect().catch(() => {}); // failures arrive through the 'closed' event
  }

  stop() {
    clearTimeout(this.reconnectTimer);
    this.status = 'stopped';
    this.conn?.close();
  }

  step(now) {
    if (!this.state || !this.snap || !this.conn) return;
    const buttons = this.decide(now);
    const viewTick = Math.max(0, this.snap.tick - RENDER_DELAY_TICKS);
    this.state.predict(buttons, radToYaw16(this.yaw), viewTick);
    this.conn.sendInput(this.state.recent());
    this.maybeChat(now);
    this.maybeScoreboard(now);
  }

  decide(now) {
    const { x, y } = this.state;
    const map = this.state.map;
    if (!this.snap.selfAlive) {
      this.target = null;
      this.reachable = null;
      return 0;
    }
    if (!this.reachable) this.reachable = reachableCells(map, [Math.floor(x), Math.floor(y)]);
    const enemy = this.pickEnemy(x, y);
    if (enemy) {
      if (now >= this.jitterAt) {
        this.jitter = rand(-0.07, 0.07);
        this.jitterAt = now + 500;
      }
      let btn = 0;
      const dist = Math.hypot(enemy.x - x, enemy.y - y);
      const diff = wrapAngle(Math.atan2(enemy.y - y, enemy.x - x) + this.jitter - this.yaw);
      this.yaw += clamp(diff, TURN_FIGHT);
      if (Math.abs(diff) < 0.12) {
        btn |= BUTTON.FIRE;
        if (dist < 9 && Math.random() < 0.01) btn |= BUTTON.ROCKET;
      }
      if (now >= this.strafeAt) {
        this.strafe = [0, BUTTON.LEFT, BUTTON.RIGHT][Math.floor(Math.random() * 3)];
        this.strafeAt = now + rand(800, 1500);
      }
      btn |= this.strafe;
      if (dist > 3) btn |= BUTTON.FWD;
      return btn;
    }
    // Wander between reachable floor cells; re-pick when arrived or stuck.
    if (this.target && Math.hypot(this.target[0] + 0.5 - x, this.target[1] + 0.5 - y) < 0.4) this.target = null;
    if (now >= this.stuckAt) {
      if (this.stuckPos && Math.hypot(x - this.stuckPos[0], y - this.stuckPos[1]) < 0.15) this.target = null;
      this.stuckPos = [x, y];
      this.stuckAt = now + 2000;
    }
    if (!this.target && this.reachable.length) {
      this.target = this.reachable[Math.floor(Math.random() * this.reachable.length)];
    }
    if (!this.target) return 0;
    const tx = this.target[0] + 0.5, ty = this.target[1] + 0.5;
    const diff = wrapAngle(Math.atan2(ty - y, tx - x) - this.yaw);
    this.yaw += clamp(diff, TURN_WALK);
    return Math.abs(diff) < 0.6 ? BUTTON.FWD : 0;
  }

  // Nearest living enemy with a clear line of sight.
  pickEnemy(x, y) {
    const me = this.conn.yourId;
    const candidates = this.snap.players
      .filter((p) => p.id !== me && p.alive)
      .map((p) => ({ p, d: Math.hypot(p.x - x, p.y - y) }))
      .sort((a, b) => a.d - b.d);
    for (const { p } of candidates) {
      if (hasLineOfSight(this.state.map, x, y, p.x, p.y)) return p;
    }
    return null;
  }

  maybeChat(now) {
    if (now < this.chatAt) return;
    this.chatAt = now + rand(8000, 15000);
    this.conn.sendChat(CHAT_LINES[Math.floor(Math.random() * CHAT_LINES.length)]);
  }

  maybeScoreboard(now) {
    if (this.scoreBusy || now < this.scoreAt) return;
    this.scoreBusy = true;
    this.scoreAt = now + rand(3000, 6000);
    const conn = this.conn;
    conn.requestScoreboard()
      .catch(() => {})
      .finally(() => { this.scoreBusy = false; });
  }

  // Row data for the table.
  view(now) {
    const conn = this.conn;
    const st = conn ? conn.getStats() : this.lastStats;
    if (conn) this.lastStats = st;
    const me = conn ? conn.players.get(conn.yourId) : null;
    let status = this.status;
    if (status === 'waiting') status = `waiting ${Math.max(0, Math.ceil((this.reconnectAt - now) / 1000))}s`;
    return {
      name: this.name,
      status,
      rtt: st?.rtt ?? null,
      snaps: st?.snapsPerSec ?? 0,
      loss: st?.lossPct ?? 0,
      kills: me?.kills ?? 0,
      deaths: me?.deaths ?? 0,
      kc: `${this.kcRecv} / ${this.kcAborted}`,
      close: conn ? '' : this.closeText,
      connected: !!conn && !!this.snap,
    };
  }
}

const bots = [];
for (let i = 1; i <= N; i++) bots.push(new Bot(i));

const tbody = $('table').querySelector('tbody');
const tfoot = $('table').querySelector('tfoot');
const rows = bots.map(() => {
  const tr = document.createElement('tr');
  for (let c = 0; c < 8; c++) tr.append(document.createElement('td'));
  tbody.append(tr);
  return tr;
});
const totalsRow = document.createElement('tr');
for (let c = 0; c < 8; c++) totalsRow.append(document.createElement('td'));
tfoot.append(totalsRow);

function renderTable() {
  const now = performance.now();
  let connected = 0, snaps = 0, loss = 0, rttSum = 0, rttN = 0;
  let kills = 0, deaths = 0, kcRecv = 0, kcAborted = 0;
  bots.forEach((bot, i) => {
    const v = bot.view(now);
    const cells = rows[i].children;
    const values = [
      v.name, v.status, v.rtt == null ? '-' : v.rtt.toFixed(1), v.snaps, v.loss.toFixed(2),
      `${v.kills} / ${v.deaths}`, v.kc, v.close,
    ];
    values.forEach((t, c) => { cells[c].textContent = String(t); });
    rows[i].classList.toggle('bad', v.status === 'waiting' || v.status === 'stopped');
    if (v.connected) connected++;
    if (v.rtt != null && v.connected) { rttSum += v.rtt; rttN++; }
    snaps += v.snaps;
    loss += v.connected ? v.loss : 0;
    kills += v.kills;
    deaths += v.deaths;
    kcRecv += bot.kcRecv;
    kcAborted += bot.kcAborted;
  });
  const avgRtt = rttN ? (rttSum / rttN).toFixed(1) : '-';
  const avgLoss = connected ? (loss / connected).toFixed(2) : '-';
  const totals = ['total', `${connected} / ${N} live`, avgRtt, snaps, avgLoss,
    `${kills} / ${deaths}`, `${kcRecv} / ${kcAborted}`, ''];
  totals.forEach((t, c) => { totalsRow.children[c].textContent = String(t); });
  $('summary').textContent = `${N} bots, ${connected} connected`;
}

$('stop').addEventListener('click', () => {
  stopped = true;
  for (const b of bots) b.stop();
  $('stop').disabled = true;
  renderTable();
});
addEventListener('pagehide', () => { for (const b of bots) b.conn?.close(); });

bots.forEach((bot, i) => setTimeout(() => bot.connect(), i * 200));

let lastT = performance.now(), acc = 0;
setInterval(() => {
  const now = performance.now();
  acc += Math.min(now - lastT, 250);
  lastT = now;
  while (acc >= STEP_MS) {
    acc -= STEP_MS;
    for (const b of bots) b.step(now);
  }
}, 8);
setInterval(renderTable, 500);
renderTable();
