// Browser game client: input, prediction, interpolation, killcam, HUD.

import { SkirmishConnection } from './net.js';
import { ClientState, SnapshotBuffer, collectEffects } from './client_state.js';
import { createRenderer, drawMinimap } from './render.js';
import { BUTTON, CLOSE_TEXT, WEAPON_NAME, NAME_MAX } from './protocol.js';
import { TICK_RATE, radToYaw16, yaw16ToRad, wrapAngle } from './sim.js';

const STEP_MS = 1000 / TICK_RATE;
const MOUSE_SENS = 0.0022;
const ROCKET_COOLDOWN_MS = 1500;
const MINI_PX = 180;
const $ = (id) => document.getElementById(id);
const el = {
  canvas: $('view'), mini: $('minimap'), overlay: $('overlay'), join: $('join'), name: $('name'),
  connect: $('connect'), joinMsg: $('joinmsg'), health: $('health'), rocketBar: $('rocket-bar'),
  respawn: $('respawn'), dead: $('dead'), killcam: $('killcam'), killcamText: $('killcam-text'),
  feed: $('feed'), chatlog: $('chatlog'), chatbox: $('chatbox'), chatInput: $('chatinput'),
  scoreboard: $('scoreboard'), stats: $('stats'),
};
const enc = new TextEncoder();

let conn = null;
let state = null;            // ClientState once welcomed
let snaps = new SnapshotBuffer();
let killcam = null;          // {killer, frames, finished, startAt, skipped, reason}
let alive = true;
let respawnAt = 0;
let rocketReadyAt = 0;
let hp = 100;
let yaw = 0;                 // local view yaw (radians)
const keys = new Set();
let mouseFire = false, mouseRocket = false, fireLatch = false, rocketLatch = false;
let gunKick = 0, lastShotAt = -1e9;
let chatOpen = false, scoreOpen = false, showStats = false, showMini = true;
let scoreRows = null;
let acc = 0, last = performance.now(), lastHud = 0;

const renderer = createRenderer(el.canvas);
// Headless test hook: ?autoplay=NAME joins immediately and needs no pointer lock.
const AUTOPLAY = new URLSearchParams(location.search).get('autoplay');
const miniCtx = el.mini.getContext('2d');

function nameOf(id) {
  return conn?.players.get(id)?.name ?? `#${id}`;
}

function showJoinMsg(text) {
  el.joinMsg.textContent = text;
}

function logLine(text, cls = '') {
  const d = document.createElement('div');
  if (cls) d.className = cls;
  d.textContent = text;
  el.chatlog.append(d);
  while (el.chatlog.children.length > 12) el.chatlog.firstChild.remove();
  setTimeout(() => d.remove(), 20000);
}

function addFeed(text) {
  const d = document.createElement('div');
  d.textContent = text;
  el.feed.prepend(d);
  while (el.feed.children.length > 6) el.feed.lastChild.remove();
  setTimeout(() => { d.style.opacity = '0'; }, 6000);
  setTimeout(() => d.remove(), 6600);
}

// ---- session ----

function bind(c) {
  // Handlers ignore events from a connection that has been replaced.
  const on = (event, fn) => c.on(event, (data) => { if (c === conn) fn(data); });

  on('welcome', (w) => {
    state = new ClientState(c.map);
    renderer.setMap(c.map);
    snaps = new SnapshotBuffer();
    killcam = null;
    alive = true;
    el.overlay.hidden = true;
    logLine(`joined as ${c.name} (${w.players.length} others here)`, 'sys');
  });
  on('snapshot', onSnapshot);
  on('join', (j) => logLine(`${j.name} joined`, 'sys'));
  on('leave', (l) => logLine(`${nameOf(l.id)} left`, 'sys'));
  on('kill', (k) => {
    addFeed(`${nameOf(k.killer)} [${WEAPON_NAME[k.weapon] || '?'}] ${nameOf(k.victim)}`);
  });
  on('chat', (m) => logLine(`${nameOf(m.id)}: ${m.text}`));
  on('notice', (n) => logLine(n.text, 'sys'));
  on('killcamStart', (h) => {
    killcam = { killer: h.killerId, victim: h.victimId, frames: [], finished: false, startAt: null, skipped: false, reason: '' };
  });
  on('killcamFrame', (f) => {
    if (!killcam) return;
    killcam.frames.push(f);
    if (killcam.startAt === null) killcam.startAt = performance.now();
  });
  on('killcamEnd', (e) => {
    if (killcam) {
      killcam.finished = true;
      killcam.reason = e.reason;
      if (!killcam.frames.length) killcam = null;
    }
  });
  on('closed', (info) => {
    state = null;
    killcam = null;
    scoreRows = null;
    el.overlay.hidden = false;
    el.connect.disabled = false;
    const text = CLOSE_TEXT[info.closeCode] || '';
    showJoinMsg(`disconnected: code ${info.closeCode ?? 'none'}${text ? ` (${text})` : ''}${info.reason ? ` - ${info.reason}` : ''}`);
    document.exitPointerLock?.();
  });
}

function onSnapshot(s) {
  if (!state) return;
  const now = performance.now();
  snaps.push(s, now);
  state.onSnapshot(s);
  const wasAlive = alive;
  alive = s.selfAlive;
  hp = s.selfHp;
  respawnAt = now + s.respawnMs;
  rocketReadyAt = now + s.rocketCooldownMs;
  if (alive && !wasAlive) killcam = null; // respawned: the killcam stream was reset
}

async function connectAs(name) {
  if (!name || enc.encode(name).length > NAME_MAX) {
    showJoinMsg(`name must be 1-${NAME_MAX} bytes`);
    return;
  }
  try {
    localStorage.setItem('skirmish-name', name);
  } catch {
    // Storage may be blocked; the name just is not remembered.
  }
  el.connect.disabled = true;
  showJoinMsg('connecting...');
  if (conn) conn.close();
  const c = new SkirmishConnection(name);
  conn = c;
  bind(c);
  try {
    await c.connect();
    showJoinMsg('joining...');
  } catch (err) {
    if (conn === c) showJoinMsg(`connect failed: ${err.message}`);
    el.connect.disabled = false;
  }
}

function join(event) {
  event.preventDefault();
  connectAs(el.name.value.trim());
}

// ---- input ----

function step() {
  if (!state || !conn) return;
  const now = performance.now();
  let buttons = 0;
  if (!chatOpen && alive) {
    if (keys.has('KeyW')) buttons |= BUTTON.FWD;
    if (keys.has('KeyS')) buttons |= BUTTON.BACK;
    if (keys.has('KeyA')) buttons |= BUTTON.LEFT;
    if (keys.has('KeyD')) buttons |= BUTTON.RIGHT;
    if (mouseFire || fireLatch) buttons |= BUTTON.FIRE;
    if (mouseRocket || rocketLatch) buttons |= BUTTON.ROCKET;
  }
  if (buttons & BUTTON.FIRE) {
    lastShotAt = now;
    gunKick = 1;
  }
  fireLatch = false;
  rocketLatch = false;
  const viewTick = Math.max(0, Math.floor(snaps.renderTick(now)));
  state.predict(buttons, radToYaw16(yaw), viewTick);
  conn.sendInput(state.recent());
}

function openChat() {
  chatOpen = true;
  keys.clear();
  el.chatbox.hidden = false;
  el.chatInput.focus();
}

function closeChat() {
  chatOpen = false;
  el.chatInput.value = '';
  el.chatbox.hidden = true;
  el.chatInput.blur();
}

function openScoreboard() {
  scoreOpen = true;
  el.scoreboard.hidden = false;
  renderScoreboard(conn ? [...conn.players.values()] : []);
  conn.requestScoreboard()
    .then((list) => { if (scoreOpen) renderScoreboard(list); })
    .catch(() => {});
}

function renderScoreboard(list) {
  const body = el.scoreboard.querySelector('tbody');
  body.replaceChildren();
  for (const p of [...list].sort((a, b) => b.kills - a.kills || a.deaths - b.deaths)) {
    const tr = document.createElement('tr');
    if (conn && p.id === conn.yourId) tr.className = 'me';
    for (const v of [p.name, p.kills, p.deaths]) {
      const td = document.createElement('td');
      td.textContent = String(v);
      tr.append(td);
    }
    body.append(tr);
  }
}

addEventListener('keydown', (e) => {
  if (e.target === el.chatInput || !state) return;
  if (e.code === 'KeyT' || (e.code === 'Enter' && !chatOpen)) {
    if (!chatOpen) {
      e.preventDefault();
      openChat();
    }
    return;
  }
  if (chatOpen) return;
  if (e.code === 'Tab') {
    e.preventDefault();
    if (!e.repeat && !scoreOpen) openScoreboard();
    return;
  }
  if (e.code === 'F3') {
    e.preventDefault();
    showStats = !showStats;
    el.stats.hidden = !showStats;
    return;
  }
  if (e.code === 'KeyM') {
    showMini = !showMini;
    el.mini.hidden = !showMini;
    return;
  }
  if (e.code === 'Space') {
    e.preventDefault();
    if (killcam && !killcam.finished) conn.abortKillcam();
    if (killcam) killcam.skipped = true;
    return;
  }
  if (e.code.startsWith('Key') || e.code.startsWith('Arrow')) e.preventDefault();
  keys.add(e.code);
});

addEventListener('keyup', (e) => {
  keys.delete(e.code);
  if (e.code === 'Tab') {
    scoreOpen = false;
    el.scoreboard.hidden = true;
  }
});
addEventListener('blur', () => keys.clear());
addEventListener('pagehide', () => conn?.close());

el.chatbox.addEventListener('submit', (e) => {
  e.preventDefault();
  const text = el.chatInput.value.trim();
  closeChat();
  if (text && conn) conn.sendChat(text);
});
el.chatInput.addEventListener('keydown', (e) => {
  if (e.code === 'Escape') {
    e.preventDefault();
    closeChat();
  }
});

el.canvas.addEventListener('mousedown', (e) => {
  if (!state) return;
  if (!AUTOPLAY && document.pointerLockElement !== el.canvas) {
    el.canvas.requestPointerLock?.();
    return;
  }
  if (e.button === 0) {
    mouseFire = true;
    fireLatch = true;
  } else if (e.button === 2) {
    mouseRocket = true;
    rocketLatch = true;
  }
});
addEventListener('mouseup', (e) => {
  if (e.button === 0) mouseFire = false;
  if (e.button === 2) mouseRocket = false;
});
el.canvas.addEventListener('contextmenu', (e) => e.preventDefault());
addEventListener('mousemove', (e) => {
  if (AUTOPLAY || document.pointerLockElement === el.canvas) yaw = wrapAngle(yaw + e.movementX * MOUSE_SENS);
});

el.join.addEventListener('submit', join);
addEventListener('resize', () => renderer.resize());
if (AUTOPLAY) {
  el.overlay.hidden = true;
  connectAs(AUTOPLAY.slice(0, NAME_MAX));
} else {
  try {
    el.name.value = localStorage.getItem('skirmish-name') || '';
  } catch {
    // Storage may be blocked.
  }
}

// ---- rendering ----

function liveScene(now) {
  const rt = snaps.renderTick(now);
  const ip = snaps.sample(rt);
  return {
    map: state.map,
    eye: { x: state.x, y: state.y, yaw },
    players: ip ? ip.players : [],
    projectiles: ip ? ip.projectiles : [],
    effects: collectEffects(snaps.items, rt),
    selfId: conn.yourId,
    names: nameOf,
    killcam: false,
    victimId: -1,
    dead: !alive,
    showGun: alive,
    gunKick,
    muzzle: now - lastShotAt < 70,
    time: now,
  };
}

// Killcam scene from the killer's eye, or null when the playback is over.
function killcamScene(now) {
  const kc = killcam;
  if (!kc || kc.skipped || kc.startAt === null) return null;
  const frames = kc.frames;
  let idx = Math.floor((now - kc.startAt) / STEP_MS);
  if (idx >= frames.length) {
    if (kc.finished) return null;
    idx = frames.length - 1; // still downloading: hold the last frame
  }
  const f = frames[idx];
  const killer = f.players.find((p) => p.id === kc.killer);
  if (!killer) return null;
  return {
    map: state.map,
    eye: { x: killer.x, y: killer.y, yaw: yaw16ToRad(killer.yaw16) },
    players: f.players,
    projectiles: f.projectiles,
    effects: collectEffects(frames.slice(Math.max(0, idx - 40), idx + 1), f.tick),
    selfId: kc.killer,
    names: nameOf,
    killcam: true,
    victimId: kc.victim,
    dead: true,
    showGun: false,
    gunKick: 0,
    muzzle: false,
    time: now,
  };
}

function render(now) {
  if (!state || !conn) return;
  const kscene = !alive ? killcamScene(now) : null;
  const scene = kscene || liveScene(now);
  renderer.render(scene);
  if (showMini) drawMinimap(miniCtx, MINI_PX, scene);
  el.killcam.hidden = !kscene;
  if (kscene) el.killcamText.textContent = `killed by ${nameOf(killcam.killer)}`;
  el.dead.hidden = alive;
  document.body.classList.toggle('dead', !alive);
}

function updateHud(now) {
  if (now - lastHud < 100 || !state) return;
  lastHud = now;
  el.health.textContent = alive ? `HP ${hp}` : 'DEAD';
  const cd = Math.max(0, rocketReadyAt - now);
  el.rocketBar.style.width = `${(100 * (1 - cd / ROCKET_COOLDOWN_MS)).toFixed(1)}%`;
  el.respawn.hidden = alive;
  if (!alive) el.respawn.textContent = `respawn in ${Math.ceil(Math.max(0, respawnAt - now) / 1000)}`;
  if (showStats && conn) {
    const s = conn.getStats();
    el.stats.textContent = [
      `rtt         ${s.rtt == null ? '-' : s.rtt.toFixed(1)} ms`,
      `snapshots/s ${s.snapsPerSec}`,
      `snap loss   ${s.lossPct.toFixed(2)} %`,
      `unacked in  ${state.pending.length}`,
      `pred error  ${state.errorLast.toFixed(4)} (avg ${state.errorAvg.toFixed(4)})`,
      `datagrams   in ${s.dgInPerSec}/s  out ${s.dgOutPerSec}/s`,
      `killcam     ${(s.killcamBytes / 1024).toFixed(1)} KiB`,
      `session     ${s.closed ? `closed ${s.closed.closeCode} ${s.closed.reason}` : 'open'}`,
    ].join('\n');
  }
}

function frame(now) {
  requestAnimationFrame(frame);
  acc += Math.min(now - last, 250);
  last = now;
  while (acc >= STEP_MS) {
    acc -= STEP_MS;
    step();
  }
  gunKick *= 0.85;
  render(performance.now());
  updateHud(now);
}

requestAnimationFrame(frame);
