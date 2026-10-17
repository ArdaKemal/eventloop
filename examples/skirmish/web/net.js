// WebTransport session for both the game and the bots.

import {
  PROTOCOL_NAME, encodeHello, encodeInput, encodePing, encodeChat,
  encodeScoreboardRequest, decodeControl, decodeDatagram, decodeScoreboard,
  decodeKillcamHeader, decodeKillcamFrame, ByteQueue, Deframer,
} from './protocol.js';

// localhost resolves to ::1 first and Chrome's WebTransport does not fall back
// to IPv4, while the server binds 127.0.0.1 by default. Reload on the IPv4
// literal so the page origin and the WebTransport authority stay equal.
if (location.hostname === 'localhost') {
  location.replace(location.href.replace('//localhost', '//127.0.0.1'));
}

const MAX_DATAGRAMS_IN_FLIGHT = 64;
const KILLCAM_HEADER_BYTES = 5;

export class SkirmishConnection {
  constructor(name) {
    this.name = name;
    this.handlers = new Map();
    this.wt = null;
    this.ctrlWriter = null;
    this.dgWriter = null;
    this.yourId = -1;
    this.map = null;
    this.tickRate = 60;
    this.snapshotRate = 30;
    this.players = new Map(); // id -> {id, name, kills, deaths}
    this.closed = false;      // no further sends
    this.reported = false;    // 'closed' event emitted
    this.closeInfo = null;
    this.killcam = null;      // active killcam {reader, aborted}
    this.rtt = null;
    this.lastSnapTick = -1;
    this.dgInFlight = 0;
    this.timers = [];
    this.counters = { snaps: 0, snapsStale: 0, snapsLost: 0, dgIn: 0, dgOut: 0, dgDropped: 0, killcamBytes: 0 };
    this.prevCounters = null;
    this.rates = { snapsPerSec: 0, dgInPerSec: 0, dgOutPerSec: 0 };
  }

  // Events: welcome, join, leave, kill, chat, notice, snapshot, killcamStart,
  // killcamFrame, killcamEnd, closed ({closeCode, reason}).
  on(event, fn) {
    this.handlers.set(event, fn);
    return this;
  }

  emit(event, data) {
    const fn = this.handlers.get(event);
    if (!fn) return;
    try {
      fn(data);
    } catch (err) {
      console.error(`skirmish handler ${event} failed`, err);
    }
  }

  async connect() {
    try {
      const res = await fetch('/cert-hash', { cache: 'no-store' });
      if (!res.ok) throw new Error(`cert-hash HTTP ${res.status}`);
      const { sha256 } = await res.json();
      const value = Uint8Array.from(atob(sha256), (c) => c.charCodeAt(0));
      this.wt = new WebTransport(`https://${location.host}/arena`, {
        serverCertificateHashes: [{ algorithm: 'sha-256', value }],
        protocols: [PROTOCOL_NAME],
      });
      this.wt.closed.then(
        (info) => this.onClosed(info?.closeCode ?? 0, info?.reason ?? ''),
        (err) => this.onClosed(err?.closeCode ?? null, err?.message || 'session failed'),
      );
      await this.wt.ready;
      const control = await this.wt.createBidirectionalStream();
      this.ctrlWriter = control.writable.getWriter();
      await this.ctrlWriter.write(encodeHello(this.name));
      this.dgWriter = this.wt.datagrams.writable.getWriter();
      this.readControl(control.readable);
      this.readDatagrams();
      this.readUnidirectional();
      this.timers.push(setInterval(() => this.sendDatagram(encodePing(performance.now())), 500));
      this.timers.push(setInterval(() => this.updateRates(), 1000));
    } catch (err) {
      this.onClosed(null, err?.message || String(err));
      throw err;
    }
  }

  async readControl(readable) {
    const deframer = new Deframer();
    const reader = readable.getReader();
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        for (const msg of deframer.push(value)) {
          let event;
          try {
            event = decodeControl(msg);
          } catch {
            this.closeSession(3, 'protocol error');
            return;
          }
          this.onControl(event);
        }
      }
    } catch {
      // Stream error: the session close event reports the outcome.
    }
  }

  onControl(ev) {
    switch (ev.event) {
      case 'welcome':
        this.yourId = ev.yourId;
        this.map = ev.map;
        this.tickRate = ev.tickRate;
        this.snapshotRate = ev.snapshotRate;
        this.players = new Map(ev.players.map((p) => [p.id, p]));
        break;
      case 'join':
        this.players.set(ev.id, { id: ev.id, name: ev.name, kills: 0, deaths: 0 });
        break;
      case 'leave':
        this.players.delete(ev.id);
        break;
      case 'kill': {
        const killer = this.players.get(ev.killer);
        if (killer) killer.kills++;
        const victim = this.players.get(ev.victim);
        if (victim) victim.deaths++;
        break;
      }
      default:
        break;
    }
    this.emit(ev.event, ev);
  }

  async readDatagrams() {
    const reader = this.wt.datagrams.readable.getReader();
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        this.counters.dgIn++;
        this.onDatagram(value);
      }
    } catch {
      // Session closing.
    }
  }

  onDatagram(bytes) {
    let msg;
    try {
      msg = decodeDatagram(bytes);
    } catch {
      return; // malformed datagrams are dropped
    }
    if (msg.kind === 'pong') {
      this.rtt = performance.now() - msg.timeMs;
      return;
    }
    if (msg.tick <= this.lastSnapTick) {
      this.counters.snapsStale++;
      return;
    }
    if (this.lastSnapTick >= 0) {
      const step = this.tickRate / this.snapshotRate;
      this.counters.snapsLost += Math.max(0, Math.round((msg.tick - this.lastSnapTick) / step) - 1);
    }
    this.lastSnapTick = msg.tick;
    this.counters.snaps++;
    this.emit('snapshot', msg);
  }

  async readUnidirectional() {
    const reader = this.wt.incomingUnidirectionalStreams.getReader();
    try {
      for (;;) {
        const { value: stream, done } = await reader.read();
        if (done) break;
        this.readKillcam(stream);
      }
    } catch {
      // Session closing.
    }
  }

  // Killcam: u8 kind, u8 killer, u8 victim, u16 count, then count x {u16 len, u32 tick, body}.
  async readKillcam(stream) {
    const reader = stream.getReader();
    const kc = { reader, aborted: false };
    if (this.killcam) this.abortKillcam();
    this.killcam = kc;
    const queue = new ByteQueue();
    let header = null, received = 0, want = -1;
    let reason = 'complete';
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        this.counters.killcamBytes += value.length;
        queue.push(value);
        if (!header) {
          const h = queue.take(KILLCAM_HEADER_BYTES);
          if (h) {
            header = decodeKillcamHeader(h);
            this.emit('killcamStart', header);
          }
        }
        while (header && received < header.frameCount) {
          if (want < 0) {
            const l = queue.take(2);
            if (!l) break;
            want = l[0] | (l[1] << 8);
          }
          const entry = queue.take(want);
          if (!entry) break;
          want = -1;
          received++;
          this.emit('killcamFrame', decodeKillcamFrame(entry));
        }
      }
      if (kc.aborted) reason = 'aborted';
      else if (!header || received < header.frameCount) reason = 'truncated';
    } catch {
      reason = kc.aborted ? 'aborted' : 'reset';
    }
    if (this.killcam === kc) this.killcam = null;
    this.emit('killcamEnd', { reason, received, total: header ? header.frameCount : 0 });
  }

  // Cancels the killcam stream (STOP_SENDING). Returns false if none is in progress.
  abortKillcam() {
    const kc = this.killcam;
    if (!kc || kc.aborted) return false;
    kc.aborted = true;
    kc.reader.cancel().catch(() => {});
    return true;
  }

  sendInput(entries) {
    if (!entries.length) return false;
    return this.sendDatagram(encodeInput(entries));
  }

  sendDatagram(bytes) {
    if (!this.dgWriter || this.closed) return false;
    if (this.dgInFlight >= MAX_DATAGRAMS_IN_FLIGHT) {
      this.counters.dgDropped++;
      return false;
    }
    this.dgInFlight++;
    this.dgWriter.write(bytes).catch(() => {}).finally(() => { this.dgInFlight--; });
    this.counters.dgOut++;
    return true;
  }

  // One bidi stream: request, FIN, response to FIN. Updates kills/deaths in the roster.
  async requestScoreboard() {
    const stream = await this.wt.createBidirectionalStream();
    const writer = stream.writable.getWriter();
    await writer.write(encodeScoreboardRequest());
    await writer.close();
    const reader = stream.readable.getReader();
    const parts = [];
    let total = 0;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      parts.push(value);
      total += value.length;
    }
    const bytes = new Uint8Array(total);
    let o = 0;
    for (const p of parts) {
      bytes.set(p, o);
      o += p.length;
    }
    const list = decodeScoreboard(bytes);
    for (const e of list) {
      const p = this.players.get(e.id);
      if (p) {
        p.kills = e.kills;
        p.deaths = e.deaths;
      }
    }
    return list;
  }

  async sendChat(text) {
    const bytes = encodeChat(text);
    if (!bytes.length || this.closed) return false;
    try {
      const stream = await this.wt.createUnidirectionalStream();
      const writer = stream.getWriter();
      await writer.write(bytes);
      await writer.close();
      return true;
    } catch {
      return false;
    }
  }

  onClosed(closeCode, reason) {
    this.closed = true;
    for (const t of this.timers) clearInterval(t);
    this.timers = [];
    if (this.reported) return;
    this.reported = true;
    this.closeInfo = { closeCode, reason };
    this.emit('closed', this.closeInfo);
  }

  closeSession(code, reason) {
    if (!this.wt || this.closed) return;
    this.closed = true;
    this.ctrlWriter?.close().catch(() => {});
    try {
      this.wt.close({ closeCode: code, reason });
    } catch {
      // Already closed.
    }
  }

  close() {
    this.closeSession(0, 'client left');
  }

  updateRates() {
    const c = this.counters, p = this.prevCounters || { snaps: 0, dgIn: 0, dgOut: 0 };
    this.rates = {
      snapsPerSec: c.snaps - p.snaps,
      dgInPerSec: c.dgIn - p.dgIn,
      dgOutPerSec: c.dgOut - p.dgOut,
    };
    this.prevCounters = { ...c };
  }

  getStats() {
    const c = this.counters;
    const seen = c.snaps + c.snapsLost;
    return {
      rtt: this.rtt,
      snapsPerSec: this.rates.snapsPerSec,
      dgInPerSec: this.rates.dgInPerSec,
      dgOutPerSec: this.rates.dgOutPerSec,
      lossPct: seen ? (100 * c.snapsLost) / seen : 0,
      killcamBytes: c.killcamBytes,
      closed: this.closeInfo,
    };
  }
}
