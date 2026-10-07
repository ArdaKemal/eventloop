// Parley browser client. No build step and no dependencies.
//
// Realtime events arrive over a WebSocket (RFC 8441 Extended CONNECT on the
// page's HTTP/2 connection) or, when the browser cannot open one, over
// server-sent events with commands posted to /api/command.

const $ = (id) => document.getElementById(id);
const MAX_UPLOAD = 16 * 1024 * 1024;
const TYPING_INTERVAL = 3000;
const TYPING_TIMEOUT = 4500;

const state = {
  me: null,
  users: new Map(),
  convs: new Map(),
  active: null,
  typing: new Map(), // conv id -> Map(user id -> {timer, recording})
  replyTo: null,
  lastTypingSent: 0,
};

// ---------------------------------------------------------------------------
// Helpers

function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value == null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'dataset') Object.assign(node.dataset, value);
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else if (key in node && typeof value !== 'string') node[key] = value;
    else node.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat()) {
    if (child == null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function icon(name, cls) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  if (cls) svg.setAttribute('class', cls);
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', `#i-${name}`);
  svg.append(use);
  return svg;
}

const COLORS = ['#00a884', '#7f66ff', '#ff2e74', '#007bfc', '#f79d00', '#02a698', '#d3396d', '#5f66cd', '#a62c71', '#1fa855'];
const colorFor = (id) => COLORS[id % COLORS.length];

function initials(name) {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  return ((parts[0]?.[0] ?? '?') + (parts.length > 1 ? parts.at(-1)[0] : '')).toUpperCase();
}

function avatar(conv, size = '') {
  if (conv.group) {
    return h('div', { class: `avatar ${size}`, style: `background:${colorFor(conv.id + 3)}` }, icon('group'));
  }
  const user = conv.user ?? peerOf(conv);
  return h('div', {
    class: `avatar ${size}${user?.online && !conv.self ? ' online' : ''}`,
    style: `background:${colorFor(user?.id ?? 0)}`,
  }, initials(user?.name ?? '?'));
}

function userAvatar(user, size = '') {
  return avatar({ user, group: false, self: user.id === state.me?.id }, size);
}

const clock = (time) => new Date(time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

function dayLabel(time) {
  const date = new Date(time);
  const today = new Date();
  const yesterday = new Date(today.getFullYear(), today.getMonth(), today.getDate() - 1);
  if (date.toDateString() === today.toDateString()) return 'Today';
  if (date.toDateString() === yesterday.toDateString()) return 'Yesterday';
  if (today - date < 6 * 864e5) return date.toLocaleDateString([], { weekday: 'long' });
  return date.toLocaleDateString([], { day: 'numeric', month: 'long', year: 'numeric' });
}

function listTime(time) {
  const label = dayLabel(time);
  return label === 'Today' ? clock(time) : label.length > 10 ? new Date(time).toLocaleDateString() : label;
}

function lastSeen(user) {
  if (user.online) return 'online';
  if (!user.last_seen) return user.about || 'offline';
  const label = dayLabel(user.last_seen);
  return `last seen ${label === 'Today' ? 'today' : label.toLowerCase()} at ${clock(user.last_seen)}`;
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} kB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function formatDuration(ms) {
  if (!Number.isFinite(ms) || ms < 0) ms = 0;
  const seconds = Math.round(ms / 1000);
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
}

function linkify(text) {
  const nodes = [];
  const pattern = /\bhttps?:\/\/[^\s<>"']+[^\s<>"'.,;:!?)\]]/g;
  let last = 0;
  for (const match of text.matchAll(pattern)) {
    nodes.push(text.slice(last, match.index));
    nodes.push(h('a', { href: match[0], target: '_blank', rel: 'noopener noreferrer' }, match[0]));
    last = match.index + match[0].length;
  }
  nodes.push(text.slice(last));
  return nodes;
}

let toastTimer;
function toast(text) {
  const node = $('toast');
  node.textContent = text;
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.hidden = true; }, 3500);
}

// ---------------------------------------------------------------------------
// Server API

class HttpError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

async function api(path, body) {
  const init = body === undefined ? {} : {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  };
  const response = await fetch(path, init);
  let data = {};
  try { data = await response.json(); } catch { /* empty body */ }
  if (!response.ok) throw new HttpError(data.error || response.statusText, response.status);
  return data;
}

function upload(file, onProgress) {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    // The server refuses path separators, quotes, and line breaks in names.
    const name = (file.name || 'file').replace(/[\\/"\r\n]/g, '_').slice(0, 120);
    request.open('POST', `/api/upload?name=${encodeURIComponent(name)}`);
    request.setRequestHeader('content-type', file.type || 'application/octet-stream');
    request.upload.onprogress = (event) => event.lengthComputable && onProgress(event.loaded / event.total);
    request.onload = () => {
      let data = {};
      try { data = JSON.parse(request.responseText); } catch { /* not JSON */ }
      if (request.status === 201) resolve(data.media);
      else reject(new HttpError(data.error || `Upload failed (${request.status})`, request.status));
    };
    request.onerror = () => reject(new HttpError('Upload failed', 0));
    request.send(file);
  });
}

// ---------------------------------------------------------------------------
// Realtime transport

const realtime = {
  socket: null,
  events: null,
  mode: null,
  websocketBroken: false,
  attempt: 0,
  timer: null,

  start() {
    clearTimeout(this.timer);
    if (this.websocketBroken || !('WebSocket' in window)) this.openEvents();
    else this.openSocket();
  },

  openSocket() {
    const socket = new WebSocket(`wss://${location.host}/api/ws`);
    let opened = false;
    socket.onopen = () => { opened = true; this.socket = socket; this.connected('WebSocket'); };
    socket.onmessage = (event) => receive(event.data);
    socket.onclose = async () => {
      if (this.socket === socket) this.socket = null;
      if (opened) { this.lost(); return; }
      // Refused while plain requests work: no Extended CONNECT on this
      // connection (HTTP/1.1, or HTTP/3 in browsers without RFC 9220).
      // Use server-sent events instead.
      const reachable = await fetch('/api/bootstrap').then((r) => r.ok, () => false);
      if (!reachable) { this.lost(); return; }
      this.websocketBroken = true;
      this.openEvents();
    };
  },

  openEvents() {
    const events = new EventSource('/api/events');
    this.events = events;
    events.onopen = () => this.connected('server-sent events');
    events.onmessage = (event) => receive(event.data);
    events.onerror = () => {
      if (events.readyState !== EventSource.CLOSED) { showConnection('Reconnecting…'); return; }
      if (this.events === events) this.events = null;
      this.lost();
    };
  },

  connected(mode) {
    this.mode = mode;
    this.attempt = 0;
    showConnection(null);
    resync();
  },

  lost() {
    if (!state.me) return;
    showConnection('Connecting…', true);
    const delay = Math.min(30000, 1000 * 2 ** this.attempt++);
    this.timer = setTimeout(async () => {
      try { await api('/api/bootstrap'); } catch (error) {
        if (error.status === 401) { signedOut(); return; }
      }
      this.start();
    }, delay);
  },

  stop() {
    clearTimeout(this.timer);
    const { socket, events } = this;
    this.socket = this.events = null;
    socket?.close();
    events?.close();
  },

  send(command) {
    if (this.socket?.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify(command));
      return Promise.resolve();
    }
    return api('/api/command', command);
  },
};

function showConnection(text, offline = false) {
  const node = $('connection');
  node.hidden = !text;
  node.textContent = text ?? '';
  node.classList.toggle('offline', offline);
  updateTransport();
}

function updateTransport() {
  const navigation = performance.getEntriesByType('navigation')[0];
  const protocol = { h2: 'HTTP/2', h3: 'HTTP/3', 'http/1.1': 'HTTP/1.1' }[navigation?.nextHopProtocol] ?? navigation?.nextHopProtocol;
  $('transport').textContent = realtime.mode
    ? `Page loaded over ${protocol || 'HTTPS'} · realtime via ${realtime.mode}` : '';
}

function receive(text) {
  let event;
  try { event = JSON.parse(text); } catch { return; }
  switch (event.t) {
  case 'message': onMessage(event.message); break;
  case 'receipt': onReceipt(event); break;
  case 'typing': onTyping(event); break;
  case 'presence':
  case 'user': onUser(event.user); break;
  case 'conversation': onConversation(event.conversation); break;
  case 'error': onCommandError(event.client_id, event.error); break;
  default: break; // ping
  }
}

// ---------------------------------------------------------------------------
// State

function peerOf(conv) {
  if (conv.group) return null;
  const other = conv.members.find((member) => member.user !== state.me.id) ?? conv.members[0];
  return state.users.get(other?.user);
}

function titleOf(conv) {
  return conv.group ? conv.title : (peerOf(conv)?.name ?? 'Unknown');
}

function member(conv, id) {
  return conv.members.find((entry) => entry.user === id);
}

function mergeConversation(data) {
  const existing = state.convs.get(data.id);
  const conv = existing ?? { messages: [], loaded: false, more: true };
  Object.assign(conv, {
    id: data.id, group: data.group, title: data.title, members: data.members,
    created: data.created, unread: data.unread ?? conv.unread ?? 0,
  });
  if (data.last && (!conv.last || data.last.id >= conv.last.id)) conv.last = data.last;
  state.convs.set(conv.id, conv);
  return conv;
}

async function resync() {
  let data;
  try { data = await api('/api/bootstrap'); } catch (error) {
    if (error.status === 401) signedOut();
    return;
  }
  state.me = data.me;
  state.users = new Map(data.users.map((user) => [user.id, user]));
  for (const conv of data.conversations) mergeConversation(conv);
  for (const conv of state.convs.values()) {
    const mine = member(conv, state.me.id);
    if (conv.last && mine && conv.last.id > mine.delivered && conv.last.from !== state.me.id) {
      realtime.send({ t: 'delivered', conv: conv.id, upto: conv.last.id }).catch(() => {});
    }
    // Pick up messages missed while disconnected.
    if (conv.loaded) await loadLatest(conv);
  }
  renderMe();
  renderChatList();
  if (state.active) { renderHeader(); markRead(); }
  updateTransport();
}

function onMessage(message) {
  const conv = state.convs.get(message.conv);
  if (!conv) { resync(); return; }
  const fromMe = message.from === state.me.id;
  if (conv.loaded) insertMessage(conv, message);
  if (!conv.last || message.id >= conv.last.id) conv.last = message;
  clearTyping(conv.id, message.from);
  if (!fromMe) {
    const active = state.active === conv.id && pageVisible();
    if (!active) {
      conv.unread = (conv.unread ?? 0) + 1;
      notify(conv, message);
    }
    realtime.send({ t: active ? 'read' : 'delivered', conv: conv.id, upto: message.id }).catch(() => {});
  }
  renderChatList();
  if (state.active === conv.id) appendRendered(conv, message);
}

function insertMessage(conv, message) {
  const pending = message.client_id ? conv.messages.findIndex((m) => !m.id && m.client_id === message.client_id) : -1;
  if (pending >= 0) conv.messages[pending] = message;
  else if (!conv.messages.some((m) => m.id === message.id)) conv.messages.push(message);
  conv.messages.sort((a, b) => (a.id || Infinity) - (b.id || Infinity));
}

function onReceipt(event) {
  const conv = state.convs.get(event.conv);
  const entry = conv && member(conv, event.user);
  if (!entry) return;
  entry.delivered = Math.max(entry.delivered, event.delivered);
  entry.read = Math.max(entry.read, event.read);
  if (event.user === state.me.id) {
    // Read on another device.
    const unread = conv.messages.filter((m) => m.id > entry.read && m.from !== state.me.id).length;
    conv.unread = conv.loaded ? unread : (entry.read >= (conv.last?.id ?? 0) ? 0 : conv.unread);
  }
  renderChatList();
  if (state.active === conv.id) updateTicks(conv);
}

function onTyping(event) {
  let users = state.typing.get(event.conv);
  if (!users) state.typing.set(event.conv, users = new Map());
  clearTimeout(users.get(event.user)?.timer);
  users.set(event.user, {
    recording: event.recording,
    timer: setTimeout(() => clearTyping(event.conv, event.user), TYPING_TIMEOUT),
  });
  renderChatList();
  if (state.active === event.conv) renderHeader();
}

function clearTyping(convId, userId) {
  const users = state.typing.get(convId);
  if (!users?.has(userId)) return;
  clearTimeout(users.get(userId).timer);
  users.delete(userId);
  renderChatList();
  if (state.active === convId) renderHeader();
}

function typingText(conv) {
  const users = [...(state.typing.get(conv.id) ?? new Map()).entries()];
  if (!users.length) return null;
  const recording = users.some(([, value]) => value.recording);
  const verb = recording ? 'recording audio…' : 'typing…';
  if (!conv.group) return verb;
  const names = users.map(([id]) => state.users.get(id)?.name.split(' ')[0] ?? 'Someone');
  return `${names.join(', ')} ${names.length > 1 ? 'are' : 'is'} ${verb}`;
}

function onUser(user) {
  state.users.set(user.id, { ...state.users.get(user.id), ...user });
  if (user.id === state.me.id) state.me = { ...state.me, ...user, online: true };
  renderMe();
  renderChatList();
  if (state.active) renderHeader();
}

function onConversation(data) {
  mergeConversation(data);
  renderChatList();
}

function onCommandError(clientId, error) {
  toast(error);
  if (!clientId) return;
  for (const conv of state.convs.values()) {
    const message = conv.messages.find((m) => m.client_id === clientId && !m.id);
    if (message) { message.failed = true; if (state.active === conv.id) renderMessages(true); }
  }
}

const pageVisible = () => document.visibilityState === 'visible' && document.hasFocus();

function markRead() {
  const conv = state.convs.get(state.active);
  if (!conv || !pageVisible()) return;
  const mine = member(conv, state.me.id);
  const last = [...conv.messages].reverse().find((m) => m.id)?.id ?? conv.last?.id ?? 0;
  if (conv.unread) { conv.unread = 0; renderChatList(); }
  if (mine && last > mine.read) realtime.send({ t: 'read', conv: conv.id, upto: last }).catch(() => {});
}

function notify(conv, message) {
  updateTitle();
  if (!document.hidden || !('Notification' in window) || Notification.permission !== 'granted') return;
  const sender = state.users.get(message.from)?.name ?? 'Someone';
  const body = previewText(message);
  const note = new Notification(conv.group ? `${sender} @ ${conv.title}` : sender, { body, tag: `conv-${conv.id}` });
  note.onclick = () => { window.focus(); openConversation(conv.id); note.close(); };
}

function updateTitle() {
  const unread = [...state.convs.values()].reduce((sum, conv) => sum + (conv.unread ? 1 : 0), 0);
  document.title = unread ? `(${unread}) Parley` : 'Parley';
}

// ---------------------------------------------------------------------------
// Sign in

let authMode = 'login';

function showAuth() {
  $('app').hidden = true;
  $('auth').hidden = false;
  $('auth-form').password.value = '';
}

function signedOut() {
  realtime.stop();
  state.me = null;
  state.convs.clear();
  state.active = null;
  showAuth();
}

function startApp(me) {
  state.me = me;
  $('auth').hidden = true;
  $('app').hidden = false;
  realtime.start();
}

for (const tab of document.querySelectorAll('.tab')) {
  tab.addEventListener('click', () => {
    authMode = tab.dataset.mode;
    document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t === tab));
    document.querySelector('.register-only').hidden = authMode !== 'register';
    const form = $('auth-form');
    form.name.required = authMode === 'register';
    form.password.autocomplete = authMode === 'register' ? 'new-password' : 'current-password';
    form.querySelector('button.primary').textContent = authMode === 'register' ? 'Create account' : 'Sign in';
    $('auth-error').textContent = '';
  });
}

$('auth-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.target;
  const button = form.querySelector('button.primary');
  button.disabled = true;
  $('auth-error').textContent = '';
  try {
    const body = { username: form.username.value.trim().toLowerCase(), password: form.password.value };
    if (authMode === 'register') body.name = form.name.value.trim() || form.username.value.trim();
    const data = await api(authMode === 'register' ? '/api/register' : '/api/login', body);
    startApp(data.me);
  } catch (error) {
    $('auth-error').textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

$('logout').addEventListener('click', async () => {
  try { await api('/api/logout', {}); } catch { /* signed out anyway */ }
  signedOut();
});

// ---------------------------------------------------------------------------
// Chat list

function previewText(message) {
  if (!message) return '';
  const label = { image: '📷 Photo', audio: `🎤 Voice message (${formatDuration(message.media?.duration)})`, file: `📄 ${message.media?.name ?? 'Document'}` }[message.kind];
  if (message.kind === 'text') return message.text;
  return message.text ? `${label.split(' ')[0]} ${message.text}` : label;
}

function sortedConversations() {
  return [...state.convs.values()].sort((a, b) => (b.last?.time ?? b.created) - (a.last?.time ?? a.created));
}

function renderMe() {
  if (!state.me) return;
  const button = $('me-button');
  button.replaceChildren(userAvatar(state.me, 'small'));
  button.title = `${state.me.name} (@${state.me.username})`;
}

function ticksFor(conv, message) {
  if (message.failed) return icon('alert', 'failed');
  if (!message.id) return icon('clock', 'pending');
  const others = conv.members.filter((entry) => entry.user !== state.me.id);
  if (others.every((entry) => entry.read >= message.id)) return icon('checks', 'read');
  if (others.every((entry) => entry.delivered >= message.id)) return icon('checks');
  return icon('check');
}

function renderChatList() {
  if (!state.me) return;
  const filter = $('search').value.trim().toLowerCase();
  const items = [];
  for (const conv of sortedConversations()) {
    const title = titleOf(conv);
    if (filter && !title.toLowerCase().includes(filter)) continue;
    if (!conv.last && !conv.group && state.active !== conv.id) continue;
    const typing = typingText(conv);
    const last = conv.last;
    const sender = conv.group && last && last.from !== state.me.id ? `${state.users.get(last.from)?.name.split(' ')[0] ?? ''}: ` : '';
    items.push(h('li', {
      class: `chat-item${state.active === conv.id ? ' active' : ''}${conv.unread ? ' unread' : ''}`,
      onclick: () => openConversation(conv.id),
    },
    avatar(conv),
    h('div', { class: 'body' },
      h('div', { class: 'row' }, h('span', { class: 'name' }, title),
        h('span', { class: 'time' }, last ? listTime(last.time) : '')),
      h('div', { class: 'row' },
        h('span', { class: 'preview' },
          typing ? h('span', { class: 'typing' }, typing)
            : [last && last.from === state.me.id ? ticksFor(conv, last) : null, sender, previewText(last) || (conv.group ? 'Group created' : '')]),
        conv.unread ? h('span', { class: 'badge' }, conv.unread) : null))));
  }
  $('chat-list').replaceChildren(...items);

  // Contacts matching the search, for starting new chats.
  const contacts = filter ? [...state.users.values()].filter((user) => user.id !== state.me.id &&
    (user.name.toLowerCase().includes(filter) || user.username.includes(filter))) : [];
  $('contact-results').hidden = !contacts.length;
  $('contact-list').replaceChildren(...contacts.map(contactItem));
  updateTitle();
}

function contactItem(user, onclick = () => startDirect(user.id)) {
  return h('li', { class: 'chat-item', onclick },
    userAvatar(user),
    h('div', { class: 'body' },
      h('div', { class: 'row' }, h('span', { class: 'name' }, user.name)),
      h('div', { class: 'row' }, h('span', { class: 'preview' }, user.about || `@${user.username}`))));
}

$('search').addEventListener('input', renderChatList);

async function startDirect(userId) {
  try {
    const data = await api('/api/conversations', { user: userId });
    const conv = mergeConversation(data.conversation);
    $('search').value = '';
    $('picker').close();
    openConversation(conv.id);
  } catch (error) { toast(error.message); }
}

// ---------------------------------------------------------------------------
// Conversation view

async function loadLatest(conv) {
  const data = await api(`/api/messages?conv=${conv.id}`);
  const pending = conv.messages.filter((m) => !m.id);
  const known = new Map(conv.messages.filter((m) => m.id).map((m) => [m.id, m]));
  for (const message of data.messages) known.set(message.id, message);
  conv.messages = [...known.values()].sort((a, b) => a.id - b.id);
  for (const message of pending) {
    if (!conv.messages.some((m) => m.client_id === message.client_id)) {
      if (Date.now() - message.created > 10000) message.failed = true;
      conv.messages.push(message);
    }
  }
  if (!conv.loaded) conv.more = data.more;
  conv.loaded = true;
  if (state.active === conv.id) renderMessages();
}

async function loadOlder(conv) {
  if (!conv.more || conv.loadingOlder) return;
  const first = conv.messages.find((m) => m.id);
  if (!first) return;
  conv.loadingOlder = true;
  $('history-loader').hidden = false;
  try {
    const data = await api(`/api/messages?conv=${conv.id}&before=${first.id}`);
    conv.messages = [...data.messages, ...conv.messages];
    conv.more = data.more;
    if (state.active === conv.id) {
      const box = $('messages');
      const fromBottom = box.scrollHeight - box.scrollTop;
      renderMessages(true);
      box.scrollTop = box.scrollHeight - fromBottom;
    }
  } catch (error) { toast(error.message); } finally {
    conv.loadingOlder = false;
    $('history-loader').hidden = true;
  }
}

async function openConversation(id) {
  const conv = state.convs.get(id);
  if (!conv) return;
  if (state.active !== id) {
    state.active = id;
    setReply(null);
    $('input').value = $('input').dataset[`draft${id}`] ?? '';
    autosize();
  }
  $('empty').hidden = true;
  $('chat').hidden = false;
  $('app').classList.add('chatting');
  renderHeader();
  renderChatList();
  renderMessages();
  if (!conv.loaded) {
    try { await loadLatest(conv); } catch (error) { toast(error.message); }
  }
  markRead();
  if (matchMedia('(min-width: 761px)').matches) $('input').focus();
}

$('back').addEventListener('click', () => {
  $('app').classList.remove('chatting');
  state.active = null;
  $('chat').hidden = true;
  $('empty').hidden = false;
  renderChatList();
});

function renderHeader() {
  const conv = state.convs.get(state.active);
  if (!conv) return;
  $('chat-avatar').replaceChildren(avatar(conv, 'small'));
  $('chat-name').textContent = titleOf(conv);
  const status = $('chat-status');
  const typing = typingText(conv);
  status.classList.toggle('typing', !!typing);
  if (typing) status.textContent = typing;
  else if (conv.group) {
    status.textContent = conv.members
      .map((entry) => (entry.user === state.me.id ? 'You' : state.users.get(entry.user)?.name ?? '?'))
      .sort((a, b) => (a === 'You') - (b === 'You') || a.localeCompare(b)).join(', ');
  } else {
    status.textContent = lastSeen(peerOf(conv) ?? {});
  }
}

function nearBottom() {
  const box = $('messages');
  return box.scrollHeight - box.scrollTop - box.clientHeight < 120;
}

function scrollToBottom() {
  const box = $('messages');
  box.scrollTop = box.scrollHeight;
}

function renderMessages(keepScroll = false) {
  const conv = state.convs.get(state.active);
  if (!conv) return;
  const box = $('messages');
  const top = box.scrollTop;
  const nodes = [];
  let previous = null;
  for (const message of conv.messages) {
    nodes.push(...messageNodes(conv, message, previous));
    previous = message;
  }
  $('message-list').replaceChildren(...nodes);
  if (keepScroll) box.scrollTop = top; else scrollToBottom();
}

function appendRendered(conv, message) {
  const stick = nearBottom() || message.from === state.me.id;
  const index = conv.messages.indexOf(message);
  const previous = conv.messages[index - 1] ?? null;
  const row = message.client_id && document.querySelector(`.msg[data-client="${CSS.escape(message.client_id)}"]`);
  if (row && index >= 0) row.replaceWith(messageNodes(conv, message, previous).at(-1));
  else if (index >= 0 && index === conv.messages.length - 1) $('message-list').append(...messageNodes(conv, message, previous));
  else renderMessages(true);
  if (stick) scrollToBottom();
}

function updateTicks(conv) {
  for (const node of document.querySelectorAll('.msg.out[data-id]')) {
    const message = conv.messages.find((m) => m.id === Number(node.dataset.id));
    const old = node.querySelector('.meta svg');
    if (message && old) old.replaceWith(ticksFor(conv, message));
  }
}

function messageNodes(conv, message, previous) {
  const nodes = [];
  const time = message.time ?? message.created;
  if (!previous || new Date(previous.time ?? previous.created).toDateString() !== new Date(time).toDateString()) {
    nodes.push(h('div', { class: 'day' }, h('span', {}, dayLabel(time))));
    previous = null;
  }
  const mine = message.from === state.me.id;
  const first = !previous || previous.from !== message.from || time - (previous.time ?? previous.created) > 5 * 60000;
  const sender = state.users.get(message.from);
  const kind = message.kind;
  const bubble = h('div', {
    class: `bubble${kind !== 'text' ? ` media ${kind}` : ''}${message.text && kind !== 'text' ? ' has-caption' : ''}`,
  });

  if (conv.group && !mine && first) {
    bubble.append(h('div', { class: 'sender', style: `color:${colorFor(message.from)}` }, sender?.name ?? 'Unknown'));
  }
  if (message.reply_to) bubble.append(quoteNode(conv, message.reply_to));
  if (kind === 'image') {
    const src = message.media?.url ?? message.localUrl;
    bubble.append(h('img', {
      class: 'photo', src, loading: 'lazy', alt: message.media?.name ?? 'Photo',
      onclick: () => message.media && openLightbox(message.media),
      onload: () => { if (state.active === conv.id && nearBottom()) scrollToBottom(); },
    }));
  } else if (kind === 'audio') {
    bubble.append(audioNote(message));
  } else if (kind === 'file') {
    bubble.append(documentNode(message.media ?? message.localMedia));
  }
  if (message.uploadProgress !== undefined) {
    bubble.append(h('div', { class: 'upload-progress' }, h('div', { style: `width:${Math.round(message.uploadProgress * 100)}%` })));
  }
  const meta = h('span', { class: 'meta' }, clock(time), mine ? ticksFor(conv, message) : null);
  if (message.text) bubble.append(h('div', { class: 'text' }, linkify(message.text), meta));
  else bubble.append(meta);

  const row = h('div', {
    class: `msg ${mine ? 'out' : 'in'}${first ? ' first' : ''}`,
    dataset: { id: message.id ?? '', client: message.client_id ?? '' },
  }, bubble);
  if (message.id) {
    row.append(h('button', { class: 'reply-action', title: 'Reply', onclick: () => setReply(message) }, icon('reply')));
    row.addEventListener('dblclick', () => setReply(message));
  }
  if (message.failed) {
    bubble.title = 'Not sent. Click to retry.';
    bubble.style.cursor = 'pointer';
    bubble.addEventListener('click', () => retry(conv, message));
  }
  nodes.push(row);
  return nodes;
}

function quoteNode(conv, id) {
  const target = conv.messages.find((m) => m.id === id);
  const name = target ? (target.from === state.me.id ? 'You' : state.users.get(target.from)?.name) : 'Message';
  return h('div', {
    class: 'quote',
    onclick: () => {
      const node = document.querySelector(`.msg[data-id="${id}"]`);
      if (!node) return;
      node.scrollIntoView({ block: 'center', behavior: 'smooth' });
      node.classList.remove('flash');
      void node.offsetWidth;
      node.classList.add('flash');
    },
  }, h('strong', {}, name ?? 'Unknown'), h('span', {}, target ? previewText(target) : 'Earlier message'));
}

function documentNode(media) {
  const extension = (media?.name?.split('.').pop() ?? '').toUpperCase().slice(0, 5);
  return h('a', { class: 'doc', href: media?.url ?? '#', download: media?.name ?? true },
    icon('doc'),
    h('div', { class: 'info' }, h('div', {}, media?.name ?? 'Document'),
      h('small', {}, [formatSize(media?.size ?? 0), extension].filter(Boolean).join(' · '))),
    icon('down', 'download'));
}

let playing = null;
function audioNote(message) {
  const duration = message.media?.duration || message.duration || 0;
  const audio = new Audio();
  audio.preload = 'none';
  audio.src = message.media?.url ?? message.localUrl ?? '';
  const progress = h('div', { class: 'progress' });
  const knob = h('div', { class: 'knob' });
  const label = h('span', { class: 'duration' }, formatDuration(duration));
  const button = h('button', { title: 'Play' }, icon('play'));
  const total = () => (Number.isFinite(audio.duration) && audio.duration > 0 ? audio.duration * 1000 : duration);
  const track = h('div', {
    class: 'track',
    onclick: (event) => {
      const ratio = event.offsetX / event.currentTarget.clientWidth;
      if (total() > 0) audio.currentTime = (ratio * total()) / 1000;
    },
  }, progress, knob);
  button.addEventListener('click', () => {
    if (audio.paused) {
      if (playing && playing !== audio) playing.pause();
      playing = audio;
      audio.play().catch(() => toast('Cannot play this audio'));
    } else {
      audio.pause();
    }
  });
  audio.addEventListener('play', () => button.replaceChildren(icon('pause')));
  audio.addEventListener('pause', () => button.replaceChildren(icon('play')));
  audio.addEventListener('timeupdate', () => {
    const ratio = Math.min(1, (audio.currentTime * 1000) / (total() || 1));
    progress.style.width = knob.style.left = `${ratio * 100}%`;
    label.textContent = formatDuration(audio.currentTime * 1000);
  });
  audio.addEventListener('ended', () => {
    progress.style.width = knob.style.left = '0%';
    label.textContent = formatDuration(duration);
  });
  return h('div', { class: 'audio-note' }, button, track, label);
}

function openLightbox(media) {
  $('lightbox-image').src = media.url;
  $('lightbox-download').href = media.url;
  $('lightbox-download').download = media.name;
  $('lightbox').hidden = false;
}
$('lightbox-close').addEventListener('click', () => { $('lightbox').hidden = true; });
$('lightbox').addEventListener('click', (event) => { if (event.target.id === 'lightbox') $('lightbox').hidden = true; });

$('messages').addEventListener('scroll', () => {
  const conv = state.convs.get(state.active);
  if (conv && $('messages').scrollTop < 80) loadOlder(conv);
});

// ---------------------------------------------------------------------------
// Composer

function setReply(message) {
  state.replyTo = message;
  $('reply-bar').hidden = !message;
  if (!message) return;
  $('reply-name').textContent = message.from === state.me.id ? 'You' : state.users.get(message.from)?.name ?? '';
  $('reply-text').textContent = previewText(message);
  $('input').focus();
}
$('reply-cancel').addEventListener('click', () => setReply(null));

function autosize() {
  const input = $('input');
  input.style.height = 'auto';
  input.style.height = `${Math.min(input.scrollHeight, 140)}px`;
  $('send-button').replaceChildren(icon(input.value.trim() ? 'send' : 'mic'));
  $('send-button').title = input.value.trim() ? 'Send' : 'Record voice note';
}

$('input').addEventListener('input', () => {
  autosize();
  if (state.active) $('input').dataset[`draft${state.active}`] = $('input').value;
  sendTyping(false);
});

$('input').addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
    event.preventDefault();
    sendText();
  } else if (event.key === 'Escape') {
    setReply(null);
  }
});

$('send-button').addEventListener('click', () => {
  if ($('input').value.trim()) sendText();
  else startRecording();
});

function sendTyping(recording) {
  const now = Date.now();
  if (!state.active || now - state.lastTypingSent < TYPING_INTERVAL) return;
  state.lastTypingSent = now;
  realtime.send({ t: 'typing', conv: state.active, recording }).catch(() => {});
}

function newPending(conv, fields) {
  const message = {
    client_id: crypto.randomUUID(), conv: conv.id, from: state.me.id, created: Date.now(),
    reply_to: state.replyTo?.id ?? 0, ...fields,
  };
  if (!message.reply_to) delete message.reply_to;
  conv.messages.push(message);
  setReply(null);
  appendRendered(conv, message);
  return message;
}

async function dispatch(conv, message, media) {
  message.failed = false;
  const command = { t: 'send', conv: conv.id, client_id: message.client_id, text: message.text ?? '' };
  if (message.reply_to) command.reply_to = message.reply_to;
  if (media) { command.media = media.id; command.duration = message.duration ?? 0; }
  try {
    await realtime.send(command);
  } catch (error) {
    message.failed = true;
    toast(error.message);
    if (state.active === conv.id) renderMessages(true);
  }
  askNotificationPermission();
}

function sendText() {
  const conv = state.convs.get(state.active);
  const input = $('input');
  const text = input.value.trim();
  if (!conv || !text) return;
  if (new TextEncoder().encode(text).length > 4096) { toast('Messages are limited to 4096 bytes'); return; }
  input.value = '';
  delete input.dataset[`draft${conv.id}`];
  autosize();
  const message = newPending(conv, { kind: 'text', text });
  dispatch(conv, message);
}

function retry(conv, message) {
  if (!message.failed) return;
  message.failed = false;
  if (message.file && !message.media) sendFile(conv, message.file, message.text, message);
  else dispatch(conv, message, message.media);
  renderMessages(true);
}

function kindOf(file) {
  if (/^image\/(jpeg|png|gif|webp)$/.test(file.type)) return 'image';
  if (file.type.startsWith('audio/')) return 'audio';
  return 'file';
}

async function sendFile(conv, file, caption = '', existing = null, duration = 0) {
  if (file.size > MAX_UPLOAD) { toast(`${file.name} is larger than 16 MB`); return; }
  const kind = kindOf(file);
  const message = existing ?? newPending(conv, {
    kind, text: caption, file, duration,
    localUrl: kind === 'file' ? null : URL.createObjectURL(file),
    localMedia: { name: file.name, size: file.size, url: '#' },
  });
  message.uploadProgress = 0;
  const redraw = () => { if (state.active === conv.id) renderMessages(true); };
  redraw();
  try {
    let lastDraw = 0;
    const media = await upload(file, (ratio) => {
      message.uploadProgress = ratio;
      if (Date.now() - lastDraw > 150) { lastDraw = Date.now(); redraw(); }
    });
    message.media = { ...media, duration };
    delete message.uploadProgress;
    redraw();
    await dispatch(conv, message, media);
  } catch (error) {
    delete message.uploadProgress;
    message.failed = true;
    toast(error.message);
    redraw();
  }
}

// Attachments: menu, file picker, drag and drop, paste.
$('attach-button').addEventListener('click', (event) => {
  event.stopPropagation();
  $('attach-menu').hidden = !$('attach-menu').hidden;
  $('emoji-panel').hidden = true;
});
for (const button of $('attach-menu').querySelectorAll('button')) {
  button.addEventListener('click', () => {
    $('attach-menu').hidden = true;
    const input = $('file-input');
    input.accept = button.dataset.accept;
    input.value = '';
    input.click();
  });
}
document.addEventListener('click', (event) => {
  if (!event.target.closest('.attach-wrap')) $('attach-menu').hidden = true;
});
$('file-input').addEventListener('change', (event) => previewFiles([...event.target.files]));

let dragDepth = 0;
$('chat').addEventListener('dragenter', (event) => {
  if (![...event.dataTransfer.types].includes('Files')) return;
  dragDepth++;
  $('drop-hint').hidden = false;
});
$('chat').addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; $('drop-hint').hidden = true; } });
$('chat').addEventListener('dragover', (event) => event.preventDefault());
$('chat').addEventListener('drop', (event) => {
  event.preventDefault();
  dragDepth = 0;
  $('drop-hint').hidden = true;
  previewFiles([...event.dataTransfer.files]);
});
$('input').addEventListener('paste', (event) => {
  const files = [...event.clipboardData.files];
  if (files.length) { event.preventDefault(); previewFiles(files); }
});

let previewQueue = [];
function previewFiles(files) {
  if (!files.length || !state.active) return;
  const tooLarge = files.filter((file) => file.size > MAX_UPLOAD);
  if (tooLarge.length) toast(`${tooLarge.map((f) => f.name).join(', ')}: larger than 16 MB`);
  previewQueue = files.filter((file) => file.size <= MAX_UPLOAD);
  if (!previewQueue.length) return;
  const body = $('preview-body');
  body.replaceChildren(...previewQueue.map((file) => (kindOf(file) === 'image'
    ? h('img', { src: URL.createObjectURL(file), alt: file.name })
    : documentNode({ name: file.name, size: file.size, url: '#' }))));
  $('preview-title').textContent = previewQueue.length > 1 ? `Send ${previewQueue.length} files` : `Send ${previewQueue[0].name}`;
  $('preview-caption').value = $('input').value.trim();
  $('preview').returnValue = '';
  $('preview').showModal();
  $('preview-caption').focus();
}

$('preview').addEventListener('close', () => {
  const files = previewQueue;
  previewQueue = [];
  for (const image of $('preview-body').querySelectorAll('img')) URL.revokeObjectURL(image.src);
  if ($('preview').returnValue !== 'send') return;
  const conv = state.convs.get(state.active);
  if (!conv) return;
  const caption = $('preview-caption').value.trim();
  if (caption && caption === $('input').value.trim()) { $('input').value = ''; autosize(); }
  files.forEach((file, index) => sendFile(conv, file, index === 0 ? caption : ''));
});
$('preview-caption').addEventListener('keydown', (event) => {
  if (event.key === 'Enter') { event.preventDefault(); $('preview').close('send'); }
});

// Emoji
const EMOJI = '😀 😂 🤣 😊 😍 🥰 😘 😎 🤔 😅 😭 😡 🥳 😴 🤯 👍 👎 👏 🙏 💪 👋 🤝 ❤️ 🧡 💛 💚 💙 💜 🖤 💔 🔥 ✨ 🎉 🎂 🎁 ☕ 🍕 🍻 ⚽ 🚀 ✅ ❌ ⭐ 💯 👀 🙈 🤷 🤦 😢 😮 😇 🤗 😬 🙃 😉 😋 🤤 🤩 😏'.split(' ');
$('emoji-panel').append(...EMOJI.map((emoji) => h('button', {
  type: 'button',
  onclick: () => {
    const input = $('input');
    const start = input.selectionStart ?? input.value.length;
    input.setRangeText(emoji, start, input.selectionEnd ?? start, 'end');
    input.focus();
    autosize();
  },
}, emoji)));
$('emoji-button').addEventListener('click', () => {
  $('emoji-panel').hidden = !$('emoji-panel').hidden;
});

// Voice notes
let recorder = null;
async function startRecording() {
  if (!navigator.mediaDevices?.getUserMedia || !window.MediaRecorder) { toast('Recording is not supported in this browser'); return; }
  let stream;
  try { stream = await navigator.mediaDevices.getUserMedia({ audio: true }); } catch {
    toast('Microphone permission denied');
    return;
  }
  const type = ['audio/webm;codecs=opus', 'audio/ogg;codecs=opus', 'audio/mp4', 'audio/webm']
    .find((candidate) => MediaRecorder.isTypeSupported(candidate));
  const media = new MediaRecorder(stream, type ? { mimeType: type } : undefined);
  const chunks = [];
  const started = Date.now();
  recorder = { media, stream, chunks, started, send: false, conv: state.active };
  media.ondataavailable = (event) => event.data.size && chunks.push(event.data);
  media.onstop = () => {
    stream.getTracks().forEach((track) => track.stop());
    clearInterval(recorder.timer);
    const { send, conv: convId } = recorder;
    recorder = null;
    $('recorder').hidden = true;
    $('composer').hidden = false;
    const duration = Date.now() - started;
    if (!send || duration < 500) return;
    const mime = (media.mimeType || 'audio/webm').split(';')[0];
    const extension = { 'audio/webm': 'webm', 'audio/ogg': 'ogg', 'audio/mp4': 'm4a' }[mime] ?? 'audio';
    const stamp = new Date(started).toISOString().slice(0, 19).replace('T', ' ').replaceAll(':', '.');
    const file = new File(chunks, `Voice note ${stamp}.${extension}`, { type: mime });
    const conv = state.convs.get(convId);
    if (conv) sendFile(conv, file, '', null, duration);
  };
  media.start(250);
  $('composer').hidden = true;
  $('recorder').hidden = false;
  $('record-time').textContent = '0:00';
  recorder.timer = setInterval(() => {
    $('record-time').textContent = formatDuration(Date.now() - started);
    sendTyping(true);
  }, 500);
}
function stopRecording(send) {
  if (!recorder) return;
  recorder.send = send;
  recorder.media.stop();
}
$('record-cancel').addEventListener('click', () => stopRecording(false));
$('record-send').addEventListener('click', () => stopRecording(true));

// ---------------------------------------------------------------------------
// Dialogs: new chat, new group, profile

let pickerMode = 'chat';
const groupSelection = new Set();

function renderPicker() {
  const filter = $('picker-search').value.trim().toLowerCase();
  const users = [...state.users.values()]
    .filter((user) => user.id !== state.me.id)
    .filter((user) => !filter || user.name.toLowerCase().includes(filter) || user.username.includes(filter))
    .sort((a, b) => a.name.localeCompare(b.name));
  $('picker-list').replaceChildren(...users.map((user) => {
    if (pickerMode === 'chat') return contactItem(user);
    const box = h('input', { type: 'checkbox', checked: groupSelection.has(user.id) });
    const item = contactItem(user, (event) => {
      if (event.target !== box) box.checked = !box.checked;
      if (box.checked) groupSelection.add(user.id); else groupSelection.delete(user.id);
    });
    item.append(box);
    return item;
  }));
  if (!users.length) $('picker-list').append(h('li', { class: 'muted', style: 'padding:24px;text-align:center' }, 'No other people yet. Invite someone to create an account!'));
}

function openPicker(mode) {
  pickerMode = mode;
  groupSelection.clear();
  $('picker-title').textContent = mode === 'chat' ? 'New chat' : 'New group';
  $('group-name-row').hidden = mode !== 'group';
  $('picker-actions').hidden = mode !== 'group';
  $('group-name').value = '';
  $('picker-search').value = '';
  $('picker-error').textContent = '';
  renderPicker();
  $('picker').showModal();
}

$('new-chat').addEventListener('click', () => openPicker('chat'));
$('new-group').addEventListener('click', () => openPicker('group'));
$('picker-search').addEventListener('input', renderPicker);
$('create-group').addEventListener('click', async (event) => {
  event.preventDefault();
  try {
    const data = await api('/api/conversations', {
      group: true, title: $('group-name').value.trim(), members: [...groupSelection],
    });
    const conv = mergeConversation(data.conversation);
    $('picker').close();
    openConversation(conv.id);
  } catch (error) {
    $('picker-error').textContent = error.message;
  }
});

$('me-button').addEventListener('click', () => {
  $('profile-avatar').replaceChildren(userAvatar(state.me, 'large'));
  $('profile-username').textContent = `@${state.me.username}`;
  $('profile-name').value = state.me.name;
  $('profile-about').value = state.me.about ?? '';
  $('profile-error').textContent = '';
  $('profile').showModal();
});
$('profile-form').addEventListener('submit', async (event) => {
  if (event.submitter?.value !== 'save') return;
  event.preventDefault();
  try {
    await api('/api/profile', { name: $('profile-name').value.trim(), about: $('profile-about').value.trim() });
    $('profile').close();
  } catch (error) {
    $('profile-error').textContent = error.message;
  }
});

function askNotificationPermission() {
  if ('Notification' in window && Notification.permission === 'default') Notification.requestPermission();
}

// ---------------------------------------------------------------------------
// Start

document.addEventListener('visibilitychange', markRead);
window.addEventListener('focus', markRead);
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && !$('lightbox').hidden) $('lightbox').hidden = true;
});

(async () => {
  try {
    const data = await api('/api/bootstrap');
    startApp(data.me);
  } catch (error) {
    if (error.status === 401) showAuth();
    else { showAuth(); $('auth-error').textContent = 'Cannot reach the server'; }
  }
})();
