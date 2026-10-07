'use strict';

// Lantern browser client: hash routes for home, search, channel, watch, and
// upload. Uploads go in chunks and resume after a reload or a lost connection.

const view = document.getElementById('view');
const searchForm = document.getElementById('search');
let leaving = () => {}; // cleanup for the current page

function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else if (key === 'class') node.className = value;
    else if (value !== false && value != null) node.setAttribute(key, value === true ? '' : value);
  }
  node.append(...children.flat().filter((child) => child != null && child !== false));
  return node;
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const body = response.headers.get('content-type') === 'application/json' ? await response.json() : null;
  if (!response.ok) throw Object.assign(new Error(body?.error || `HTTP ${response.status}`), { status: response.status, body });
  return body;
}

// ---------------------------------------------------------------------------
// Formatting

function duration(ms) {
  const total = Math.round(ms / 1000);
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor(total / 60) % 60;
  const seconds = String(total % 60).padStart(2, '0');
  return hours ? `${hours}:${String(minutes).padStart(2, '0')}:${seconds}` : `${minutes}:${seconds}`;
}

const compact = new Intl.NumberFormat(undefined, { notation: 'compact' });
const views = (count) => `${compact.format(count)} ${count === 1 ? 'view' : 'views'}`;

function ago(seconds) {
  const elapsed = Date.now() / 1000 - seconds;
  const units = [['year', 31536000], ['month', 2592000], ['week', 604800], ['day', 86400],
                 ['hour', 3600], ['minute', 60]];
  const format = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  for (const [unit, size] of units)
    if (elapsed >= size) return format.format(-Math.floor(elapsed / size), unit);
  return 'just now';
}

function bytes(count) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let index = 0;
  while (count >= 1000 && index < units.length - 1) { count /= 1000; ++index; }
  return `${count.toFixed(index ? 1 : 0)} ${units[index]}`;
}

function avatar(name) {
  let hash = 0;
  for (const c of name) hash = (hash * 31 + c.codePointAt(0)) >>> 0;
  return h('span', { class: 'avatar', style: `background: hsl(${hash % 360} 55% 45%)`, 'aria-hidden': true },
           [...name][0]?.toUpperCase() ?? '?');
}

const channelLink = (name) => h('a', { href: `#/channel/${encodeURIComponent(name)}` }, name);

function thumbnail(video) {
  return h('a', { class: 'thumb', href: `#/watch/${video.id}` },
    video.thumbnail && h('img', { src: `/t/${video.id}`, alt: '', loading: 'lazy' }),
    h('span', { class: 'duration' }, duration(video.duration)));
}

function card(video, compactCard = false) {
  return h('article', { class: 'card' },
    thumbnail(video),
    h('div', { class: 'meta' },
      !compactCard && avatar(video.channel),
      h('div', {},
        h('a', { href: `#/watch/${video.id}` }, h('h3', { title: video.title }, video.title)),
        h('div', { class: 'byline' }, channelLink(video.channel)),
        h('div', { class: 'byline' }, `${views(video.views)} • ${ago(video.created)}`))));
}

// ---------------------------------------------------------------------------
// Pages

async function listing(query, emptyText) {
  const { videos } = await api(`/api/videos?${query}`);
  if (!videos.length)
    return h('p', { class: 'empty' }, emptyText, ' ', h('a', { href: '#/upload' }, 'Upload a video'));
  return h('div', { class: 'grid' }, videos.map((video) => card(video)));
}

async function home() {
  document.title = 'Lantern';
  return listing('', 'Nothing here yet.');
}

async function search(text) {
  document.title = `${text} - Lantern`;
  searchForm.q.value = text;
  return listing(`q=${encodeURIComponent(text)}`, `No results for “${text}”.`);
}

async function channel(name) {
  document.title = `${name} - Lantern`;
  const grid = await listing(`channel=${encodeURIComponent(name)}`, 'This channel has no videos.');
  return h('div', {}, h('div', { class: 'channel-row', style: 'margin-bottom: 24px' }, avatar(name),
    h('h1', { style: 'margin: 0' }, name)), grid);
}

async function watch(id) {
  const [video, { videos }] = await Promise.all([api(`/api/videos/${id}`), api('/api/videos')]);
  document.title = `${video.title} - Lantern`;
  const player = h('video', { class: 'player', src: `/v/${video.id}`, controls: true, autoplay: true,
                              playsinline: true, poster: video.thumbnail ? `/t/${video.id}` : null });
  const stats = h('div', { class: 'stats' }, `${views(video.views)} • ${ago(video.created)}`);
  const transport = h('div', { class: 'transport' });
  let counted = false;
  player.addEventListener('playing', async () => {
    if (counted) return;
    counted = true;
    try {
      video.views = (await api(`/api/videos/${video.id}/view`, { method: 'POST' })).views;
      stats.textContent = `${views(video.views)} • ${ago(video.created)}`;
    } catch { /* counted on the next visit */ }
  });
  // Show which HTTP version carried the video bytes.
  const showTransport = () => {
    const entry = performance.getEntriesByType('resource').findLast((e) => e.name.endsWith(`/v/${video.id}`));
    const names = { 'http/1.1': 'HTTP/1.1', h2: 'HTTP/2', h3: 'HTTP/3' };
    if (entry?.nextHopProtocol) transport.textContent = `Streaming over ${names[entry.nextHopProtocol] ?? entry.nextHopProtocol}`;
  };
  player.addEventListener('progress', showTransport);
  leaving = () => { player.pause(); player.removeAttribute('src'); player.load(); };

  const others = videos.filter((other) => other.id !== video.id);
  return h('div', { class: 'watch' },
    h('section', {},
      player,
      h('h1', {}, video.title),
      h('div', { class: 'channel-row' }, avatar(video.channel),
        h('div', {}, h('div', { class: 'name' }, channelLink(video.channel)),
          h('div', { class: 'byline' }, `${bytes(video.size)} • ${video.mime}`))),
      h('div', { class: 'description' }, stats, video.description || 'No description.'),
      transport),
    h('aside', { class: 'next', 'aria-label': 'Up next' }, others.map((other) => card(other, true))));
}

// ---------------------------------------------------------------------------
// Upload

const playable = ['video/mp4', 'video/webm', 'video/ogg', 'video/quicktime'];
const pendingKey = 'lantern.pending';
const pendingUploads = () => JSON.parse(localStorage.getItem(pendingKey) || '[]');
function savePending(list) { localStorage.setItem(pendingKey, JSON.stringify(list)); }
const sameFile = (entry, file) =>
  entry.name === file.name && entry.size === file.size && entry.modified === file.lastModified;

// Reads the duration and draws a frame a quarter of the way in, without
// uploading anything: the server stores videos as they are.
function inspect(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const probe = h('video', { muted: true, preload: 'auto', src: url });
    const done = (value, error) => { URL.revokeObjectURL(url); error ? reject(error) : resolve(value); };
    probe.addEventListener('error', () => done(null, new Error('This browser cannot play this file.')));
    const draw = () => {
      const canvas = h('canvas', { width: 640, height: 360 });
      const context = canvas.getContext('2d');
      context.fillStyle = '#000';
      context.fillRect(0, 0, 640, 360);
      const scale = Math.min(640 / probe.videoWidth, 360 / probe.videoHeight) || 1;
      const width = probe.videoWidth * scale;
      const height = probe.videoHeight * scale;
      context.drawImage(probe, (640 - width) / 2, (360 - height) / 2, width, height);
      canvas.toBlob((image) => done({ duration: Math.round(probe.duration * 1000), image }), 'image/jpeg', 0.82);
    };
    const pick = () => {
      probe.addEventListener('seeked', draw, { once: true });
      probe.currentTime = Math.min(probe.duration / 4, 30);
    };
    probe.addEventListener('loadedmetadata', () => {
      if (Number.isFinite(probe.duration)) return pick();
      // Recordings from MediaRecorder carry no duration; seeking past the
      // end makes the browser find it.
      probe.addEventListener('seeked', () => {
        if (!Number.isFinite(probe.duration)) return done(null, new Error('This video has no known length.'));
        pick();
      }, { once: true });
      probe.currentTime = 1e101;
    }, { once: true });
  });
}

// PUTs one chunk with progress. Resolves with the server's upload state,
// including after a 409 that reports where to resume.
function putChunk(id, offset, blob, onProgress, uploads) {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    uploads.current = request;
    request.open('PUT', `/api/uploads/${id}?offset=${offset}`);
    request.responseType = 'json';
    request.upload.onprogress = (event) => onProgress(offset + event.loaded);
    request.onload = () => {
      if (request.status === 200 || request.status === 409) resolve(request.response);
      else reject(Object.assign(new Error(request.response?.error || `HTTP ${request.status}`), { status: request.status }));
    };
    request.onerror = () => reject(new Error('Connection lost'));
    request.onabort = () => reject(Object.assign(new Error('Paused'), { paused: true }));
    request.send(blob);
  });
}

function upload() {
  document.title = 'Upload - Lantern';
  const input = h('input', { type: 'file', accept: playable.join(','), hidden: true });
  const drop = h('label', { class: 'drop' },
    input,
    h('svg', { viewBox: '0 0 24 24', width: 48, height: 48 }),
    h('strong', {}, 'Drag a video here or choose a file'),
    h('span', { class: 'hint' }, 'MP4, WebM, Ogg, or QuickTime. Large files upload in resumable chunks.'));
  drop.querySelector('svg').innerHTML = '<path d="M11 16V7.8l-3.3 3.3-1.4-1.4L12 4l5.7 5.7-1.4 1.4L13 7.8V16h-2Zm-6 4v-6h2v4h10v-4h2v6H5Z"/>';
  const page = h('div', { class: 'upload' }, h('h1', {}, 'Upload a video'), drop);

  const pending = pendingUploads();
  if (pending.length) {
    page.append(h('ul', { class: 'pending' }, pending.map((entry) =>
      h('li', {},
        h('span', {}, `“${entry.title}” stopped at ${Math.floor(entry.received / entry.size * 100)}%. Choose ${entry.name} again to resume.`),
        h('button', { class: 'button', onclick: async (event) => {
          event.target.disabled = true;
          try { await api(`/api/uploads/${entry.id}`, { method: 'DELETE' }); } catch (error) { if (error.status !== 404) return alert(error.message); }
          savePending(pendingUploads().filter((other) => other.id !== entry.id));
          event.target.closest('li').remove();
        } }, 'Discard')))));
  }

  const choose = (file) => file && showForm(page, file);
  input.addEventListener('change', () => choose(input.files[0]));
  drop.addEventListener('dragover', (event) => { event.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (event) => {
    event.preventDefault();
    drop.classList.remove('over');
    choose(event.dataTransfer.files[0]);
  });
  return page;
}

async function showForm(page, file) {
  page.querySelector('.form')?.remove();
  const resume = pendingUploads().find((entry) => sameFile(entry, file));
  const error = h('p', { class: 'error' });
  const title = h('input', { name: 'title', maxlength: 100, required: true,
                             value: resume?.title ?? file.name.replace(/\.[^.]+$/, '') });
  const description = h('textarea', { name: 'description', maxlength: 5000 });
  description.value = resume?.description ?? '';
  const channelName = h('input', { name: 'channel', maxlength: 50, required: true,
                                   value: resume?.channel ?? localStorage.getItem('lantern.channel') ?? '' });
  const bar = h('div');
  const status = h('div', {}, `${file.name} • ${bytes(file.size)}`);
  const preview = h('div', { class: 'thumb' });
  const start = h('button', { class: 'button primary', type: 'submit' }, resume ? 'Resume upload' : 'Upload');
  const pause = h('button', { class: 'button', type: 'button', hidden: true }, 'Pause');
  const form = h('form', { class: 'form' },
    h('div', { class: 'fields' },
      h('label', {}, 'Title', title),
      h('label', {}, 'Description', description),
      h('label', {}, 'Channel name', channelName),
      error,
      h('div', { class: 'actions' }, pause, start)),
    h('div', { class: 'preview' }, preview, status, h('div', { class: 'progress' }, bar)));
  page.append(form);
  for (const field of resume ? [title, description, channelName] : []) field.disabled = true;

  let details;
  try {
    if (!playable.includes(file.type)) throw new Error('Choose an MP4, WebM, Ogg, or QuickTime video.');
    details = await inspect(file);
    preview.append(h('img', { src: URL.createObjectURL(details.image), alt: '' }),
                   h('span', { class: 'duration' }, duration(details.duration)));
  } catch (failure) {
    error.textContent = failure.message;
    start.disabled = true;
    return;
  }

  const uploads = { current: null, paused: false };
  leaving = () => { uploads.paused = true; uploads.current?.abort(); };
  pause.addEventListener('click', () => { uploads.paused = true; uploads.current?.abort(); });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    error.textContent = '';
    start.disabled = true;
    pause.hidden = false;
    uploads.paused = false;
    localStorage.setItem('lantern.channel', channelName.value.trim());
    try {
      let state = resume ?? pendingUploads().find((entry) => sameFile(entry, file));
      if (state) {
        state = { ...state, ...(await api(`/api/uploads/${state.id}`)) };
      } else {
        const fields = new URLSearchParams({ size: file.size, type: file.type, duration: details.duration,
          title: title.value, description: description.value, channel: channelName.value });
        state = { ...(await api('/api/uploads', { method: 'POST', body: fields })),
                  name: file.name, modified: file.lastModified, title: title.value.trim(),
                  description: description.value, channel: channelName.value.trim() };
        await api(`/api/uploads/${state.id}/thumbnail`, { method: 'PUT', body: details.image,
                                                          headers: { 'content-type': 'image/jpeg' } });
      }
      const remember = () => savePending([...pendingUploads().filter((e) => e.id !== state.id), state]);
      remember();
      await sendChunks(state, file, uploads, bar, status, remember);
      status.textContent = 'Publishing…';
      const video = await api(`/api/uploads/${state.id}/publish`, { method: 'POST' });
      savePending(pendingUploads().filter((entry) => entry.id !== state.id));
      leaving = () => {};
      location.hash = `#/watch/${video.id}`;
    } catch (failure) {
      if (failure.status === 404) savePending(pendingUploads().filter((entry) => !sameFile(entry, file)));
      error.textContent = failure.paused ? '' : failure.message;
      status.textContent = failure.paused ? 'Paused' : status.textContent;
      start.textContent = 'Resume upload';
      start.disabled = false;
      pause.hidden = true;
    }
  });
}

async function sendChunks(state, file, uploads, bar, status, remember) {
  let started = performance.now();
  let startedAt = state.received;
  let retries = 0;
  const show = (received) => {
    bar.style.width = `${received / file.size * 100}%`;
    const seconds = (performance.now() - started) / 1000;
    const rate = seconds > 0.5 ? (received - startedAt) / seconds : 0;
    const left = rate ? ` • ${duration((file.size - received) / rate * 1000)} left` : '';
    status.textContent = `${Math.floor(received / file.size * 100)}% • ${bytes(received)} of ${bytes(file.size)}` +
      (rate ? ` • ${bytes(rate)}/s${left}` : '');
  };
  show(state.received);
  while (state.received < file.size) {
    if (uploads.paused) throw Object.assign(new Error('Paused'), { paused: true });
    const end = Math.min(state.received + state.chunk, file.size);
    try {
      const reply = await putChunk(state.id, state.received, file.slice(state.received, end), show, uploads);
      state.received = reply.received;
      retries = 0;
    } catch (failure) {
      if (failure.paused || failure.status === 404 || ++retries > 5) throw failure;
      status.textContent = `${failure.message}; retrying…`;
      await new Promise((resolve) => setTimeout(resolve, 500 * 2 ** retries));
      // A stale offset is harmless: the server answers 409 with its own.
      try { Object.assign(state, await api(`/api/uploads/${state.id}`)); } catch (lost) { if (lost.status === 404) throw lost; }
      started = performance.now();
      startedAt = state.received;
    }
    remember();
    show(state.received);
  }
}

// ---------------------------------------------------------------------------
// Routing

let routeSerial = 0;
async function route() {
  const serial = ++routeSerial;
  leaving();
  leaving = () => {};
  const [, page = '', argument = ''] = location.hash.split('/');
  const value = decodeURIComponent(argument);
  if (page !== 'search') searchForm.q.value = '';
  let content;
  try {
    if (page === 'watch') content = await watch(value);
    else if (page === 'upload') content = upload();
    else if (page === 'search') content = await search(value);
    else if (page === 'channel') content = await channel(value);
    else content = await home();
  } catch (failure) {
    content = h('p', { class: 'empty' }, failure.message, ' ', h('a', { href: '#/' }, 'Go home'));
  }
  if (serial !== routeSerial) return; // a later navigation won
  view.replaceChildren(content);
  window.scrollTo(0, 0);
}

searchForm.addEventListener('submit', (event) => {
  event.preventDefault();
  const text = searchForm.q.value.trim();
  location.hash = text ? `#/search/${encodeURIComponent(text)}` : '#/';
});
window.addEventListener('hashchange', route);
route();
