// Three.js renderer: lit procedural level, low-poly players, effects, first-person gun, killcam.
// Camera: forward = (cos yaw, sin yaw), right = (-sin yaw, cos yaw), as in PROTOCOL.md.
// Map x -> world X, map y -> world Z, Y up. Yaw 0 faces +X; a figure's local +X is its forward.

import * as THREE from 'three';
import { EFFECT } from './protocol.js';
import { TWO_PI, yaw16ToRad } from './sim.js';

const WALL_H = 1.2;
const EYE_H = 0.5;
const PLANE = 0.66;           // camera plane half-length: about 67 degree horizontal FOV at any aspect
const SKY = 0x1a2033;
const FOG_DENSITY = 0.028;
const FIG_SCALE = 0.85;
const WALL_LIGHTS = 4;
const BLAST_LIGHTS = 3;
const BLAST_POOL = 12;
const TRACER_POOL = 24;
const ROCKET_POOL = 24;
const TRAIL_LEN = 10;
const TRACER_Y = 0.42;
const ROCKET_Y = 0.5;
const TRACER_LIFE = 0.1;      // s
const BLAST_LIFE = 0.3;       // s
const FALL_S = 0.35;          // s for a dead figure to fall over
const FADE_S = 1.0;           // s for a dead figure to fade to a corpse
const FLASH_MS = 70;
const LABEL_DIST = 22;

const WALL_RGB = [null, [190, 70, 56], [60, 110, 190], [70, 150, 80], [180, 150, 70]];
const WALL_CSS = WALL_RGB.map((c) => (c ? `rgb(${c.join(',')})` : null));

const hueOf = (id) => (id * 67 + 20) % 360;

export function playerColor(id) {
  return `hsl(${hueOf(id)} 70% 50%)`;
}

// ---- procedural textures (no image files) ----

function rng(seed) {
  let s = seed;
  return () => {
    s = (s * 16807) % 2147483647;
    return s / 2147483647;
  };
}

function canvasTexture(paint, repeat = false) {
  const size = 256;
  const c = document.createElement('canvas');
  c.width = size;
  c.height = size;
  paint(c.getContext('2d'), size);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  t.anisotropy = 8;
  if (repeat) t.wrapS = t.wrapT = THREE.RepeatWrapping;
  return t;
}

function paintBrick(g, s) {
  const r = rng(7);
  g.fillStyle = '#4a4a46';
  g.fillRect(0, 0, s, s);
  const rows = 8, bw = s / 4, bh = s / rows;
  for (let row = 0; row < rows; row++) {
    const off = row % 2 ? bw / 2 : 0;
    for (let col = -1; col < 4; col++) {
      const v = 0.8 + r() * 0.35;
      g.fillStyle = `rgb(${(160 * v) | 0},${(70 * v) | 0},${(52 * v) | 0})`;
      g.fillRect(col * bw + off + 3, row * bh + 3, bw - 6, bh - 6);
    }
  }
  for (let i = 0; i < 80; i++) {
    g.fillStyle = `rgba(0,0,0,${(r() * 0.15).toFixed(3)})`;
    g.fillRect(r() * s, r() * s, 2 + r() * 6, 2 + r() * 6);
  }
}

function paintMetal(g, s) {
  const grad = g.createLinearGradient(0, 0, s, s);
  grad.addColorStop(0, '#5a7896');
  grad.addColorStop(1, '#2e4359');
  g.fillStyle = grad;
  g.fillRect(0, 0, s, s);
  g.strokeStyle = '#17202c';
  g.lineWidth = 5;
  g.strokeRect(0, 0, s, s);
  g.beginPath();
  g.moveTo(s / 2, 0);
  g.lineTo(s / 2, s);
  g.moveTo(0, s / 2);
  g.lineTo(s, s / 2);
  g.stroke();
  g.fillStyle = '#9db4c8';
  for (const qx of [0, s / 2]) {
    for (const qy of [0, s / 2]) {
      for (const dx of [14, s / 2 - 14]) {
        for (const dy of [14, s / 2 - 14]) {
          g.beginPath();
          g.arc(qx + dx, qy + dy, 3, 0, TWO_PI);
          g.fill();
        }
      }
    }
  }
}

function paintConcrete(g, s) {
  const r = rng(11);
  g.fillStyle = '#6f7268';
  g.fillRect(0, 0, s, s);
  for (let i = 0; i < 1400; i++) {
    g.fillStyle = r() < 0.5 ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.08)';
    g.fillRect(r() * s, r() * s, 1 + r() * 2, 1 + r() * 2);
  }
  g.strokeStyle = 'rgba(20,20,18,0.35)';
  g.lineWidth = 1.5;
  g.beginPath();
  g.moveTo(20, 0);
  g.lineTo(60, 90);
  g.lineTo(40, 170);
  g.lineTo(90, 256);
  g.stroke();
}

function paintTrimBase(g, s) {
  g.fillStyle = '#1d2430';
  g.fillRect(0, 0, s, s);
  g.strokeStyle = '#0d1118';
  g.lineWidth = 6;
  g.strokeRect(0, 0, s, s);
  g.fillStyle = '#2a3343';
  g.fillRect(14, 14, s - 28, s - 28);
  g.fillStyle = 'rgba(255,179,71,0.35)';
  g.fillRect(0, s * 0.2, s, 10);
  g.fillRect(0, s * 0.8, s, 10);
}

function paintTrimGlow(g, s) {
  g.fillStyle = '#000';
  g.fillRect(0, 0, s, s);
  g.fillStyle = '#ffb347';
  g.fillRect(0, s * 0.2, s, 10);
  g.fillRect(0, s * 0.8, s, 10);
  g.fillStyle = '#ffd98a';
  g.fillRect(s * 0.45, 0, 8, s);
}

function paintFloor(g, s) {
  const r = rng(3);
  g.fillStyle = '#2b2e38';
  g.fillRect(0, 0, s, s);
  for (let i = 0; i < 500; i++) {
    g.fillStyle = `rgba(255,255,255,${(r() * 0.04).toFixed(3)})`;
    g.fillRect(r() * s, r() * s, 2, 2);
  }
  g.strokeStyle = '#4a4e5e';
  g.lineWidth = 4;
  g.strokeRect(2, 2, s - 4, s - 4);
}

function paintFlash(g, s) {
  const c = s / 2;
  const gr = g.createRadialGradient(c, c, 0, c, c, c);
  gr.addColorStop(0, 'rgba(255,255,255,1)');
  gr.addColorStop(0.35, 'rgba(255,240,190,0.8)');
  gr.addColorStop(1, 'rgba(255,200,80,0)');
  g.fillStyle = gr;
  g.fillRect(0, 0, s, s);
}

function labelTexture(name, hue) {
  const c = document.createElement('canvas');
  c.width = 256;
  c.height = 64;
  const g = c.getContext('2d');
  g.fillStyle = 'rgba(8,10,16,0.6)';
  g.fillRect(0, 0, 256, 64);
  g.fillStyle = `hsl(${hue} 80% 72%)`;
  g.font = 'bold 30px ui-monospace, Menlo, Consolas, monospace';
  g.textAlign = 'center';
  g.textBaseline = 'middle';
  g.fillText(name, 128, 34, 240);
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  return t;
}

// ---- renderer ----

const styleOf = (c) => (c >= 1 && c <= 4 ? c : 1);

// scene = {
//   map, eye: {x, y, yaw (radians)},
//   players: [{id, x, y, yaw16, hp, alive, fired}], projectiles: [{id, x, y}],
//   effects: [{kind, x1, y1, x2, y2, age (s)}], selfId (body hidden),
//   names: id => string, killcam (bool), victimId (highlighted in killcam),
//   dead (bool), showGun, gunKick (0..1), muzzle (bool), time (ms)
// }
class Renderer {
  constructor(canvas) {
    this.canvas = canvas;
    this.renderer = new THREE.WebGLRenderer({ canvas, antialias: true, powerPreference: 'high-performance' });
    this.renderer.shadowMap.enabled = true;
    this.renderer.shadowMap.type = THREE.PCFShadowMap;
    this.renderer.toneMapping = THREE.ACESFilmicToneMapping;
    this.renderer.toneMappingExposure = 1.35;

    this.scene = new THREE.Scene();
    this.scene.background = new THREE.Color(SKY);
    this.scene.fog = new THREE.FogExp2(SKY, FOG_DENSITY);
    this.camera = new THREE.PerspectiveCamera(60, 16 / 9, 0.02, 80);
    this.scene.add(this.camera);

    // Fixed light count (intensity 0 when unused) so the shaders never recompile.
    this.scene.add(new THREE.HemisphereLight(0xb8c8ee, 0x3a2c20, 1.7));
    this.sun = new THREE.DirectionalLight(0xffe2b8, 2.6);
    this.sun.castShadow = true;
    this.sun.shadow.mapSize.set(1024, 1024);
    this.sun.shadow.bias = -0.0005;
    this.sun.shadow.normalBias = 0.02;
    this.scene.add(this.sun, this.sun.target);
    this.wallLights = [];
    for (let i = 0; i < WALL_LIGHTS; i++) {
      const l = new THREE.PointLight(0xffb347, 0, 5, 2);
      this.scene.add(l);
      this.wallLights.push(l);
    }
    this.blastLights = [];
    for (let i = 0; i < BLAST_LIGHTS; i++) {
      const l = new THREE.PointLight(0xff9a40, 0, 10, 2);
      this.scene.add(l);
      this.blastLights.push(l);
    }

    this.geo = {
      leg: new THREE.CapsuleGeometry(0.09, 0.3, 3, 8),
      torso: new THREE.BoxGeometry(0.24, 0.36, 0.34),
      pack: new THREE.BoxGeometry(0.14, 0.3, 0.22),
      head: new THREE.SphereGeometry(0.12, 12, 8),
      visor: new THREE.BoxGeometry(0.06, 0.05, 0.22),
      arm: new THREE.BoxGeometry(0.1, 0.3, 0.1),
      gunPart: new THREE.BoxGeometry(0.42, 0.12, 0.09),
      wall: new THREE.BoxGeometry(1, WALL_H, 1),
      plane: new THREE.PlaneGeometry(1, 1),
      rocket: new THREE.SphereGeometry(0.1, 10, 8),
      blast: new THREE.SphereGeometry(1, 16, 12),
    };
    this.flashTex = canvasTexture(paintFlash);
    this.floorTex = canvasTexture(paintFloor, true);
    const wallMat = (paint, opts) => new THREE.MeshStandardMaterial({ map: canvasTexture(paint), ...opts });
    this.wallMats = [
      null,
      wallMat(paintBrick, { roughness: 0.9 }),
      wallMat(paintMetal, { roughness: 0.4, metalness: 0.1 }),
      wallMat(paintConcrete, { roughness: 0.95 }),
      new THREE.MeshStandardMaterial({
        map: canvasTexture(paintTrimBase),
        emissiveMap: canvasTexture(paintTrimGlow),
        emissive: 0xffffff,
        emissiveIntensity: 1.1,
        roughness: 0.5,
        metalness: 0.1,
      }),
    ];
    this.floorMat = new THREE.MeshStandardMaterial({ map: this.floorTex, roughness: 0.9 });

    this.figures = new Map();
    this.rockets = new Map();
    this.rocketFree = [];
    this.rocketCount = 0;
    this.level = [];

    this.rocketMat = new THREE.MeshBasicMaterial({ color: 0xffa040 });
    this.trailMat = new THREE.LineBasicMaterial({
      color: 0xff9a3a, transparent: true, opacity: 0.7, blending: THREE.AdditiveBlending, depthWrite: false,
    });
    this.tracers = [];
    for (let i = 0; i < TRACER_POOL; i++) {
      const g = new THREE.BufferGeometry();
      g.setAttribute('position', new THREE.BufferAttribute(new Float32Array(6), 3));
      const line = new THREE.Line(g, new THREE.LineBasicMaterial({
        color: 0xffe6a0, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false,
      }));
      line.frustumCulled = false;
      line.visible = false;
      this.scene.add(line);
      this.tracers.push(line);
    }
    this.blasts = [];
    for (let i = 0; i < BLAST_POOL; i++) {
      const m = new THREE.Mesh(this.geo.blast, new THREE.MeshBasicMaterial({
        color: 0xffa640, transparent: true, blending: THREE.AdditiveBlending, depthWrite: false,
      }));
      m.visible = false;
      this.scene.add(m);
      this.blasts.push(m);
    }

    // First-person gun, a child of the camera.
    this.gun = new THREE.Group();
    const gunMat = new THREE.MeshStandardMaterial({ color: 0x6a717e, roughness: 0.45, metalness: 0.2 });
    const gunDark = new THREE.MeshStandardMaterial({ color: 0x2a2e36, roughness: 0.6, metalness: 0.1 });
    const addGun = (geo, mat, x, y, z) => {
      const m = new THREE.Mesh(geo, mat);
      m.position.set(x, y, z);
      this.gun.add(m);
    };
    addGun(new THREE.BoxGeometry(0.08, 0.12, 0.36), gunMat, 0, 0, 0);
    addGun(new THREE.BoxGeometry(0.035, 0.035, 0.2), gunDark, 0, 0.01, -0.28);
    addGun(new THREE.BoxGeometry(0.05, 0.13, 0.06), gunDark, 0, -0.12, 0.08);
    addGun(new THREE.BoxGeometry(0.02, 0.04, 0.04), gunDark, 0, 0.08, -0.1);
    this.gunFlash = new THREE.Sprite(new THREE.SpriteMaterial({
      map: this.flashTex, color: 0xffd36b, blending: THREE.AdditiveBlending, depthWrite: false, transparent: true,
    }));
    this.gunFlash.position.set(0, 0.01, -0.4);
    this.gunFlash.scale.setScalar(0.22);
    this.gunFlash.visible = false;
    this.gun.add(this.gunFlash);
    this.gunLight = new THREE.PointLight(0xffd27a, 0.5, 4, 2);
    this.gunLight.position.set(0, 0, -0.45);
    this.gun.add(this.gunLight);
    this.camera.add(this.gun);

    this.resize();
  }

  resize() {
    const w = this.canvas.clientWidth || innerWidth;
    const h = this.canvas.clientHeight || innerHeight;
    this.renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
    this.renderer.setSize(w, h, false);
    this.camera.aspect = w / h;
    this.camera.fov = (2 * Math.atan(PLANE / this.camera.aspect) * 180) / Math.PI;
    this.camera.updateProjectionMatrix();
  }

  // Builds the static level for a WELCOME map: instanced walls per style, floor, lights.
  setMap(map) {
    for (const o of this.level) {
      this.scene.remove(o);
      if (o.isInstancedMesh) o.dispose();
      else o.geometry.dispose();
    }
    this.level = [];
    const { w, h, cells } = map;

    const count = [0, 0, 0, 0, 0];
    for (const c of cells) if (c) count[styleOf(c)]++;
    const meshes = [];
    for (let s = 1; s <= 4; s++) {
      if (!count[s]) continue;
      const m = new THREE.InstancedMesh(this.geo.wall, this.wallMats[s], count[s]);
      m.castShadow = true;
      m.receiveShadow = true;
      meshes[s] = m;
    }
    const fill = [0, 0, 0, 0, 0];
    const trims = [];
    const mtx = new THREE.Matrix4();
    for (let cy = 0; cy < h; cy++) {
      for (let cx = 0; cx < w; cx++) {
        const c = cells[cy * w + cx];
        if (!c) continue;
        const s = styleOf(c);
        mtx.makeTranslation(cx + 0.5, WALL_H / 2, cy + 0.5);
        meshes[s].setMatrixAt(fill[s]++, mtx);
        if (s === 4) trims.push(cx, cy);
      }
    }
    for (let s = 1; s <= 4; s++) {
      const m = meshes[s];
      if (!m) continue;
      m.instanceMatrix.needsUpdate = true;
      m.computeBoundingSphere();
      this.scene.add(m);
      this.level.push(m);
    }

    const floorGeo = new THREE.PlaneGeometry(w, h);
    floorGeo.rotateX(-Math.PI / 2);
    const floor = new THREE.Mesh(floorGeo, this.floorMat);
    floor.position.set(w / 2, 0, h / 2);
    floor.receiveShadow = true;
    this.floorTex.repeat.set(w, h);
    this.scene.add(floor);
    this.level.push(floor);

    // Wall-trim lights sit just outside a glowing wall, facing an open cell when one exists.
    const nTrim = trims.length / 2;
    const stride = Math.max(1, Math.floor(nTrim / WALL_LIGHTS));
    const open = [[1, 0], [-1, 0], [0, 1], [0, -1]];
    this.wallLights.forEach((light, k) => {
      const t = k * stride;
      if (t >= nTrim) {
        light.intensity = 0;
        return;
      }
      const cx = trims[2 * t], cy = trims[2 * t + 1];
      let ox = 0, oy = 0;
      for (const [dx, dy] of open) {
        const nx = cx + dx, ny = cy + dy;
        if (nx >= 0 && ny >= 0 && nx < w && ny < h && cells[ny * w + nx] === 0) {
          ox = dx * 0.62;
          oy = dy * 0.62;
          break;
        }
      }
      light.position.set(cx + 0.5 + ox, 0.8, cy + 0.5 + oy);
      light.intensity = 0.9;
    });

    const mx = w / 2, my = h / 2;
    this.sun.position.set(mx - 7, 18, my + 5);
    this.sun.target.position.set(mx, 0, my);
    const r = Math.max(w, h) / 2 + 2;
    const sc = this.sun.shadow.camera;
    sc.left = -r;
    sc.right = r;
    sc.top = r;
    sc.bottom = -r;
    sc.near = 1;
    sc.far = 60;
    sc.updateProjectionMatrix();
  }

  render(view) {
    const { camera } = this;
    const e = view.eye;
    camera.position.set(e.x, EYE_H, e.y);
    camera.lookAt(e.x + Math.cos(e.yaw), EYE_H, e.y + Math.sin(e.yaw));
    this.updateFigures(view);
    this.updateRockets(view);
    this.updateTracers(view);
    this.updateBlasts(view);
    this.updateGun(view);
    this.renderer.render(this.scene, camera);
  }

  // ---- players ----

  makeFigure(id) {
    const G = this.geo;
    const body = new THREE.MeshStandardMaterial({
      color: new THREE.Color().setHSL(hueOf(id) / 360, 0.7, 0.5), roughness: 0.6,
    });
    const dark = new THREE.MeshStandardMaterial({ color: 0x3a3f4a, roughness: 0.7, metalness: 0.1 });
    const skin = new THREE.MeshStandardMaterial({ color: 0xd9ad86, roughness: 0.8 });
    const mats = [body, dark, skin];
    for (const m of mats) m.transparent = true;

    const group = new THREE.Group();
    group.scale.setScalar(FIG_SCALE);
    const pivot = new THREE.Group();
    group.add(pivot);
    const add = (geo, mat, x, y, z) => {
      const m = new THREE.Mesh(geo, mat);
      m.position.set(x, y, z);
      m.castShadow = true;
      pivot.add(m);
    };
    add(G.leg, dark, 0, 0.24, 0.09);
    add(G.leg, dark, 0, 0.24, -0.09);
    add(G.torso, body, 0, 0.66, 0);
    add(G.pack, dark, -0.16, 0.66, 0);
    add(G.head, skin, 0, 1.02, 0);
    add(G.visor, dark, 0.12, 1.03, 0);
    add(G.arm, body, 0.02, 0.6, -0.2);
    add(G.arm, body, 0.04, 0.6, 0.2);
    add(G.gunPart, dark, 0.22, 0.6, 0.2);
    const muzzle = new THREE.Sprite(new THREE.SpriteMaterial({
      map: this.flashTex, color: 0xffd36b, blending: THREE.AdditiveBlending, depthWrite: false, transparent: true,
    }));
    muzzle.position.set(0.46, 0.6, 0.2);
    muzzle.scale.setScalar(0.3);
    muzzle.visible = false;
    pivot.add(muzzle);

    const label = new THREE.Sprite(new THREE.SpriteMaterial({ transparent: true, depthWrite: false }));
    label.scale.set(0.9, 0.225, 1);
    const bar = new THREE.Group();
    const back = new THREE.Mesh(G.plane, new THREE.MeshBasicMaterial({ color: 0x300808 }));
    back.scale.set(0.6, 0.07, 1);
    const fill = new THREE.Mesh(G.plane, new THREE.MeshBasicMaterial({ color: 0x55ff55 }));
    fill.scale.set(0.6, 0.07, 1);
    fill.position.z = 0.001;
    bar.add(back, fill);
    this.scene.add(group, label, bar);
    return { id, name: null, group, pivot, mats, body, muzzle, label, bar, fill, deadAt: -1, flashUntil: 0 };
  }

  figure(id, name) {
    let f = this.figures.get(id);
    if (!f) {
      f = this.makeFigure(id);
      this.figures.set(id, f);
    }
    if (f.name !== name) {
      f.name = name;
      const mat = f.label.material;
      mat.map?.dispose();
      mat.map = labelTexture(name, hueOf(id));
      mat.needsUpdate = true;
    }
    return f;
  }

  updateFigures(view) {
    const now = view.time;
    const seen = new Set();
    const eye = view.eye;
    for (const p of view.players) {
      seen.add(p.id);
      const f = this.figure(p.id, view.names(p.id));
      const self = p.id === view.selfId;
      f.group.visible = !self;
      f.group.position.set(p.x, 0, p.y);
      f.group.rotation.y = -yaw16ToRad(p.yaw16);

      if (p.alive) f.deadAt = -1;
      else if (f.deadAt < 0) f.deadAt = now;
      let fall = 0, opacity = 1;
      if (f.deadAt >= 0) {
        const t = (now - f.deadAt) / 1000;
        fall = Math.min(1, t / FALL_S);
        opacity = t < FALL_S ? 1 : Math.max(0.25, 1 - (0.75 * (t - FALL_S)) / FADE_S);
      }
      f.pivot.rotation.z = (-fall * Math.PI) / 2;
      for (const m of f.mats) m.opacity = opacity;
      const hl = view.killcam && p.id === view.victimId ? 0.6 : 0;
      f.body.emissive.setRGB(hl, 0, 0);

      if (p.fired) f.flashUntil = now + FLASH_MS;
      f.muzzle.visible = p.alive && now < f.flashUntil;

      const dist = Math.hypot(p.x - eye.x, p.y - eye.y);
      const show = p.alive && !self && dist < LABEL_DIST;
      f.label.visible = show;
      f.bar.visible = show;
      if (show) {
        f.label.position.set(p.x, 1.2, p.y);
        f.bar.position.set(p.x, 1.1, p.y);
        f.bar.quaternion.copy(this.camera.quaternion);
        const frac = Math.max(0, Math.min(100, p.hp)) / 100;
        f.fill.scale.x = Math.max(0.001, 0.6 * frac);
        f.fill.position.x = -0.3 + 0.3 * frac;
        f.fill.material.color.setHex(frac > 0.3 ? 0x55ff55 : 0xff5555);
      }
    }
    for (const [id, f] of this.figures) {
      if (seen.has(id)) continue;
      f.group.visible = false;
      f.label.visible = false;
      f.bar.visible = false;
    }
  }

  // ---- projectiles, effects ----

  makeRocket() {
    const pos = new Float32Array(TRAIL_LEN * 3);
    const tg = new THREE.BufferGeometry();
    tg.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    const trail = new THREE.Line(tg, this.trailMat);
    trail.frustumCulled = false;
    const mesh = new THREE.Mesh(this.geo.rocket, this.rocketMat);
    this.scene.add(mesh, trail);
    this.rocketCount++;
    return { mesh, trail, pos, hist: [] };
  }

  updateRockets(view) {
    const live = new Set();
    for (const q of view.projectiles) {
      let r = this.rockets.get(q.id);
      if (!r) {
        r = this.rocketFree.pop() || (this.rocketCount < ROCKET_POOL ? this.makeRocket() : null);
        if (!r) continue;
        r.hist.length = 0;
        this.rockets.set(q.id, r);
      }
      live.add(q.id);
      const hist = r.hist;
      hist.push(q.x, q.y);
      if (hist.length > TRAIL_LEN * 2) hist.splice(0, 2);
      const n = hist.length / 2;
      for (let i = 0; i < n; i++) {
        r.pos[3 * i] = hist[2 * i];
        r.pos[3 * i + 1] = ROCKET_Y;
        r.pos[3 * i + 2] = hist[2 * i + 1];
      }
      r.trail.geometry.attributes.position.needsUpdate = true;
      r.trail.geometry.setDrawRange(0, n);
      r.mesh.position.set(q.x, ROCKET_Y, q.y);
      r.mesh.visible = true;
      r.trail.visible = true;
    }
    for (const [id, r] of this.rockets) {
      if (live.has(id)) continue;
      r.mesh.visible = false;
      r.trail.visible = false;
      this.rockets.delete(id);
      this.rocketFree.push(r);
    }
  }

  // Effects are stateless: each frame shows those whose age is inside their lifetime.
  updateTracers(view) {
    let n = 0;
    for (const e of view.effects) {
      if (e.kind !== EFFECT.TRACER || e.age >= TRACER_LIFE || n >= TRACER_POOL) continue;
      const line = this.tracers[n++];
      const a = line.geometry.attributes.position.array;
      a[0] = e.x1; a[1] = TRACER_Y; a[2] = e.y1;
      a[3] = e.x2; a[4] = TRACER_Y; a[5] = e.y2;
      line.geometry.attributes.position.needsUpdate = true;
      line.material.opacity = 1 - e.age / TRACER_LIFE;
      line.visible = true;
    }
    for (let i = n; i < TRACER_POOL; i++) this.tracers[i].visible = false;
  }

  updateBlasts(view) {
    let n = 0, li = 0;
    for (const e of view.effects) {
      if (e.kind !== EFFECT.EXPLOSION || e.age >= BLAST_LIFE || n >= BLAST_POOL) continue;
      const t = e.age / BLAST_LIFE;
      const b = this.blasts[n++];
      b.position.set(e.x1, ROCKET_Y, e.y1);
      b.scale.setScalar(0.3 + 1.7 * t);
      b.material.opacity = 1 - t;
      b.visible = true;
      if (li < BLAST_LIGHTS) {
        const l = this.blastLights[li++];
        l.position.copy(b.position);
        l.intensity = 8 * (1 - t);
      }
    }
    for (let i = n; i < BLAST_POOL; i++) this.blasts[i].visible = false;
    for (let i = li; i < BLAST_LIGHTS; i++) this.blastLights[i].intensity = 0;
  }

  // ---- first-person gun ----

  updateGun(view) {
    const show = !!view.showGun;
    this.gun.visible = show;
    const k = view.gunKick || 0;
    this.gun.position.set(0.22, -0.21 - 0.012 * k + 0.004 * Math.sin(view.time / 180), -0.4 + 0.05 * k);
    this.gun.rotation.x = 0.12 * k;
    const flash = show && view.muzzle;
    this.gunFlash.visible = flash;
    this.gunLight.intensity = flash ? 2.5 : 0.5;
  }
}

export function createRenderer(canvas) {
  return new Renderer(canvas);
}

// Top-down view on a square canvas context of the given size (pixels).
export function drawMinimap(ctx, size, scene) {
  const map = scene.map, eye = scene.eye;
  const s = size / Math.max(map.w, map.h);
  ctx.fillStyle = 'rgba(8, 10, 16, 0.8)';
  ctx.fillRect(0, 0, size, size);
  for (let cy = 0; cy < map.h; cy++) {
    for (let cx = 0; cx < map.w; cx++) {
      const c = map.cells[cy * map.w + cx];
      if (!c) continue;
      ctx.fillStyle = WALL_CSS[c] || WALL_CSS[1];
      ctx.fillRect(cx * s, cy * s, s + 0.5, s + 0.5);
    }
  }
  ctx.fillStyle = '#ffa33a';
  for (const q of scene.projectiles) {
    ctx.beginPath();
    ctx.arc(q.x * s, q.y * s, 1.5, 0, TWO_PI);
    ctx.fill();
  }
  for (const p of scene.players) {
    if (p.id === scene.selfId) continue;
    ctx.fillStyle = p.alive ? playerColor(p.id) : '#666';
    ctx.beginPath();
    ctx.arc(p.x * s, p.y * s, 3, 0, TWO_PI);
    ctx.fill();
  }
  const dx = Math.cos(eye.yaw), dy = Math.sin(eye.yaw);
  const px = -dy * PLANE, py = dx * PLANE;
  const L = 3;
  ctx.fillStyle = 'rgba(255, 255, 255, 0.15)';
  ctx.beginPath();
  ctx.moveTo(eye.x * s, eye.y * s);
  ctx.lineTo((eye.x + (dx + px) * L) * s, (eye.y + (dy + py) * L) * s);
  ctx.lineTo((eye.x + (dx - px) * L) * s, (eye.y + (dy - py) * L) * s);
  ctx.fill();
  ctx.fillStyle = '#fff';
  ctx.beginPath();
  ctx.arc(eye.x * s, eye.y * s, 3.5, 0, TWO_PI);
  ctx.fill();
}
