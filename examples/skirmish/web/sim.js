// Shared simulation rules for the browser client (game and bots).
// Mirrors examples/skirmish/PROTOCOL.md; all math is float64.

export const TICK_RATE = 60;
export const TICK_DT = 1 / 60;
export const MOVE_SPEED = 4.0;
export const PLAYER_RADIUS = 0.25;
export const TWO_PI = 2 * Math.PI;

// Map is {w, h, cells: Uint8Array} row-major (y * w + x). Outside counts as wall.
export function cellAt(map, cx, cy) {
  if (cx < 0 || cy < 0 || cx >= map.w || cy >= map.h) return 1;
  return map.cells[cy * map.w + cx];
}

// True when the box [x-r, x+r] x [y-r, y+r] overlaps a wall cell (open intervals,
// so a box exactly touching a cell edge is not blocked).
export function isBlocked(map, x, y, r) {
  const x0 = Math.floor(x - r), x1 = Math.ceil(x + r) - 1;
  const y0 = Math.floor(y - r), y1 = Math.ceil(y + r) - 1;
  for (let cy = y0; cy <= y1; cy++) {
    for (let cx = x0; cx <= x1; cx++) {
      if (cellAt(map, cx, cy) !== 0) return true;
    }
  }
  return false;
}

// Moves along one axis (horizontal: x, otherwise y) and returns the new coordinate
// on that axis. The other coordinate of (x, y) is the current one.
export function moveAxis(map, x, y, d, horizontal) {
  const p = horizontal ? x : y;
  if (d === 0) return p;
  const np = p + d;
  const blocked = horizontal
    ? isBlocked(map, np, y, PLAYER_RADIUS)
    : isBlocked(map, x, np, PLAYER_RADIUS);
  if (!blocked) return np;
  return d > 0
    ? Math.floor(np + PLAYER_RADIUS) - PLAYER_RADIUS - 0.001
    : Math.floor(np - PLAYER_RADIUS) + 1 + PLAYER_RADIUS + 0.001;
}

// One input applied to a position. Buttons: bit0 fwd, bit1 back, bit2 left, bit3 right.
// Dead players do not move. Returns a new {x, y}.
export function stepMove(map, x, y, buttons, yaw16, alive = true) {
  if (!alive) return { x, y };
  const yaw = yaw16 / 65536 * TWO_PI;
  const fx = Math.cos(yaw), fy = Math.sin(yaw);
  const rx = -Math.sin(yaw), ry = Math.cos(yaw);
  const fwd = (buttons & 1) ? 1 : 0, back = (buttons & 2) ? 1 : 0;
  const left = (buttons & 4) ? 1 : 0, right = (buttons & 8) ? 1 : 0;
  let mx = (fwd - back) * fx + (right - left) * rx;
  let my = (fwd - back) * fy + (right - left) * ry;
  const len = Math.sqrt(mx * mx + my * my);
  if (len > 0) { mx /= len; my /= len; }
  const dx = mx * 4.0 / 60, dy = my * 4.0 / 60;
  const nx = moveAxis(map, x, y, dx, true);
  const ny = moveAxis(map, nx, y, dy, false);
  return { x: nx, y: ny };
}

export function yaw16ToRad(v) {
  return v / 65536 * TWO_PI;
}

export function radToYaw16(rad) {
  const f = ((rad % TWO_PI) + TWO_PI) % TWO_PI;
  return Math.round(f / TWO_PI * 65536) & 0xffff;
}

// Wraps an angle in radians to [-pi, pi].
export function wrapAngle(a) {
  return a - TWO_PI * Math.round(a / TWO_PI);
}

// Grid DDA. The ray is origin + t * (dx, dy) for t in [0, maxT); t is measured in
// units of (dx, dy). Returns {t, cell, side} for the first wall (side 0 = crossed an
// x grid line, 1 = a y grid line) or null.
export function raycast(map, ox, oy, dx, dy, maxT) {
  let mapX = Math.floor(ox), mapY = Math.floor(oy);
  const origin = cellAt(map, mapX, mapY);
  if (origin !== 0) return { t: 0, cell: origin, side: 0 };
  const ddx = dx === 0 ? Infinity : Math.abs(1 / dx);
  const ddy = dy === 0 ? Infinity : Math.abs(1 / dy);
  let stepX, stepY, sdx, sdy;
  if (dx < 0) { stepX = -1; sdx = (ox - mapX) * ddx; } else { stepX = 1; sdx = (mapX + 1 - ox) * ddx; }
  if (dy < 0) { stepY = -1; sdy = (oy - mapY) * ddy; } else { stepY = 1; sdy = (mapY + 1 - oy) * ddy; }
  for (let i = 0; i < 100000; i++) {
    let t, side;
    if (sdx < sdy) {
      t = sdx; sdx += ddx; mapX += stepX; side = 0;
    } else {
      t = sdy; sdy += ddy; mapY += stepY; side = 1;
    }
    if (t >= maxT) return null;
    const cell = cellAt(map, mapX, mapY);
    if (cell !== 0) return { t, cell, side };
  }
  return null;
}

// Line of sight between two points: no wall strictly between them.
export function hasLineOfSight(map, ax, ay, bx, by) {
  return raycast(map, ax, ay, bx - ax, by - ay, 1 - 1e-9) === null;
}
