'use strict';
// Minimal RFC 6455 WebSocket server (text frames, ping/pong, close) — no dependencies.
const crypto = require('crypto');
const clients = new Set();
function frame(str) {
  const p = Buffer.from(str), n = p.length; let h;
  if (n < 126) h = Buffer.from([0x81, n]); else if (n < 65536) { h = Buffer.alloc(4); h[0] = 0x81; h[1] = 126; h.writeUInt16BE(n, 2); } else { h = Buffer.alloc(10); h[0] = 0x81; h[1] = 127; h.writeBigUInt64BE(BigInt(n), 2); }
  return Buffer.concat([h, p]);
}
function accept(req, socket, onAuth) {
  const key = req.headers['sec-websocket-key']; const user = onAuth(req);
  if (!key || !user) { socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n'); return socket.destroy(); }
  const acc = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${acc}\r\n\r\n`);
  socket.user = user; clients.add(socket);
  socket.on('data', (buf) => { const op = buf[0] & 0x0f; if (op === 0x8) { clients.delete(socket); socket.end(); } else if (op === 0x9) socket.write(Buffer.from([0x8a, 0])); });
  socket.on('close', () => clients.delete(socket)); socket.on('error', () => clients.delete(socket));
  return socket;
}
function broadcast(type, data) { if (!clients.size) return; const f = frame(JSON.stringify({ type, data })); for (const c of clients) { try { c.write(f); } catch { clients.delete(c); } } }
function send(socket, type, data) { try { socket.write(frame(JSON.stringify({ type, data }))); } catch {} }
function prune(valid) { for (const c of [...clients]) if (!valid(c.user)) { try { c.end(); } catch { /* gone */ } clients.delete(c); } }
function closeAll() { for (const c of clients) { try { c.end(); } catch { /* gone */ } } clients.clear(); }
module.exports = { accept, broadcast, send, prune, closeAll, count: () => clients.size };
