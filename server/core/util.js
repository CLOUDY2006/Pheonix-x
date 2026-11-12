'use strict';
const crypto = require('crypto');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const uid = (p) => `${p}-${crypto.randomBytes(4).toString('hex')}`;
const sha256 = (s) => crypto.createHash('sha256').update(typeof s === 'string' ? s : JSON.stringify(s)).digest('hex');
const clamp = (n, a, b) => Math.max(a, Math.min(b, n));
const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];
module.exports = { sleep, uid, sha256, clamp, pick };
