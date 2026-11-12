'use strict';
// Tiny pub/sub. Everything the dashboard sees flows through here (and out over WebSocket).
const { EventEmitter } = require('events');
const bus = new EventEmitter();
bus.setMaxListeners(100);
module.exports = bus;
