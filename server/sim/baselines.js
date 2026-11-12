'use strict';
// Static facts the generator and detection baselines share.
module.exports = {
  geos: { 'US-NY': { city: 'New York', ip: '198.51.100.' }, 'GB-LON': { city: 'London', ip: '203.0.113.' }, 'US-TX': { city: 'Austin', ip: '192.0.2.' }, 'SG-SIN': { city: 'Singapore', ip: '198.18.0.' } },
  unusualGeos: { 'RU-MOW': 'Moscow', 'KP-FNJ': 'Pyongyang(sim)', 'NG-LOS': 'Lagos', 'BR-SAO': 'Sao Paulo', 'RO-BUC': 'Bucharest' },
  businessHours: [7, 19], // UTC hours considered normal
};
