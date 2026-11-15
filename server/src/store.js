'use strict';

const fs = require('node:fs');
const path = require('node:path');

/**
 * Single-file JSON store with atomic writes.
 *
 * Deliberately dependency-free for the MVP. Replace this module with Mongo/Postgres
 * when you need more than one server instance; nothing else imports the storage detail.
 */
function openStore(file) {
  const absolute = path.resolve(file);
  let db = { products: [], keys: [], activations: [] };

  if (fs.existsSync(absolute)) {
    const raw = fs.readFileSync(absolute, 'utf8').trim();
    if (raw) {
      try {
        db = JSON.parse(raw);
      } catch (err) {
        throw new Error(`store: ${absolute} is not valid JSON (${err.message})`);
      }
    }
  }
  db.products ||= [];
  db.keys ||= [];
  db.activations ||= [];

  function save() {
    fs.mkdirSync(path.dirname(absolute), { recursive: true });
    const tmp = `${absolute}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
    fs.renameSync(tmp, absolute);
  }

  if (!fs.existsSync(absolute)) save();

  return { db, save, file: absolute };
}

module.exports = { openStore };
