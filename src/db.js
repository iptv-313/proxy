const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const dbPath = process.env.DB_PATH
  ? path.resolve(process.env.DB_PATH)
  : path.resolve(__dirname, "../database.sqlite");
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS access_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,
      label TEXT,
      is_admin INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS portals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      url TEXT NOT NULL,
      mac TEXT,
      type TEXT DEFAULT 'stalker',
      is_active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Never create a publicly known default credential. A fresh database must
  // be bootstrapped explicitly through INITIAL_ADMIN_CODE.
  db.get("SELECT count(*) as count FROM access_codes", (err, row) => {
    if (row && row.count === 0) {
      const initialCode = process.env.INITIAL_ADMIN_CODE;
      if (!initialCode) {
        console.error("No access codes exist. Set INITIAL_ADMIN_CODE once to bootstrap the first admin account.");
        return;
      }
      db.run(
        "INSERT INTO access_codes (code, label, is_admin) VALUES (?, ?, ?)",
        [initialCode, "Initial Admin", 1],
        (insertErr) => {
          if (insertErr) console.error("Could not create initial admin access code:", insertErr.message);
          else console.log("Initial admin access code created from INITIAL_ADMIN_CODE.");
        },
      );
    }
  });
});

module.exports = {
  db,
  verifyCode: (code) => {
    return new Promise((resolve, reject) => {
      db.get("SELECT * FROM access_codes WHERE code = ?", [code], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });
  },
  getAccessCodes: () => {
    return new Promise((resolve, reject) => {
      db.all("SELECT * FROM access_codes ORDER BY created_at DESC", [], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });
  },
  addAccessCode: (code, label, isAdmin = 0) => {
    return new Promise((resolve, reject) => {
      db.run("INSERT INTO access_codes (code, label, is_admin) VALUES (?, ?, ?)", [code, label, isAdmin], function(err) {
        if (err) reject(err);
        resolve({ id: this.lastID });
      });
    });
  },
  deleteAccessCode: (id) => {
    return new Promise((resolve, reject) => {
      db.run("DELETE FROM access_codes WHERE id = ?", [id], (err) => {
        if (err) reject(err);
        resolve();
      });
    });
  },
  getPortals: () => {
    return new Promise((resolve, reject) => {
      db.all("SELECT * FROM portals WHERE is_active = 1 ORDER BY created_at DESC", [], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });
  },
  addPortal: (name, url, mac, type = 'stalker') => {
    return new Promise((resolve, reject) => {
      db.run("INSERT INTO portals (name, url, mac, type) VALUES (?, ?, ?, ?)", [name, url, mac, type], function(err) {
        if (err) reject(err);
        resolve({ id: this.lastID });
      });
    });
  },
  deletePortal: (id) => {
    return new Promise((resolve, reject) => {
      db.run("DELETE FROM portals WHERE id = ?", [id], (err) => {
        if (err) reject(err);
        resolve();
      });
    });
  }
};
