DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS reservations;
DROP TABLE IF EXISTS meal_slots;
DROP TABLE IF EXISTS admins;

CREATE TABLE IF NOT EXISTS users (
    netid TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS meal_slots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL,        -- e.g. "2025-02-03"
    meal_type TEXT NOT NULL,   -- e.g. "breakfast", "lunch", "dinner"
    capacity INTEGER NOT NULL DEFAULT 25,
    UNIQUE(date, meal_type)
);

CREATE TABLE IF NOT EXISTS reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    netid TEXT NOT NULL,
    meal_slot_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    UNIQUE(netid, meal_slot_id),
    FOREIGN KEY(netid) REFERENCES users(netid) ON DELETE CASCADE,
    FOREIGN KEY(meal_slot_id) REFERENCES meal_slots(id) ON DELETE CASCADE
);

CREATE INDEX idx_reservations_netid ON reservations (netid);
CREATE INDEX idx_reservations_meal_slot ON reservations (meal_slot_id);

CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

