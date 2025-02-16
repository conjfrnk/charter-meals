DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS meal_slots;
DROP TABLE IF EXISTS reservations;
DROP TABLE IF EXISTS admins;
DROP TABLE IF EXISTS settings;

CREATE TABLE IF NOT EXISTS users (
    netid TEXT PRIMARY KEY,
    name TEXT
);

CREATE TABLE IF NOT EXISTS meal_slots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL,
    meal_type TEXT NOT NULL,
    capacity INTEGER NOT NULL DEFAULT 25,
    UNIQUE(date, meal_type)
);

CREATE TABLE IF NOT EXISTS reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    netid TEXT NOT NULL,
    meal_slot_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    added_by TEXT,  -- If not NULL, indicates this reservation was manually added by an admin.
    UNIQUE(netid, meal_slot_id),
    FOREIGN KEY(netid) REFERENCES users(netid) ON DELETE CASCADE,
    FOREIGN KEY(meal_slot_id) REFERENCES meal_slots(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- Trigger to enforce meal slot capacity only for reservations added by users.
-- (Admin‑added reservations have a non‑NULL added_by and bypass this check.)
CREATE TRIGGER IF NOT EXISTS limit_reservations
BEFORE INSERT ON reservations
WHEN NEW.added_by IS NULL
BEGIN
  SELECT
    CASE
      WHEN ((SELECT COUNT(*) FROM reservations WHERE meal_slot_id = NEW.meal_slot_id) >=
            (SELECT capacity FROM meal_slots WHERE id = NEW.meal_slot_id))
      THEN RAISE(ABORT, 'This meal slot is full.')
    END;
END;
