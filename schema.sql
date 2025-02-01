DROP TABLE IF EXISTS reservations;
DROP TABLE IF EXISTS meal_slots;
DROP TABLE IF EXISTS users;

CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY
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
    user_email TEXT NOT NULL,
    meal_slot_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY(user_email) REFERENCES users(email),
    FOREIGN KEY(meal_slot_id) REFERENCES meal_slots(id),
    UNIQUE(user_email, meal_slot_id)
);
