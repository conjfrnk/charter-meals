CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS meal_slots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL,        -- e.g. "2025-02-03"
    meal_type TEXT NOT NULL,   -- e.g. "breakfast", "lunch", "dinner"
    capacity INTEGER NOT NULL DEFAULT 25
);

CREATE TABLE IF NOT EXISTS reservations (
    user_email TEXT NOT NULL,
    meal_slot_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    UNIQUE(user_email, meal_slot_id)
);
