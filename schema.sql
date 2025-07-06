DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS meal_slots;
DROP TABLE IF EXISTS reservations;
DROP TABLE IF EXISTS admins;
DROP TABLE IF EXISTS settings;
DROP TABLE IF EXISTS website_content;
DROP TABLE IF EXISTS archived_users;
DROP TABLE IF EXISTS archived_meal_slots;
DROP TABLE IF EXISTS archived_reservations;

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
    added_by TEXT,
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

CREATE TABLE IF NOT EXISTS website_content (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content_key TEXT UNIQUE NOT NULL,
    content_value TEXT NOT NULL,
    description TEXT,
    last_updated TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Insert default website content
INSERT OR IGNORE INTO website_content (content_key, content_value, description) VALUES
('welcome_header', 'Welcome to Charter!!', 'Main header on the meal signup page'),
('welcome_message', 'We can''t wait to see you at Charter meals!', 'Welcome message below the header'),
('contact_info', 'Contact our kitchen managers, Tiffany and Hector, if you have any questions.', 'Contact information text'),
('feedback_link', 'https://forms.gle/PawcrnA9y9CtAgDM9', 'Feedback form URL'),
('feedback_text', 'If you have any feedback on this website, please fill out this form. Thanks! -Connor', 'Feedback text with link'),
('meal_rules_title', 'Rules for Meal Sign-Up', 'Title for the meal rules section'),
('meal_rules', 'You can sign up for a maximum of 2 meals per week (pub nights count as one meal).\nIn order to give everyone a chance to attend pub night, you may select at most 1 pub night (dinner of Tuesday or Thursday).\nAgain for the sake of fairness, if you attended a pub night last week, you cannot sign up for one this week (i.e. you can only sign up for a pub night every two weeks).\nIf a meal time is full or otherwise ineligible, the checkbox will not appear.', 'Meal signup rules (one rule per line)');

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

-- Archive tables for sentimental data preservation
CREATE TABLE IF NOT EXISTS archived_users (
    netid TEXT PRIMARY KEY,
    name TEXT,
    archived_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS archived_meal_slots (
    id INTEGER PRIMARY KEY,
    date TEXT NOT NULL,
    meal_type TEXT NOT NULL,
    capacity INTEGER NOT NULL DEFAULT 25,
    archived_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS archived_reservations (
    id INTEGER PRIMARY KEY,
    netid TEXT NOT NULL,
    meal_slot_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    added_by TEXT,
    archived_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for faster queries
CREATE INDEX IF NOT EXISTS idx_meal_slots_date ON meal_slots(date);
CREATE INDEX IF NOT EXISTS idx_reservations_netid ON reservations(netid);
CREATE INDEX IF NOT EXISTS idx_reservations_meal_slot_id ON reservations(meal_slot_id);
