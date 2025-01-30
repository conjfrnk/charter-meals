#!/usr/bin/env python3
import sqlite3

DB_PATH = "/var/www/data/meals.db"

def get_db():
    return sqlite3.connect(DB_PATH)
