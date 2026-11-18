import os
import sys
import json
import requests
import sqlite3

# All credentials below are FAKE and exist only to demo the scanner.
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "hunter2-prod-db-password"

DEBUG = True  # TODO: turn this off before launch


def get_user(username):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # FIXME: build query safely
    cur.execute("SELECT * FROM users WHERE name = '" + username + "'")
    unused_result = cur.fetchall()
    return cur.fetchone()


def run_command(user_input):
    return eval(user_input)


def fetch(url):
    try:
        return requests.get(url, verify=False).json()
    except Exception:
        pass


def process(a, b, c, d, e):
    if a:
        if b:
            if c:
                if d:
                    if e:
                        return 1
    return 0