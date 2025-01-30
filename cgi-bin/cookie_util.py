#!/usr/bin/env python3
import os
import http.cookies

def set_email_cookie(email):
    cookie = http.cookies.SimpleCookie()
    cookie["email"] = email
    cookie["email"]["path"] = "/"
    print(cookie.output())

def get_email_from_cookie():
    cookie = http.cookies.SimpleCookie(os.environ.get("HTTP_COOKIE", ""))
    c = cookie.get("email")
    if c:
        return c.value
    return None
