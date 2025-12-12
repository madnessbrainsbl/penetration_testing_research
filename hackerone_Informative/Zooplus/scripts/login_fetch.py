#!/usr/bin/env python3
"""
Small helper to log in to Zooplus (Keycloak) with username/password
and fetch a list of URLs using the authenticated session.

Usage:
  python login_fetch.py --username USER --password PASS --url https://www.zooplus.de/account/overview ...

Notes:
- Only performs GET requests; no state-changing calls.
- Built for quick triage/IDOR checks between accounts.
"""

import argparse
import re
import sys
import urllib.parse

import requests

AUTH_URL = (
    "https://login.zooplus.de/auth/realms/zooplus/protocol/openid-connect/auth"
)

UA = {"User-Agent": "Mozilla/5.0 (Cursor pentest helper)"}
COMMON_HEADERS = {
    **UA,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "de-DE,de;q=0.9,en;q=0.8",
    "Referer": "https://www.zooplus.de/account/overview",
}


def login(session: requests.Session, username: str, password: str) -> tuple[str | None, str | None]:
    """
    Simulate browser login to obtain session cookies.
    Returns (access_token_or_none, identity_token_or_none).
    Note: token endpoint may reject direct exchange; if so, identity is taken from cookie.
    """
    params = {
        "response_type": "code",
        "client_id": "shop-myzooplus-prod-zooplus",
        "redirect_uri": "https://www.zooplus.de/web/sso-myzooplus/login",
        "state": "pentest-state",
        "login": "true",
        "ui_locales": "de-DE",
        "scope": "openid",
    }
    r1 = session.get(AUTH_URL, params=params, headers=UA)
    r1.raise_for_status()

    m = re.search(r'action="([^"]*login-actions/[^"]+)"', r1.text)
    if not m:
        raise RuntimeError("Login form action not found")
    action = m.group(1).replace("&amp;", "&")
    if not action.startswith("http"):
        action = urllib.parse.urljoin(r1.url, action)

    data = {
        "username": username,
        "password": password,
        "credentialId": "",
    }
    r2 = session.post(action, data=data, headers=UA, allow_redirects=False)
    if r2.status_code not in (302, 303):
        raise RuntimeError(f"Unexpected login POST response: {r2.status_code}")

    # Follow redirect to set session; token exchange may be blocked, so rely on cookies.
    loc = r2.headers.get("Location", "")
    session.get(loc, headers=UA, allow_redirects=True)
    session.get(
        "https://www.zooplus.de/web/sso-myzooplus/login-successful.htm",
        headers=UA,
        allow_redirects=True,
    )
    # Prime main domain cookies (sid/csrf) by loading account page.
    session.get("https://www.zooplus.de/account/overview", headers=UA, allow_redirects=True)
    identity = session.cookies.get("KEYCLOAK_IDENTITY")
    return None, identity


def fetch(
    session: requests.Session, url: str, bearer: str | None
) -> tuple[int, str, str]:
    headers = dict(COMMON_HEADERS)
    csrf = session.cookies.get("csrfToken")
    if csrf:
        headers["x-csrf-token"] = csrf
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    r = session.get(url, headers=headers, allow_redirects=False)
    body = r.text
    location = r.headers.get("Location", "")
    return r.status_code, location, body


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument(
        "--url",
        action="append",
        dest="urls",
        required=True,
        help="URL to fetch (repeatable)",
    )
    args = parser.parse_args()

    with requests.Session() as s:
        access_token, identity = login(s, args.username, args.password)
        bearer = access_token or identity
        print(f"Logged in as {args.username}. Cookies: {s.cookies.get_dict()}")
        for url in args.urls:
            try:
                status, location, body = fetch(s, url, bearer)
                preview = body[:400].replace("\n", " ")
                print(f"[{status}] {url}")
                if location:
                    print(f"  Location: {location}")
                print(f"  Body (first 400 chars): {preview}")
            except Exception as exc:  # noqa: BLE001
                print(f"[error] {url}: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()

