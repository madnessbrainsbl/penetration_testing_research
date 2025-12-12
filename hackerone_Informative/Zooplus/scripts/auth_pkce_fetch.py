#!/usr/bin/env python3
"""
PKCE auth-code flow against Zooplus Keycloak, then fetch APIs with Bearer.

Usage:
  python auth_pkce_fetch.py --username USER --password PASS --url https://www.zooplus.de/myaccount/api/order-details/v3/customer/lastOrders [...]
"""
import argparse
import base64
import hashlib
import re
import secrets
import sys
import urllib.parse

import requests

AUTH_BASE = "https://login.zooplus.de/auth/realms/zooplus/protocol/openid-connect"
UA = {"User-Agent": "Mozilla/5.0 (pkce helper)"}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def get_code(
    session: requests.Session,
    username: str,
    password: str,
    client_id: str,
    redirect_uri: str,
) -> tuple[str, str]:
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = b64url(hashlib.sha256(code_verifier.encode()).digest())
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    params = {
        "response_type": "code",
        "response_mode": "fragment",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "state": state,
        "nonce": nonce,
        "prompt": "login",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    authorize_url = f"{AUTH_BASE}/auth"
    r1 = session.get(authorize_url, params=params, headers=UA)
    r1.raise_for_status()
    m = re.search(r'action="([^"]*login-actions/[^"]+)"', r1.text)
    if not m:
        raise RuntimeError("login form action not found")
    action = m.group(1).replace("&amp;", "&")
    if not action.startswith("http"):
        action = urllib.parse.urljoin(r1.url, action)
    data = {"username": username, "password": password, "credentialId": ""}
    r2 = session.post(action, data=data, headers=UA, allow_redirects=False)
    if r2.status_code not in (302, 303):
        raise RuntimeError(f"unexpected login POST: {r2.status_code}")
    loc = r2.headers.get("Location", "")
    # Follow once if no fragment yet.
    if "#code=" not in loc:
        r3 = session.get(loc, headers=UA, allow_redirects=False)
        loc = r3.headers.get("Location", loc)
    parsed = urllib.parse.urlparse(loc)
    frag = urllib.parse.parse_qs(parsed.fragment)
    code = frag.get("code", [None])[0]
    if not code:
        raise RuntimeError("code not found in redirect")
    return code, code_verifier


def exchange_token(
    session: requests.Session,
    code: str,
    code_verifier: str,
    client_id: str,
    redirect_uri: str,
) -> str:
    token_url = f"{AUTH_BASE}/token"
    resp = session.post(
        token_url,
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded", **UA},
    )
    resp.raise_for_status()
    token = resp.json().get("access_token")
    if not token:
        raise RuntimeError("no access_token in token response")
    return token


def fetch(session: requests.Session, url: str, token: str) -> tuple[int, str, str]:
    headers = {
        **UA,
        "Accept": "application/json, text/plain, */*",
        "Authorization": f"Bearer {token}",
    }
    csrf = session.cookies.get("csrfToken")
    if csrf:
        headers["x-csrf-token"] = csrf
    r = session.get(url, headers=headers, allow_redirects=False)
    return r.status_code, r.headers.get("Location", ""), r.text[:400].replace("\n", " ")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--client-id", default="frontend-authorizer-zooplus")
    parser.add_argument(
        "--redirect-uri",
        default="https://www.zooplus.de/web/sso-myzooplus/silent-check-sso.htm",
    )
    parser.add_argument("--url", action="append", dest="urls", required=True)
    args = parser.parse_args()

    with requests.Session() as s:
        code, verifier = get_code(
            s, args.username, args.password, args.client_id, args.redirect_uri
        )
        token = exchange_token(
            s, code, verifier, args.client_id, args.redirect_uri
        )
        print("access_token obtained")
        # establish shop cookies on main domain
        s.get("https://www.zooplus.de/web/sso-myzooplus/login-successful.htm", headers=UA, allow_redirects=True)
        s.get("https://www.zooplus.de/account/overview", headers=UA, allow_redirects=True)
        for url in args.urls:
            try:
                status, loc, body = fetch(s, url, token)
                print(f"[{status}] {url}")
                if loc:
                    print(f"  Location: {loc}")
                print(f"  Body: {body}")
            except Exception as exc:  # noqa: BLE001
                print(f"[error] {url}: {exc}", file=sys.stderr)
                continue


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

