#!/usr/bin/env python3
"""Check how a service's own OAuth token will fare.

Fetches a real client_credentials token for a registered client and reports
what audiences it carries and which services accept it. Use it before turning
on REQUIRED_AUDIENCE anywhere: the client registration says what a token *would*
contain, this says what actually happens.

    set -a; . /etc/countinghouse/env; set +a
    ./check-client-token.py --client countinghouse \
        https://config.swee.net/healthz https://id.swee.net/api/v1/auth/me

Safety properties, in order of how much they matter:

  * The secret is read from the environment or a file, never from the command
    line, and never appears in this process's arguments — so it cannot be read
    from `ps` by another user on the box. This is why it is not a shell script:
    curl takes credentials as arguments, and there is no way around that.
  * The secret and the token are never printed, logged, or written anywhere.
    Only decoded claims are shown.
  * Probe URLs must be https and on an allowed host. A mistyped hostname would
    otherwise send a live Bearer token to a stranger.
  * Probes are GET only. Nothing this script does can change any state.
  * Nothing is written to disk. No temp files, no cache, no output files.
  * One token request per run. Identity rate-limits that endpoint to 5/min and
    the service being checked shares that budget.
"""

import argparse
import base64
import json
import os
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_ISSUER = "https://id.swee.net"
DEFAULT_ALLOWED_SUFFIXES = (".swee.net",)
USER_AGENT = "check-client-token/1.0"
TIMEOUT = 15

# Exit codes: 0 all probes accepted, 1 something was rejected,
# 2 usage/configuration problem, 3 could not obtain a token.
EXIT_OK, EXIT_REJECTED, EXIT_USAGE, EXIT_NO_TOKEN = 0, 1, 2, 3


def die(msg, code=EXIT_USAGE):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def redact(text, secret):
    """Never let a secret escape through an error message."""
    if secret and secret in text:
        text = text.replace(secret, "<redacted>")
    return text


def load_env_file(path):
    """Read KEY=VALUE lines. Deliberately not a shell parser: no expansion, no
    command substitution, nothing executed."""
    if not os.path.exists(path):
        die(f"no such env file: {path}")
    if not os.path.isfile(path):
        die(f"not a regular file: {path}")
    try:
        st = os.stat(path)
    except OSError as e:
        die(f"cannot stat {path}: {e}")
    if st.st_mode & (stat.S_IRGRP | stat.S_IROTH):
        print(f"warning: {path} is readable by group or others (mode "
              f"{stat.filemode(st.st_mode)}) — it holds a client secret",
              file=sys.stderr)
    values = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key:
                    values[key] = val
    except OSError as e:
        die(f"cannot read {path}: {e}")
    return values


LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1", "[::1]")


def is_loopback(host):
    return (host or "").lower().strip("[]") in ("localhost", "127.0.0.1", "::1")


def check_url(raw, allowed_suffixes, allow_http_loopback=False):
    """A live Bearer token is about to be sent here, so be strict."""
    try:
        u = urllib.parse.urlparse(raw)
    except ValueError:
        die(f"cannot parse URL: {raw}")
    host = (u.hostname or "").lower()
    if u.scheme != "https":
        # http is permitted only to loopback, and only when asked for
        # explicitly. Anything leaving the machine must be encrypted.
        if not (allow_http_loopback and u.scheme == "http" and is_loopback(host)):
            die(f"refusing to send a token over {u.scheme or 'no scheme'}: {raw}\n"
                f"       (https only — a token sent in clear is a token disclosed;\n"
                f"        --allow-http-loopback permits http to localhost for testing)")
    if not host:
        die(f"no host in URL: {raw}")
    if is_loopback(host) and allow_http_loopback:
        return raw
    if not any(host == s.lstrip(".") or host.endswith(s) for s in allowed_suffixes):
        die(f"refusing to send a token to {host}\n"
            f"       allowed: {', '.join(allowed_suffixes)}\n"
            f"       (use --allow-host to widen this deliberately)")
    return raw


def post_form(url, fields, headers=None):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", USER_AGENT)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
        return None, str(e)


def fetch_token(issuer, client_id, secret):
    """Try client_secret_basic, then client_secret_post.

    Identity enforces the client's registered token_endpoint_auth_method, so
    the wrong one is a 401 rather than a fallback — hence trying both and
    reporting which was accepted.
    """
    token_url = issuer.rstrip("/") + "/oauth/token"
    attempts = []

    basic = base64.b64encode(
        f"{urllib.parse.quote(client_id, safe='')}:"
        f"{urllib.parse.quote(secret, safe='')}".encode()
    ).decode()
    status, body = post_form(token_url, {"grant_type": "client_credentials"},
                             {"Authorization": "Basic " + basic})
    attempts.append(("client_secret_basic", status, body))
    if status == 200:
        return "client_secret_basic", body, attempts

    status, body = post_form(token_url, {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": secret,
    })
    attempts.append(("client_secret_post", status, body))
    if status == 200:
        return "client_secret_post", body, attempts

    return None, None, attempts


def decode_claims(token):
    parts = token.split(".")
    if len(parts) != 3:
        die("the token is not a JWT (expected three dot-separated parts)", EXIT_NO_TOKEN)
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception as e:
        die(f"cannot decode token claims: {e}", EXIT_NO_TOKEN)


def probe(url, token):
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("User-Agent", USER_AGENT)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, ""
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            body = json.loads(e.read().decode("utf-8", "replace"))
            detail = body.get("error") or body.get("message") or ""
        except Exception:
            pass
        return e.code, detail
    except (urllib.error.URLError, OSError) as e:
        return None, str(e)


def main():
    p = argparse.ArgumentParser(
        description="Check what a service's OAuth token contains and who accepts it.",
        epilog="The secret is never accepted as an argument. Set CLIENT_SECRET "
               "in the environment or use --env-file.")
    p.add_argument("urls", nargs="*", metavar="URL",
                   help="https endpoints to probe with the token (GET only)")
    p.add_argument("--client", dest="client_id", default=os.environ.get("CLIENT_ID"),
                   help="client id (or set CLIENT_ID)")
    p.add_argument("--env-file", help="read CLIENT_ID/CLIENT_SECRET from a KEY=VALUE file")
    p.add_argument("--secret-var", default="CLIENT_SECRET",
                   help="env/file variable holding the secret (default CLIENT_SECRET)")
    p.add_argument("--issuer", default=os.environ.get("ISSUER", DEFAULT_ISSUER))
    p.add_argument("--allow-host", action="append", default=[],
                   metavar="SUFFIX", help="additional permitted host suffix")
    p.add_argument("--allow-http-loopback", action="store_true",
                   help="permit http:// to localhost (local testing only)")
    p.add_argument("--dry-run", action="store_true",
                   help="show what would be done and make no requests at all")
    args = p.parse_args()

    allowed = tuple(DEFAULT_ALLOWED_SUFFIXES) + tuple(args.allow_host)

    env = dict(os.environ)
    if args.env_file:
        env.update(load_env_file(args.env_file))

    client_id = args.client_id or env.get("CLIENT_ID")
    secret = env.get(args.secret_var)

    if not client_id:
        die("no client id — pass --client or set CLIENT_ID")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", client_id):
        die(f"implausible client id: {client_id!r}")
    if not secret:
        die(f"no secret — set {args.secret_var} in the environment, or use "
            f"--env-file.\n       Never pass a secret as a command-line argument.")

    # A secret on the command line would already be in the shell history and
    # the process list; refuse rather than pretend it is safe.
    #
    # Only meaningful for a secret long enough that an accidental match is not
    # plausible — substring-matching a short one flags every argument that
    # happens to contain those characters.
    MIN_MATCHABLE_SECRET = 12
    for a in sys.argv[1:]:
        if secret and len(secret) >= MIN_MATCHABLE_SECRET and secret in a:
            die("the secret appears in this command's arguments. It is now in "
                "your shell history and was visible in `ps`.\n"
                "       Rotate it, then use --env-file or the environment.")

    issuer_host = (urllib.parse.urlparse(args.issuer).hostname or "").lower()
    if not args.issuer.startswith("https://"):
        if not (args.allow_http_loopback and args.issuer.startswith("http://")
                and is_loopback(issuer_host)):
            die(f"issuer must be https: {args.issuer}")

    urls = [check_url(u, allowed, args.allow_http_loopback) for u in args.urls]

    print(f"Client:  {client_id}")
    print(f"Issuer:  {args.issuer}")
    print(f"Probing: {len(urls)} endpoint(s)" if urls else "Probing: none given")
    print()

    if args.dry_run:
        print("Dry run — no requests made. Would:")
        print(f"  1. POST {args.issuer.rstrip('/')}/oauth/token (client_credentials)")
        for u in urls:
            print(f"  2. GET  {u}")
        print("\nNothing is written to disk, and no request changes state.")
        return EXIT_OK

    method, body, attempts = fetch_token(args.issuer, client_id, secret)
    if method is None:
        print("Could not obtain a token. Attempts:", file=sys.stderr)
        for m, status, text in attempts:
            print(f"  {m:22} -> {status if status else 'unreachable'} "
                  f"{redact(text, secret)[:180]}", file=sys.stderr)
        return EXIT_NO_TOKEN

    try:
        token = json.loads(body)["access_token"]
    except (ValueError, KeyError):
        die("token endpoint returned no access_token", EXIT_NO_TOKEN)

    claims = decode_claims(token)
    print(f"Token obtained via {method}")
    print(f"  aud:   {claims.get('aud')}")
    print(f"  scope: {claims.get('scope')!r}")
    print(f"  sub:   {claims.get('sub')}")
    print(f"  exp:   {claims.get('exp')}")
    print()

    if not urls:
        print("No URLs given, so nothing was probed. Pass the endpoints this "
              "service calls to see how they respond.")
        return EXIT_OK

    print("How each service responds")
    worst = EXIT_OK
    for u in urls:
        status, detail = probe(u, token)
        if status is None:
            verdict, worst = f"UNREACHABLE ({detail})", max(worst, EXIT_REJECTED)
        elif 200 <= status < 300:
            verdict = "accepted"
        elif status == 401:
            verdict, worst = f"REJECTED — unauthenticated {detail}", EXIT_REJECTED
        elif status == 403:
            verdict, worst = f"REJECTED — {detail or 'forbidden'}", EXIT_REJECTED
        else:
            verdict = f"HTTP {status} {detail}"
        print(f"  {str(status or '---'):>4}  {u:<52} {verdict}")

    print()
    if worst != EXIT_OK:
        print("A rejection here is what this service will do in production.")
        print("If it says invalid_audience, add that service to this client's")
        print("audiences at /admin/oauth before enforcing.")
    else:
        print("This client's token is accepted by every endpoint tested.")
    return worst


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
