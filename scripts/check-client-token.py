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


def _stat_and_warn(path):
    """Common checks for any file we are about to read a secret out of."""
    if not os.path.exists(path):
        die(f"no such file: {path}")
    if not os.path.isfile(path):
        die(f"not a regular file: {path}")
    if not os.access(path, os.R_OK):
        die(f"cannot read {path}\n"
            f"       it likely belongs to the service user — try:\n"
            f"       sudo {' '.join(sys.argv)}")
    try:
        st = os.stat(path)
    except OSError as e:
        die(f"cannot stat {path}: {e}")
    # Warn only on world-readable. Group-readable is the normal shape for a
    # service config — root owns it, the service's own group reads it — so
    # warning about 640 fires on correct deployments and teaches people to
    # ignore the warning that matters.
    if st.st_mode & stat.S_IROTH:
        print(f"warning: {path} is world-readable "
              f"(mode {stat.filemode(st.st_mode)}) — it holds a client secret",
              file=sys.stderr)


def read_config(path):
    """Read scalar values out of a simple config file, keyed by dotted path.

    This is NOT a YAML parser. It understands `key: value` and `KEY=VALUE`,
    nested by indentation, which is what service config files in this estate
    actually contain. It deliberately refuses anything it cannot read plainly
    rather than guessing — a misread secret is a confusing 401, and a misread
    *key* could send the wrong value somewhere.

    Unsupported, and rejected rather than mangled: multi-line scalars (| and >),
    anchors and aliases (& and *), and flow mappings ({a: b}).
    """
    _stat_and_warn(path)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError as e:
        die(f"cannot read {path}: {e}")

    values, stack = {}, []
    for lineno, raw in enumerate(lines, 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw.lstrip().startswith("- "):
            continue  # list item: not a scalar mapping, skip
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()

        if ":" in line:
            key, _, val = line.partition(":")
        elif "=" in line:
            key, _, val = line.partition("=")
        else:
            continue
        key, val = key.strip(), val.strip()
        if not key:
            continue

        # Strip a trailing comment from an unquoted value.
        if val and val[0] not in "\"'":
            val = val.split(" #", 1)[0].strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]

        if val in ("|", ">", "|-", ">-"):
            die(f"{path}:{lineno}: multi-line values are not supported by this "
                f"reader.\n       Pass the secret via the environment instead.")
        if val.startswith("&") or val.startswith("*"):
            die(f"{path}:{lineno}: YAML anchors/aliases are not supported by "
                f"this reader.\n       Pass the secret via the environment instead.")
        if val.startswith("{"):
            die(f"{path}:{lineno}: inline mappings are not supported by this "
                f"reader.\n       Pass the secret via the environment instead.")

        while stack and stack[-1][0] >= indent:
            stack.pop()
        path_parts = [k for _, k in stack] + [key]

        if val == "":
            stack.append((indent, key))
            continue

        dotted = ".".join(path_parts)
        if dotted in values and values[dotted] != val:
            die(f"{path}: {dotted} appears more than once with different "
                f"values — refusing to guess which is meant")
        values[dotted] = val
    return values


def find_value(values, explicit, candidates, what, path):
    """Resolve one setting: an explicit key path, else the first candidate that
    matches exactly one entry. Ambiguity is an error, never a guess."""
    # Key names vary in case between YAML (client_secret) and env-style files
    # (OAUTH_CLIENT_SECRET), so match case-insensitively throughout.
    def norm(k):
        return k.lower().replace("-", "_")

    if explicit:
        for k in values:
            if norm(k) == norm(explicit):
                return values[k], k
        tail = {k: v for k, v in values.items()
                if norm(k.split(".")[-1]) == norm(explicit)}
        if len(tail) == 1:
            k, v = next(iter(tail.items()))
            return v, k
        if not tail:
            die(f"{path}: no key {explicit!r} found. Run --print-keys to see "
                f"what this file contains.")
        die(f"{path}: {explicit!r} is ambiguous — matches {', '.join(sorted(tail))}.\n"
            f"       Give the full dotted path.")

    for cand in candidates:
        hits = {k: v for k, v in values.items()
                if norm(k) == norm(cand) or norm(k.split(".")[-1]) == norm(cand)}
        if len(hits) == 1:
            k, v = next(iter(hits.items()))
            return v, k
        if len(hits) > 1:
            die(f"{path}: {cand!r} is ambiguous — matches {', '.join(sorted(hits))}.\n"
                f"       Pass --{what}-key with the full dotted path.")
    die(f"{path}: could not find the {what}. Looked for: "
        f"{', '.join(candidates)}.\n"
        f"       Run --print-keys to see the file's structure, then pass "
        f"--{what}-key.")


def is_loopback(host):
    """Loopback is the one place an unencrypted token is not a disclosure."""
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
        epilog="The secret is never accepted as a command-line argument. Point "
               "--config at the service's own config file, or set CLIENT_SECRET "
               "in the environment.")
    p.add_argument("urls", nargs="*", metavar="URL",
                   help="https endpoints to probe with the token (GET only)")
    p.add_argument("--config", metavar="FILE",
                   help="the service's config file, e.g. /etc/countinghouse/config.yaml")
    p.add_argument("--print-keys", action="store_true",
                   help="list the settings found in --config (names only, no values) "
                        "and exit")
    p.add_argument("--client", dest="client_id", default=None,
                   help="client id (else read from --config, else CLIENT_ID)")
    p.add_argument("--client-key", metavar="PATH",
                   help="dotted path to the client id in --config")
    p.add_argument("--secret-key", metavar="PATH",
                   help="dotted path to the client secret in --config")
    p.add_argument("--issuer", default=os.environ.get("ISSUER", DEFAULT_ISSUER))
    p.add_argument("--allow-host", action="append", default=[],
                   metavar="SUFFIX", help="additional permitted host suffix")
    p.add_argument("--allow-http-loopback", action="store_true",
                   help="permit http:// to localhost (local testing only)")
    p.add_argument("--dry-run", action="store_true",
                   help="show what would be done and make no requests at all")
    args = p.parse_args()

    allowed = tuple(DEFAULT_ALLOWED_SUFFIXES) + tuple(args.allow_host)

    CLIENT_ID_KEYS = ("client_id", "oauth_client_id", "identity_client_id")
    SECRET_KEYS = ("client_secret", "oauth_client_secret", "identity_client_secret")

    client_id = args.client_id
    secret = None
    source = "the environment"

    if args.config:
        values = read_config(args.config)
        if args.print_keys:
            print(f"Settings found in {args.config}")
            print("(names only — values are never shown)\n")
            for k in sorted(values):
                looks_secret = any(w in k.lower() for w in ("secret", "password", "token", "key"))
                print(f"  {k}{'   <- looks like a secret' if looks_secret else ''}")
            print(f"\nPass --secret-key and, if needed, --client-key with the "
                  f"path you want.")
            return EXIT_OK
        secret, skey = find_value(values, args.secret_key, SECRET_KEYS, "secret", args.config)
        if not client_id:
            try:
                client_id, ckey = find_value(values, args.client_key, CLIENT_ID_KEYS,
                                             "client", args.config)
            except SystemExit:
                raise
        source = f"{args.config} ({skey})"
    else:
        if args.print_keys:
            die("--print-keys needs --config")
        client_id = client_id or os.environ.get("CLIENT_ID")
        secret = os.environ.get("CLIENT_SECRET")

    if not client_id:
        die("no client id — pass --client, or provide it in --config")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", client_id):
        die(f"implausible client id: {client_id!r}")
    if not secret:
        die("no client secret found.\n"
            "       Point --config at the service's config file, or set "
            "CLIENT_SECRET in the environment.\n"
            "       Never pass a secret as a command-line argument.")

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
                "       Rotate it, then use --config or the environment.")

    issuer_host = (urllib.parse.urlparse(args.issuer).hostname or "").lower()
    if not args.issuer.startswith("https://"):
        if not (args.allow_http_loopback and args.issuer.startswith("http://")
                and is_loopback(issuer_host)):
            die(f"issuer must be https: {args.issuer}")

    urls = [check_url(u, allowed, args.allow_http_loopback) for u in args.urls]

    print(f"Client:  {client_id}")
    print(f"Secret:  from {source}")
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
