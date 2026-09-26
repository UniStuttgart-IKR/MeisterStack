#!/usr/bin/env python3
"""Shared urllib transport for the chaos harness.

CHAOS_CA, CHAOS_CERT and CHAOS_KEY override files under CHAOS_PKI_DIR
(default /mnt/vmstore/MeisterStack/labpki). The default client is the root
break-glass identity. Missing any file, or CHAOS_SCHEME=http, selects HTTP.

HTTPS validates the CA chain but disables hostname verification. This trusts
any accepted CA-issued server identity rather than authenticating the target IP.
"""

import os
import ssl
import urllib.error
import urllib.request

PKI_DIR = os.environ.get("CHAOS_PKI_DIR", "/mnt/vmstore/MeisterStack/labpki")
CA = os.environ.get("CHAOS_CA", os.path.join(PKI_DIR, "ca.crt"))
CERT = os.environ.get("CHAOS_CERT", os.path.join(PKI_DIR, "root.crt"))
KEY = os.environ.get("CHAOS_KEY", os.path.join(PKI_DIR, "root.key"))

_ctx = None
_opener = None


def available():
    """Whether local TLS files exist and HTTP was not forced; this does not probe the server."""
    if os.environ.get("CHAOS_SCHEME") == "http":
        return False
    return all(os.path.exists(p) for p in (CA, CERT, KEY))


def scheme():
    return "https" if available() else "http"


def context():
    """The one SSLContext, built once."""
    global _ctx
    if _ctx is None:
        _ctx = ssl.create_default_context(cafile=CA)
        _ctx.load_cert_chain(certfile=CERT, keyfile=KEY)
        # CA validation remains enabled; target-name verification is disabled.
        _ctx.check_hostname = False
    return _ctx


def opener():
    """A urllib opener that presents the break-glass identity."""
    global _opener
    if _opener is None:
        if not available():
            _opener = urllib.request.build_opener()
        else:
            _opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=context())
            )
    return _opener


def urlopen(req, timeout=20):
    """Drop-in for `urllib.request.urlopen` that speaks this lab's TLS."""
    return opener().open(req, timeout=timeout)


def describe():
    if not available():
        return "plain http (no TLS material, or CHAOS_SCHEME=http)"
    return f"mTLS, ca={CA}, cert={CERT}"


def probe(ip, port, path, scheme_="https", client_cert=True, timeout=10):
    """Return an HTTP status, or 0 for a transport failure.

    No listener, timeout and TLS refusal are indistinguishable at zero.
    Certificate loading can fail before the request reaches this handler.
    """
    ctx = None
    if scheme_ == "https":
        ctx = ssl.create_default_context(cafile=CA)
        ctx.check_hostname = False
        if client_cert:
            ctx.load_cert_chain(certfile=CERT, keyfile=KEY)
    handler = urllib.request.HTTPSHandler(context=ctx) if ctx else urllib.request.HTTPHandler()
    opener_ = urllib.request.build_opener(handler)
    req = urllib.request.Request(f"{scheme_}://{ip}:{port}{path}", method="GET")
    try:
        with opener_.open(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        # A refusal IS an answer, and the interesting one: 401 is the edge
        # saying it wants a credential.
        return e.code
    except Exception:
        return 0


if __name__ == "__main__":
    # `python3 mtls.py <ip> <port> [path]` — the three questions S13 asks an
    # edge, as three numbers, for a person who wants to ask them by hand or
    # for a self-test that knows what the answer should be.
    import json
    import sys

    ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
    path = sys.argv[3] if len(sys.argv) > 3 else "/apis/meister.io/v1/vms"
    print(json.dumps({
        "http": probe(ip, port, path, scheme_="http"),
        "naked": probe(ip, port, path, client_cert=False),
        "full": probe(ip, port, path, client_cert=True),
    }, sort_keys=True))
