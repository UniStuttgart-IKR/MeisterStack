#!/usr/bin/env python3
"""The transport, after Image 58 turned auth on.

The harness was written against a lab whose REST ports were plain http. Since
Image 58 both tiers require mTLS (`chain = ["mtls"]` at the cluster,
`["mtls", "oidc"]` at the cloud), and every request the old transport made
died at the first byte:

    ApiError HTTP 0: BadStatusLine:  2

That is TLS answering a client that spoke http — not a bug in the lab, and not
something a scenario can work around. So the transport learns TLS here, in one
place, and `ops.py` and `invariants.py` ask this module for their opener.

The credential is the break-glass identity (CN=root, O=system:masters) from
`tools/meister-ca --admin root`, the same one `cli.mtls.toml` names. It is the
only credential that gets through both tiers: a user certificate is refused at
the cluster, which keeps no user directory. The harness is an operator tool
run by hand against a lab, and this is the operator's key.

Everything is overridable from the environment, so a lab with its own PKI
needs no edit here:

    CHAOS_PKI_DIR   default /mnt/vmstore/MeisterStack/labpki
    CHAOS_CA        default $CHAOS_PKI_DIR/ca.crt
    CHAOS_CERT      default $CHAOS_PKI_DIR/root.crt
    CHAOS_KEY       default $CHAOS_PKI_DIR/root.key
    CHAOS_SCHEME    force "http" to talk to a lab that has auth off

`verify_hostname` is off and the CA check is on, deliberately: the serving
certificates are issued to the node names, the harness dials IP addresses, and
weakening the CA check instead would be the wrong half to give up.
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
    """Is there TLS material to use? No = the lab still speaks http."""
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
        # The certificates name nodes; the harness dials IPs. Keep the CA
        # check, drop the name check -- the other way round would be the
        # weakening that actually matters.
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
    """One question about an edge, answered with a NUMBER.

    Deliberately not `ops.call`: that one is the harness talking to a lab it
    trusts, with the break-glass identity and a raised exception when the
    transport fails. This is the opposite -- it asks what the edge does to a
    caller who has less, and the transport failing IS the answer.

    Returns the http status, or 0 for "nothing answered": no listener, a
    connection refused, a handshake the edge would not do. A security
    statement made of these three numbers is a measurement; the same
    statement written as a constant survives the change that disproves it
    (D-H1).
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
