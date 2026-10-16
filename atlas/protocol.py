"""Current upstream remote wire semantics, not local admin schemas."""
import ipaddress
import json
import re
import time

from core import Failure, logged
from research.model import public_key, integer

METHODS = {"self": "debug_remotegetself", "peers": "debug_remotegetpeers", "tree": "debug_remotegettree"}


@logged
def address(key):
    # Exact AddrForKey algorithm, including byte-wrapped leading-zero count
    # and discarded incomplete byte. Checked against published Go fixtures.
    bits = ''.join(f'{b ^ 255:08b}' for b in bytes.fromhex(public_key(key)))
    leading = len(bits)-len(bits.lstrip('1'))
    tail = bits[leading+1:]
    full = bytes(int(tail[i:i+8], 2) for i in range(0, len(tail)-7, 8))
    return str(ipaddress.IPv6Address((bytes([2, leading % 256])+full[:14]).ljust(16, b'\0')))


@logged
def projection(key, method, reply):
    if method not in METHODS: raise Failure("atlas_invalid_remote_method")
    expected = address(key)
    if not isinstance(reply, dict) or set(reply) != {expected} or not isinstance(reply[expected], dict):
        raise Failure("atlas_remote_target_envelope_mismatch")
    value = reply[expected]
    if method == "self":
        if public_key(value.get("key")) != key: raise Failure("atlas_remote_self_identity_mismatch")
        count = value.get("routing_entries")
        if isinstance(count, str) and re.fullmatch(r"[0-9]{1,20}", count): count = int(count)
        return {"key": key, "routing_entries": integer(count)}
    # Empty upstream keys map serializes as {}, not necessarily {keys:[]}.
    if set(value) - {'keys'}: raise Failure('atlas_invalid_remote_key_list_fields')
    keys = value.get("keys", [])
    if not isinstance(keys, list) or len(keys) > 4096: raise Failure("atlas_invalid_remote_key_list")
    clean = [public_key(k) for k in keys]
    return {"keys": sorted(set(clean)), "returned_rows": len(clean), "duplicate_rows": len(clean)-len(set(clean)),
            "complete": None, "semantics": "reported_peers_no_up_or_latency" if method == "peers" else "tree_key_references_NO_parent_edges"}


@logged
def query(ctx, key, method):
    start = time.monotonic()
    try:
        result = ctx.run([ctx.p.ctl, "-json", "-endpoint=unix://"+str(ctx.p.node_sock), METHODS[method], "key="+public_key(key)], timeout=8)
        reply = json.loads(result.stdout)
        if not isinstance(reply, dict) or reply.get("error") or reply.get("status") == "error":
            raise Failure("atlas_remote_error_response")
        data = projection(key, method, reply)
    except (Failure, OSError, ValueError, TypeError, OverflowError):
        return "unknown", (time.monotonic()-start)*1000, None
    return "ok", (time.monotonic()-start)*1000, data
