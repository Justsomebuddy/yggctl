"""Opt-in privacy posture: profiles, cost, and the anonymity-set guard.

This module only manages a validated local posture file. It does not pad
packets, does not change the daemon and makes no network request; the transport
side of a privacy profile is a separate component by design.

The two invariants enforced here (and not merely documented):

* an enabled posture must name a real profile, never "off";
* private flows may never be logged, so the posture cannot combine
  ``enabled`` with ``log_private_flows``.
"""

import json

from core import Failure, atomic, logged

STATE = "privacy.json"

# cell: bytes per fixed-size cell; mean_delay: milliseconds of Poisson release
# jitter; cover_interval: milliseconds between dummy cells (0 = off);
# max_padding_share: budget used by the estimate.
PROFILES = {
    "mobile": {
        "cell": 1280,
        "mean_delay": 0.0,
        "cover_interval": 0.0,
        "max_padding_share": 0.10,
        "note": "small cells for metered links; no added delay",
    },
    "balanced": {
        "cell": 2048,
        "mean_delay": 10.0,
        "cover_interval": 0.0,
        "max_padding_share": 0.20,
        "note": "fixed 2 KiB cells with Poisson delay, no cover traffic",
    },
    "paranoid": {
        "cell": 2048,
        "mean_delay": 25.0,
        "cover_interval": 200.0,
        "max_padding_share": 0.50,
        "note": "longer mixing delay and steady cover traffic",
    },
    "bulk": {
        "cell": 65535,
        "mean_delay": 0.0,
        "cover_interval": 0.0,
        "max_padding_share": 0.03,
        "note": "jumbo cells; padding only hides frame boundaries",
    },
}

OFF = "off"
DEFAULT_PROFILE = "balanced"
DEFAULT_MINIMUM = 50
DEFAULTS = {"enabled": False, "profile": DEFAULT_PROFILE, "log_private_flows": False}
HEADER = 4


@logged
def profile(name):
    """Named profile, or None for the explicit 'off' posture."""
    if name == OFF:
        return None
    if name not in PROFILES:
        raise Failure(f"unknown_privacy_profile:{name}")
    return PROFILES[name]


@logged
def overhead(picked, chunk):
    """Filler share for one application chunk: byte-weighted, header aware."""
    if chunk <= 0:
        raise Failure("privacy_chunk_must_be_positive")
    capacity = picked["cell"] - HEADER
    cells = -(-chunk // capacity)
    return (cells * picked["cell"] - chunk) / chunk


@logged
def estimate(name, chunk, mbps, rtt):
    """Cost of a profile on a path measured by `throughput`/`ping`.

    Delay is the exponential mixing delay: median = mean*ln2, p95 = mean*3.
    """
    from math import log

    if chunk <= 0 or mbps < 0 or rtt < 0:
        raise Failure("privacy_measurements_must_be_positive")
    picked = profile(name)
    if picked is None:
        return {
            "profile": OFF,
            "overhead_pct": 0.0,
            "added_delay_ms": 0.0,
            "cover_kbps": 0.0,
            "fits_budget": True,
        }
    share = overhead(picked, chunk)
    cover_kbps = picked["cell"] * 8 / picked["cover_interval"] if picked["cover_interval"] else 0.0
    return {
        "profile": name,
        "cell": picked["cell"],
        "chunk": chunk,
        "overhead_pct": round(share * 100, 2),
        "added_delay_ms": round(picked["mean_delay"] * log(2), 2),
        "added_delay_p95_ms": round(picked["mean_delay"] * 3.0, 2),
        "cover_kbps": round(cover_kbps, 2),
        "fits_budget": share <= picked["max_padding_share"],
        "path_mbps": mbps,
        "path_rtt_ms": rtt,
    }


@logged
def anonymity_gate(participants, minimum=DEFAULT_MINIMUM):
    """Refuse the strongest posture while the observed crowd is too small."""
    if participants < 0:
        raise Failure("privacy_participants_must_be_non_negative")
    return {
        "allowed": participants >= minimum,
        "participants": participants,
        "minimum": minimum,
        "reason": None if participants >= minimum else "anonymity_set_too_small",
        "scope": "local_observation_not_network_size",
    }


@logged
def validate(values):
    """Normalized posture or a stable failure code."""
    if not isinstance(values, dict):
        raise Failure("privacy_config_not_an_object")
    unknown = set(values) - set(DEFAULTS)
    if unknown:
        raise Failure("unknown_privacy_keys:" + ",".join(sorted(unknown)))
    merged = dict(DEFAULTS)
    merged.update(values)
    if not isinstance(merged["enabled"], bool) or not isinstance(merged["log_private_flows"], bool):
        raise Failure("privacy_flags_must_be_boolean")
    if not isinstance(merged["profile"], str):
        raise Failure("privacy_profile_must_be_string")
    profile(merged["profile"])
    if merged["enabled"] and merged["profile"] == OFF:
        raise Failure("privacy_enabled_profile_required")
    if merged["enabled"] and merged["log_private_flows"]:
        raise Failure("privacy_flows_must_not_be_logged")
    return merged


@logged
def load(ctx):
    """Stored posture or the disabled default; invalid content fails closed."""
    raw = ctx.read_state(STATE, 65536)
    if raw is None:
        return dict(DEFAULTS)
    try:
        values = json.loads(raw)
    except ValueError:
        raise Failure("privacy_config_not_json") from None
    return validate(values)


@logged
def save(ctx, values):
    merged = validate(values)
    atomic(ctx.p.state / STATE, json.dumps(merged, sort_keys=True).encode() + b"\n", 0o600)
    return merged


@logged
def enable(ctx, name, participants, mbps, chunk, force=False):
    """Turn the posture on, unless the crowd or the cost says no."""
    picked = profile(name)
    if picked is None:
        raise Failure("privacy_off_cannot_be_enabled")
    gate = anonymity_gate(participants)
    cost = estimate(name, chunk, mbps, 0.0)
    verdict = {
        "enabled": True,
        "profile": name,
        "gate": gate,
        "cost": {key: cost[key] for key in ("overhead_pct", "cover_kbps", "fits_budget")},
    }
    if not force and (not gate["allowed"] or not cost["fits_budget"]):
        verdict["refused"] = True
        verdict["hint"] = "pass --force only after reviewing the cost"
        return verdict
    values = load(ctx)
    values.update({"enabled": True, "profile": name})
    return {**save(ctx, values), "gate": gate}
