# Existing privileged state: admission, not provisioning

The public tree has no installer. Previously, `mkdir(exist_ok=True)` and a
root-owned lock did **not** attest an existing state directory or its other
files. The external role migration validates its own migration scope; that is
not a general mutable-state ACL audit. Do not infer such an audit from an
integrity manifest covering installed code/configuration.

## Source 5.12.0 behavior

Before a root lock-taking operation creates/opens its lock, and again after
acquiring that lock, `checks.state_custody` admits the pre-provisioned state.
The configuration/key health gate also invokes this check. It performs metadata
and ACL reads only, never repairs permissions, changes ownership or rewrites
queue/history/cursor contents.

* The state directory and **every ancestor through `/`** must be root-owned
  directories, not symlinks, with no group/other write permission.
* Existing protected leaves must be root-owned single-link regular files with
  exactly the modes below. Missing leaves are allowed for normal creation; a
  missing state directory/ancestor is not automatically provisioned by root.
* Extended access ACLs are refused on these objects; extended default ACLs are
  also refused on directories. Even a currently restrictive ACL needs explicit
  operator review rather than an implicit exception. ACL-read errors other than
  Linux `ENODATA` fail closed; unsupported ACL inspection is not a PASS.

| Protected leaf | Mode |
| --- | --- |
| `.console.lock`, `.worker.lock` | `0600` |
| `alert-state.json`, `alerts-forwarded.json`, `simplex-attempts.json` | `0600` |
| `alerts.jsonl`, `metrics.jsonl` | `0640` |
| `notify.state` | `0644` |

The group may differ: the parent and protected files must not grant group write.
Group-readable queue/metrics are deliberate. Role-owned `research/` and `atlas/`
are **not** included in this root-only leaf policy. Their history is still
role-writable and unverified. Read-only history commands do not authenticate it.
Unknown root-state files, backups and the entire filesystem are not audited by
this finite allowlist.

## Failure and recovery

`untrusted_state_custody`, `state_extended_acl_requires_review` and
`state_acl_unavailable` are explicit refusals. Ordinary missing-path/metadata
errors also fail the operation. Stop affected workers and investigate ownership,
ancestor replacement, ACLs and provenance before any separately authorized
repair. Preserve exact evidence/preimages first; do not recursively chown/chmod,
delete ACLs, recreate a queue or reset a cursor to make a check green.

An external installer must pre-provision state and validate the candidate before
publishing/restarting it. The runtime checks repeat on subsequent collector and
forwarder lock acquisition; no bundled systemd startup hook is claimed. Older
installers are not retroactively qualified by this source release.

These are discrete checks under a cooperative advisory lock, not isolation from
root, the same privileged writer, malicious storage, or a concurrent privileged
permission change. They cannot establish authenticity of already-modified data
or recover previously lost events. Synthetic tests and native offline filesystem
probes are not proof of a particular installation's security.
