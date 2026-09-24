# fix-permissions

![vibe coded](https://img.shields.io/badge/vibe-coded-ff69b4)
![python 3](https://img.shields.io/badge/python-3-3776AB)
![heresy: 3/10](https://img.shields.io/badge/heresy-3%2F10-blueviolet)

dekube transform that generates a `fix-permissions` busybox service for non-root containers with bind-mounted volumes. **The Custodian** — the 8th monk.

> Heresy level: 3/10 — rewrites filesystem ownership behind the user's back. Not malicious, but presumptuous.

## Why

Bitnami images (PostgreSQL, Redis, MongoDB) and other non-root containers (`securityContext.runAsUser`) expect Unix permissions on their data directories. The host directory is typically owned by your user (UID 1000), so the container can't write to it. This causes `mkdir: cannot create directory: Permission denied`.

In Kubernetes, init containers or the kubelet handle this. In compose, someone has to chown.

## What it does

1. Scans K8s manifests for containers with `securityContext.runAsUser` (container-level takes precedence over pod-level) and for pod-level `securityContext.fsGroup` — K8s recursively chgrps volumes to `fsGroup` and makes them group-writable (plus setgid on directories), so a pod can need fixing even with no `runAsUser` at all
2. Inspects the **final** compose service volumes for bind mounts (`./`, `../`, `/` prefixes) and named (docker-managed) volumes
3. Generates a single `fix-permissions` service that, per fixed path, runs `chown -R <uid>[:<gid>]` (or `chgrp` when only `fsGroup` applies), plus `chmod -R g+rwX` and `find <path> -type d -exec chmod g+s` whenever a gid is involved — same as K8s's own volume ownership walk, and applied whether or not `runAsUser` is also set (a sidecar with a *different* `runAsUser` sharing the same fsGroup-managed volume still needs the group write bit even after the main container's `chown` ran first)
4. Adds `depends_on: {fix-permissions: {condition: service_completed_successfully}}` to every service it fixes, so compose can't start it before the chown/chgrp finishes, and `group_add: [<fsGroup>]` when a gid applies — without it, the fix is invisible to a container whose own primary/supplementary groups don't happen to include that gid
5. If a container's image gets swapped by an earlier transform (e.g. bitnami replacing an image), both the manifest UID *and* fsGroup are dropped for that service — they belonged to the original image, not the replacement

A single path failing to fix (e.g. an NFS-backed named volume with `root_squash`) only logs a warning — it doesn't block every other fixed service. The fixer script always exits 0.

Runs at priority 8000 — after everything that touches volumes (bitnami at 1500, flatten-internal-urls at 2000). This ensures it sees the final volume layout, including any rewrites from other transforms.

Every fix is logged to stderr for transparency.

## Install

Built into the helmfile2compose distribution — no install needed.

Via [dekube-manager](https://github.com/dekubeio/dekube-manager):

```bash
python3 dekube-manager.py fix-permissions
```

## Priority

8000 (after all other transforms that may add or rewrite volumes).

## License

Public domain.
