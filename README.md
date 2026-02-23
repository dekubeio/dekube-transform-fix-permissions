# fix-permissions

![vibe coded](https://img.shields.io/badge/vibe-coded-ff69b4)
![python 3](https://img.shields.io/badge/python-3-3776AB)
![heresy: 3/10](https://img.shields.io/badge/heresy-3%2F10-blueviolet)

h2c transform that generates a `fix-permissions` busybox service for non-root containers with bind-mounted volumes. **The Custodian** — the 8th bishop.

> Heresy level: 3/10 — rewrites filesystem ownership behind the user's back. Not malicious, but presumptuous.

## Why

Bitnami images (PostgreSQL, Redis, MongoDB) and other non-root containers (`securityContext.runAsUser`) expect Unix permissions on their data directories. The host directory is typically owned by your user (UID 1000), so the container can't write to it. This causes `mkdir: cannot create directory: Permission denied`.

In Kubernetes, init containers or the kubelet handle this. In compose, someone has to chown.

## What it does

1. Scans K8s manifests for containers with `securityContext.runAsUser` (container-level takes precedence over pod-level)
2. Inspects the **final** compose service volumes for bind mounts (`./`, `../`, `/` prefixes)
3. Generates a single `fix-permissions` service that runs `chown -R <uid>` as root

Runs at priority 8000 — after everything that touches volumes (bitnami at 1500, flatten-internal-urls at 2000). This ensures it sees the final volume layout, including any rewrites from other transforms.

Every chown is logged to stderr for transparency.

## Install

Built into the helmfile2compose distribution — no install needed.

Via [h2c-manager](https://github.com/helmfile2compose/h2c-manager):

```bash
python3 h2c-manager.py fix-permissions
```

## Priority

8000 (after all other transforms that may add or rewrite volumes).

## License

Public domain.
