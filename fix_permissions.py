"""fix-permissions — h2c transform (The Custodian).

Scans K8s manifests for non-root containers (securityContext.runAsUser)
and inspects final compose service volumes for bind mounts. Generates a
busybox service that chowns bind-mounted directories to the correct UID.

Runs late (priority 8000) so it sees volumes after all other transforms
(bitnami, flatten-internal-urls, etc.) have done their work.
"""

import sys

_WORKLOAD_KINDS = ("DaemonSet", "Deployment", "Job", "StatefulSet")


def _log(msg):
    print(f"  [fix-permissions] {msg}", file=sys.stderr)


def _get_run_as_user(pod_spec, container):
    """Extract runAsUser from container or pod securityContext (container wins)."""
    for ctx in (container.get("securityContext") or {}, pod_spec.get("securityContext") or {}):
        uid = ctx.get("runAsUser")
        if uid is not None:
            return int(uid)
    return None


def _collect_uids(manifests):
    """Scan workload manifests and return {service_name: uid} for non-root containers.

    Covers main containers, init containers, and sidecars, using the same
    naming conventions as the workload converter.
    """
    uids = {}
    for kind in _WORKLOAD_KINDS:
        for m in manifests.get(kind, []):
            name = (m.get("metadata") or {}).get("name", "unknown")
            spec = (m.get("spec") or {})
            pod_spec = ((spec.get("template") or {}).get("spec") or {})
            containers = pod_spec.get("containers") or []

            # Main container
            if containers:
                uid = _get_run_as_user(pod_spec, containers[0])
                if uid and uid > 0:
                    uids[name] = uid

            # Sidecar containers (containers[1:])
            for sc in containers[1:]:
                sc_name = sc.get("name", "sidecar")
                svc_name = f"{name}-sidecar-{sc_name}"
                uid = _get_run_as_user(pod_spec, sc)
                if uid and uid > 0:
                    uids[svc_name] = uid

            # Init containers
            for ic in pod_spec.get("initContainers") or []:
                ic_name = ic.get("name", "init")
                svc_name = f"{name}-init-{ic_name}"
                uid = _get_run_as_user(pod_spec, ic)
                if uid and uid > 0:
                    uids[svc_name] = uid

    return uids


def _is_bind_mount(volume_str):
    """Check if a compose volume string is a bind mount (not a named volume)."""
    host_part = volume_str.split(":")[0]
    return host_part.startswith("./") or host_part.startswith("../") or host_part.startswith("/")


def _extract_data_paths(compose_svc, volume_root):
    """Extract host paths from bind-mounted data volumes of a compose service.

    Only paths under volume_root are considered — configmap/secret file mounts
    and ephemeral paths (/tmp, /dev/shm) are not data volumes.
    """
    paths = set()
    for vol in compose_svc.get("volumes") or []:
        if isinstance(vol, str) and _is_bind_mount(vol):
            host_path = vol.split(":")[0]
            if host_path.startswith(volume_root):
                paths.add(host_path)
    return paths


class FixPermissions:
    """Generate a fix-permissions service for non-root bind-mounted volumes."""

    name = "fix-permissions"
    priority = 8000  # after everything that touches volumes

    def transform(self, compose_services, ingress_entries, ctx):
        uids = _collect_uids(ctx.manifests)
        if not uids:
            return

        volume_root = ctx.config.get("volume_root", "./data")

        by_uid = {}
        for svc_name, uid in sorted(uids.items()):
            if svc_name not in compose_services:
                continue
            for path in sorted(_extract_data_paths(compose_services[svc_name], volume_root)):
                by_uid.setdefault(uid, set()).add(path)

        if not by_uid:
            return

        chown_cmds = []
        volumes = []
        for uid, paths in sorted(by_uid.items()):
            mount_paths = [f"/fixperm/{i}" for i in range(len(volumes), len(volumes) + len(paths))]
            chown_cmds.append(f"chown -R {uid} {' '.join(mount_paths)}")
            for host_path, mount_path in zip(sorted(paths), mount_paths):
                volumes.append(f"{host_path}:{mount_path}")

        compose_services["fix-permissions"] = {
            "image": "busybox", "restart": "no", "user": "0",
            "command": ["sh", "-c", " && ".join(chown_cmds)],
            "volumes": volumes,
        }

        for uid, paths in sorted(by_uid.items()):
            for path in sorted(paths):
                _log(f"chown -R {uid} {path}")
