"""fix-permissions — h2c transform (The Custodian).

Scans K8s manifests for non-root containers (securityContext.runAsUser)
and inspects final compose service volumes for bind mounts. Generates a
busybox service that chowns bind-mounted directories to the correct UID.

Runs late (priority 8000) so it sees volumes after all other transforms
(bitnami, flatten-internal-urls, etc.) have done their work.
"""

from dekube import iter_workloads, iter_named_containers, log  # pylint: disable=import-error


class FixPermissions:  # pylint: disable=too-few-public-methods  # contract: one class, one method
    """Generate a fix-permissions service for non-root bind-mounted volumes."""

    name = "fix-permissions"
    priority = 8000  # after everything that touches volumes

    @staticmethod
    def _get_run_as_user(pod_spec, container):
        """Extract runAsUser from container or pod securityContext (container wins)."""
        for ctx in (container.get("securityContext") or {}, pod_spec.get("securityContext") or {}):
            uid = ctx.get("runAsUser")
            if uid is not None:
                return int(uid)
        return None

    @staticmethod
    def _collect_uids(manifests):
        """Scan workload manifests and return {service_name: (uid, image)} for non-root containers.

        Covers main containers, init containers, and sidecars, using the same
        naming conventions as the workload converter.
        """
        uids = {}
        for name, pod_spec in iter_workloads(manifests):
            for svc_name, container in iter_named_containers(name, pod_spec):
                uid = FixPermissions._get_run_as_user(pod_spec, container)
                if uid and uid > 0:
                    uids[svc_name] = (uid, container.get("image", ""))
        return uids

    @staticmethod
    def _is_bind_mount(volume_str):
        """Check if a compose volume string is a bind mount (not a named volume)."""
        host_part = volume_str.split(":")[0]
        return host_part.startswith("./") or host_part.startswith("../") or host_part.startswith("/")

    @staticmethod
    def _extract_data_paths(compose_svc, volume_root):
        """Extract host paths from bind-mounted data volumes of a compose service.

        Only paths under volume_root are considered — configmap/secret file mounts
        and ephemeral paths (/tmp, /dev/shm) are not data volumes.
        """
        paths = set()
        for vol in compose_svc.get("volumes") or []:
            if isinstance(vol, str) and FixPermissions._is_bind_mount(vol):
                host_path = vol.split(":")[0]
                if host_path == volume_root or host_path.startswith(volume_root + "/"):
                    paths.add(host_path)
        return paths

    def transform(self, compose_services, ingress_entries, ctx):  # pylint: disable=unused-argument  # Transform contract signature
        """Generate fix-permissions service for non-root bind-mounted volumes."""
        manifest_uids = self._collect_uids(ctx.manifests)
        if not manifest_uids:
            return

        volume_root = ctx.config.get("volume_root", "./data")

        # Resolve effective UID per service:
        # 1. compose user: field wins (explicit, set by user or transform)
        # 2. manifest UID used only if image hasn't changed (no transform swap)
        uids: dict[str, int] = {}
        for svc_name, (manifest_uid, manifest_image) in manifest_uids.items():
            svc = compose_services.get(svc_name)
            if not svc:
                continue
            user = svc.get("user")
            if user is not None:
                uid = int(str(user).split(":")[0])  # "1000" or "1000:1000"
                if uid > 0:
                    uids[svc_name] = uid
            elif svc.get("image", "") == manifest_image:
                uids[svc_name] = manifest_uid
            else:
                log(self.name, f"{svc_name}: image changed, skipping (manifest UID {manifest_uid} no longer reliable)")

        if not uids:
            return

        by_uid = {}
        for svc_name, uid in sorted(uids.items()):
            for path in sorted(self._extract_data_paths(compose_services[svc_name], volume_root)):
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
                log(self.name, f"chown -R {uid} {path}")
