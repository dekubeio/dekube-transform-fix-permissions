"""fix-permissions — h2c transform (The Custodian).

Scans K8s manifests for non-root containers (securityContext.runAsUser) and
pod-level fsGroup, then inspects final compose service volumes for bind
mounts and named volumes. Generates a busybox service that chowns/chgrps
them to the correct owner, and wires a completion-gated ``depends_on`` from
every service it fixes so compose can't race the chown on first start.

Runs late (priority 8000) so it sees volumes after all other transforms
(bitnami, flatten-internal-urls, etc.) have done their work.
"""

from dekube import iter_workloads, iter_named_containers, log  # pylint: disable=import-error


class FixPermissions:  # pylint: disable=too-few-public-methods  # contract: one class, one method
    """Generate a fix-permissions service for non-root bind-mounted/named volumes."""

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
    def _get_fs_group(pod_spec):
        """Extract fsGroup from pod-level securityContext (pod-level only, no container field).

        K8s recursively chgrps volumes to fsGroup and makes them group-writable, so a
        container can write to them even without a matching (or any) runAsUser.
        """
        gid = (pod_spec.get("securityContext") or {}).get("fsGroup")
        return int(gid) if gid is not None else None

    @staticmethod
    def _collect_owners(manifests):
        """Scan workload manifests, return {service_name: (uid, gid, image)}.

        uid/gid are each None when not set. A service is included as soon as either
        is set — fsGroup alone (no runAsUser) is a real K8s ownership fact too.
        Covers main containers, init containers, and sidecars, using the same
        naming conventions as the workload converter.
        """
        owners = {}
        for name, pod_spec in iter_workloads(manifests):
            gid = FixPermissions._get_fs_group(pod_spec)
            for svc_name, container in iter_named_containers(name, pod_spec):
                uid = FixPermissions._get_run_as_user(pod_spec, container)
                uid = uid if uid and uid > 0 else None
                if uid is not None or gid is not None:
                    owners[svc_name] = (uid, gid, container.get("image", ""))
        return owners

    @staticmethod
    def _is_bind_mount(volume_str):
        """Check if a compose volume string is a bind mount (not a named/anonymous volume)."""
        host_part = volume_str.split(":")[0]
        return host_part.startswith("./") or host_part.startswith("../") or host_part.startswith("/")

    @staticmethod
    def _is_named_volume(volume_str):
        """Check if a compose volume string references a named docker volume.

        Needs an explicit target (":") — a bare container path with no ":" is an
        anonymous volume mount, not addressable by name from another service.
        """
        if ":" not in volume_str:
            return False
        host_part = volume_str.split(":")[0]
        return bool(host_part) and not FixPermissions._is_bind_mount(volume_str)

    @staticmethod
    def _extract_data_paths(compose_svc, volume_root):
        """Extract bind-mount host paths (under volume_root) and named-volume sources
        from a compose service — anything the fix-permissions service can remount
        and chown/chgrp.

        Bind mounts are restricted to volume_root — configmap/secret file mounts and
        ephemeral paths (/tmp, /dev/shm) are not data volumes. Named volumes have no
        such host-path concept, so every one referenced by the service is included.
        """
        paths = set()
        for vol in compose_svc.get("volumes") or []:
            if not isinstance(vol, str):
                continue
            if FixPermissions._is_bind_mount(vol):
                host_path = vol.split(":")[0]
                if host_path == volume_root or host_path.startswith(volume_root + "/"):
                    paths.add(host_path)
            elif FixPermissions._is_named_volume(vol):
                paths.add(vol.split(":")[0])
        return paths

    @staticmethod
    def _add_completion_dependency(svc, dep_name):
        """Add ``depends_on: {dep_name: {condition: service_completed_successfully}}``.

        Merges with whatever form the service already has: short (list, implies
        ``service_started``) or long (dict) — mixing the two forms on one service is
        invalid compose, so an existing list is upgraded to the equivalent dict first.
        """
        existing = svc.get("depends_on")
        if isinstance(existing, list):
            deps = {d: {"condition": "service_started"} for d in existing}
        elif isinstance(existing, dict):
            deps = dict(existing)
        else:
            deps = {}
        deps[dep_name] = {"condition": "service_completed_successfully"}
        svc["depends_on"] = deps

    @staticmethod
    def _owner_sort_key(owner):
        """Sort key for (uid, gid) tuples where either side may be None."""
        uid, gid = owner
        return (uid is None, uid or 0, gid is None, gid or 0)

    def transform(self, compose_services, ingress_entries, ctx):  # pylint: disable=unused-argument  # Transform contract signature
        """Generate fix-permissions service for non-root bind-mounted/named volumes."""
        manifest_owners = self._collect_owners(ctx.manifests)
        if not manifest_owners:
            return

        volume_root = ctx.config.get("volume_root", "./data")

        # Resolve effective (uid, gid) per service:
        # 1. compose user: field wins for uid (explicit, set by user or transform)
        # 2. manifest uid used only if image hasn't changed (no transform swap)
        # 3. fsGroup always carried through — it's a pod-level K8s ownership fact,
        #    independent of any per-container user override
        owners: dict[str, tuple[int | None, int | None]] = {}
        for svc_name, (manifest_uid, gid, manifest_image) in manifest_owners.items():
            svc = compose_services.get(svc_name)
            if not svc:
                continue
            uid = manifest_uid
            user = svc.get("user")
            if user is not None:
                parsed_uid = int(str(user).split(":")[0])  # "1000" or "1000:1000"
                uid = parsed_uid if parsed_uid > 0 else None
            elif manifest_uid is not None and svc.get("image", "") != manifest_image:
                log(self.name, f"{svc_name}: image changed, skipping (manifest UID {manifest_uid} no longer reliable)")
                uid = None
            if uid is not None or gid is not None:
                owners[svc_name] = (uid, gid)

        if not owners:
            return

        by_owner = {}
        fixed_services = set()
        for svc_name, owner in sorted(owners.items()):
            data_paths = sorted(self._extract_data_paths(compose_services[svc_name], volume_root))
            if not data_paths:
                continue
            fixed_services.add(svc_name)
            for path in data_paths:
                by_owner.setdefault(owner, set()).add(path)

        if not by_owner:
            return

        chown_cmds = []
        volumes = []
        for (uid, gid), paths in sorted(by_owner.items(), key=lambda kv: self._owner_sort_key(kv[0])):
            mount_paths = [f"/fixperm/{i}" for i in range(len(volumes), len(volumes) + len(paths))]
            targets = " ".join(mount_paths)
            if uid is not None and gid is not None:
                chown_cmds.append(f"chown -R {uid}:{gid} {targets}")
            elif uid is not None:
                chown_cmds.append(f"chown -R {uid} {targets}")
            else:
                chown_cmds.append(f"chgrp -R {gid} {targets} && chmod -R g+rwX {targets}")
            for host_path, mount_path in zip(sorted(paths), mount_paths):
                volumes.append(f"{host_path}:{mount_path}")

        compose_services["fix-permissions"] = {
            "image": "busybox", "restart": "no", "user": "0",
            "command": ["sh", "-c", " && ".join(chown_cmds)],
            "volumes": volumes,
        }

        for svc_name in sorted(fixed_services):
            self._add_completion_dependency(compose_services[svc_name], "fix-permissions")

        for (uid, gid), paths in sorted(by_owner.items(), key=lambda kv: self._owner_sort_key(kv[0])):
            owner_desc = f"{uid}:{gid}" if uid is not None and gid is not None else (
                f"uid {uid}" if uid is not None else f"gid {gid}")
            for path in sorted(paths):
                log(self.name, f"chown {owner_desc} {path}")
