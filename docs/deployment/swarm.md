# Deploy the probe on Docker Swarm

This is the sanitized reference for the topology the first real-cluster
deployment established (design.md §11.2.3 D, Appendix E.1). **Every
site-specific value below is a placeholder**; the only literals are documented
fixed defaults (`probe-gateway:8443` / `:8444`, `/var/run/docker.sock`, the
`/etc/dbagent-probe/…` and `/var/lib/dbagent-probe` paths, `write_enabled:
false`, `coordinator_https: false`, and the distroless-nonroot UID/GID
`65532`).

## How the probe reaches the Docker Engine API

The probe **dials the mounted unix socket directly**. The stack mounts
`/var/run/docker.sock:/var/run/docker.sock:ro` and sets — or simply omits, since
it is the default — `docker_api_base_url: unix:///var/run/docker.sock`. There is
**no socket-proxy service in the shipped stack**, and adding one is not the
supported path.

Accepted forms of `docker_api_base_url`:

| Form | Meaning |
|---|---|
| `unix://` + absolute socket path | dial that socket (default `unix:///var/run/docker.sock`) |
| `http://host:port`, `https://host:port` | plain HTTP transport: the test transport, and an operator-run socket proxy |

Any other scheme, and a `unix://` path that is missing, relative, not a
socket, or not reachable (including permission denied on a `root:docker` 0660
socket), makes the probe exit non-zero at startup with a named error —
**before** enrollment consumes the single-use bootstrap token. A token that a
failed run consumed must be reissued. Construction issues a real `GET /_ping`
against the Engine API so socket permission failures are not deferred past
enrollment.

> **The `:ro` mount flag is not a security control.** A read-only bind mount of
> the socket file does not make the Engine API read-only. `write_enabled` and
> the signed write channel do (design.md Section 8.1, `docs/security.md`).

### Socket group membership (`DOCKER_SOCKET_GID`)

The shipped probe image runs as non-root **UID/GID 65532**. A typical Linux
Docker socket is owned `root:docker` with mode `0660`. Bind-mounting the socket
preserves that numeric ownership, so UID 65532 gets `EACCES` unless the
container process also runs with the host `docker` group as a group ID.

Both `deploy/compose/probe.yml` and `deploy/compose/probe-swarm-stack.yml`
require `DOCKER_SOCKET_GID`, but they pass it differently because Swarm's stack
schema rejects Compose's `group_add`:

| Artifact | Mechanism |
|---|---|
| `probe.yml` (Compose) | `group_add: ["${DOCKER_SOCKET_GID:?…}"]` — supplemental group |
| `probe-swarm-stack.yml` (Swarm) | `user: "65532:${DOCKER_SOCKET_GID:?…}"` — primary UID:GID |

```bash
# Prefer the socket's group (handles a renamed/custom docker group):
export DOCKER_SOCKET_GID="$(stat -c '%g' /var/run/docker.sock)"
# Equivalent when the group is still named "docker":
# export DOCKER_SOCKET_GID="$(getent group docker | cut -d: -f3)"

docker compose -f deploy/compose/probe.yml up -d
# or
docker stack deploy -c deploy/compose/probe-swarm-stack.yml dbagent-probe
```

`docker compose config` / `docker stack config` interpolate the variable at
render time; the numeric GID is what matters inside the container (the host
group name does not exist there). Without `DOCKER_SOCKET_GID` the compose/stack
file refuses to render (`:?` required-variable syntax).

### Operator escape hatch: your own socket proxy

A site that forbids socket mounts may instead set
`docker_api_base_url` to an `http://host:port` (or `https://`) proxy endpoint
and run its own proxy.
**Understand what this costs**: a TCP proxy in front of `/var/run/docker.sock`
grants root-equivalent control of the manager node to everything that can reach
that port — and the probe must join the Presto overlay network, so the proxy
would sit on a network shared with the very engine the probe is deployed to
investigate. If you take this path, use an **endpoint-filtering** proxy on a
**dedicated** network. No shipped compose file, stack file or chart defines such
a service.

## Where the coordinator's config lives: `config_paths`

The probe reads platform config by `cat`-ing a path inside the
coordinator/worker container. The default layout is `/etc/presto/...`; the
prestodb server tarball puts it somewhere else, so override it **per key**:

```yaml
config_paths:
  config: <IN_CONTAINER_CONFIG_DIR>/config.properties
  jvm:    <IN_CONTAINER_CONFIG_DIR>/jvm.config
  node:   <IN_CONTAINER_CONFIG_DIR>/node.properties
```

Keys are the Appendix B.1 `presto_config` `file` values (`config`, `jvm`,
`node`, and catalog entries of the form `catalog:` plus the catalog name —
quote the catalog form). Values must be **absolute** paths; a relative or empty
value is a named load-time error. Keys you omit keep their `/etc/presto/...`
default, one key at a time. The key is ignored on Kubernetes, where the probe
reads a ConfigMap key rather than a path.

## Topology

The control plane runs via compose (`--profile apps`) on one node. The probe
runs as a **Swarm service on a manager node**, attached to the *existing,
external* Presto overlay network so Swarm service DNS resolves
`<COORDINATOR_SERVICE>`, and reaching probe-gateway through an `extra_hosts`
entry so the gateway certificate's SAN matches without DNS.

## Probe config

Docker config, mounted at `/etc/dbagent-probe/config.yaml`:

```yaml
platform_key: <PLATFORM_KEY>
gateway_address: probe-gateway:8443
bootstrap_address: probe-gateway:8444
bootstrap_token: ${BOOTSTRAP_TOKEN}        # or BOOTSTRAP_TOKEN_FILE
bootstrap_ca_pin: "sha256:<64-HEX>"        # from the dashboard platform page
state_dir: /var/lib/dbagent-probe
credentials_mount: /etc/dbagent-probe/platform-credentials
write_enabled: false
coordinator_service: <COORDINATOR_SERVICE>
worker_service: <WORKER_SERVICE>
coordinator_port: <COORDINATOR_PORT>
coordinator_https: false
docker_api_base_url: unix:///var/run/docker.sock
config_paths:
  config: <IN_CONTAINER_CONFIG_DIR>/config.properties
  jvm:    <IN_CONTAINER_CONFIG_DIR>/jvm.config
  node:   <IN_CONTAINER_CONFIG_DIR>/node.properties
```

## Probe stack

`deploy/compose/probe-swarm-stack.yml`, shape only:

```yaml
services:
  probe:
    image: <REGISTRY>/probe:<APP_VERSION>
    environment:
      PROBE_CONFIG: /etc/dbagent-probe/config.yaml
      BOOTSTRAP_TOKEN_FILE: /run/secrets/bootstrap_token
    extra_hosts: ["probe-gateway:<CONTROL_PLANE_IP>"]
    networks: [<PRESTO_OVERLAY_NETWORK>]
    configs:  [{source: probe_config, target: /etc/dbagent-probe/config.yaml}]
    secrets:
      - {source: bootstrap_token,    target: bootstrap_token}
      - {source: platform_username,  target: /etc/dbagent-probe/platform-credentials/username}
      - {source: platform_password,  target: /etc/dbagent-probe/platform-credentials/password}
    user: "65532:${DOCKER_SOCKET_GID}"  # host docker group GID; see above
    volumes:
      - probe-state:/var/lib/dbagent-probe
      - /var/run/docker.sock:/var/run/docker.sock:ro   # no proxy service
    deploy:
      replicas: 1
      placement: {constraints: ["node.role == manager"]}
      restart_policy: {condition: on-failure}
networks:
  <PRESTO_OVERLAY_NETWORK>: {external: true}
volumes:
  probe-state:
```

## Deployment sequence

Each step blocks the next.

1. Bring up the control plane:
   `docker compose -f deploy/compose/control-plane.yml --profile apps up -d`
   (project `dbagent-control-plane`; the `migrate`, `signing-key`,
   `bootstrap-admin` and `seed-playbooks` one-shots must all complete).
2. **Change the bootstrap admin password** (`POST /auth/change-password`).
   `bootstrap_admin` sets `must_change_password=true`, and every other dashboard
   endpoint returns 403 `password_change_required` until this is done — which is
   why it comes *before* creating the platform.
3. Create the platform in the dashboard → one-time bootstrap token; read the
   bootstrap CA fingerprint from the same page → `bootstrap_ca_pin`.
4. `docker secret create` the bootstrap token and the platform credentials
   (`username`, `password`, optional `ca.crt`):
   ```bash
   printf '%s' "$TOKEN" | docker secret create bootstrap_token -
   printf '%s' "$PLATFORM_USER" | docker secret create platform_username -
   printf '%s' "$PLATFORM_PASS" | docker secret create platform_password -
   ```
5. `docker stack deploy -c deploy/compose/probe-swarm-stack.yml dbagent-probe`
   on a manager node.
6. Watch the platform reach **`online`** in the dashboard.

### Why step 6 does not promise `pending_credentials` → `online`

Steps 4 and 5 create and mount the platform credentials, so per design.md
Section 8.4 the probe detects them at startup and may register straight to
`online`. The PENDING_CREDENTIALS transition is required — and witnessed — only
by the **acceptance walkthrough** (`docs/acceptance/m6-real-cluster-walkthrough.md`),
whose step 4 deliberately deploys the probe *without* credentials and whose
step 5 observes the resulting state. Do not use this deployment sequence as
walkthrough evidence, and do not expect the pending state here.

## Placeholders

The permitted set of angle-bracket tokens is closed (design.md §11.2.3 D):
`<PLATFORM_KEY>`, `<GATEWAY_HOST>`, `<CONTROL_PLANE_IP>`,
`<PRESTO_OVERLAY_NETWORK>`, `<COORDINATOR_SERVICE>`, `<WORKER_SERVICE>`,
`<COORDINATOR_PORT>`, `<IN_CONTAINER_CONFIG_DIR>`, `<REGISTRY>`,
`<APP_VERSION>` and `<64-HEX>` (only ever immediately after the literal
`sha256:`). This page uses a subset — `<GATEWAY_HOST>` does not appear, because
the stack reaches the gateway through the fixed `extra_hosts` name
`probe-gateway`. No live-cluster hostname, IP, service name, port, token,
password or fingerprint appears anywhere on this page.
