# Deploy probe on Docker Swarm

```bash
echo -n "$TOKEN" | docker secret create bootstrap_token -
echo -n "$USER" | docker secret create platform_username -
echo -n "$PASS" | docker secret create platform_password -
docker stack deploy -c deploy/compose/probe-swarm-stack.yml rca-probe
```

Placement constrains the probe to manager nodes (`node.role == manager`) so the Docker socket is available.
`write_enabled` defaults to false in the sample config.
