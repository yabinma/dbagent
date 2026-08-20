# Toolpack reference

## Engine tools

- `presto_cluster_info` — admission-independent
- `presto_nodes` — admission-independent
- `presto_list_queries` — admission-independent
- `presto_query_detail` — admission-independent
- `presto_query_json_section` — admission-independent
- `presto_config` — admission-independent
- `presto_session_properties` — admission-bound
- `presto_jmx` — admission-bound

## Runtime tools

- `pod_logs` / `container_logs`
- `k8s_pods` / `swarm_tasks`
- `k8s_describe` / `docker_inspect`
- `k8s_events` / `docker_events`
- `resource_usage`

## Host tools

- `jvm_thread_dump`
- `jvm_heap_histo`

## Write-ops (when write channel enabled)

- `k8s_patch_configmap`
- `k8s_rollout_restart`
- `k8s_delete_pod`
- `swarm_update_service_env`
- `swarm_restart_service`
- `presto_kill_query`

## Control tools (worker, no probe)

- `read_evidence`
- `fetch_source`
- `diff_versions`
- `search_commits`
