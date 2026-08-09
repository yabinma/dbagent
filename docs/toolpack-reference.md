# Toolpack reference

## Engine tools

- `presto_cluster_info`
- `presto_nodes`
- `presto_list_queries`
- `presto_query_detail`
- `presto_query_json_section`
- `presto_config`
- `presto_session_properties`
- `presto_jmx`

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
