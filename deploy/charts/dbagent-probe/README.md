# dbagent-probe Helm chart

Data-plane probe (one per Presto cluster). Set `writeEnabled: true` only when
remediation write-ops are desired — the write Role is bound iff that flag is set.
