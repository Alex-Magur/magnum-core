# OPA Policy — Execution Gate & Traffic Control
# ADR Б12: Per-tool rate limits, Per-user quotas, RAM limit gate
package forge.execution_gate

default allow = false

# Allow if within rate limits and memory budget
allow {
    input.tool_calls_count < input.tool_rate_limit
    input.user_quota_remaining > 0
    input.system_ram_used_pct < 85
}
