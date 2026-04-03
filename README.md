# core-agent-engine

Rust core for an agent runtime: tool schemas via `schemars`, permission gating, and robust terminal execution.

## Commands

```powershell
cargo check
```

## Notes

- Tool input/output structs derive `serde` + `schemars::JsonSchema`.
- `BashCommand` enforces a regex-based allow/deny policy before execution.
- On Windows, PowerShell execution prefers `$LASTEXITCODE` over `$?` to avoid false positives when commands write to stderr.
