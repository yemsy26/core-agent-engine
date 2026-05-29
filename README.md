# core-agent-engine

A high-performance, secure asynchronous runtime for autonomous AI agents implemented in native Rust. Built on top of `tokio`, this engine provides a deterministic execution sandbox and system firewall, mitigating prompt injection risks and operational hallucinations in production environments.

## 🛡️ Strategic Architecture (2026 Production-Grade)

* **Deterministic Permission Firewall (`Secure-by-Default`):** Intercepts and validates all system-level payloads using a strict `PermissionPolicy` loop driven by compiled Regular Expressions before process spawning.
* **Active Physical Verification Pipeline:** Eliminates agent "success hallucinations" by pairing command execution with native filesystem verification (`std::fs`). The runtime physical confirms environmental mutations before returning execution states.
* **Asynchronous Event Auditing (Glass-Box Streaming):** Designed with internal non-blocking channels to stream real-time security decisions, evaluating `Allow`/`Deny` sequences transparently for host monitoring.
* **Low-Latency Architecture:** Zero-cost abstractions optimized for local LLM orchestration (e.g., Ollama / Llama.cpp local sockets), cutting infrastructure overhead down to microsecond response brackets.

## Execution Flow

```text
[Agent Tool Call] ──> [Regex Permission Firewall] ──> [Physical Verification] ──> [Audit Stream]
                               │                                │
                               └──> Deny ──> (Engine Error)     └──> Verification Fail ──> (Bail)
```
