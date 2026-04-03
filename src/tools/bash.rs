use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::process::Command;

use crate::security::{PermissionPolicy, ToolKind};
use crate::types::EngineError;

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct BashCommand {
    pub command: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct BashResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl BashCommand {
    pub async fn run(&self, policy: &PermissionPolicy) -> Result<BashResult, EngineError> {
        policy.enforce(ToolKind::Bash, &self.command)?;

        if cfg!(windows) {
            run_windows_powershell(&self.command).await
        } else {
            run_posix_sh(&self.command).await
        }
    }
}

async fn run_posix_sh(command: &str) -> Result<BashResult, EngineError> {
    let output = Command::new("sh")
        .arg("-lc")
        .arg(command)
        .output()
        .await
        .map_err(|e| EngineError::ToolExecution(e.to_string()))?;

    let exit_code = output.status.code().unwrap_or(1);

    Ok(BashResult {
        exit_code,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

async fn run_windows_powershell(command: &str) -> Result<BashResult, EngineError> {
    // Based on leaked robustness logic:
    // Prefer $LASTEXITCODE when a native exe ran, because $? can become $false when stderr is redirected.
    // This wrapper forces a final explicit exit with the computed code.
    //
    // We also emit a unique marker line with the numeric exit code so we can parse it reliably.
    const MARKER: &str = "__CORE_AGENT_ENGINE_EXITCODE__";

    let script = format!(
        "{cmd}\n; $_ec = if ($null -ne $LASTEXITCODE) {{ $LASTEXITCODE }} elseif ($?) {{ 0 }} else {{ 1 }}\n; Write-Output '{marker}=' + $_ec\n; exit $_ec",
        cmd = command,
        marker = MARKER
    );

    let output = Command::new("pwsh")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .await
        .map_err(|e| EngineError::ToolExecution(e.to_string()))?;

    let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();

    let mut parsed_exit = output.status.code().unwrap_or(1);
    for line in stdout_str.lines().rev() {
        if let Some(v) = line.strip_prefix(&format!("{MARKER}=")) {
            if let Ok(n) = v.trim().parse::<i32>() {
                parsed_exit = n;
                break;
            }
        }
    }

    Ok(BashResult {
        exit_code: parsed_exit,
        stdout: stdout_str,
        stderr: stderr_str,
    })
}
