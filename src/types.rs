use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("when_to_use must start with 'Use this agent when'")]
    WhenToUsePrefix,

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("tool execution failed: {0}")]
    ToolExecution(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AgentMetadata {
    pub identifier: String,
    pub when_to_use: String,
    pub system_prompt: String,
}

impl AgentMetadata {
    pub fn validate(&self) -> Result<(), EngineError> {
        if !self.when_to_use.starts_with("Use this agent when") {
            return Err(EngineError::WhenToUsePrefix);
        }
        Ok(())
    }
}
