pub mod security;
pub mod tools;
pub mod types;

pub use security::{PermissionDecision, PermissionPolicy, PermissionRule, ToolKind};
pub use tools::bash::{BashCommand, BashResult};
pub use types::{AgentMetadata, EngineError};

pub fn json_schema_for<T: schemars::JsonSchema>() -> serde_json::Value {
    let schema = schemars::schema_for!(T);
    serde_json::to_value(&schema).expect("schema serialization must succeed")
}
