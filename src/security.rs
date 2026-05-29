use regex::Regex;

use crate::types::EngineError;

/// Defines the kind of tool being requested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolKind {
    Bash,
}

/// A security event emitted by the firewall upon evaluation.
#[derive(Clone, Debug)]
pub enum SecurityEvent {
    Allowed { tool: ToolKind, command: String },
    Denied { tool: ToolKind, command: String },
}

/// A single permission rule evaluated by the firewall.
#[derive(Clone, Debug)]
pub struct PermissionRule {
    pub tool: ToolKind,
    pub pattern: Regex,
}

/// The deterministic permission firewall policy.
#[derive(Clone, Debug, Default)]
pub struct PermissionPolicy {
    pub allow: Vec<PermissionRule>,
    pub deny: Vec<PermissionRule>,
    pub event_tx: Option<tokio::sync::mpsc::Sender<SecurityEvent>>,
}

/// The decision made by the firewall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissionDecision {
    Allow,
    Deny,
}

impl PermissionPolicy {
    /// Evaluates a command against the firewall rules.
    pub fn decide(&self, tool: ToolKind, command: &str) -> PermissionDecision {
        if self
            .deny
            .iter()
            .any(|r| r.tool == tool && r.pattern.is_match(command))
        {
            return PermissionDecision::Deny;
        }
        if self
            .allow
            .iter()
            .any(|r| r.tool == tool && r.pattern.is_match(command))
        {
            return PermissionDecision::Allow;
        }
        PermissionDecision::Deny
    }

    /// Enforces the policy and streams the event to the audit channel.
    pub async fn enforce(&self, tool: ToolKind, command: &str) -> Result<(), EngineError> {
        let decision = self.decide(tool, command);

        if let Some(tx) = &self.event_tx {
            let event = match decision {
                PermissionDecision::Allow => SecurityEvent::Allowed {
                    tool,
                    command: command.to_string(),
                },
                PermissionDecision::Deny => SecurityEvent::Denied {
                    tool,
                    command: command.to_string(),
                },
            };
            let _ = tx.send(event).await;
        }

        match decision {
            PermissionDecision::Allow => Ok(()),
            PermissionDecision::Deny => Err(EngineError::PermissionDenied(format!(
                "{tool:?}({command})"
            ))),
        }
    }
}

/// Parses strings like: Bash(npm .*) into a PermissionRule.
pub fn parse_permission_rule(s: &str) -> Result<PermissionRule, EngineError> {
    let (tool_str, rest) = s
        .split_once('(')
        .ok_or_else(|| EngineError::PermissionDenied("invalid rule format".to_string()))?;
    let pattern_str = rest
        .strip_suffix(')')
        .ok_or_else(|| EngineError::PermissionDenied("invalid rule format".to_string()))?;

    let tool = match tool_str {
        "Bash" => ToolKind::Bash,
        _ => {
            return Err(EngineError::PermissionDenied(
                "unknown tool in rule".to_string(),
            ))
        }
    };

    let pattern = Regex::new(pattern_str)
        .map_err(|e| EngineError::PermissionDenied(format!("invalid regex: {e}")))?;

    Ok(PermissionRule { tool, pattern })
}
