use regex::Regex;

use crate::types::EngineError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolKind {
    Bash,
}

#[derive(Clone, Debug)]
pub struct PermissionRule {
    pub tool: ToolKind,
    pub pattern: Regex,
}

#[derive(Clone, Debug, Default)]
pub struct PermissionPolicy {
    pub allow: Vec<PermissionRule>,
    pub deny: Vec<PermissionRule>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissionDecision {
    Allow,
    Deny,
}

impl PermissionPolicy {
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

    pub fn enforce(&self, tool: ToolKind, command: &str) -> Result<(), EngineError> {
        match self.decide(tool, command) {
            PermissionDecision::Allow => Ok(()),
            PermissionDecision::Deny => Err(EngineError::PermissionDenied(format!(
                "{tool:?}({command})"
            ))),
        }
    }
}

// Parses strings like: Bash(npm .*)
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
