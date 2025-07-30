use async_trait::async_trait;
use super::context::CommandContext;

/// Result type for command execution
pub type CommandResult = Result<String, CommandError>;

/// Errors that can occur during command execution
#[derive(Debug)]
pub enum CommandError {
    /// Invalid arguments provided to the command
    InvalidArguments(String),
    /// Filesystem operation failed
    FilesystemError(String),
    /// Permission denied
    PermissionDenied(String),
    /// Command not found
    NotFound(String),
    /// Generic execution error
    ExecutionError(String),
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandError::InvalidArguments(msg) => write!(f, "{}", msg),
            CommandError::FilesystemError(msg) => write!(f, "{}", msg),
            CommandError::PermissionDenied(msg) => write!(f, "{}", msg),
            CommandError::NotFound(msg) => write!(f, "{}", msg),
            CommandError::ExecutionError(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for CommandError {}

/// Trait that all honeypot commands must implement
#[async_trait]
pub trait Command: Send + Sync {
    /// The name of the command (e.g., "echo", "ls", "cat")
    fn name(&self) -> &'static str;
    
    /// Aliases for this command (e.g., ["ll"] for ls)
    fn aliases(&self) -> Vec<&'static str> {
        vec![]
    }
    
    /// Execute the command with the given arguments and context
    async fn execute(&self, args: &str, context: &mut CommandContext) -> CommandResult;
    
    /// Get help text for this command
    fn help(&self) -> String {
        format!("Usage: {} [options]\nNo help available for this command.", self.name())
    }
    
    /// Get version information for this command
    fn version(&self) -> String {
        format!("{} (GNU coreutils) 8.32", self.name())
    }
    
    /// Whether this command modifies the filesystem
    fn modifies_filesystem(&self) -> bool {
        false
    }
    
    /// Whether this command requires special privileges
    fn requires_privileges(&self) -> bool {
        false
    }
}

/// Trait for commands that can handle state changes (like cd)
#[async_trait]
pub trait StatefulCommand: Command {
    /// Execute the command and potentially modify the context state
    async fn execute_with_state_change(&self, args: &str, context: &mut CommandContext) -> CommandResult;
}