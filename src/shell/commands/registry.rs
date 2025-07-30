use std::collections::HashMap;
use std::sync::Arc;
use super::command_trait::{Command, StatefulCommand, CommandResult, CommandError};
use super::context::CommandContext;

/// Registry that holds all available commands
pub struct CommandRegistry {
    /// Map of command names to command implementations
    commands: HashMap<String, Arc<dyn Command>>,
    /// Map of command names to stateful command implementations
    stateful_commands: HashMap<String, Arc<dyn StatefulCommand>>,
}

impl CommandRegistry {
    /// Create a new empty command registry
    pub fn new() -> Self {
        Self {
            commands: HashMap::new(),
            stateful_commands: HashMap::new(),
        }
    }
    
    /// Register a regular command
    pub fn register_command(&mut self, command: Arc<dyn Command>) {
        let name = command.name().to_string();
        
        // Register the main command name
        self.commands.insert(name.clone(), command.clone());
        
        // Register all aliases
        for alias in command.aliases() {
            self.commands.insert(alias.to_string(), command.clone());
        }
    }
    
    /// Register a stateful command (like cd)
    pub fn register_stateful_command(&mut self, command: Arc<dyn StatefulCommand>) {
        let name = command.name().to_string();
        
        // Register the main command name
        self.stateful_commands.insert(name.clone(), command.clone());
        
        // Register all aliases
        for alias in command.aliases() {
            self.stateful_commands.insert(alias.to_string(), command.clone());
        }
    }
    
    /// Execute a command by name with the given arguments and context
    pub async fn execute_command(&self, command_name: &str, args: &str, context: &mut CommandContext) -> CommandResult {
        // First check for stateful commands (they take precedence)
        if let Some(command) = self.stateful_commands.get(command_name) {
            return command.execute_with_state_change(args, context).await;
        }
        
        // Then check for regular commands
        if let Some(command) = self.commands.get(command_name) {
            return command.execute(args, context).await;
        }
        
        // Command not found
        Err(CommandError::NotFound(format!("bash: {}: command not found", command_name)))
    }
    
    /// Check if a command exists
    pub fn has_command(&self, command_name: &str) -> bool {
        self.commands.contains_key(command_name) || self.stateful_commands.contains_key(command_name)
    }
    
    /// Get all available command names
    pub fn get_command_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.commands.keys()
            .chain(self.stateful_commands.keys())
            .cloned()
            .collect();
        names.sort();
        names.dedup();
        names
    }
    
    /// Get help for a specific command
    pub async fn get_command_help(&self, command_name: &str) -> Option<String> {
        if let Some(command) = self.stateful_commands.get(command_name) {
            return Some(command.help());
        }
        
        if let Some(command) = self.commands.get(command_name) {
            return Some(command.help());
        }
        
        None
    }
}

impl Default for CommandRegistry {
    fn default() -> Self {
        Self::new()
    }
}