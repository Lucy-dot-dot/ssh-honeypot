use super::context::CommandContext;
use super::registry::CommandRegistry;

/// Handles command parsing and execution
pub struct CommandDispatcher {
    registry: CommandRegistry,
}

impl CommandDispatcher {
    /// Create a new command dispatcher with an empty registry
    pub fn new() -> Self {
        Self {
            registry: CommandRegistry::new(),
        }
    }
    
    /// Create a new command dispatcher with the given registry
    pub fn with_registry(registry: CommandRegistry) -> Self {
        Self { registry }
    }
    
    /// Get a mutable reference to the registry for command registration
    pub fn registry_mut(&mut self) -> &mut CommandRegistry {
        &mut self.registry
    }
    
    /// Execute a full command line (handles parsing and pipes)
    pub async fn execute(&self, command_line: &str, context: &mut CommandContext) -> String {
        if command_line.trim().is_empty() {
            return String::new();
        }
        
        // Split on pipes for basic pipe support
        let mut cmd_parts = command_line.split('|');
        let primary_cmd = cmd_parts.next().unwrap_or("").trim();
        
        // Parse the primary command
        let (cmd_name, args) = self.parse_command(primary_cmd);
        
        // Execute the primary command
        let mut output = self.registry.execute_command(&cmd_name, &args, context).await.unwrap_or_else(|error| format!("{}\r\n", error));
        
        // Handle basic pipe operations (currently only grep)
        for piped_cmd in cmd_parts {
            let piped_cmd = piped_cmd.trim();
            if piped_cmd.starts_with("grep ") {
                let grep_term = piped_cmd[5..].trim();
                output = self.apply_grep_filter(&output, grep_term);
            }
            // Could add more pipe operations here (sort, head, tail, etc.)
        }
        
        output
    }
    
    /// Parse a command line into command name and arguments
    fn parse_command(&self, command_line: &str) -> (String, String) {
        let mut parts = command_line.splitn(2, ' ');
        let cmd_name = parts.next().unwrap_or("").to_string();
        let args = parts.next().unwrap_or("").to_string();
        (cmd_name, args)
    }
    
    /// Apply grep filtering to output (simple implementation)
    fn apply_grep_filter(&self, input: &str, pattern: &str) -> String {
        let filtered_lines: Vec<&str> = input
            .lines()
            .filter(|line| line.contains(pattern))
            .collect();
        
        if filtered_lines.is_empty() {
            String::new()
        } else {
            filtered_lines.join("\n") + "\n"
        }
    }
    
    /// Check if a command exists in the registry
    pub fn has_command(&self, command_name: &str) -> bool {
        self.registry.has_command(command_name)
    }
    
    /// Get help for a command
    pub async fn get_help(&self, command_name: &str) -> Option<String> {
        self.registry.get_command_help(command_name).await
    }
    
    /// Get all available commands
    pub fn list_commands(&self) -> Vec<String> {
        self.registry.get_command_names()
    }
}

impl Default for CommandDispatcher {
    fn default() -> Self {
        Self::new()
    }
}