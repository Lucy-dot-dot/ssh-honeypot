use std::sync::Arc;
use tokio::sync::RwLock;
use crate::shell::filesystem::fs2::FileSystem;

/// Context passed to all command implementations containing shared state
#[derive(Clone)]
pub struct CommandContext {
    /// Current working directory
    pub cwd: String,
    /// Username of the current session
    pub username: String,
    /// Hostname of the honeypot
    pub hostname: String,
    /// Virtual filesystem
    pub filesystem: Arc<RwLock<FileSystem>>,
    /// Session authentication ID for logging
    pub auth_id: String,
    /// Environment variables (simplified)
    pub env_vars: std::collections::HashMap<String, String>,
}

impl CommandContext {
    /// Create a new command context
    pub fn new(
        cwd: String,
        username: String,
        hostname: String,
        filesystem: Arc<RwLock<FileSystem>>,
        auth_id: String,
    ) -> Self {
        let mut env_vars = std::collections::HashMap::new();
        env_vars.insert("USER".to_string(), username.clone());
        env_vars.insert("HOME".to_string(), format!("/home/{}", username));
        env_vars.insert("PWD".to_string(), cwd.clone());
        env_vars.insert("HOSTNAME".to_string(), hostname.clone());
        env_vars.insert("SHELL".to_string(), "/bin/bash".to_string());
        env_vars.insert("PATH".to_string(), "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string());
        
        Self {
            cwd,
            username,
            hostname,
            filesystem,
            auth_id,
            env_vars,
        }
    }
    
    /// Update the current working directory
    pub fn set_cwd(&mut self, new_cwd: String) {
        self.cwd = new_cwd.clone();
        self.env_vars.insert("PWD".to_string(), new_cwd);
    }
    
    /// Get an environment variable
    pub fn get_env(&self, key: &str) -> Option<&String> {
        self.env_vars.get(key)
    }
    
    /// Set an environment variable
    pub fn set_env(&mut self, key: String, value: String) {
        self.env_vars.insert(key, value);
    }
    
    /// Get the command prompt string
    pub fn get_prompt(&self) -> String {
        format!("{}@{}:{}$ ", self.username, self.hostname, 
                if self.cwd == format!("/home/{}", self.username) { "~" } else { &self.cwd })
    }
}