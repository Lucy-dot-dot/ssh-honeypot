// Legacy command handlers

// New trait-based command system
pub mod command_trait;
pub mod context;
pub mod registry;
pub mod dispatcher;
pub mod echo_command;
pub mod cat_command;
pub mod date_command;
pub mod free_command;
pub mod ps_command;
pub mod uname_command;
pub mod ls_command;
pub mod builtin_commands;


// New trait-based exports
#[allow(unused)]
pub use command_trait::{Command, StatefulCommand, CommandResult, CommandError};
pub use context::CommandContext;
#[allow(unused)]
pub use registry::CommandRegistry;
pub use dispatcher::CommandDispatcher;
pub use echo_command::EchoCommand;
pub use cat_command::CatCommand;
pub use date_command::DateCommand;
pub use free_command::FreeCommand;
pub use ps_command::PsCommand;
pub use uname_command::UnameCommand;
pub use ls_command::LsCommand;
pub use builtin_commands::{PwdCommand, WhoamiCommand, IdCommand, CdCommand, WgetCommand, CurlCommand, SudoCommand, ExitCommand};