// Legacy command handlers

// New trait-based command system
pub mod builtin_commands;
pub mod cat_command;
pub mod command_trait;
pub mod context;
pub mod date_command;
pub mod dispatcher;
pub mod echo_command;
pub mod free_command;
pub mod ls_command;
pub mod ps_command;
pub mod registry;
pub mod test_command;
pub mod uname_command;

// New trait-based exports
pub use builtin_commands::{
    CdCommand, ColonCommand, CurlCommand, ExitCommand, ExportCommand, FalseCommand, IdCommand,
    PwdCommand, SudoCommand, TrueCommand, UnsetCommand, WgetCommand, WhoamiCommand,
};
pub use cat_command::CatCommand;
#[allow(unused)]
pub use command_trait::{Command, CommandError, CommandResult, StatefulCommand};
pub use context::CommandContext;
pub use date_command::DateCommand;
pub use dispatcher::CommandDispatcher;
pub use echo_command::EchoCommand;
pub use free_command::FreeCommand;
pub use ls_command::LsCommand;
pub use ps_command::PsCommand;
#[allow(unused)]
pub use registry::CommandRegistry;
pub use test_command::TestCommand;
pub use uname_command::UnameCommand;
