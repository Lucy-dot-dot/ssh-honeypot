pub mod cat;
pub mod ps;
pub mod free;
pub mod echo;
mod uname;
mod ls;

pub use cat::handle_cat_command;
pub use ps::handle_ps_command;
pub use free::handle_free_command;
pub use echo::handle_echo_command;
pub use uname::handle_uname_command;
pub use ls::handle_ls_command;