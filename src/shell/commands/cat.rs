use crate::shell::filesystem::fs2::{FileContent, FileSystem};

/// Executes the `cat` command for a given file path, attempting to display the file's content.
///
/// # Arguments
///
/// * `cmd` - A string slice containing the `cat` command and the file path, starting with "cat ".
/// * `fs` - A reference to the `FileSystem` object that represents the file system.
///
/// # Returns
///
/// A `String` representing the content of the file if successful, or an appropriate error message
/// if the provided file path does not exist, points to a directory, or is a symbolic link.
///
/// # Behavior
///
/// 1. Extracts the file path from the input command (ignoring the "cat " prefix).
/// 2. Resolves the file path within the given file system, following symbolic links if necessary.
/// 3. Depending on the resolved file type, returns:
///    - The content of the file as text, if the file is a regular file.
///    - An error message if the file path does not exist.
///    - An error message if the file is a directory.
///    - An error message if the resolved file is still a symbolic link.
///
/// # Examples
///
/// ```
/// let cmd = "cat /path/to/file";
/// let fs = FileSystem::new(); // Assume a pre-configured file system object.
/// let output = handle_cat_command(cmd, &fs);
///
/// if output.starts_with("cat: ") {
///     eprintln!("{}", output); // Handle the error output.
/// } else {
///     println!("{}", output); // Properly display the file content.
/// }
/// ```
///
/// # Errors
///
/// Returns error messages in the following cases:
/// * File does not exist: `cat: <file_path>: No such file or directory`
/// * File is a directory: `cat: <file_path>: Is a directory`
/// * File is a symbolic link: `cat: <file_path>: Is a symbolic link`
///
/// # Safety
///
/// The function uses `unsafe` code when creating a string from file contents (`String::from_utf8_unchecked`).
pub fn handle_cat_command(cmd: &str, fs: &FileSystem) -> String {
    let file_path = cmd.strip_prefix("cat ").unwrap_or("").trim();
    match fs.follow_symlink(file_path) {
        Ok(content) => { 
            match content.file_content {
                None => {
                    format!("cat: {}: No such file or directory\r\n", file_path)
                },
                Some(ref content) => {
                    match content {
                        FileContent::Directory(_) => {
                            format!("cat: {}: Is a directory\r\n", file_path)
                        }
                        FileContent::RegularFile(bytes) => {
                            String::from_utf8_lossy(bytes).to_string()
                        },
                        FileContent::SymbolicLink(_) => {
                            // unreachable, since we already resolved the symlink
                            format!("cat: {}: Is a symbolic link\r\n", file_path)
                        }
                    }
                }
            }
        },
        Err(_) => format!("cat: {}: No such file or directory\r\n", file_path)
    }
}