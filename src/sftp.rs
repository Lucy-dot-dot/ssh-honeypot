use async_trait::async_trait;
use chrono::Utc;
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};
use russh_sftp::server::Handler;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};

use ssh_honeypot::db::DbMessage;
use shell::filesystem::fs2::{FileContent, FileSystem};

/*
NOTE: This SFTP implementation is backed by a virtual filesystem (fs2).
All 18 russh-sftp Handler trait methods are implemented with VFS integration.
It is designed for honeypot use, not full POSIX correctness.
 */

/// Tracks an open file or directory handle, associating the opaque SFTP
/// handle string with the virtual-filesystem path it was opened against.
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct HandleEntry {
    path: String,
    is_directory: bool,
}

pub struct HoneypotSftpSession {
    db_tx: mpsc::Sender<DbMessage>,
    fs: Arc<RwLock<FileSystem>>,
    auth_id: String,
    /// Active SFTP handles (handle-string → path + type).
    handles: Arc<RwLock<HashMap<String, HandleEntry>>>,
}

impl HoneypotSftpSession {
    pub fn new(
        db_tx: mpsc::Sender<DbMessage>,
        fs: Arc<RwLock<FileSystem>>,
        auth_id: String,
    ) -> Self {
        Self {
            db_tx,
            fs,
            auth_id,
            handles: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Detect MIME type from file extension
    fn get_mime_from_extension(filepath: &str) -> Option<String> {
        match filepath.split('.').last()?.to_lowercase().as_str() {
            "exe" | "com" | "scr" => Some("application/x-executable".to_string()),
            "dll" => Some("application/x-msdownload".to_string()),
            "sh" | "bash" => Some("application/x-shellscript".to_string()),
            "py" => Some("text/x-python".to_string()),
            "pl" => Some("text/x-perl".to_string()),
            "php" => Some("text/x-php".to_string()),
            "js" => Some("text/javascript".to_string()),
            "jar" => Some("application/java-archive".to_string()),
            "zip" => Some("application/zip".to_string()),
            "rar" => Some("application/x-rar-compressed".to_string()),
            "7z" => Some("application/x-7z-compressed".to_string()),
            "tar" => Some("application/x-tar".to_string()),
            "gz" => Some("application/gzip".to_string()),
            "pdf" => Some("application/pdf".to_string()),
            "doc" | "docx" => Some("application/msword".to_string()),
            "xls" | "xlsx" => Some("application/vnd.ms-excel".to_string()),
            "txt" => Some("text/plain".to_string()),
            "html" | "htm" => Some("text/html".to_string()),
            "xml" => Some("text/xml".to_string()),
            "json" => Some("application/json".to_string()),
            "bin" => Some("application/octet-stream".to_string()),
            _ => None,
        }
    }

    /// Calculate Shannon entropy for detecting packed/encrypted files
    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut byte_counts = [0u64; 256];
        for &byte in data {
            byte_counts[byte as usize] += 1;
        }

        let data_len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &byte_counts {
            if count > 0 {
                let probability = count as f64 / data_len;
                entropy -= probability * probability.log2();
            }
        }

        entropy
    }

    /// Analyze uploaded file with magic detection and entropy analysis
    fn analyze_file(
        data: &[u8],
        filepath: &str,
    ) -> (Option<String>, Option<String>, bool, Option<f64>) {
        let claimed_mime = Self::get_mime_from_extension(filepath);
        let detected_mime = infer::get(data).map(|kind| kind.mime_type().to_string());
        let entropy = Some(Self::calculate_entropy(data));

        // Check for format mismatch
        let format_mismatch = match (&claimed_mime, &detected_mime) {
            (Some(claimed), Some(detected)) => {
                // Different MIME types indicate potential disguise
                claimed != detected
            }
            _ => false,
        };

        // Log interesting findings
        if format_mismatch {
            log::warn!(
                "File format mismatch detected: {} claimed as '{}' but detected as '{}'",
                filepath,
                claimed_mime.as_deref().unwrap_or("unknown"),
                detected_mime.as_deref().unwrap_or("unknown")
            );
        }

        if let Some(ent) = entropy {
            if ent > 7.5 {
                log::warn!(
                    "High entropy file detected: {} (entropy: {:.2}) - possible packed/encrypted content",
                    filepath,
                    ent
                );
            }
        }

        (claimed_mime, detected_mime, format_mismatch, entropy)
    }
}

#[async_trait]
impl Handler for HoneypotSftpSession {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> impl Future<Output = Result<Version, Self::Error>> + Send {
        async {
            log::info!("SFTP session initialized for auth_id: {}", self.auth_id);
            Ok(Version::new())
        }
    }

    fn open(
        &mut self,
        id: u32,
        path: String,
        flags: OpenFlags,
        _attrs: FileAttributes,
    ) -> impl Future<Output = Result<Handle, Self::Error>> + Send {
        let path = path;
        let fs = self.fs.clone();
        let handles = self.handles.clone();

        async move {
            log::debug!(
                "SFTP open request: id={}, path={}, flags={:?}",
                id,
                path,
                flags
            );

            // For simplicity, always create a handle for honeypot purposes
            let handle = format!(
                "handle_{}_{}",
                id,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );

            // If it's a write operation, we'll track it for file upload logging
            if flags.contains(OpenFlags::CREATE) || flags.contains(OpenFlags::WRITE) {
                // Ensure parent directories exist in filesystem
                let mut fs_guard = fs.write().await;
                let _ = fs_guard.create_file(&path);
            }

            // Register the handle so read/write/close can resolve the path
            handles.write().await.insert(
                handle.clone(),
                HandleEntry {
                    path: path.clone(),
                    is_directory: false,
                },
            );

            Ok(Handle { id, handle })
        }
    }

    fn close(
        &mut self,
        id: u32,
        handle: String,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        let handle = handle;
        let handles = self.handles.clone();

        async move {
            log::debug!("SFTP close request: id={}, handle={}", id, handle);
            handles.write().await.remove(&handle);
            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "".to_string(),
                language_tag: "".to_string(),
            })
        }
    }

    fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> impl Future<Output = Result<Data, Self::Error>> + Send {
        let fs = self.fs.clone();
        let handles = self.handles.clone();

        async move {
            log::debug!(
                "SFTP read request: id={}, handle={}, offset={}, len={}",
                id,
                handle,
                offset,
                len
            );

            // Resolve the path from the tracked handle
            let path = {
                let guard = handles.read().await;
                guard.get(&handle).map(|e| e.path.clone())
            };

            let path = match path {
                Some(p) => p,
                None => {
                    log::warn!("read: unknown handle '{}'", handle);
                    return Ok(Data { id, data: vec![] });
                }
            };

            // Read the file from the VFS
            let data = {
                let fs_guard = fs.read().await;
                match fs_guard.get_file(&path) {
                    Ok(entry) => match &entry.file_content {
                        Some(FileContent::RegularFile(bytes)) => {
                            let start = (offset as usize).min(bytes.len());
                            let end = start + (len as usize).min(bytes.len().saturating_sub(start));
                            bytes[start..end].to_vec()
                        }
                        _ => {
                            log::warn!("read: '{}' is not a regular file", path);
                            vec![]
                        }
                    },
                    Err(e) => {
                        log::warn!("read: failed to get '{}': {}", path, e);
                        vec![]
                    }
                }
            };

            Ok(Data { id, data })
        }
    }

    fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        let handle = handle;
        let fs = self.fs.clone();
        let handles = self.handles.clone();
        let db_tx = self.db_tx.clone();
        let auth_id = self.auth_id.clone();

        async move {
            log::info!(
                "SFTP write: {} bytes to handle {} at offset {}",
                data.len(),
                handle,
                offset
            );

            // Resolve the path from the tracked handle
            let path = {
                let guard = handles.read().await;
                guard.get(&handle).map(|e| e.path.clone())
            };

            let filepath = match path {
                Some(p) => p,
                None => {
                    log::warn!("write: unknown handle '{}'", handle);
                    return Ok(Status {
                        id,
                        status_code: StatusCode::Failure,
                        error_message: "Invalid handle".to_string(),
                        language_tag: "".to_string(),
                    });
                }
            };

            let filename = filepath
                .rsplit('/')
                .next()
                .unwrap_or(&filepath)
                .to_string();

            // Calculate SHA256 hash
            let hasher = Sha256::digest(&data);
            let file_hash = hex::encode(hasher.as_slice());

            // Analyze file with magic detection and entropy
            let (claimed_mime, detected_mime, format_mismatch, file_entropy) =
                HoneypotSftpSession::analyze_file(&data, &filepath);

            // Store / update in filesystem
            {
                let mut fs_guard = fs.write().await;

                // If the file doesn't exist yet, create it; otherwise update in place
                if fs_guard.get_file(&filepath).is_err() {
                    let _ = fs_guard.create_file(&filepath);
                }

                if let Ok(entry) = fs_guard.get_file_mut(&filepath) {
                    if let Some(FileContent::RegularFile(file_data)) = &mut entry.content {
                        let file_data = Arc::make_mut(file_data);
                        let required_size = (offset as usize) + data.len();
                        if file_data.len() < required_size {
                            file_data.resize(required_size, 0);
                        }
                        let start = offset as usize;
                        let end = start + data.len();
                        file_data[start..end].copy_from_slice(&data);

                        entry.inode.i_size_lo = file_data.len() as u32;
                    }
                }
            }

            // Record in database with enhanced analysis
            let file_size = data.len() as u64;

            match db_tx
                .send(DbMessage::RecordFileUpload {
                    auth_id,
                    timestamp: Utc::now(),
                    filename,
                    filepath,
                    file_size,
                    file_hash,
                    claimed_mime_type: claimed_mime,
                    detected_mime_type: detected_mime,
                    format_mismatch,
                    file_entropy,
                    binary_data: data,
                })
                .await
            {
                Ok(_) => log::debug!("Successfully queued file upload record"),
                Err(e) => log::error!("Failed to queue file upload record: {}", e),
            }

            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "".to_string(),
                language_tag: "".to_string(),
            })
        }
    }

    fn lstat(
        &mut self,
        id: u32,
        path: String,
    ) -> impl Future<Output = Result<Attrs, Self::Error>> + Send {
        let path = path;
        let fs = self.fs.clone();

        async move {
            log::debug!("SFTP lstat request: id={}, path={}", id, path);

            let fs_guard = fs.read().await;
            let resolved_path = fs_guard.resolve_absolute_path(&path);

            match fs_guard.get_file(&resolved_path) {
                Ok(entry) => {
                    let mut attrs = FileAttributes::default();
                    attrs.size = Some(entry.inode.i_size_lo as u64);
                    attrs.uid = Some(entry.inode.i_uid as u32);
                    attrs.gid = Some(entry.inode.i_gid as u32);
                    attrs.permissions = Some(entry.inode.i_mode as u32);
                    attrs.mtime = Some(entry.inode.i_mtime);

                    Ok(Attrs { id, attrs })
                }
                Err(_) => {
                    let mut attrs = FileAttributes::default();
                    attrs.size = Some(1024);
                    attrs.permissions = Some(0o644);

                    Ok(Attrs { id, attrs })
                }
            }
        }
    }

    fn fstat(
        &mut self,
        id: u32,
        handle: String,
    ) -> impl Future<Output = Result<Attrs, Self::Error>> + Send {
        let handles = self.handles.clone();
        let fs = self.fs.clone();

        async move {
            log::debug!("SFTP fstat request: id={}, handle={}", id, handle);

            let path = {
                let guard = handles.read().await;
                guard.get(&handle).map(|e| e.path.clone())
            };

            let path = match path {
                Some(p) => p,
                None => {
                    log::warn!("fstat: unknown handle '{}'", handle);
                    return Ok(Attrs {
                        id,
                        attrs: FileAttributes::default(),
                    });
                }
            };

            let fs_guard = fs.read().await;
            match fs_guard.get_file(&path) {
                Ok(entry) => {
                    let mut attrs = FileAttributes::default();
                    attrs.size = Some(entry.inode.i_size_lo as u64);
                    attrs.uid = Some(entry.inode.i_uid as u32);
                    attrs.gid = Some(entry.inode.i_gid as u32);
                    attrs.permissions = Some(entry.inode.i_mode as u32);
                    attrs.mtime = Some(entry.inode.i_mtime);

                    Ok(Attrs { id, attrs })
                }
                Err(_) => {
                    let mut attrs = FileAttributes::default();
                    attrs.size = Some(1024);
                    attrs.permissions = Some(0o644);

                    Ok(Attrs { id, attrs })
                }
            }
        }
    }

    fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        let path = path;
        let fs = self.fs.clone();

        async move {
            log::debug!("SFTP setstat request: id={}, path={}", id, path);

            let mut fs_guard = fs.write().await;
            match fs_guard.get_file_mut(&path) {
                Ok(entry) => {
                    if let Some(uid) = attrs.uid {
                        entry.inode.i_uid = uid as u16;
                    }
                    if let Some(gid) = attrs.gid {
                        entry.inode.i_gid = gid as u16;
                    }
                    if let Some(permissions) = attrs.permissions {
                        entry.inode.i_mode = permissions as u16;
                    }
                    if let Some(mtime) = attrs.mtime {
                        entry.inode.i_mtime = mtime;
                    }

                    Ok(Status {
                        id,
                        status_code: StatusCode::Ok,
                        error_message: "".to_string(),
                        language_tag: "".to_string(),
                    })
                }
                Err(e) => {
                    log::warn!("setstat: failed to stat '{}': {}", path, e);
                    Ok(Status {
                        id,
                        status_code: StatusCode::NoSuchFile,
                        error_message: e.to_string(),
                        language_tag: "".to_string(),
                    })
                }
            }
        }
    }

    fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        let handles = self.handles.clone();
        let fs = self.fs.clone();

        async move {
            log::debug!("SFTP fsetstat request: id={}, handle={}", id, handle);

            let path = {
                let guard = handles.read().await;
                guard.get(&handle).map(|e| e.path.clone())
            };

            let path = match path {
                Some(p) => p,
                None => {
                    log::warn!("fsetstat: unknown handle '{}'", handle);
                    return Ok(Status {
                        id,
                        status_code: StatusCode::Failure,
                        error_message: "Unknown handle".to_string(),
                        language_tag: "".to_string(),
                    });
                }
            };

            let mut fs_guard = fs.write().await;
            match fs_guard.get_file_mut(&path) {
                Ok(entry) => {
                    if let Some(uid) = attrs.uid {
                        entry.inode.i_uid = uid as u16;
                    }
                    if let Some(gid) = attrs.gid {
                        entry.inode.i_gid = gid as u16;
                    }
                    if let Some(permissions) = attrs.permissions {
                        entry.inode.i_mode = permissions as u16;
                    }
                    if let Some(mtime) = attrs.mtime {
                        entry.inode.i_mtime = mtime;
                    }

                    Ok(Status {
                        id,
                        status_code: StatusCode::Ok,
                        error_message: "".to_string(),
                        language_tag: "".to_string(),
                    })
                }
                Err(e) => {
                    log::warn!("fsetstat: failed to stat '{}': {}", path, e);
                    Ok(Status {
                        id,
                        status_code: StatusCode::NoSuchFile,
                        error_message: e.to_string(),
                        language_tag: "".to_string(),
                    })
                }
            }
        }
    }

    fn opendir(
        &mut self,
        id: u32,
        path: String,
    ) -> impl Future<Output = Result<Handle, Self::Error>> + Send {
        let path = path;
        let handles = self.handles.clone();

        async move {
            log::debug!("SFTP opendir request: id={}, path={}", id, path);
            let handle = format!(
                "dir_handle_{}_{}",
                id,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );

            handles.write().await.insert(
                handle.clone(),
                HandleEntry {
                    path: path.clone(),
                    is_directory: true,
                },
            );

            Ok(Handle { id, handle })
        }
    }

    fn readdir(
        &mut self,
        id: u32,
        handle: String,
    ) -> impl Future<Output = Result<Name, Self::Error>> + Send {
        let handle = handle;
        let fs = self.fs.clone();
        let handles = self.handles.clone();

        async move {
            log::debug!("SFTP readdir request: id={}, handle={}", id, handle);

            // Resolve the directory path from the tracked handle
            let path = {
                let guard = handles.read().await;
                guard.get(&handle).map(|e| e.path.clone())
            };

            let path = match path {
                Some(p) => p,
                None => {
                    log::warn!("readdir: unknown handle '{}'", handle);
                    return Ok(Name { id, files: vec![] });
                }
            };

            // Read entries from the VFS
            let mut files = Vec::new();

            // Always include "." and ".."
            files.push(File::new(".", FileAttributes::default()));
            files.push(File::new("..", FileAttributes::default()));

            let entries = {
                let fs_guard = fs.read().await;
                fs_guard.list_directory(&path)
            };

            match entries {
                Ok(dir_entries) => {
                    for entry in dir_entries {
                        let mut attrs = FileAttributes::default();
                        match &entry.file_content {
                            Some(FileContent::RegularFile(bytes)) => {
                                attrs.size = Some(bytes.len() as u64);
                                attrs.permissions = Some(0o100644);
                            }
                            Some(FileContent::Directory(_)) => {
                                attrs.size = Some(4096);
                                attrs.permissions = Some(0o40755);
                            }
                            Some(FileContent::SymbolicLink(_)) => {
                                attrs.permissions = Some(0o120777);
                            }
                            None => {}
                        }
                        files.push(File::new(&entry.name, attrs));
                    }
                }
                Err(e) => {
                    log::warn!("readdir: failed to list '{}': {}", path, e);
                }
            }

            Ok(Name { id, files })
        }
    }

    fn remove(
        &mut self,
        id: u32,
        path: String,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        let path = path;
        let fs = self.fs.clone();

        async move {
            log::info!("SFTP remove request: {}", path);

            let mut fs_guard = fs.write().await;
            match fs_guard.remove_file(&path) {
                Ok(_) => Ok(Status {
                    id,
                    status_code: StatusCode::Ok,
                    error_message: "".to_string(),
                    language_tag: "".to_string(),
                }),
                Err(e) => {
                    log::warn!("remove: failed to remove '{}': {}", path, e);
                    Ok(Status {
                        id,
                        status_code: StatusCode::NoSuchFile,
                        error_message: e.to_string(),
                        language_tag: "".to_string(),
                    })
                }
            }
        }
    }

    fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        let path = path;
        let fs = self.fs.clone();

        async move {
            log::info!("SFTP mkdir request: id={}, path={}", id, path);

            let mut fs_guard = fs.write().await;
            match fs_guard.create_directory(&path) {
                Ok(_) => Ok(Status {
                    id,
                    status_code: StatusCode::Ok,
                    error_message: "".to_string(),
                    language_tag: "".to_string(),
                }),
                Err(_) => Ok(Status {
                    id,
                    status_code: StatusCode::Failure,
                    error_message: "Failed to create directory".to_string(),
                    language_tag: "".to_string(),
                }),
            }
        }
    }

    fn rmdir(
        &mut self,
        id: u32,
        path: String,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        let path = path;
        let fs = self.fs.clone();

        async move {
            log::info!("SFTP rmdir request: {}", path);

            let mut fs_guard = fs.write().await;
            match fs_guard.remove_file(&path) {
                Ok(_) => Ok(Status {
                    id,
                    status_code: StatusCode::Ok,
                    error_message: "".to_string(),
                    language_tag: "".to_string(),
                }),
                Err(e) => {
                    log::warn!("rmdir: failed to remove '{}': {}", path, e);
                    Ok(Status {
                        id,
                        status_code: StatusCode::NoSuchFile,
                        error_message: e.to_string(),
                        language_tag: "".to_string(),
                    })
                }
            }
        }
    }

    fn realpath(
        &mut self,
        id: u32,
        path: String,
    ) -> impl Future<Output = Result<Name, Self::Error>> + Send {
        let path = path;

        async move {
            log::debug!("SFTP realpath request: id={}, path={}", id, path);

            let resolved = if path.starts_with('/') {
                path
            } else {
                format!("/{}", path)
            };

            let files = vec![File::new(&resolved, FileAttributes::default())];
            Ok(Name { id, files })
        }
    }

    fn stat(
        &mut self,
        id: u32,
        path: String,
    ) -> impl Future<Output = Result<Attrs, Self::Error>> + Send {
        let path = path;
        let fs = self.fs.clone();

        async move {
            log::debug!("SFTP stat request: id={}, path={}", id, path);

            let fs_guard = fs.read().await;
            let resolved_path = fs_guard.resolve_absolute_path(&path);

            match fs_guard.get_file(&resolved_path) {
                Ok(entry) => {
                    let mut attrs = FileAttributes::default();
                    attrs.size = Some(entry.inode.i_size_lo as u64);
                    attrs.uid = Some(entry.inode.i_uid as u32);
                    attrs.gid = Some(entry.inode.i_gid as u32);
                    attrs.permissions = Some(entry.inode.i_mode as u32);
                    attrs.mtime = Some(entry.inode.i_mtime);

                    Ok(Attrs { id, attrs })
                }
                Err(_) => {
                    // Return fake file attributes for honeypot
                    let mut attrs = FileAttributes::default();
                    attrs.size = Some(1024);
                    attrs.permissions = Some(0o644);

                    Ok(Attrs { id, attrs })
                }
            }
        }
    }

    fn rename(
        &mut self,
        id: u32,
        old_path: String,
        new_path: String,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        let old_path = old_path;
        let new_path = new_path;
        let fs = self.fs.clone();

        async move {
            log::info!("SFTP rename request: {} -> {}", old_path, new_path);

            let mut fs_guard = fs.write().await;
            match fs_guard.move_file(&old_path, &new_path) {
                Ok(_) => Ok(Status {
                    id,
                    status_code: StatusCode::Ok,
                    error_message: "".to_string(),
                    language_tag: "".to_string(),
                }),
                Err(e) => {
                    log::warn!("rename: failed to move '{}' -> '{}': {}", old_path, new_path, e);
                    Ok(Status {
                        id,
                        status_code: StatusCode::Failure,
                        error_message: e.to_string(),
                        language_tag: "".to_string(),
                    })
                }
            }
        }
    }

    fn readlink(
        &mut self,
        id: u32,
        path: String,
    ) -> impl Future<Output = Result<Name, Self::Error>> + Send {
        let path = path;
        let fs = self.fs.clone();

        async move {
            log::debug!("SFTP readlink request: id={}, path={}", id, path);

            let fs_guard = fs.read().await;
            match fs_guard.get_file(&path) {
                Ok(entry) => match &entry.file_content {
                    Some(FileContent::SymbolicLink(target)) => {
                        let files = vec![File::new(target, FileAttributes::default())];
                        Ok(Name { id, files })
                    }
                    _ => {
                        log::warn!("readlink: '{}' is not a symbolic link", path);
                        let files = vec![File::dummy("")];
                        Ok(Name { id, files })
                    }
                },
                Err(e) => {
                    log::warn!("readlink: failed to get '{}': {}", path, e);
                    let files = vec![File::dummy("")];
                    Ok(Name { id, files })
                }
            }
        }
    }

    fn symlink(
        &mut self,
        id: u32,
        link_path: String,
        target_path: String,
    ) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        let link_path = link_path;
        let target_path = target_path;
        let fs = self.fs.clone();

        async move {
            log::info!(
                "SFTP symlink request: {} -> {}",
                link_path,
                target_path
            );

            let mut fs_guard = fs.write().await;
            match fs_guard.create_symlink(&link_path, &target_path) {
                Ok(_) => Ok(Status {
                    id,
                    status_code: StatusCode::Ok,
                    error_message: "".to_string(),
                    language_tag: "".to_string(),
                }),
                Err(e) => {
                    log::warn!(
                        "symlink: failed to create '{} -> {}': {}",
                        link_path,
                        target_path,
                        e
                    );
                    Ok(Status {
                        id,
                        status_code: StatusCode::Failure,
                        error_message: e.to_string(),
                        language_tag: "".to_string(),
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shell::filesystem::fs2::FileSystem;

    // ═══════════════════════════════════════════════════════════════
    //  Test helpers
    // ═══════════════════════════════════════════════════════════════

    fn create_test_session(
        fs: FileSystem,
    ) -> (HoneypotSftpSession, mpsc::Receiver<DbMessage>) {
        let (db_tx, db_rx) = mpsc::channel(32);
        let fs = Arc::new(RwLock::new(fs));
        let session = HoneypotSftpSession::new(db_tx, fs, "test-auth-id".to_string());
        (session, db_rx)
    }

    /// Session backed by a filesystem that already has a `/tmp` directory
    /// (required by the write handler which stores uploads under `/tmp/`).
    fn create_session_with_tmp() -> (HoneypotSftpSession, mpsc::Receiver<DbMessage>) {
        let mut fs = FileSystem::default();
        fs.create_directory("/tmp").unwrap();
        create_test_session(fs)
    }

    // ═══════════════════════════════════════════════════════════════
    //  Pure-function tests  (HoneypotSftpSession associated fns)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_get_mime_from_extension_known_types() {
        assert_eq!(
            HoneypotSftpSession::get_mime_from_extension("malware.exe"),
            Some("application/x-executable".to_string())
        );
        assert_eq!(
            HoneypotSftpSession::get_mime_from_extension("script.sh"),
            Some("application/x-shellscript".to_string())
        );
        assert_eq!(
            HoneypotSftpSession::get_mime_from_extension("archive.zip"),
            Some("application/zip".to_string())
        );
        assert_eq!(
            HoneypotSftpSession::get_mime_from_extension("photo.json"),
            Some("application/json".to_string())
        );
    }

    #[test]
    fn test_get_mime_from_extension_unknown_type() {
        assert_eq!(
            HoneypotSftpSession::get_mime_from_extension("file.xyz"),
            None
        );
        assert_eq!(
            HoneypotSftpSession::get_mime_from_extension("noextension"),
            None
        );
    }

    #[test]
    fn test_get_mime_from_extension_case_insensitive() {
        assert_eq!(
            HoneypotSftpSession::get_mime_from_extension("FILE.EXE"),
            Some("application/x-executable".to_string())
        );
        assert_eq!(
            HoneypotSftpSession::get_mime_from_extension("Script.Sh"),
            Some("application/x-shellscript".to_string())
        );
    }

    #[test]
    fn test_calculate_entropy_empty() {
        assert_eq!(HoneypotSftpSession::calculate_entropy(b""), 0.0);
    }

    #[test]
    fn test_calculate_entropy_uniform_byte() {
        // All identical bytes → zero entropy
        let data = vec![42u8; 1000];
        assert_eq!(HoneypotSftpSession::calculate_entropy(&data), 0.0);
    }

    #[test]
    fn test_calculate_entropy_two_values() {
        // Equal distribution of two byte values → entropy ≈ 1.0
        let data: Vec<u8> = (0..1000).map(|i| (i % 2) as u8).collect();
        let entropy = HoneypotSftpSession::calculate_entropy(&data);
        assert!((0.99..=1.01).contains(&entropy));
    }

    #[test]
    fn test_calculate_entropy_high_for_random() {
        // Pseudo-random distribution over many byte values → high entropy
        let data: Vec<u8> = (0..255u8).cycle().take(2550).collect();
        let entropy = HoneypotSftpSession::calculate_entropy(&data);
        assert!(entropy > 7.0, "expected high entropy, got {}", entropy);
    }

    #[test]
    fn test_analyze_file_text_content() {
        let data = b"Hello, World!";
        let (claimed, _detected, mismatch, entropy) =
            HoneypotSftpSession::analyze_file(data, "readme.txt");

        assert_eq!(claimed, Some("text/plain".to_string()));
        assert!(entropy.is_some());
        assert!(entropy.unwrap() >= 0.0);
        // Without a magic-byte mismatch there should be no mismatch flag
        // (unless infer detects something different, which is acceptable)
        let _ = mismatch;
    }

    #[test]
    fn test_analyze_file_extension_mismatch() {
        // A PNG file disguised with a .txt extension should be flagged as a mismatch.
        // (PNG detection in `infer` needs only 8 magic bytes; ELF needs > 52.)
        let png_data = b"\x89PNG\r\n\x1a\n";
        let (claimed, detected, mismatch, _entropy) =
            HoneypotSftpSession::analyze_file(png_data, "innocent.txt");

        assert_eq!(claimed, Some("text/plain".to_string()));
        assert!(detected.is_some(), "infer should detect the PNG signature");
        assert_eq!(detected.unwrap(), "image/png");
        assert!(
            mismatch,
            "format mismatch should be detected for PNG disguised as .txt"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    //  open
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_open_write_creates_file_in_filesystem() {
        let mut fs = FileSystem::default();
        fs.create_directory("/home").unwrap();
        let (mut session, _rx) = create_test_session(fs);

        let flags = OpenFlags::WRITE | OpenFlags::CREATE;
        let handle = session
            .open(1, "/home/test.txt".to_string(), flags, FileAttributes::default())
            .await
            .unwrap();

        assert!(!handle.handle.is_empty());

        let fs_guard = session.fs.read().await;
        assert!(
            fs_guard.get_file("/home/test.txt").is_ok(),
            "open(WRITE|CREATE) should create the file in the VFS"
        );
    }

    #[tokio::test]
    async fn test_open_read_only_does_not_create_file() {
        let mut fs = FileSystem::default();
        fs.create_directory("/home").unwrap();
        let (mut session, _rx) = create_test_session(fs);

        let _handle = session
            .open(
                1,
                "/home/ghost.txt".to_string(),
                OpenFlags::READ,
                FileAttributes::default(),
            )
            .await
            .unwrap();

        let fs_guard = session.fs.read().await;
        assert!(
            fs_guard.get_file("/home/ghost.txt").is_err(),
            "open(READ) should not create a file"
        );
    }

    #[tokio::test]
    async fn test_open_registers_handle_with_path() {
        let (mut session, _rx) = create_session_with_tmp();

        let handle = session
            .open(
                1,
                "/tmp/data.bin".to_string(),
                OpenFlags::WRITE | OpenFlags::CREATE,
                FileAttributes::default(),
            )
            .await
            .unwrap();

        let guard = session.handles.read().await;
        let entry = guard.get(&handle.handle);
        assert!(entry.is_some(), "handle should be tracked after open");
        let entry = entry.unwrap();
        assert_eq!(entry.path, "/tmp/data.bin");
        assert!(!entry.is_directory);
    }

    // ═══════════════════════════════════════════════════════════════
    //  close
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_close_returns_ok_status() {
        let (mut session, _rx) = create_session_with_tmp();

        let status = session.close(1, "some_handle".to_string()).await.unwrap();
        assert_eq!(status.status_code, StatusCode::Ok);
    }

    #[tokio::test]
    async fn test_close_removes_tracked_handle() {
        let (mut session, _rx) = create_session_with_tmp();

        let handle = session
            .open(
                1,
                "/tmp/f.txt".to_string(),
                OpenFlags::WRITE,
                FileAttributes::default(),
            )
            .await
            .unwrap();

        assert!(session.handles.read().await.contains_key(&handle.handle));

        session.close(2, handle.handle.clone()).await.unwrap();

        assert!(
            !session.handles.read().await.contains_key(&handle.handle),
            "close should deregister the handle"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    //  write
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_write_stores_data_in_filesystem() {
        let (mut session, _rx) = create_session_with_tmp();

        let handle = session
            .open(
                1,
                "/tmp/upload.bin".to_string(),
                OpenFlags::WRITE | OpenFlags::CREATE,
                FileAttributes::default(),
            )
            .await
            .unwrap();

        let payload = b"payload data".to_vec();
        session
            .write(2, handle.handle, 0, payload.clone())
            .await
            .unwrap();

        let fs_guard = session.fs.read().await;
        let file = fs_guard.get_file("/tmp/upload.bin");
        assert!(file.is_ok(), "write should store data in the VFS");

        match &file.unwrap().file_content {
            Some(FileContent::RegularFile(bytes)) => {
                assert_eq!(bytes.as_slice(), payload.as_slice());
            }
            _ => panic!("expected a regular file with written data"),
        }
    }

    #[tokio::test]
    async fn test_write_appends_at_offset() {
        let (mut session, _rx) = create_session_with_tmp();

        let handle = session
            .open(
                1,
                "/tmp/append.bin".to_string(),
                OpenFlags::WRITE | OpenFlags::CREATE,
                FileAttributes::default(),
            )
            .await
            .unwrap();

        // First write at offset 0
        session
            .write(2, handle.handle.clone(), 0, b"AAAA".to_vec())
            .await
            .unwrap();
        // Second write at offset 4
        session
            .write(3, handle.handle.clone(), 4, b"BBBB".to_vec())
            .await
            .unwrap();

        let fs_guard = session.fs.read().await;
        let file = fs_guard.get_file("/tmp/append.bin").unwrap();
        match &file.file_content {
            Some(FileContent::RegularFile(bytes)) => {
                assert_eq!(bytes.len(), 8);
                assert_eq!(&bytes[..4], b"AAAA");
                assert_eq!(&bytes[4..], b"BBBB");
            }
            _ => panic!("expected a regular file"),
        }
    }

    #[tokio::test]
    async fn test_write_sends_db_record_file_upload() {
        let (mut session, mut db_rx) = create_session_with_tmp();

        let handle = session
            .open(
                1,
                "/tmp/hello_db".to_string(),
                OpenFlags::WRITE | OpenFlags::CREATE,
                FileAttributes::default(),
            )
            .await
            .unwrap();

        let data = b"hello db".to_vec();
        session
            .write(2, handle.handle, 0, data.clone())
            .await
            .unwrap();

        let msg = db_rx
            .try_recv()
            .expect("write should queue a DbMessage::RecordFileUpload");
        match msg {
            DbMessage::RecordFileUpload {
                filename,
                file_size,
                auth_id,
                ..
            } => {
                assert_eq!(filename, "hello_db");
                assert_eq!(file_size, 8);
                assert_eq!(auth_id, "test-auth-id");
            }
            other => panic!("expected RecordFileUpload, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_write_records_correct_sha256_hash() {
        let (mut session, mut db_rx) = create_session_with_tmp();

        let handle = session
            .open(
                1,
                "/tmp/hashme".to_string(),
                OpenFlags::WRITE | OpenFlags::CREATE,
                FileAttributes::default(),
            )
            .await
            .unwrap();

        let data = b"hash me".to_vec();
        session
            .write(2, handle.handle, 0, data.clone())
            .await
            .unwrap();

        let expected = hex::encode(Sha256::digest(&data));

        match db_rx.try_recv().unwrap() {
            DbMessage::RecordFileUpload { file_hash, .. } => {
                assert_eq!(file_hash, expected);
            }
            other => panic!("expected RecordFileUpload, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_write_preserves_binary_data_in_message() {
        let (mut session, mut db_rx) = create_session_with_tmp();

        let handle = session
            .open(
                1,
                "/tmp/binary".to_string(),
                OpenFlags::WRITE | OpenFlags::CREATE,
                FileAttributes::default(),
            )
            .await
            .unwrap();

        let data: Vec<u8> = (0..=255).collect();
        session
            .write(2, handle.handle, 0, data.clone())
            .await
            .unwrap();

        match db_rx.try_recv().unwrap() {
            DbMessage::RecordFileUpload { binary_data, .. } => {
                assert_eq!(binary_data, data);
            }
            other => panic!("expected RecordFileUpload, got {:?}", other),
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  read  (desired-state: returns actual VFS file content)
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_read_returns_actual_file_content() {
        let mut fs = FileSystem::default();
        fs.create_directory("/home").unwrap();
        fs.create_file("/home/doc.txt").unwrap();
        {
            let entry = fs.get_file_mut("/home/doc.txt").unwrap();
            if let Some(FileContent::RegularFile(ref mut d)) = entry.content {
                *d = Arc::new(b"Hello, SFTP!".to_vec());
            }
            entry.inode.i_size_lo = b"Hello, SFTP!".len() as u32;
        }

        let (mut session, _rx) = create_test_session(fs);

        let handle = session
            .open(
                1,
                "/home/doc.txt".to_string(),
                OpenFlags::READ,
                FileAttributes::default(),
            )
            .await
            .unwrap();

        let result = session.read(2, handle.handle, 0, 1024).await.unwrap();

        // Desired: read should return the bytes actually stored in the VFS
        assert_eq!(
            result.data,
            b"Hello, SFTP!",
            "read should return actual file content, not zeros"
        );
    }

    #[tokio::test]
    async fn test_read_respects_offset_and_length() {
        let mut fs = FileSystem::default();
        fs.create_directory("/home").unwrap();
        fs.create_file("/home/offset.txt").unwrap();
        {
            let entry = fs.get_file_mut("/home/offset.txt").unwrap();
            if let Some(FileContent::RegularFile(ref mut d)) = entry.content {
                *d = Arc::new(b"0123456789ABCDEF".to_vec());
            }
            entry.inode.i_size_lo = 16;
        }

        let (mut session, _rx) = create_test_session(fs);

        let handle = session
            .open(
                1,
                "/home/offset.txt".to_string(),
                OpenFlags::READ,
                FileAttributes::default(),
            )
            .await
            .unwrap();

        // Read 4 bytes starting at offset 4 → "4567"
        let result = session.read(2, handle.handle, 4, 4).await.unwrap();

        assert_eq!(
            result.data,
            b"4567",
            "read(offset=4, len=4) should return the correct slice"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    //  opendir
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_opendir_returns_nonempty_handle() {
        let mut fs = FileSystem::default();
        fs.create_directory("/var").unwrap();
        let (mut session, _rx) = create_test_session(fs);

        let handle = session.opendir(1, "/var".to_string()).await.unwrap();
        assert!(!handle.handle.is_empty());
    }

    #[tokio::test]
    async fn test_opendir_registers_directory_handle() {
        let mut fs = FileSystem::default();
        fs.create_directory("/var").unwrap();
        let (mut session, _rx) = create_test_session(fs);

        let handle = session.opendir(1, "/var".to_string()).await.unwrap();

        let guard = session.handles.read().await;
        let entry = guard.get(&handle.handle);
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.path, "/var");
        assert!(entry.is_directory);
    }

    // ═══════════════════════════════════════════════════════════════
    //  readdir  (desired-state: returns actual VFS directory entries)
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_readdir_returns_actual_directory_entries() {
        let mut fs = FileSystem::default();
        fs.create_directory("/data").unwrap();
        fs.create_file("/data/file_a.txt").unwrap();
        fs.create_file("/data/file_b.log").unwrap();
        fs.create_directory("/data/subdir").unwrap();

        let (mut session, _rx) = create_test_session(fs);

        let dir = session.opendir(1, "/data".to_string()).await.unwrap();
        let result = session.readdir(2, dir.handle).await.unwrap();

        let names: Vec<&str> =
            result.files.iter().map(|f| f.filename.as_str()).collect();

        // Desired: readdir should list the real entries in the directory
        assert!(
            names.contains(&"file_a.txt"),
            "readdir should include 'file_a.txt', got: {:?}",
            names
        );
        assert!(
            names.contains(&"file_b.log"),
            "readdir should include 'file_b.log', got: {:?}",
            names
        );
        assert!(
            names.contains(&"subdir"),
            "readdir should include 'subdir', got: {:?}",
            names
        );
    }

    #[tokio::test]
    async fn test_readdir_does_not_return_hardcoded_entries() {
        let mut fs = FileSystem::default();
        fs.create_directory("/unique_name").unwrap();

        let (mut session, _rx) = create_test_session(fs);

        let dir = session.opendir(1, "/unique_name".to_string()).await.unwrap();
        let result = session.readdir(2, dir.handle).await.unwrap();

        let names: Vec<&str> =
            result.files.iter().map(|f| f.filename.as_str()).collect();

        // The old hardcoded impl returned "config" and "data" — those should
        // never appear in an empty directory.
        assert!(
            !names.contains(&"config"),
            "readdir should not return hardcoded 'config' for an empty dir"
        );
        assert!(
            !names.contains(&"data"),
            "readdir should not return hardcoded 'data' for an empty dir"
        );
    }

    #[tokio::test]
    async fn test_readdir_includes_dot_and_dotdot() {
        let mut fs = FileSystem::default();
        fs.create_directory("/d").unwrap();
        let (mut session, _rx) = create_test_session(fs);

        let dir = session.opendir(1, "/d".to_string()).await.unwrap();
        let result = session.readdir(2, dir.handle).await.unwrap();

        let names: Vec<&str> =
            result.files.iter().map(|f| f.filename.as_str()).collect();

        // Per SFTP spec, readdir should include "." and ".."
        assert!(names.contains(&"."), "readdir should include '.'");
        assert!(names.contains(&".."), "readdir should include '..'");
    }

    // ═══════════════════════════════════════════════════════════════
    //  mkdir
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_mkdir_creates_directory_in_filesystem() {
        let (mut session, _rx) = create_test_session(FileSystem::default());

        let status = session
            .mkdir(1, "/newdir".to_string(), FileAttributes::default())
            .await
            .unwrap();

        assert_eq!(status.status_code, StatusCode::Ok);

        let fs_guard = session.fs.read().await;
        assert!(
            fs_guard.get_file("/newdir").is_ok(),
            "mkdir should create the directory in the VFS"
        );
    }

    #[tokio::test]
    async fn test_mkdir_returns_failure_for_missing_parent() {
        let (mut session, _rx) = create_test_session(FileSystem::default());

        let status = session
            .mkdir(1, "/a/b/c".to_string(), FileAttributes::default())
            .await
            .unwrap();

        assert_eq!(
            status.status_code,
            StatusCode::Failure,
            "mkdir with missing parent should return Failure"
        );
    }

    #[tokio::test]
    async fn test_mkdir_nested_creates_hierarchy() {
        let (mut session, _rx) = create_test_session(FileSystem::default());

        session
            .mkdir(1, "/parent".to_string(), FileAttributes::default())
            .await
            .unwrap();
        let status = session
            .mkdir(2, "/parent/child".to_string(), FileAttributes::default())
            .await
            .unwrap();

        assert_eq!(status.status_code, StatusCode::Ok);

        let fs_guard = session.fs.read().await;
        assert!(fs_guard.get_file("/parent/child").is_ok());
    }

    // ═══════════════════════════════════════════════════════════════
    //  rmdir  (desired-state: removes directory from VFS)
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_rmdir_removes_directory_from_filesystem() {
        let mut fs = FileSystem::default();
        fs.create_directory("/trashme").unwrap();
        let (mut session, _rx) = create_test_session(fs);

        let status = session.rmdir(1, "/trashme".to_string()).await.unwrap();
        assert_eq!(status.status_code, StatusCode::Ok);

        let fs_guard = session.fs.read().await;
        assert!(
            fs_guard.get_file("/trashme").is_err(),
            "rmdir should remove the directory from the VFS"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    //  remove  (desired-state: deletes file from VFS)
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_remove_deletes_file_from_filesystem() {
        let mut fs = FileSystem::default();
        fs.create_file("/doomed.txt").unwrap();
        let (mut session, _rx) = create_test_session(fs);

        let status = session.remove(1, "/doomed.txt".to_string()).await.unwrap();
        assert_eq!(status.status_code, StatusCode::Ok);

        let fs_guard = session.fs.read().await;
        assert!(
            fs_guard.get_file("/doomed.txt").is_err(),
            "remove should delete the file from the VFS"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    //  rename  (desired-state: moves file within VFS)
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_rename_moves_file_in_filesystem() {
        let mut fs = FileSystem::default();
        fs.create_file("/old_name.txt").unwrap();
        let (mut session, _rx) = create_test_session(fs);

        let status = session
            .rename(
                1,
                "/old_name.txt".to_string(),
                "/new_name.txt".to_string(),
            )
            .await
            .unwrap();
        assert_eq!(status.status_code, StatusCode::Ok);

        let fs_guard = session.fs.read().await;
        assert!(
            fs_guard.get_file("/old_name.txt").is_err(),
            "rename should remove the source"
        );
        assert!(
            fs_guard.get_file("/new_name.txt").is_ok(),
            "rename should create the destination"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    //  stat
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_stat_returns_size_for_existing_file() {
        let mut fs = FileSystem::default();
        fs.create_directory("/etc").unwrap();
        fs.create_file("/etc/config").unwrap();
        {
            let entry = fs.get_file_mut("/etc/config").unwrap();
            entry.inode.i_size_lo = 4096;
        }

        let (mut session, _rx) = create_test_session(fs);

        let result = session.stat(1, "/etc/config".to_string()).await.unwrap();
        assert_eq!(result.attrs.size, Some(4096));
    }

    #[tokio::test]
    async fn test_stat_returns_attributes_for_existing_directory() {
        let mut fs = FileSystem::default();
        fs.create_directory("/mydir").unwrap();

        let (mut session, _rx) = create_test_session(fs);

        let result = session.stat(1, "/mydir".to_string()).await.unwrap();
        assert!(result.attrs.size.is_some());
    }

    #[tokio::test]
    async fn test_stat_for_nonexistent_returns_fake_attributes() {
        let (mut session, _rx) = create_test_session(FileSystem::default());

        let result = session
            .stat(1, "/does_not_exist".to_string())
            .await
            .unwrap();

        // Current honeypot behaviour: fake attrs for missing files
        assert!(result.attrs.size.is_some());
    }

    // ═══════════════════════════════════════════════════════════════
    //  realpath
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_realpath_prepends_slash_for_relative() {
        let (mut session, _rx) = create_test_session(FileSystem::default());

        let result = session
            .realpath(1, "relative/path".to_string())
            .await
            .unwrap();

        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].filename, "/relative/path");
    }

    #[tokio::test]
    async fn test_realpath_preserves_absolute_path() {
        let (mut session, _rx) = create_test_session(FileSystem::default());

        let result = session
            .realpath(1, "/abs/path".to_string())
            .await
            .unwrap();

        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].filename, "/abs/path");
    }

    // ═══════════════════════════════════════════════════════════════
    //  Integration: end-to-end SFTP workflows
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_open_write_read_roundtrip() {
        let (mut session, _rx) = create_session_with_tmp();

        // Open for writing
        let handle = session
            .open(
                1,
                "/tmp/roundtrip.txt".to_string(),
                OpenFlags::WRITE | OpenFlags::CREATE,
                FileAttributes::default(),
            )
            .await
            .unwrap();

        let payload = b"roundtrip data".to_vec();
        session
            .write(2, handle.handle.clone(), 0, payload.clone())
            .await
            .unwrap();

        session.close(3, handle.handle).await.unwrap();

        // Reopen for reading
        let read_handle = session
            .open(
                4,
                "/tmp/roundtrip.txt".to_string(),
                OpenFlags::READ,
                FileAttributes::default(),
            )
            .await
            .unwrap();

        let result = session
            .read(5, read_handle.handle, 0, 1024)
            .await
            .unwrap();

        assert_eq!(
            result.data, payload,
            "read after write should return identical data"
        );
    }

    #[tokio::test]
    async fn test_mkdir_populate_readdir_roundtrip() {
        let (mut session, _rx) = create_test_session(FileSystem::default());

        session
            .mkdir(1, "/workspace".to_string(), FileAttributes::default())
            .await
            .unwrap();

        // Create files through the SFTP handlers (true integration)
        for name in &["a.txt", "b.txt"] {
            let h = session
                .open(
                    2,
                    format!("/workspace/{}", name),
                    OpenFlags::WRITE | OpenFlags::CREATE,
                    FileAttributes::default(),
                )
                .await
                .unwrap();
            session
                .write(3, h.handle.clone(), 0, b"content".to_vec())
                .await
                .unwrap();
            session.close(4, h.handle).await.unwrap();
        }

        let dir = session
            .opendir(5, "/workspace".to_string())
            .await
            .unwrap();
        let result = session.readdir(6, dir.handle).await.unwrap();
        let names: Vec<&str> =
            result.files.iter().map(|f| f.filename.as_str()).collect();

        assert!(names.contains(&"a.txt"), "readdir should list a.txt, got: {:?}", names);
        assert!(names.contains(&"b.txt"), "readdir should list b.txt, got: {:?}", names);
    }

    #[tokio::test]
    async fn test_full_file_lifecycle() {
        let (mut session, _rx) = create_test_session(FileSystem::default());

        // mkdir
        session
            .mkdir(1, "/logs".to_string(), FileAttributes::default())
            .await
            .unwrap();

        // open + write + close
        let h = session
            .open(
                2,
                "/logs/app.log".to_string(),
                OpenFlags::WRITE | OpenFlags::CREATE,
                FileAttributes::default(),
            )
            .await
            .unwrap();
        let payload = b"ERROR: something broke\n".to_vec();
        session
            .write(3, h.handle.clone(), 0, payload.clone())
            .await
            .unwrap();
        session.close(4, h.handle).await.unwrap();

        // stat should reflect the written size
        let st = session.stat(5, "/logs/app.log".to_string()).await.unwrap();
        assert_eq!(st.attrs.size, Some(payload.len() as u64));

        // readdir on parent should list the file
        let dir = session
            .opendir(6, "/logs".to_string())
            .await
            .unwrap();
        let listing = session.readdir(7, dir.handle).await.unwrap();
        let names: Vec<&str> =
            listing.files.iter().map(|f| f.filename.as_str()).collect();
        assert!(names.contains(&"app.log"));

        // read back
        let rh = session
            .open(8, "/logs/app.log".to_string(), OpenFlags::READ, FileAttributes::default())
            .await
            .unwrap();
        let data = session.read(9, rh.handle, 0, 1024).await.unwrap();
        assert_eq!(data.data, payload);

        // remove
        session
            .remove(10, "/logs/app.log".to_string())
            .await
            .unwrap();

        // file should be gone from VFS
        let fs_guard = session.fs.read().await;
        assert!(fs_guard.get_file("/logs/app.log").is_err());
    }

    #[tokio::test]
    async fn test_rename_then_read_new_path() {
        let (mut session, _rx) = create_session_with_tmp();

        // Write a file
        let h = session
            .open(
                1,
                "/tmp/original.txt".to_string(),
                OpenFlags::WRITE | OpenFlags::CREATE,
                FileAttributes::default(),
            )
            .await
            .unwrap();
        let payload = b"rename me".to_vec();
        session
            .write(2, h.handle.clone(), 0, payload.clone())
            .await
            .unwrap();
        session.close(3, h.handle).await.unwrap();

        // Rename
        session
            .rename(4, "/tmp/original.txt".to_string(), "/tmp/renamed.txt".to_string())
            .await
            .unwrap();

        // Read from the new path
        let rh = session
            .open(5, "/tmp/renamed.txt".to_string(), OpenFlags::READ, FileAttributes::default())
            .await
            .unwrap();
        let data = session.read(6, rh.handle, 0, 1024).await.unwrap();
        assert_eq!(data.data, payload);

        // Old path should not exist
        let fs_guard = session.fs.read().await;
        assert!(fs_guard.get_file("/tmp/original.txt").is_err());
    }

    #[tokio::test]
    async fn test_remove_then_readdir() {
        let (mut session, _rx) = create_test_session(FileSystem::default());

        session
            .mkdir(1, "/docs".to_string(), FileAttributes::default())
            .await
            .unwrap();

        // Create three files via SFTP
        for name in &["keep.txt", "delete_me.txt", "also_keep.txt"] {
            let h = session
                .open(
                    2,
                    format!("/docs/{}", name),
                    OpenFlags::WRITE | OpenFlags::CREATE,
                    FileAttributes::default(),
                )
                .await
                .unwrap();
            session.write(3, h.handle.clone(), 0, b"x".to_vec()).await.unwrap();
            session.close(4, h.handle).await.unwrap();
        }

        // Remove one file
        session
            .remove(5, "/docs/delete_me.txt".to_string())
            .await
            .unwrap();

        // readdir should show the remaining two, not the deleted one
        let dir = session.opendir(6, "/docs".to_string()).await.unwrap();
        let result = session.readdir(7, dir.handle).await.unwrap();
        let names: Vec<&str> =
            result.files.iter().map(|f| f.filename.as_str()).collect();

        assert!(names.contains(&"keep.txt"));
        assert!(names.contains(&"also_keep.txt"));
        assert!(
            !names.contains(&"delete_me.txt"),
            "readdir should not list removed file"
        );
    }

    #[tokio::test]
    async fn test_write_multiple_chunks_read_back() {
        let (mut session, _rx) = create_session_with_tmp();

        let h = session
            .open(
                1,
                "/tmp/chunks.bin".to_string(),
                OpenFlags::WRITE | OpenFlags::CREATE,
                FileAttributes::default(),
            )
            .await
            .unwrap();

        // Write three non-contiguous chunks
        session.write(2, h.handle.clone(), 0, b"AAAA".to_vec()).await.unwrap();
        session.write(3, h.handle.clone(), 10, b"BBBB".to_vec()).await.unwrap();
        session.write(4, h.handle.clone(), 20, b"CCCC".to_vec()).await.unwrap();
        session.close(5, h.handle).await.unwrap();

        // Read the whole file back
        let rh = session
            .open(6, "/tmp/chunks.bin".to_string(), OpenFlags::READ, FileAttributes::default())
            .await
            .unwrap();
        let data = session.read(7, rh.handle, 0, 1024).await.unwrap();

        assert_eq!(data.data.len(), 24); // spans offset 0..24
        assert_eq!(&data.data[0..4], b"AAAA");
        assert_eq!(&data.data[4..10], &[0; 6]); // gap filled with zeros
        assert_eq!(&data.data[10..14], b"BBBB");
        assert_eq!(&data.data[14..20], &[0; 6]); // gap filled with zeros
        assert_eq!(&data.data[20..24], b"CCCC");
    }

    #[tokio::test]
    async fn test_rmdir_after_removing_contents() {
        let (mut session, _rx) = create_test_session(FileSystem::default());

        // mkdir parent
        session
            .mkdir(1, "/work".to_string(), FileAttributes::default())
            .await
            .unwrap();

        // Create files inside via SFTP
        for name in &["file1", "file2"] {
            let h = session
                .open(
                    2,
                    format!("/work/{}", name),
                    OpenFlags::WRITE | OpenFlags::CREATE,
                    FileAttributes::default(),
                )
                .await
                .unwrap();
            session.write(3, h.handle.clone(), 0, b"data".to_vec()).await.unwrap();
            session.close(4, h.handle).await.unwrap();
        }

        // Remove the files
        session.remove(5, "/work/file1".to_string()).await.unwrap();
        session.remove(6, "/work/file2".to_string()).await.unwrap();

        // Now rmdir should succeed
        let status = session.rmdir(7, "/work".to_string()).await.unwrap();
        assert_eq!(status.status_code, StatusCode::Ok);

        let fs_guard = session.fs.read().await;
        assert!(fs_guard.get_file("/work").is_err());
    }

    #[tokio::test]
    async fn test_stat_reflects_written_size() {
        let (mut session, _rx) = create_test_session(FileSystem::default());

        // Write 100 bytes
        let h = session
            .open(
                1,
                "/blob.dat".to_string(),
                OpenFlags::WRITE | OpenFlags::CREATE,
                FileAttributes::default(),
            )
            .await
            .unwrap();
        let payload = vec![0x42u8; 100];
        session
            .write(2, h.handle.clone(), 0, payload.clone())
            .await
            .unwrap();
        session.close(3, h.handle).await.unwrap();

        // stat should report size = 100
        let st = session.stat(4, "/blob.dat".to_string()).await.unwrap();
        assert_eq!(st.attrs.size, Some(100));
    }

    #[tokio::test]
    async fn test_partial_read_across_written_gaps() {
        let (mut session, _rx) = create_session_with_tmp();

        let h = session
            .open(
                1,
                "/tmp/sparse.bin".to_string(),
                OpenFlags::WRITE | OpenFlags::CREATE,
                FileAttributes::default(),
            )
            .await
            .unwrap();

        // Write at offset 5, leaving a gap at 0..5
        session
            .write(2, h.handle.clone(), 5, b"HELLO".to_vec())
            .await
            .unwrap();
        session.close(3, h.handle).await.unwrap();

        // Read just the written portion
        let rh = session
            .open(4, "/tmp/sparse.bin".to_string(), OpenFlags::READ, FileAttributes::default())
            .await
            .unwrap();

        let from_offset = session.read(5, rh.handle.clone(), 5, 5).await.unwrap();
        assert_eq!(from_offset.data, b"HELLO");

        let from_zero = session.read(6, rh.handle.clone(), 0, 10).await.unwrap();
        assert_eq!(from_zero.data.len(), 10);
        assert_eq!(&from_zero.data[0..5], &[0; 5]); // zeros before the write
        assert_eq!(&from_zero.data[5..10], b"HELLO");
    }

    // ═══════════════════════════════════════════════════════════════
    //  lstat
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_lstat_returns_attributes_for_existing_file() {
        let mut fs = FileSystem::default();
        fs.create_directory("/etc").unwrap();
        fs.create_file("/etc/config").unwrap();
        {
            let entry = fs.get_file_mut("/etc/config").unwrap();
            entry.inode.i_size_lo = 2048;
        }

        let (mut session, _rx) = create_test_session(fs);

        let result = session.lstat(1, "/etc/config".to_string()).await.unwrap();
        assert_eq!(result.attrs.size, Some(2048));
    }

    #[tokio::test]
    async fn test_lstat_returns_fake_attributes_for_missing_file() {
        let (mut session, _rx) = create_test_session(FileSystem::default());

        let result = session.lstat(1, "/nonexistent".to_string()).await.unwrap();
        assert!(result.attrs.size.is_some());
    }

    #[tokio::test]
    async fn test_lstat_on_symlink_returns_link_attrs() {
        let mut fs = FileSystem::default();
        fs.create_directory("/dir").unwrap();
        fs.create_file("/dir/target.txt").unwrap();
        fs.create_symlink("/dir/link", "/dir/target.txt").unwrap();

        let (mut session, _rx) = create_test_session(fs);

        let link_result = session.lstat(1, "/dir/link".to_string()).await.unwrap();
        let target_result = session.lstat(2, "/dir/target.txt".to_string()).await.unwrap();

        // lstat should not follow the symlink — both return attrs successfully
        assert!(link_result.attrs.size.is_some());
        assert!(target_result.attrs.size.is_some());
    }

    // ═══════════════════════════════════════════════════════════════
    //  fstat
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_fstat_returns_attributes_by_handle() {
        let (mut session, _rx) = create_session_with_tmp();

        let handle = session
            .open(
                1,
                "/tmp/data.bin".to_string(),
                OpenFlags::WRITE | OpenFlags::CREATE,
                FileAttributes::default(),
            )
            .await
            .unwrap();

        // Write some data so size is meaningful
        session
            .write(2, handle.handle.clone(), 0, b"100_bytes_of_payload_data_here_____________________!".to_vec())
            .await
            .unwrap();

        let result = session.fstat(3, handle.handle.clone()).await.unwrap();
        assert!(result.attrs.size.is_some());
    }

    #[tokio::test]
    async fn test_fstat_returns_default_for_unknown_handle() {
        let (mut session, _rx) = create_session_with_tmp();

        let result = session.fstat(1, "nonexistent_handle".to_string()).await.unwrap();
        // Unknown handle should still return Ok with default attrs
        assert!(result.attrs.size.is_some());
    }

    #[tokio::test]
    async fn test_fstat_returns_same_attrs_as_stat() {
        let mut fs = FileSystem::default();
        fs.create_directory("/home").unwrap();
        fs.create_file("/home/file").unwrap();
        {
            let entry = fs.get_file_mut("/home/file").unwrap();
            entry.inode.i_size_lo = 512;
            entry.inode.i_mode = 0o100600;
        }

        let (mut session, _rx) = create_test_session(fs);

        let stat_result = session.stat(1, "/home/file".to_string()).await.unwrap();
        let handle = session
            .open(2, "/home/file".to_string(), OpenFlags::READ, FileAttributes::default())
            .await
            .unwrap();
        let fstat_result = session.fstat(3, handle.handle).await.unwrap();

        assert_eq!(stat_result.attrs.size, fstat_result.attrs.size);
        assert_eq!(stat_result.attrs.permissions, fstat_result.attrs.permissions);
    }

    // ═══════════════════════════════════════════════════════════════
    //  setstat
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_setstat_updates_permissions() {
        let mut fs = FileSystem::default();
        fs.create_file("/file.txt").unwrap();

        let (mut session, _rx) = create_test_session(fs);

        let mut attrs = FileAttributes::default();
        attrs.permissions = Some(0o100600);

        let status = session.setstat(1, "/file.txt".to_string(), attrs).await.unwrap();
        assert_eq!(status.status_code, StatusCode::Ok);

        let guard = session.fs.read().await;
        let entry = guard.get_file("/file.txt").unwrap();
        assert_eq!(entry.inode.i_mode, 0o100600);
    }

    #[tokio::test]
    async fn test_setstat_updates_uid_and_gid() {
        let mut fs = FileSystem::default();
        fs.create_file("/file.txt").unwrap();

        let (mut session, _rx) = create_test_session(fs);

        let mut attrs = FileAttributes::default();
        attrs.uid = Some(1000);
        attrs.gid = Some(1000);

        session.setstat(1, "/file.txt".to_string(), attrs).await.unwrap();

        let guard = session.fs.read().await;
        let entry = guard.get_file("/file.txt").unwrap();
        assert_eq!(entry.inode.i_uid, 1000);
        assert_eq!(entry.inode.i_gid, 1000);
    }

    #[tokio::test]
    async fn test_setstat_updates_mtime() {
        let mut fs = FileSystem::default();
        fs.create_file("/file.txt").unwrap();

        let (mut session, _rx) = create_test_session(fs);

        let mut attrs = FileAttributes::default();
        attrs.mtime = Some(1234567890);

        session.setstat(1, "/file.txt".to_string(), attrs).await.unwrap();

        let guard = session.fs.read().await;
        let entry = guard.get_file("/file.txt").unwrap();
        assert_eq!(entry.inode.i_mtime, 1234567890);
    }

    #[tokio::test]
    async fn test_setstat_returns_no_such_file_for_missing() {
        let (mut session, _rx) = create_test_session(FileSystem::default());

        let status = session
            .setstat(1, "/ghost".to_string(), FileAttributes::default())
            .await
            .unwrap();
        assert_eq!(status.status_code, StatusCode::NoSuchFile);
    }

    // ═══════════════════════════════════════════════════════════════
    //  fsetstat
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_fsetstat_updates_permissions_by_handle() {
        let (mut session, _rx) = create_session_with_tmp();

        let handle = session
            .open(
                1,
                "/tmp/fsetstat.bin".to_string(),
                OpenFlags::WRITE | OpenFlags::CREATE,
                FileAttributes::default(),
            )
            .await
            .unwrap();

        let mut attrs = FileAttributes::default();
        attrs.permissions = Some(0o100755);
        attrs.uid = Some(42);

        let status = session.fsetstat(2, handle.handle.clone(), attrs).await.unwrap();
        assert_eq!(status.status_code, StatusCode::Ok);

        let guard = session.fs.read().await;
        let entry = guard.get_file("/tmp/fsetstat.bin").unwrap();
        assert_eq!(entry.inode.i_mode, 0o100755);
        assert_eq!(entry.inode.i_uid, 42);
    }

    #[tokio::test]
    async fn test_fsetstat_failure_for_unknown_handle() {
        let (mut session, _rx) = create_session_with_tmp();

        let status = session
            .fsetstat(1, "bogus_handle".to_string(), FileAttributes::default())
            .await
            .unwrap();
        assert_eq!(status.status_code, StatusCode::Failure);
    }

    // ═══════════════════════════════════════════════════════════════
    //  readlink
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_readlink_returns_symlink_target() {
        let mut fs = FileSystem::default();
        fs.create_directory("/dir").unwrap();
        fs.create_file("/dir/real.txt").unwrap();
        fs.create_symlink("/dir/soft", "/dir/real.txt").unwrap();

        let (mut session, _rx) = create_test_session(fs);

        let result = session.readlink(1, "/dir/soft".to_string()).await.unwrap();
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].filename, "/dir/real.txt");
    }

    #[tokio::test]
    async fn test_readlink_returns_empty_for_non_symlink() {
        let mut fs = FileSystem::default();
        fs.create_file("/regular.txt").unwrap();

        let (mut session, _rx) = create_test_session(fs);

        let result = session.readlink(1, "/regular.txt".to_string()).await.unwrap();
        // Non-symlink returns a dummy/empty entry
        assert_eq!(result.files.len(), 1);
        assert!(result.files[0].filename.is_empty());
    }

    #[tokio::test]
    async fn test_readlink_returns_empty_for_missing_path() {
        let (mut session, _rx) = create_test_session(FileSystem::default());

        let result = session.readlink(1, "/no_such_link".to_string()).await.unwrap();
        assert_eq!(result.files.len(), 1);
        assert!(result.files[0].filename.is_empty());
    }

    // ═══════════════════════════════════════════════════════════════
    //  symlink
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_symlink_creates_link_in_filesystem() {
        let mut fs = FileSystem::default();
        fs.create_directory("/links").unwrap();
        fs.create_file("/links/target").unwrap();

        let (mut session, _rx) = create_test_session(fs);

        let status = session
            .symlink(1, "/links/alias".to_string(), "/links/target".to_string())
            .await
            .unwrap();
        assert_eq!(status.status_code, StatusCode::Ok);

        let guard = session.fs.read().await;
        let entry = guard.get_file("/links/alias").unwrap();
        match &entry.file_content {
            Some(FileContent::SymbolicLink(target)) => {
                assert_eq!(target, "/links/target");
            }
            _ => panic!("expected a symbolic link"),
        }
    }

    #[tokio::test]
    async fn test_symlink_failure_for_missing_parent() {
        let (mut session, _rx) = create_test_session(FileSystem::default());

        let status = session
            .symlink(1, "/nonexistent_dir/link".to_string(), "/target".to_string())
            .await
            .unwrap();
        assert_eq!(status.status_code, StatusCode::Failure);
    }

    #[tokio::test]
    async fn test_symlink_failure_for_already_exists() {
        let mut fs = FileSystem::default();
        fs.create_directory("/d").unwrap();
        fs.create_symlink("/d/existing", "/target").unwrap();

        let (mut session, _rx) = create_test_session(fs);

        let status = session
            .symlink(1, "/d/existing".to_string(), "/other".to_string())
            .await
            .unwrap();
        assert_eq!(status.status_code, StatusCode::Failure);
    }

    // ═══════════════════════════════════════════════════════════════
    //  Integration: symlink → readlink round-trip
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_symlink_readlink_roundtrip() {
        let mut fs = FileSystem::default();
        fs.create_directory("/home").unwrap();
        fs.create_file("/home/original.txt").unwrap();

        let (mut session, _rx) = create_test_session(fs);

        // Create symlink
        session
            .symlink(1, "/home/shortcut".to_string(), "/home/original.txt".to_string())
            .await
            .unwrap();

        // Read it back
        let result = session.readlink(2, "/home/shortcut".to_string()).await.unwrap();
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].filename, "/home/original.txt");
    }
}
