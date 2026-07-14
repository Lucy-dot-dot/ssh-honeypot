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
use crate::shell::filesystem::fs2::{FileContent, FileSystem};

/*
NOTE: This sftp implementation is quite basic and not feature complete. It may not work in many cases. And is subject to potential removal until I decide to or someone wants to have it.
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
        let db_tx = self.db_tx.clone();
        let auth_id = self.auth_id.clone();

        async move {
            log::info!(
                "SFTP write: {} bytes to handle {} at offset {}",
                data.len(),
                handle,
                offset
            );

            // Record the file upload
            let filename = format!("sftp_upload_{}", handle);
            let filepath = format!("/tmp/{}", filename);

            // Calculate SHA256 hash
            let hasher = Sha256::digest(&data);
            let file_hash = hex::encode(hasher.as_slice());

            // Analyze file with magic detection and entropy
            let (claimed_mime, detected_mime, format_mismatch, file_entropy) =
                HoneypotSftpSession::analyze_file(&data, &filepath);

            // Store in filesystem
            {
                let mut fs_guard = fs.write().await;
                if let Ok(entry) = fs_guard.create_file(&filepath) {
                    if let Some(FileContent::RegularFile(file_data)) = &mut entry.content {
                        let file_data = Arc::make_mut(file_data);
                        let required_size = (offset + data.len() as u64) as usize;
                        if file_data.len() < required_size {
                            file_data.resize(required_size, 0);
                        }
                        let start = offset as usize;
                        let end = start + data.len();
                        file_data[start..end].copy_from_slice(&data);

                        // Update file size
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

        async move {
            log::info!(
                "SFTP remove request: {} (honeypot - not actually removing)",
                path
            );
            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "".to_string(),
                language_tag: "".to_string(),
            })
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

        async move {
            log::info!(
                "SFTP rmdir request: {} (honeypot - not actually removing)",
                path
            );
            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "".to_string(),
                language_tag: "".to_string(),
            })
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

        async move {
            log::info!(
                "SFTP rename request: {} -> {} (honeypot - not actually renaming)",
                old_path,
                new_path
            );
            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "".to_string(),
                language_tag: "".to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell::filesystem::fs2::FileSystem;

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

        let payload = b"payload data".to_vec();
        session
            .write(1, "h1".to_string(), 0, payload.clone())
            .await
            .unwrap();

        let fs_guard = session.fs.read().await;
        let file = fs_guard.get_file("/tmp/sftp_upload_h1");
        assert!(file.is_ok(), "write should create the upload file in the VFS");

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

        // First write at offset 0
        session
            .write(1, "hoff".to_string(), 0, b"AAAA".to_vec())
            .await
            .unwrap();
        // Second write at offset 4
        session
            .write(2, "hoff".to_string(), 4, b"BBBB".to_vec())
            .await
            .unwrap();

        let fs_guard = session.fs.read().await;
        let file = fs_guard.get_file("/tmp/sftp_upload_hoff").unwrap();
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

        let data = b"hello db".to_vec();
        session
            .write(1, "h2".to_string(), 0, data.clone())
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
                assert_eq!(filename, "sftp_upload_h2");
                assert_eq!(file_size, 8);
                assert_eq!(auth_id, "test-auth-id");
            }
            other => panic!("expected RecordFileUpload, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_write_records_correct_sha256_hash() {
        let (mut session, mut db_rx) = create_session_with_tmp();

        let data = b"hash me".to_vec();
        session
            .write(1, "h3".to_string(), 0, data.clone())
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

        let data: Vec<u8> = (0..=255).collect();
        session
            .write(1, "hbin".to_string(), 0, data.clone())
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
    //  Integration: round-trip scenarios  (desired-state)
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

        // Desired: data read back should match what was written
        assert_eq!(
            result.data, payload,
            "read after write should return identical data"
        );
    }

    #[tokio::test]
    async fn test_mkdir_populate_readdir_roundtrip() {
        let (mut session, _rx) = create_test_session(FileSystem::default());

        // Create directory via SFTP
        session
            .mkdir(1, "/workspace".to_string(), FileAttributes::default())
            .await
            .unwrap();

        // Populate via the VFS (simulating prior file creation)
        {
            let mut fs_guard = session.fs.write().await;
            fs_guard.create_file("/workspace/a.txt").unwrap();
            fs_guard.create_file("/workspace/b.txt").unwrap();
        }

        // List via SFTP readdir
        let dir = session
            .opendir(2, "/workspace".to_string())
            .await
            .unwrap();
        let result = session.readdir(3, dir.handle).await.unwrap();
        let names: Vec<&str> =
            result.files.iter().map(|f| f.filename.as_str()).collect();

        // Desired: readdir should reflect the files we created
        assert!(
            names.contains(&"a.txt"),
            "readdir should list a.txt, got: {:?}",
            names
        );
        assert!(
            names.contains(&"b.txt"),
            "readdir should list b.txt, got: {:?}",
            names
        );
    }
}
