use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use chrono::Utc;
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode, Status, Handle, Name, File, Version, Data, Attrs};
use russh_sftp::server::Handler;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

use crate::db::DbMessage;
use crate::shell::filesystem::fs2::{FileContent, FileSystem};

pub struct HoneypotSftpSession {
    db_tx: mpsc::Sender<DbMessage>,
    fs: Arc<RwLock<FileSystem>>,
    auth_id: String,
}

impl HoneypotSftpSession {
    pub fn new(db_tx: mpsc::Sender<DbMessage>, fs: Arc<RwLock<FileSystem>>, auth_id: String) -> Self {
        Self {
            db_tx,
            fs,
            auth_id,
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
    fn analyze_file(data: &[u8], filepath: &str) -> (Option<String>, Option<String>, bool, Option<f64>) {
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
            log::warn!("File format mismatch detected: {} claimed as '{}' but detected as '{}'", 
                      filepath, 
                      claimed_mime.as_deref().unwrap_or("unknown"), 
                      detected_mime.as_deref().unwrap_or("unknown"));
        }

        if let Some(ent) = entropy {
            if ent > 7.5 {
                log::warn!("High entropy file detected: {} (entropy: {:.2}) - possible packed/encrypted content", filepath, ent);
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

    fn init(&mut self, _version: u32, _extensions: HashMap<String, String>) -> impl Future<Output = Result<Version, Self::Error>> + Send {
        async {
            log::info!("SFTP session initialized for auth_id: {}", self.auth_id);
            Ok(Version::new())
        }
    }

    fn open(&mut self, id: u32, path: String, flags: OpenFlags, _attrs: FileAttributes) -> impl Future<Output = Result<Handle, Self::Error>> + Send {
        let path = path;
        let fs = self.fs.clone();
        
        async move {
            log::debug!("SFTP open request: id={}, path={}, flags={:?}", id, path, flags);
            
            // For simplicity, always create a handle for honeypot purposes
            let handle = format!("handle_{}_{}", id, Uuid::new_v4());
            
            // If it's a write operation, we'll track it for file upload logging
            if flags.contains(OpenFlags::CREATE) || flags.contains(OpenFlags::WRITE) {
                // Ensure parent directories exist in filesystem
                let mut fs_guard = fs.write().await;
                let _ = fs_guard.create_file(&path);
            }
            
            Ok(Handle { id, handle })
        }
    }

    fn close(&mut self, id: u32, handle: String) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        let handle = handle;
        async move {
            log::debug!("SFTP close request: id={}, handle={}", id, handle);
            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "".to_string(),
                language_tag: "".to_string(),
            })
        }
    }

    fn read(&mut self, id: u32, handle: String, offset: u64, len: u32) -> impl Future<Output = Result<Data, Self::Error>> + Send {
        let handle = handle;
        let _fs = self.fs.clone();
        
        async move {
            log::debug!("SFTP read request: id={}, handle={}, offset={}, len={}", id, handle, offset, len);
            
            // For honeypot, return empty data or fake content
            Ok(Data { 
                id, 
                data: vec![0; std::cmp::min(len as usize, 1024)] // Return zeros or fake data
            })
        }
    }

    fn write(&mut self, id: u32, handle: String, offset: u64, data: Vec<u8>) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        let handle = handle;
        let fs = self.fs.clone();
        let db_tx = self.db_tx.clone();
        let auth_id = self.auth_id.clone();
        
        async move {
            log::info!("SFTP write: {} bytes to handle {} at offset {}", data.len(), handle, offset);
            
            // Record the file upload
            let filename = format!("sftp_upload_{}", handle);
            let filepath = format!("/tmp/{}", filename);
            
            // Calculate SHA256 hash
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let file_hash = format!("{:x}", hasher.finalize());
            
            // Analyze file with magic detection and entropy
            let (claimed_mime, detected_mime, format_mismatch, file_entropy) = 
                HoneypotSftpSession::analyze_file(&data, &filepath);
            
            // Store in filesystem
            {
                let mut fs_guard = fs.write().await;
                if let Ok(entry) = fs_guard.create_file(&filepath) {
                    if let Some(FileContent::RegularFile(file_data)) = &mut entry.file_content {
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
            let file_id = Uuid::new_v4().to_string();
            let file_size = data.len() as u64;
            
            match db_tx.send(DbMessage::RecordFileUpload {
                id: file_id,
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
            }).await {
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

    fn opendir(&mut self, id: u32, path: String) -> impl Future<Output = Result<Handle, Self::Error>> + Send {
        let path = path;
        
        async move {
            log::debug!("SFTP opendir request: id={}, path={}", id, path);
            let handle = format!("dir_handle_{}_{}", id, Uuid::new_v4());
            Ok(Handle { id, handle })
        }
    }

    fn readdir(&mut self, id: u32, handle: String) -> impl Future<Output = Result<Name, Self::Error>> + Send {
        let handle = handle;
        let _fs = self.fs.clone();
        
        async move {
            log::debug!("SFTP readdir request: id={}, handle={}", id, handle);
            
            // Return some fake directory entries for honeypot
            let files = vec![
                File::new(".", FileAttributes::default()),
                File::new("..", FileAttributes::default()),
                File::new("config", FileAttributes::default()),
                File::new("data", FileAttributes::default()),
            ];
            
            Ok(Name { id, files })
        }
    }

    fn remove(&mut self, id: u32, path: String) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        let path = path;

        async move {
            log::info!("SFTP remove request: {} (honeypot - not actually removing)", path);
            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "".to_string(),
                language_tag: "".to_string(),
            })
        }
    }

    fn mkdir(&mut self, id: u32, path: String, _attrs: FileAttributes) -> impl Future<Output = Result<Status, Self::Error>> + Send {
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
                })
            }
        }
    }

    fn rmdir(&mut self, id: u32, path: String) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        let path = path;

        async move {
            log::info!("SFTP rmdir request: {} (honeypot - not actually removing)", path);
            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "".to_string(),
                language_tag: "".to_string(),
            })
        }
    }

    fn realpath(&mut self, id: u32, path: String) -> impl Future<Output = Result<Name, Self::Error>> + Send {
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

    fn stat(&mut self, id: u32, path: String) -> impl Future<Output = Result<Attrs, Self::Error>> + Send {
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

    fn rename(&mut self, id: u32, old_path: String, new_path: String) -> impl Future<Output = Result<Status, Self::Error>> + Send {
        let old_path = old_path;
        let new_path = new_path;
        
        async move {
            log::info!("SFTP rename request: {} -> {} (honeypot - not actually renaming)", old_path, new_path);
            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "".to_string(),
                language_tag: "".to_string(),
            })
        }
    }
}