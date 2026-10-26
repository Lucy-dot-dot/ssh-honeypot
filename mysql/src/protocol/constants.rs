pub mod capabilities {
    /// Base server capability flags advertised in the initial handshake.
    /// Deliberately does NOT include CLIENT_COMPRESS or CLIENT_LOCAL_FILES.
    /// The server adds CLIENT_SSL to this set when TLS support is enabled
    /// (see MysqlServer::server_capabilities).
    pub const SERVER_CAPABILITIES: u32 = CLIENT_LONG_PASSWORD
        | CLIENT_FOUND_ROWS
        | CLIENT_LONG_FLAG
        | CLIENT_CONNECT_WITH_DB
        | CLIENT_NO_SCHEMA
        | CLIENT_PROTOCOL_41
        | CLIENT_INTERACTIVE
        | CLIENT_TRANSACTIONS
        | CLIENT_SECURE_CONNECTION
        | CLIENT_MULTI_STATEMENTS
        | CLIENT_MULTI_RESULTS
        | CLIENT_PS_MULTI_RESULTS
        | CLIENT_PLUGIN_AUTH
        | CLIENT_CONNECT_ATTRS
        | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
        | CLIENT_SESSION_TRACK
        | CLIENT_DEPRECATE_EOF;

    pub const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
    pub const CLIENT_FOUND_ROWS: u32 = 0x0000_0002;
    pub const CLIENT_LONG_FLAG: u32 = 0x0000_0004;
    pub const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
    pub const CLIENT_NO_SCHEMA: u32 = 0x0000_0010;
    pub const CLIENT_COMPRESS: u32 = 0x0000_0020;
    pub const CLIENT_LOCAL_FILES: u32 = 0x0000_0080;
    pub const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
    pub const CLIENT_INTERACTIVE: u32 = 0x0000_0400;
    pub const CLIENT_SSL: u32 = 0x0000_0800;
    pub const CLIENT_TRANSACTIONS: u32 = 0x0000_2000;
    pub const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
    pub const CLIENT_MULTI_STATEMENTS: u32 = 0x0001_0000;
    pub const CLIENT_MULTI_RESULTS: u32 = 0x0002_0000;
    pub const CLIENT_PS_MULTI_RESULTS: u32 = 0x0004_0000;
    pub const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
    pub const CLIENT_CONNECT_ATTRS: u32 = 0x0010_0000;
    pub const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;
    pub const CLIENT_SESSION_TRACK: u32 = 0x0080_0000;
    pub const CLIENT_DEPRECATE_EOF: u32 = 0x0100_0000;
}

pub mod status {
    pub const SERVER_STATUS_AUTOCOMMIT: u16 = 0x0002;
}

pub mod commands {
    pub const COM_QUIT: u8 = 0x01;
    pub const COM_INIT_DB: u8 = 0x02;
    pub const COM_QUERY: u8 = 0x03;
    pub const COM_FIELD_LIST: u8 = 0x04;
    pub const COM_STATISTICS: u8 = 0x09;
    pub const COM_PROCESS_INFO: u8 = 0x0a;
    pub const COM_PING: u8 = 0x0e;
}

pub mod error_codes {
    pub const ER_ACCESS_DENIED_ERROR: u16 = 1045;
    pub const ER_UNKNOWN_COM_ERROR: u16 = 1047;
    pub const ER_BAD_HS_ERROR: u16 = 1043;
}

/// utf8mb4_general_ci
pub const UTF8MB4_CHARSET: u8 = 45;

/// Auth plugin advertised by the server. After the client responds with a
/// native password scramble we send an auth switch request to
/// `mysql_clear_password` so clients transmit the password in cleartext.
pub const NATIVE_PASSWORD_PLUGIN: &str = "mysql_native_password";
pub const CLEAR_PASSWORD_PLUGIN: &str = "mysql_clear_password";
