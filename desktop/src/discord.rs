//! Discord Rich Presence for the dashboard GUI.
//!
//! Spawns a background thread that connects to a locally running Discord
//! desktop client over IPC and reports what the operator is doing
//! ("Investigating a session", "Looking into an IP", ...). The thread
//! owns the connection lifecycle: it retries while Discord is not reachable,
//! clears the presence when the dashboard exits, and pushes a fresh activity
//! whenever the GUI sends one through the [`PresenceHandle`].
//!
//! Presence is opt-in: it only starts when `discord_app_id` is set in
//! `dashboard.toml` (the Discord application's public client ID — Rich
//! Presence involves no secret). The art asset uploaded in the developer
//! portal must be named `honeypot` (see `desktop/assets/discord/`).

use discord_rich_presence::{DiscordIpc, DiscordIpcClient, activity};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Seconds between reconnect attempts while no Discord client is reachable
/// (Discord closed, still starting, or a Flatpak/Snap socket not wired up).
const RECONNECT_SECS: u64 = 10;
/// Discord truncates details/state beyond 128 characters.
const MAX_TEXT: usize = 128;
/// Key of the art asset uploaded in the Discord developer portal.
const LARGE_IMAGE_KEY: &str = "honeypot";
const LARGE_IMAGE_TEXT: &str = "SSH Honeypot Dashboard";

/// What the operator is currently doing in the dashboard. Derived from the
/// focused floating window (idle when none has focus).
#[derive(Clone, Debug, PartialEq)]
pub enum PresenceActivity {
    /// No window focused: browsing the feeds.
    Idle,
    /// Session detail window open (auth → commands / uploaded files).
    InvestigatingSession { label: String },
    /// IP report window.
    LookingIntoIp { ip: String },
    /// Password report window.
    LookingIntoPassword { query: String },
    /// Connection detail window (conn_track row + its auth attempts).
    LookingIntoConnection { ip: String },
    /// Abuse e-mail or generic report draft composer.
    DraftingAbuseEmail { ip: String },
    /// Reported-IP details or manager window.
    ReviewingReportedIps,
}

impl PresenceActivity {
    /// Upper activity line in the Discord profile.
    fn details(&self) -> String {
        match self {
            PresenceActivity::Idle => "Enjoying the dashboard".to_string(),
            PresenceActivity::InvestigatingSession { .. } => "Investigating a session".to_string(),
            PresenceActivity::LookingIntoIp { .. } => "Looking into an IP".to_string(),
            PresenceActivity::LookingIntoPassword { .. } => "Looking into a password".to_string(),
            PresenceActivity::LookingIntoConnection { .. } => {
                "Looking into a connection".to_string()
            }
            PresenceActivity::DraftingAbuseEmail { .. } => "Drafting an abuse email".to_string(),
            PresenceActivity::ReviewingReportedIps => "Reviewing reported IPs".to_string(),
        }
    }

    /// Lower contextual line (the target of the investigation), if any.
    fn state(&self) -> Option<String> {
        match self {
            PresenceActivity::Idle => None,
            PresenceActivity::InvestigatingSession { label } => Some(label.clone()),
            PresenceActivity::LookingIntoIp { ip } => Some(ip.clone()),
            PresenceActivity::LookingIntoPassword { query } => Some(query.clone()),
            PresenceActivity::LookingIntoConnection { ip } => Some(ip.clone()),
            PresenceActivity::DraftingAbuseEmail { ip } => Some(ip.clone()),
            PresenceActivity::ReviewingReportedIps => None,
        }
    }
}

/// Truncate to Discord's 128-char limit (char-boundary safe).
fn clip128(s: String) -> String {
    if s.chars().count() <= MAX_TEXT {
        return s;
    }
    format!("{}…", s.chars().take(MAX_TEXT - 1).collect::<String>())
}

/// Handle for the GUI thread to push activity changes into the presence
/// thread. Updates are cheap fire-and-forget; the presence thread ignores
/// duplicates.
#[derive(Clone)]
pub struct PresenceHandle {
    tx: Sender<PresenceActivity>,
}

impl PresenceHandle {
    pub fn update(&self, activity: PresenceActivity) {
        // Failure only means the presence thread is gone (shutdown race).
        let _ = self.tx.send(activity);
    }
}

/// Spawn the presence thread for the given Discord application ID (the
/// client ID from the developer portal, public by design).
pub fn spawn(app_id: String) -> PresenceHandle {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("discord-presence".to_string())
        .spawn(move || run(app_id, rx))
        .expect("failed to spawn discord-presence thread");
    PresenceHandle { tx }
}

fn connect(app_id: &str) -> Result<DiscordIpcClient, Box<dyn std::error::Error>> {
    let mut client = DiscordIpcClient::new(app_id)?;
    client.connect()?;
    Ok(client)
}

/// Push `current` to Discord. Returns false when the connection died and a
/// reconnect is needed.
fn push_current(
    client: &mut DiscordIpcClient,
    current: &Option<(PresenceActivity, SystemTime)>,
) -> bool {
    let Some((activity, started)) = current else {
        return true;
    };
    let start = started
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let state_string = activity.state().map(clip128);
    // The activity builders borrow &str, so the owned strings must be built
    // first and outlive the payload.
    let details = clip128(activity.details());
    let mut payload = activity::Activity::new()
        .details(&details)
        .timestamps(activity::Timestamps::new().start(start))
        .assets(
            activity::Assets::new()
                .large_image(LARGE_IMAGE_KEY)
                .large_text(LARGE_IMAGE_TEXT),
        );
    if let Some(state) = &state_string {
        payload = payload.state(state);
    }
    client.set_activity(payload).is_ok()
}

fn run(app_id: String, rx: Receiver<PresenceActivity>) {
    let mut current: Option<(PresenceActivity, SystemTime)> = None;
    let mut client: Option<DiscordIpcClient> = None;
    loop {
        // Maintain the connection: connect with retries while Discord is
        // unreachable, absorbing activity changes so nothing is lost.
        if client.is_none() {
            match connect(&app_id) {
                Ok(mut c) => {
                    if !push_current(&mut c, &current) {
                        // Died immediately (e.g. Discord quit mid-connect).
                        let _ = c.close();
                    } else {
                        client = Some(c);
                    }
                }
                Err(_) => {
                    match rx.recv_timeout(Duration::from_secs(RECONNECT_SECS)) {
                        Ok(a) => {
                            let now = SystemTime::now();
                            if current.as_ref().map(|(c, _)| c != &a).unwrap_or(true) {
                                current = Some((a, now));
                            }
                        }
                        Err(RecvTimeoutError::Timeout) => {}
                        // All senders dropped: the dashboard exited.
                        Err(RecvTimeoutError::Disconnected) => return,
                    }
                    continue;
                }
            }
        }

        let Some(ipc) = client.as_mut() else {
            unreachable!("client is guaranteed connected here");
        };
        match rx.recv() {
            Ok(a) => {
                let changed = current.as_ref().map(|(c, _)| c != &a).unwrap_or(true);
                if !changed {
                    continue;
                }
                current = Some((a, SystemTime::now()));
                if !push_current(ipc, &current) {
                    // Connection lost; drop it and reconnect on the next pass.
                    client = None;
                }
            }
            // All senders dropped: the dashboard exited — clear the presence
            // so "Playing ..." does not linger on the profile.
            Err(_) => {
                let _ = ipc.clear_activity();
                let _ = ipc.close();
                return;
            }
        }
    }
}
