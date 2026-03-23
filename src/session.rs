use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::mpsc;

use fleetwood_tacplus::types::services::fleetwood::fleetwood::SessionResponse;

/// Pending session entry: a channel sender and creation time.
struct PendingSession {
    tx: mpsc::Sender<Result<SessionResponse, tonic::Status>>,
    created: Instant,
}

/// SessionRegistry maps session IDs to pending bidi stream senders.
///
/// When cavalierctl opens a Session stream, it registers a session_id here.
/// When the webapp calls InstallToken, we look up the session and deliver
/// the token through the channel.
pub struct SessionRegistry {
    sessions: DashMap<String, PendingSession>,
    timeout: Duration,
}

impl SessionRegistry {
    pub fn new(timeout_seconds: u64) -> Self {
        Self {
            sessions: DashMap::new(),
            timeout: Duration::from_secs(timeout_seconds),
        }
    }

    /// Register a new pending session. Returns a receiver for token delivery.
    pub fn register(
        &self,
        session_id: String,
    ) -> Result<mpsc::Receiver<Result<SessionResponse, tonic::Status>>, tonic::Status> {
        if self.sessions.contains_key(&session_id) {
            return Err(tonic::Status::already_exists("session_id already registered"));
        }

        let (tx, rx) = mpsc::channel(4);
        self.sessions.insert(
            session_id,
            PendingSession {
                tx,
                created: Instant::now(),
            },
        );
        Ok(rx)
    }

    /// Deliver a token to a pending session. Returns an error if the session
    /// does not exist or has timed out.
    pub async fn deliver(
        &self,
        session_id: &str,
        response: SessionResponse,
    ) -> Result<(), tonic::Status> {
        let entry = self
            .sessions
            .remove(session_id)
            .ok_or_else(|| tonic::Status::not_found("no pending session for this session_id"))?;

        let (_, session) = entry;

        if session.created.elapsed() > self.timeout {
            return Err(tonic::Status::deadline_exceeded("session timed out"));
        }

        session
            .tx
            .send(Ok(response))
            .await
            .map_err(|_| tonic::Status::unavailable("session stream closed"))
    }

    /// Remove expired sessions. Called periodically.
    pub fn reap_expired(&self) {
        let timeout = self.timeout;
        self.sessions
            .retain(|_id, session| session.created.elapsed() < timeout);
    }
}
