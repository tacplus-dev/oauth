use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tracing::{info, warn};

use oauth_tacplus::s2sm::internal::grpc::servers::services::oauth::session::SessionHandler;
use oauth_tacplus::s2sm::ServiceManager;
use oauth_tacplus::types::common::tokenrequest::TokenMintRequest;
use oauth_tacplus::types::services::kernel::kernel::mint_client::MintClient;
use oauth_tacplus::types::services::oauth::oauth::{
    session_request, session_response, PendingTokensDeleteRequest, SessionRequest, SessionResponse,
};
use oauth_tacplus::types::services::oauth::oauth_state_service_client::OauthStateServiceClient;

/// FleetwoodImpl implements the FleetwoodServiceHandler trait.
/// Config values are atomic so they can be updated by SM config delivery
/// from kernel without restarting the service.
pub struct FleetwoodImpl {
    sm: Arc<ServiceManager>,
    session_timeout_secs: AtomicU64,
    refresh_lifetime_secs: AtomicI64,
    auto_refresh_before_secs: AtomicI64,
}

impl FleetwoodImpl {
    pub fn new(sm: Arc<ServiceManager>) -> Self {
        Self {
            sm,
            session_timeout_secs: AtomicU64::new(300),
            refresh_lifetime_secs: AtomicI64::new(604800),
            auto_refresh_before_secs: AtomicI64::new(3600),
        }
    }

    /// Apply config values delivered by kernel via SM.
    pub fn apply_session_config(&self, cfg: &oauth_tacplus::types::services::oauth::oauth::Config) {
        let timeout = if cfg.session_timeout_seconds > 0 {
            cfg.session_timeout_seconds as u64
        } else {
            300
        };
        let refresh = if cfg.refresh_token_lifetime_seconds > 0 {
            cfg.refresh_token_lifetime_seconds
        } else {
            604800
        };
        let auto_refresh = if cfg.auto_refresh_before_seconds > 0 {
            cfg.auto_refresh_before_seconds
        } else {
            3600
        };

        self.session_timeout_secs.store(timeout, Ordering::Relaxed);
        self.refresh_lifetime_secs.store(refresh, Ordering::Relaxed);
        self.auto_refresh_before_secs.store(auto_refresh, Ordering::Relaxed);

        info!(
            session_timeout = timeout,
            refresh_lifetime = refresh,
            auto_refresh_before = auto_refresh,
            "session config applied from kernel"
        );
    }

    fn session_timeout(&self) -> u64 {
        self.session_timeout_secs.load(Ordering::Relaxed)
    }

    fn refresh_lifetime(&self) -> i64 {
        self.refresh_lifetime_secs.load(Ordering::Relaxed)
    }

    fn auto_refresh_before(&self) -> i64 {
        self.auto_refresh_before_secs.load(Ordering::Relaxed)
    }
}

/// Exchange a short-lived token for a long-lived one via kernel Mint service.
/// Used by the daemon refresh loop.
/// `trace_id` is forwarded to kernel so the mint hop appears in `cavalierctl trace tail`.
async fn exchange_token(
    sm: &ServiceManager,
    input_token: &str,
    refresh_lifetime_secs: i64,
    trace_id: &str,
) -> Result<String, tonic::Status> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let request = TokenMintRequest {
        input_token: input_token.to_string(),
        exp: now + refresh_lifetime_secs,
        trace_id: trace_id.to_string(),
        ..Default::default()
    };

    let channel = sm.conn().await.ok_or_else(|| {
        tonic::Status::unavailable("no connection to kernel")
    })?;
    let mut client = MintClient::new(channel);
    let resp = client
        .token_mint(request)
        .await
        .map_err(|e| {
            warn!(error = %e, "delegation token exchange failed");
            tonic::Status::internal(format!("token exchange failed: {e}"))
        })?;

    let mint_resp = resp.into_inner();
    mint_resp
        .refresh_token
        .as_ref()
        .map(|t| &t.base64)
        .filter(|b: &&String| !b.is_empty())
        .or_else(|| {
            mint_resp
                .access_token
                .as_ref()
                .map(|t| &t.base64)
                .filter(|b: &&String| !b.is_empty())
        })
        .cloned()
        .ok_or_else(|| tonic::Status::internal("MintService returned empty token"))
}

/// Extract session_id and trace_id from the first streaming message.
async fn recv_session_id(
    inbound: &mut tonic::Streaming<SessionRequest>,
) -> Result<(String, String), tonic::Status> {
    let first = inbound
        .next()
        .await
        .ok_or_else(|| tonic::Status::invalid_argument("empty stream"))?
        .map_err(|e| tonic::Status::invalid_argument(format!("bad first message: {e}")))?;

    let trace_id = first.trace_id.clone();
    match first.msg {
        Some(session_request::Msg::SessionId(id)) => Ok((id, trace_id)),
        _ => Err(tonic::Status::invalid_argument(
            "first message must contain session_id",
        )),
    }
}

#[tonic::async_trait]
impl SessionHandler for FleetwoodImpl {
    async fn session(
        &self,
        _caller: Option<&servicemanager::auth::Caller>,
        request: tonic::Request<tonic::Streaming<SessionRequest>>,
    ) -> Result<
        tonic::Response<
            Pin<
                Box<
                    dyn tokio_stream::Stream<Item = Result<SessionResponse, tonic::Status>> + Send,
                >,
            >,
        >,
        tonic::Status,
    > {
        let bearer_owned = servicemanager::auth::extract_bearer_token(&request)
            .ok()
            .map(|s| s.to_string());

        let mut inbound = request.into_inner();
        let (session_id, _session_trace_id) = recv_session_id(&mut inbound).await?;

        if let Some(bearer_str) = bearer_owned {
            // Authenticated session (daemon mode): verify token, then
            // proactively refresh before expiry.
            let jwk_cache = self.sm.jwk_cache().await;
            let verified = servicemanager::auth::verify_token(&bearer_str, &jwk_cache)
                .map_err(|e| tonic::Status::unauthenticated(format!("invalid token: {e}")))?;

            info!(session_id = %session_id, "authenticated session opened (daemon mode)");

            let (tx, rx) = mpsc::channel(4);
            let sm = Arc::clone(&self.sm);
            let refresh_lifetime = self.refresh_lifetime();
            let auto_refresh_before = self.auto_refresh_before();
            let mut current_token = bearer_str;

            tokio::spawn(async move {
                let mut exp = verified.expiration().unwrap_or(0);

                loop {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    let sleep_secs = (exp - now - auto_refresh_before).max(1) as u64;

                    tokio::time::sleep(Duration::from_secs(sleep_secs)).await;

            match exchange_token(&sm, &current_token, refresh_lifetime, "").await {
                        Ok(new_token) => {
                            info!(session_id = %session_id, "daemon: refreshed token");

                            // Parse new token's expiry for the next refresh cycle.
                            if let Ok(parsed) = token::Token::parse(&new_token) {
                                exp = parsed.expiration().unwrap_or(0);
                            }

                            if tx
                                .send(Ok(SessionResponse {
                                    msg: Some(session_response::Msg::Token(new_token.clone())),
                                    ..Default::default()
                                }))
                                .await
                                .is_err()
                            {
                                info!(session_id = %session_id, "daemon: client disconnected");
                                break;
                            }
                            current_token = new_token;
                        }
                        Err(e) => {
                            warn!(session_id = %session_id, error = %e, "daemon: token refresh failed");
                            let _ = tx
                                .send(Ok(SessionResponse {
                                    msg: Some(session_response::Msg::Error(format!(
                                        "refresh failed: {e}"
                                    ))),
                                    ..Default::default()
                                }))
                                .await;
                            break;
                        }
                    }
                }
            });

            Ok(tonic::Response::new(Box::pin(ReceiverStream::new(rx))))
        } else {
            // Unauthenticated session (initial auth flow): watch kernel state
            // for a PendingSessionToken written by the Callback handler.
            info!(session_id = %session_id, "unauthenticated session opened, watching kernel state for token");

            let (tx, rx) = mpsc::channel(4);
            let sm = Arc::clone(&self.sm);
            let timeout = Duration::from_secs(self.session_timeout());

            tokio::spawn(async move {
                match watch_pending_token(&sm, &session_id, timeout).await {
                    Ok(token) => {
                        info!(session_id = %session_id, "token received from kernel state, delivering to CLI");
                        let _ = tx
                            .send(Ok(SessionResponse {
                                msg: Some(session_response::Msg::Token(token)),
                                ..Default::default()
                            }))
                            .await;
                    }
                    Err(e) => {
                        warn!(session_id = %session_id, error = %e, "session watch failed");
                        let _ = tx
                            .send(Ok(SessionResponse {
                                msg: Some(session_response::Msg::Error(e.to_string())),
                                ..Default::default()
                            }))
                            .await;
                    }
                }
            });

            Ok(tonic::Response::new(Box::pin(ReceiverStream::new(rx))))
        }
    }

}

/// Watch OAuthState.pending_tokens for a token matching `session_id`.
/// Returns the token string on success, or an error if the session times out.
/// Deletes the consumed entry from kernel state after delivery.
async fn watch_pending_token(
    sm: &ServiceManager,
    session_id: &str,
    timeout: Duration,
) -> Result<String, tonic::Status> {
    let channel = sm.conn().await.ok_or_else(|| {
        tonic::Status::unavailable("no connection to kernel")
    })?;
    let svc_token = sm.get_token().await.map_err(|e| {
        tonic::Status::internal(format!("failed to get service token: {e}"))
    })?;

    let mut client = OauthStateServiceClient::new(channel);

    let mut request = tonic::Request::new(Default::default());
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", svc_token).parse().map_err(|_| {
            tonic::Status::internal("invalid token metadata")
        })?,
    );

    let response = client.watch_pending_tokens(request).await.map_err(|e| {
        tonic::Status::internal(format!("failed to start state watch: {e}"))
    })?;
    let mut stream = response.into_inner();

    let result = tokio::time::timeout(timeout, async {
        while let Some(msg) = stream.next().await {
            match msg {
                Ok(entries) => {
                    if let Some(pending) = entries.entries.get(session_id) {
                        if !pending.token.is_empty() {
                            return Ok(pending.token.clone());
                        }
                    }
                }
                Err(e) => {
                    return Err(tonic::Status::internal(format!("state watch error: {e}")));
                }
            }
        }
        Err(tonic::Status::internal("state watch stream ended"))
    })
    .await;

    let token = match result {
        Ok(inner) => inner?,
        Err(_) => return Err(tonic::Status::deadline_exceeded("session timed out waiting for token")),
    };

    // Clean up the consumed entry from kernel state.
    if let Err(e) = delete_pending_token(sm, session_id).await {
        warn!(session_id = %session_id, error = %e, "failed to delete consumed pending token");
    }

    Ok(token)
}

/// Delete a pending token entry from OAuthState.
async fn delete_pending_token(
    sm: &ServiceManager,
    session_id: &str,
) -> Result<(), tonic::Status> {
    let channel = sm.conn().await.ok_or_else(|| {
        tonic::Status::unavailable("no connection to kernel")
    })?;
    let svc_token = sm.get_token().await.map_err(|e| {
        tonic::Status::internal(format!("failed to get service token: {e}"))
    })?;

    let mut client = OauthStateServiceClient::new(channel);
    let mut request = tonic::Request::new(PendingTokensDeleteRequest {
        key: session_id.to_string(),
        ..Default::default()
    });
    request.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", svc_token).parse().map_err(|_| {
            tonic::Status::internal("invalid token metadata")
        })?,
    );

    client.delete_pending_tokens(request).await?;
    Ok(())
}

/// Periodically reap unclaimed pending tokens from kernel state.
/// Reads the current session timeout from FleetwoodImpl (updated by kernel config).
pub async fn reap_expired_tokens(impl_ref: Arc<FleetwoodImpl>) {
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut tick = tokio::time::interval(Duration::from_secs(30));
    loop {
        tick.tick().await;

        let channel = match impl_ref.sm.conn().await {
            Some(c) => c,
            None => continue,
        };
        let svc_token = match impl_ref.sm.get_token().await {
            Ok(t) => t,
            Err(_) => continue,
        };

        let mut client = OauthStateServiceClient::new(channel);

        let mut request = tonic::Request::new(Default::default());
        if let Ok(val) = format!("Bearer {}", svc_token).parse() {
            request.metadata_mut().insert("authorization", val);
        }

        // Get current snapshot of pending tokens.
        let response = match client.watch_pending_tokens(request).await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let mut stream = response.into_inner();

        // Read first batch (current state).
        let entries = match stream.next().await {
            Some(Ok(e)) => e,
            _ => continue,
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let timeout_secs = impl_ref.session_timeout() as i64;
        for (key, pending) in &entries.entries {
            let age = now - pending.created_at;
            if age > timeout_secs {
                warn!(
                    session_id = %key,
                    age_secs = age,
                    "reaping unclaimed pending token"
                );
                if let Err(e) = delete_pending_token(&impl_ref.sm, key).await {
                    warn!(session_id = %key, error = %e, "failed to reap pending token");
                }
            }
        }
    }
}
