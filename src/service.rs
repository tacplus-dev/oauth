use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, RwLock};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tracing::{info, warn};

use oauth_model::s2sm::internal::grpc::servers::services::oauth::session::SessionHandler;
use oauth_model::s2sm::ServiceManager;
use oauth_model::types::common::tokenrequest::TokenMintRequest;
use oauth_model::types::services::kernel::kernel::{
    CliTokenBrokerRequest, cli_token_broker_request, CliTokenBrokerRegisterNonce,
};
use oauth_model::s2sm::internal::grpc::clients::services::kernel::cli_token_broker::BrokerStreamBidiHandle;
use oauth_model::types::services::oauth::oauth::{
    session_request, session_response, SessionRequest, SessionResponse,
};

pub struct OauthImpl {
    sm: Arc<ServiceManager>,
    broker: BrokerStreamBidiHandle,
    pending: Arc<RwLock<HashMap<String, oneshot::Sender<String>>>>,
    session_timeout_secs: AtomicU64,
    refresh_lifetime_secs: AtomicI64,
    auto_refresh_before_secs: AtomicI64,
}

impl OauthImpl {
    pub fn new(
        sm: Arc<ServiceManager>,
        broker: BrokerStreamBidiHandle,
        pending: Arc<RwLock<HashMap<String, oneshot::Sender<String>>>>,
    ) -> Self {
        Self {
            sm,
            broker,
            pending,
            session_timeout_secs: AtomicU64::new(300),
            refresh_lifetime_secs: AtomicI64::new(604800),
            auto_refresh_before_secs: AtomicI64::new(3600),
        }
    }

    pub fn broker_handle(&self) -> &BrokerStreamBidiHandle {
        &self.broker
    }

    pub fn apply_session_config(&self, cfg: &oauth_model::types::services::oauth::oauth::Config) {
        let timeout = if cfg.session_timeout_seconds > 0 { cfg.session_timeout_seconds as u64 } else { 300 };
        let refresh = if cfg.refresh_token_lifetime_seconds > 0 { cfg.refresh_token_lifetime_seconds } else { 604800 };
        let auto_refresh = if cfg.auto_refresh_before_seconds > 0 { cfg.auto_refresh_before_seconds } else { 3600 };
        self.session_timeout_secs.store(timeout, Ordering::Relaxed);
        self.refresh_lifetime_secs.store(refresh, Ordering::Relaxed);
        self.auto_refresh_before_secs.store(auto_refresh, Ordering::Relaxed);
        info!(session_timeout = timeout, refresh_lifetime = refresh, auto_refresh_before = auto_refresh, "session config applied from kernel");
    }

    fn session_timeout(&self) -> u64 { self.session_timeout_secs.load(Ordering::Relaxed) }
    fn refresh_lifetime(&self) -> i64 { self.refresh_lifetime_secs.load(Ordering::Relaxed) }
    fn auto_refresh_before(&self) -> i64 { self.auto_refresh_before_secs.load(Ordering::Relaxed) }
}

async fn exchange_token(sm: &ServiceManager, input_token: &str, refresh_lifetime_secs: i64, trace_id: &str) -> Result<String, tonic::Status> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let request = TokenMintRequest {
        input_token: input_token.to_string(),
        exp: now + refresh_lifetime_secs,
        trace_id: trace_id.to_string(),
        ..Default::default()
    };
    let resp = sm.s2s().kernel().mint_client()
        .mint_token(request)
        .await
        .map_err(|e| {
            warn!(error = %e, "delegation token exchange failed");
            tonic::Status::internal(format!("token exchange failed: {e}"))
        })?;
    let mint_resp = resp.into_inner();
    mint_resp.refresh_token.as_ref().map(|t| &t.base64).filter(|b: &&String| !b.is_empty())
        .or_else(|| mint_resp.access_token.as_ref().map(|t| &t.base64).filter(|b: &&String| !b.is_empty()))
        .cloned()
        .ok_or_else(|| tonic::Status::internal("MintService returned empty token"))
}

async fn recv_session_id<S>(inbound: &mut S) -> Result<(String, String), tonic::Status>
where
    S: tokio_stream::Stream<Item = Result<SessionRequest, tonic::Status>> + Unpin,
{
    let first = inbound.next().await
        .ok_or_else(|| tonic::Status::invalid_argument("empty stream"))?
        .map_err(|e| tonic::Status::invalid_argument(format!("bad first message: {e}")))?;
    let trace_id = first.trace_id.clone();
    match first.msg {
        Some(session_request::Msg::SessionId(id)) => Ok((id, trace_id)),
        _ => Err(tonic::Status::invalid_argument("first message must contain session_id")),
    }
}

#[tonic::async_trait]
impl SessionHandler for OauthImpl {
    async fn broker_session(
        &self,
        _caller: Option<&servicemanager::auth::Caller>,
        request: tonic::Request<Pin<Box<dyn tokio_stream::Stream<Item = Result<SessionRequest, tonic::Status>> + Send>>>,
    ) -> Result<tonic::Response<Pin<Box<dyn tokio_stream::Stream<Item = Result<SessionResponse, tonic::Status>> + Send>>>, tonic::Status> {
        let bearer_owned = servicemanager::auth::extract_bearer_token(&request).ok().map(|s| s.to_string());
        let mut inbound = request.into_inner();
        let (session_id, _trace_id) = recv_session_id(&mut inbound).await?;

        if let Some(bearer_str) = bearer_owned {
            // Authenticated session (daemon mode) — proactive refresh
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
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
                    let sleep_secs = (exp - now - auto_refresh_before).max(1) as u64;
                    tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
                    match exchange_token(&sm, &current_token, refresh_lifetime, "").await {
                        Ok(new_token) => {
                            info!(session_id = %session_id, "daemon: refreshed token");
                            if let Ok(parsed) = token::Token::parse(&new_token) { exp = parsed.expiration().unwrap_or(0); }
                            if tx.send(Ok(SessionResponse { msg: Some(session_response::Msg::Token(new_token.clone())), ..Default::default() })).await.is_err() {
                                info!(session_id = %session_id, "daemon: client disconnected");
                                break;
                            }
                            current_token = new_token;
                        }
                        Err(e) => {
                            warn!(session_id = %session_id, error = %e, "daemon: token refresh failed");
                            let _ = tx.send(Ok(SessionResponse { msg: Some(session_response::Msg::Error(format!("refresh failed: {e}"))), ..Default::default() })).await;
                            break;
                        }
                    }
                }
            });
            Ok(tonic::Response::new(Box::pin(ReceiverStream::new(rx))))
        } else {
            // Unauthenticated session — register nonce with kernel broker, wait for token
            info!(session_id = %session_id, "unauthenticated session opened, registering nonce with broker");

            let (reply_tx, reply_rx) = oneshot::channel();
            { self.pending.write().await.insert(session_id.clone(), reply_tx); }

            self.broker.send(CliTokenBrokerRequest {
                msg: Some(cli_token_broker_request::Msg::RegisterNonce(
                    CliTokenBrokerRegisterNonce { nonce: session_id.clone(), ..Default::default() },
                )),
                ..Default::default()
            }).await?;

            let (tx, rx) = mpsc::channel(4);
            let timeout = Duration::from_secs(self.session_timeout());
            tokio::spawn(async move {
                match tokio::time::timeout(timeout, reply_rx).await {
                    Ok(Ok(token)) if !token.is_empty() => {
                        info!(session_id = %session_id, "token received from broker, delivering to CLI");
                        let _ = tx.send(Ok(SessionResponse { msg: Some(session_response::Msg::Token(token)), ..Default::default() })).await;
                    }
                    Ok(Ok(_)) => {
                        warn!(session_id = %session_id, "broker returned empty token");
                        let _ = tx.send(Ok(SessionResponse { msg: Some(session_response::Msg::Error("authentication failed".into())), ..Default::default() })).await;
                    }
                    Ok(Err(_)) => {
                        warn!(session_id = %session_id, "broker sender dropped");
                        let _ = tx.send(Ok(SessionResponse { msg: Some(session_response::Msg::Error("session expired".into())), ..Default::default() })).await;
                    }
                    Err(_) => {
                        warn!(session_id = %session_id, "session timed out waiting for authentication");
                        let _ = tx.send(Ok(SessionResponse { msg: Some(session_response::Msg::Error("session timed out waiting for token".into())), ..Default::default() })).await;
                    }
                }
            });
            Ok(tonic::Response::new(Box::pin(ReceiverStream::new(rx))))
        }
    }
}
