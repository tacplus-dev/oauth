use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tracing::{info, warn};

use fleetwood_tacplus::s2sm::internal::grpc::servers::services::fleetwood::session_service::FleetwoodSessionServiceHandler;
use fleetwood_tacplus::s2sm::internal::grpc::servers::services::fleetwood::token_service::FleetwoodTokenServiceHandler;
use fleetwood_tacplus::s2sm::ServiceManager;
use fleetwood_tacplus::types::common::tokenrequest::TokenMintRequest;
use fleetwood_tacplus::types::services::fleetwood::fleetwood::{
    session_request, session_response, InstallTokenRequest, SessionRequest, SessionResponse,
};
use crate::session::SessionRegistry;

/// FleetwoodImpl implements the FleetwoodServiceHandler trait.
pub struct FleetwoodImpl {
    sessions: Arc<SessionRegistry>,
    sm: Arc<ServiceManager>,
    refresh_lifetime_secs: i64,
    auto_refresh_before_secs: i64,
}

impl FleetwoodImpl {
    pub fn new(
        sessions: Arc<SessionRegistry>,
        sm: Arc<ServiceManager>,
        refresh_lifetime_secs: i64,
        auto_refresh_before_secs: i64,
    ) -> Self {
        Self {
            sessions,
            sm,
            refresh_lifetime_secs,
            auto_refresh_before_secs,
        }
    }
}

/// Exchange a short-lived token for a long-lived one via kernel KernelMintService.
/// Shared by install_token and the daemon refresh loop.
async fn exchange_token(
    sm: &ServiceManager,
    input_token: &str,
    refresh_lifetime_secs: i64,
) -> Result<String, tonic::Status> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let request = TokenMintRequest {
        input_token: input_token.to_string(),
        exp: now + refresh_lifetime_secs,
        ..Default::default()
    };

    let resp = sm
        .grpc_clients()
        .services()
        .kernel_mint_service_client()
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
        .filter(|b| !b.is_empty())
        .or_else(|| {
            mint_resp
                .access_token
                .as_ref()
                .map(|t| &t.base64)
                .filter(|b| !b.is_empty())
        })
        .cloned()
        .ok_or_else(|| tonic::Status::internal("MintService returned empty token"))
}

/// Extract session_id from the first streaming message.
async fn recv_session_id(
    inbound: &mut tonic::Streaming<SessionRequest>,
) -> Result<String, tonic::Status> {
    let first = inbound
        .next()
        .await
        .ok_or_else(|| tonic::Status::invalid_argument("empty stream"))?
        .map_err(|e| tonic::Status::invalid_argument(format!("bad first message: {e}")))?;

    match first.msg {
        Some(session_request::Msg::SessionId(id)) => Ok(id),
        _ => Err(tonic::Status::invalid_argument(
            "first message must contain session_id",
        )),
    }
}

#[tonic::async_trait]
impl FleetwoodSessionServiceHandler for FleetwoodImpl {
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
        let session_id = recv_session_id(&mut inbound).await?;

        if let Some(bearer_str) = bearer_owned {
            // Authenticated session (daemon mode): verify token, then
            // proactively refresh before expiry.
            let jwk_cache = self.sm.jwk_cache().await;
            let verified = servicemanager::auth::verify_token(&bearer_str, &jwk_cache)
                .map_err(|e| tonic::Status::unauthenticated(format!("invalid token: {e}")))?;

            info!(session_id = %session_id, "authenticated session opened (daemon mode)");

            let (tx, rx) = mpsc::channel(4);
            let sm = Arc::clone(&self.sm);
            let refresh_lifetime = self.refresh_lifetime_secs;
            let auto_refresh_before = self.auto_refresh_before_secs;
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

                    match exchange_token(&sm, &current_token, refresh_lifetime).await {
                        Ok(new_token) => {
                            info!(session_id = %session_id, "daemon: refreshed token");

                            // Parse new token's expiry for the next refresh cycle.
                            if let Ok(parsed) = token::Token::parse(&new_token) {
                                exp = parsed.expiration().unwrap_or(0);
                            }

                            if tx
                                .send(Ok(SessionResponse {
                                    msg: Some(session_response::Msg::Token(new_token.clone())),
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
                                }))
                                .await;
                            break;
                        }
                    }
                }
            });

            Ok(tonic::Response::new(Box::pin(ReceiverStream::new(rx))))
        } else {
            // Unauthenticated session (initial auth flow): register and
            // wait for install_token to deliver the token.
            info!(session_id = %session_id, "unauthenticated session opened, waiting for token");

            let rx = self.sessions.register(session_id)?;
            Ok(tonic::Response::new(Box::pin(ReceiverStream::new(rx))))
        }
    }

}

#[tonic::async_trait]
impl FleetwoodTokenServiceHandler for FleetwoodImpl {
    async fn install_token(
        &self,
        _caller: Option<&servicemanager::auth::Caller>,
        req: InstallTokenRequest,
    ) -> Result<(), tonic::Status> {
        let session_id = &req.session_id;
        let short_lived_token = &req.token;

        info!(session_id = %session_id, "InstallToken called, exchanging token");

        let long_lived_token =
            exchange_token(&self.sm, short_lived_token, self.refresh_lifetime_secs).await?;

        let response = SessionResponse {
            msg: Some(session_response::Msg::Token(long_lived_token)),
        };

        self.sessions.deliver(session_id, response).await?;

        info!(session_id = %session_id, "token delivered to CLI session");

        Ok(())
    }
}
