mod auth;
mod nonce;
mod oidc;
mod service;

use std::sync::Arc;

use tracing_subscriber::EnvFilter;

use oauth_tacplus::s2sm::handler::Handler;
use oauth_tacplus::s2sm::internal::grpc::servers::services::oauth::auth::AuthHandler;
use oauth_tacplus::s2sm::internal::grpc::servers::services::oauth::session::SessionHandler;
use oauth_tacplus::s2sm::ServiceManager;
use oauth_tacplus::types::services::oauth::oauth::Config as FleetwoodConfig;

use crate::auth::AuthImpl;
use crate::service::FleetwoodImpl;

/// FleetwoodHandler implements the generated Handler trait.
/// It wires the SM lifecycle to the service implementations.
struct FleetwoodHandler {
    fleetwood_impl: Arc<FleetwoodImpl>,
    auth_impl: Arc<AuthImpl>,
}

#[tonic::async_trait]
impl Handler for FleetwoodHandler {
    fn session_grpc_impl(&self) -> Arc<dyn SessionHandler> {
        Arc::clone(&self.fleetwood_impl) as Arc<dyn SessionHandler>
    }

    fn auth_grpc_impl(&self) -> Arc<dyn AuthHandler> {
        Arc::clone(&self.auth_impl) as Arc<dyn AuthHandler>
    }

    async fn session_config(
        &self,
        cfg: &FleetwoodConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.fleetwood_impl.apply_session_config(cfg);
        Ok(())
    }

    async fn auth_config(
        &self,
        cfg: &FleetwoodConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.auth_impl.apply_config(cfg).await
    }

    async fn shutdown(&self) {
        tracing::info!("fleetwood shutting down");
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("oauth=info".parse().unwrap()),
        )
        .init();

    if let Err(e) = run().await {
        tracing::error!(error = %e, "fleetwood failed");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("starting fleetwood");

    let sm = Arc::new(ServiceManager::new().await?);

    // Create the session handler. Config values (session_timeout, refresh_lifetime,
    // auto_refresh_before) use proto defaults until kernel delivers config via
    // session_config() callback.
    let fleetwood_impl = Arc::new(FleetwoodImpl::new(Arc::clone(&sm)));

    // Spawn periodic reaper for unclaimed pending tokens in kernel state.
    tokio::spawn(service::reap_expired_tokens(Arc::clone(&fleetwood_impl)));

    // Create the auth handler (OAuth2/OIDC browser flows).
    let auth_impl = Arc::new(AuthImpl::new(Arc::clone(&sm)));

    // Build the Handler and run through the generated ServiceManager lifecycle.
    let handler: Arc<dyn Handler> = Arc::new(FleetwoodHandler {
        fleetwood_impl,
        auth_impl,
    });

    // sm.run() handles TLS setup, service registration, and graceful shutdown.
    sm.run(handler).await
}
