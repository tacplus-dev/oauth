mod auth;
mod nonce;
mod oidc;
mod service;
mod session;

use std::sync::Arc;

use tokio::time::{interval, Duration};
use tracing_subscriber::EnvFilter;

use oauth_tacplus::s2sm::handler::Handler;
use oauth_tacplus::s2sm::internal::grpc::servers::services::oauth::auth::AuthHandler;
use oauth_tacplus::s2sm::internal::grpc::servers::services::oauth::session::SessionHandler;
use oauth_tacplus::s2sm::internal::grpc::servers::services::oauth::token::TokenHandler;
use oauth_tacplus::s2sm::ServiceManager;
use oauth_tacplus::types::services::oauth::oauth::Config as FleetwoodConfig;
use oauth_tacplus::types::services::oauth::helpers::{config_defaults, config_from_bytes};

use crate::auth::AuthImpl;
use crate::service::FleetwoodImpl;
use crate::session::SessionRegistry;

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

    fn token_grpc_impl(&self) -> Arc<dyn TokenHandler> {
        Arc::clone(&self.fleetwood_impl) as Arc<dyn TokenHandler>
    }

    fn auth_grpc_impl(&self) -> Arc<dyn AuthHandler> {
        Arc::clone(&self.auth_impl) as Arc<dyn AuthHandler>
    }

    async fn session_config(
        &self,
        _cfg: &FleetwoodConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    async fn token_config(
        &self,
        _cfg: &FleetwoodConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
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
    let cfg = load_config();

    tracing::info!(
        session_timeout = cfg.session_timeout_seconds,
        refresh_lifetime = cfg.refresh_token_lifetime_seconds,
        auto_refresh_before = cfg.auto_refresh_before_seconds,
        oauth_enabled = cfg.enable,
        "starting fleetwood"
    );

    let sm = Arc::new(ServiceManager::new().await?);

    // Create session registry with configured timeout.
    let sessions = Arc::new(SessionRegistry::new(cfg.session_timeout_seconds as u64));

    // Spawn periodic reaper for expired sessions.
    let reaper_sessions = Arc::clone(&sessions);
    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            reaper_sessions.reap_expired();
        }
    });

    // Create the session/token handler.
    let fleetwood_impl = Arc::new(FleetwoodImpl::new(
        Arc::clone(&sessions),
        Arc::clone(&sm),
        cfg.refresh_token_lifetime_seconds,
        cfg.auto_refresh_before_seconds,
    ));

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

/// Load fleetwood-specific config from FLEETWOOD_CONFIG env var, or use defaults.
fn load_config() -> FleetwoodConfig {
    let mut cfg = match std::env::var("FLEETWOOD_CONFIG") {
        Ok(data) => config_from_bytes(data.as_bytes()).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "failed to parse FLEETWOOD_CONFIG, using defaults");
            FleetwoodConfig::default()
        }),
        Err(_) => FleetwoodConfig::default(),
    };
    config_defaults(&mut cfg);
    cfg
}
