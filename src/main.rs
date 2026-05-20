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
use oauth_tacplus::types::services::kernel::kernel::{
    CliTokenBrokerRequest, CliTokenBrokerResponse,
    cli_token_broker_request, cli_token_broker_response,
    CliTokenBrokerRegister,
};

use crate::auth::AuthImpl;
use crate::service::FleetwoodImpl;

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

    // Open the managed bidi stream to kernel's CliTokenBroker.
    // on_connect sends Register on each (re)connect.
    // on_message routes token deliveries to pending CLI sessions.
    let instance_id = sm.instance_id().to_string();
    let pending: Arc<tokio::sync::RwLock<std::collections::HashMap<String, tokio::sync::oneshot::Sender<String>>>> =
        Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));

    let pending_for_callback = Arc::clone(&pending);
    tracing::info!("initializing CLI token broker stream");
    let broker_handle = sm.grpc_clients().services().cli_token_broker_client().broker_stream(
        move |tx| {
            let id = instance_id.clone();
            async move {
                let _ = tx.send(CliTokenBrokerRequest {
                    msg: Some(cli_token_broker_request::Msg::Register(
                        CliTokenBrokerRegister { instance_id: id, ..Default::default() },
                    )),
                    ..Default::default()
                }).await;
            }
        },
        Arc::new(move |resp: CliTokenBrokerResponse| {
            let pending = Arc::clone(&pending_for_callback);
            match resp.msg {
                Some(cli_token_broker_response::Msg::TokenDelivery(delivery)) => {
                    let nonce = delivery.nonce;
                    let token = delivery.refresh_token;
                    tokio::spawn(async move {
                        let mut map = pending.write().await;
                        if let Some(sender) = map.remove(&nonce) {
                            let _ = sender.send(token);
                        }
                    });
                }
                Some(cli_token_broker_response::Msg::Error(err)) => {
                    let nonce = err.nonce;
                    tokio::spawn(async move {
                        let mut map = pending.write().await;
                        if let Some(sender) = map.remove(&nonce) {
                            let _ = sender.send(String::new());
                        }
                    });
                }
                _ => {}
            }
        }),
    );

    let fleetwood_impl = Arc::new(FleetwoodImpl::new(Arc::clone(&sm), broker_handle, Arc::clone(&pending)));
    let auth_impl = Arc::new(AuthImpl::new(Arc::clone(&sm), fleetwood_impl.broker_handle(), Arc::clone(&pending)));
    // Note: broker_handle was moved into FleetwoodImpl. AuthImpl borrows it via broker_handle().

    let handler: Arc<dyn Handler> = Arc::new(FleetwoodHandler {
        fleetwood_impl,
        auth_impl,
    });

    sm.run(handler).await
}
